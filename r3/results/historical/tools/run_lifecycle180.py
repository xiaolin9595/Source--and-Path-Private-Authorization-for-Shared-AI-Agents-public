#!/usr/bin/env python3
"""Real RA/state/revocation publication and holder-refresh E4 grid."""
from __future__ import annotations

import argparse
import atexit
import base64
import copy
import fcntl
import hashlib
import json
import os
import random
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

LOOPBACK_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def tagged(tag: bytes, value: object) -> str:
    return hashlib.sha256(tag + b"\0" + canonical(value)).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_manifest(root: Path) -> list[dict[str, object]]:
    paths = [root / "Cargo.toml", root / "Cargo.lock", root / "service" / "service.py"]
    paths += sorted((root / "src").rglob("*.rs"))
    return [
        {
            "path": str(path.relative_to(root)),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in paths
    ]


class Clock:
    def __init__(self, now: int): self.now = now
    def __call__(self) -> int: return self.now


def http(port: int, path: str, body: bytes | None = None, headers: dict[str, str] | None = None) -> tuple[int, object, bytes]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=body, headers=headers or {},
        method="POST" if body is not None else "GET",
    )
    try:
        with LOOPBACK_OPENER.open(request, timeout=300) as response:
            raw = response.read(); return response.status, json.loads(raw), raw
    except urllib.error.HTTPError as error:
        raw = error.read(); return error.code, json.loads(raw), raw


def command(argv: list[str], env: dict[str, str], timeout: int = 1800) -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.perf_counter_ns()
    result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=timeout, check=False)
    return result, (time.perf_counter_ns() - started) / 1e6


def json_command(argv: list[str], env: dict[str, str], timeout: int = 1800) -> tuple[dict, float]:
    result, elapsed = command(argv, env, timeout)
    if result.returncode:
        raise RuntimeError({"argv": argv, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr})
    value = json.loads(result.stdout)
    if isinstance(value, dict) and "error" in value:
        raise RuntimeError({"argv": argv, "value": value})
    return value, elapsed


def serve(app, handler_for, error_path: Path):
    from http.server import ThreadingHTTPServer

    base_handler = handler_for(app)

    class CapturingHandler(base_handler):
        def handle(self):
            try:
                super().handle()
            except BaseException:
                with error_path.open("a") as stream:
                    stream.write("handler-base-exception\n")
                    traceback.print_exc(file=stream)
                raise

    class CapturingHTTPServer(ThreadingHTTPServer):
        def handle_error(self, request, client_address):
            with error_path.open("a") as stream:
                stream.write(f"client={client_address!r}\n")
                traceback.print_exc(file=stream)

    server = CapturingHTTPServer(("127.0.0.1", 0), CapturingHandler)

    def server_loop():
        try:
            server.serve_forever()
        except BaseException:
            with error_path.open("a") as stream:
                stream.write("server-loop-base-exception\n")
                traceback.print_exc(file=stream)
            raise

    threading.Thread(target=server_loop, daemon=True).start()
    return server


def post_ok(port: int, path: str, payload: dict, expected: int = 201) -> tuple[dict, float]:
    started = time.perf_counter_ns()
    status, value, _ = http(port, path, canonical(payload), {"Content-Type": "application/json"})
    elapsed = (time.perf_counter_ns() - started) / 1e6
    if status != expected: raise RuntimeError((path, status, value))
    return value, elapsed


def sign_header(mutation: str, snapshot: dict, env: dict[str, str]) -> str:
    value, _ = json_command([mutation, "sign-header", canonical(snapshot).decode()], env)
    return value["signature_b64"]


def refresh(agent: str, pk: Path, vk: Path, public_file: Path, private_file: Path, registry_pk: str, nonce: int,
            ds: int, dra: int, drev: int, now: int, audience: str, body: bytes, env: dict[str, str]) -> tuple[dict, float]:
    return json_command([
        agent, "refresh", str(pk), str(vk), str(public_file), str(private_file), registry_pk, str(nonce),
        str(ds), str(dra), str(drev), str(now), audience, body.decode(),
    ], env)


class ResidentHolder:
    def __init__(self, agent: str, pk: Path, vk: Path, registry_pk: str, ds: int, dra: int, drev: int,
                 audience: str, body: bytes, env: dict[str, str], stderr_path: Path):
        self.stderr_stream = stderr_path.open("w")
        self.process = subprocess.Popen(
            [agent, "refresh-serve", str(pk), str(vk), registry_pk, str(ds), str(dra), str(drev), audience, body.decode()],
            env=env, text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.stderr_stream,
        )
        assert self.process.stdout is not None
        ready_line = self.process.stdout.readline()
        if not ready_line:
            raise RuntimeError("resident holder exited before ready")
        self.ready = json.loads(ready_line)
        if self.ready.get("ready") is not True:
            raise RuntimeError(self.ready)
        self.closed = False
        atexit.register(self.close)

    def request(self, public_file: Path, private_file: Path, nonce: int, now: int) -> tuple[dict, float]:
        assert self.process.stdin is not None and self.process.stdout is not None
        started = time.perf_counter_ns()
        self.process.stdin.write(json.dumps({
            "public_path":str(public_file), "private_path":str(private_file), "nonce":nonce, "now":now,
        }, separators=(",", ":")) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        elapsed = (time.perf_counter_ns() - started) / 1e6
        if not line:
            raise RuntimeError(f"resident holder exited with {self.process.poll()}")
        return json.loads(line), elapsed

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.process.stdin is not None:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=10)
        self.stderr_stream.close()


def invoke(port: int, artifact: dict, body: bytes) -> tuple[int, object, float]:
    started = time.perf_counter_ns()
    status, value, _ = http(
        port, "/resource/read", body,
        {"X-PlanA-Authorization": json.dumps(artifact["envelope"], separators=(",", ":"))},
    )
    return status, value, (time.perf_counter_ns() - started) / 1e6


def direct_verify(core: str, artifact: dict, body: bytes, env: dict[str, str]) -> tuple[bool, float]:
    envelope = artifact["envelope"]
    snapshot = artifact["snapshot"]
    request = {key: envelope[key] for key in (
        "protocol_version", "deployment_id", "audience", "resource", "action_onehot", "nonce",
        "request_time", "expires_at", "terminal_agent_pk", "circuit_id", "vk_id", "snapshot_digest",
    )}
    request.update(method="POST", path="/resource/read", body_sha256=hashlib.sha256(body).hexdigest())
    request_digest = tagged(b"plan-a-request-v1", request)
    payload = {
        "command": "verify", "vk_id": envelope["vk_id"],
        "public_statement": {"snapshot": snapshot, "request": request,
                             "canonical_request_sha256": request_digest,
                             "relation_request_digest": envelope["relation_request_digest"]},
        "proof_b64": envelope["proof_b64"],
    }
    started = time.perf_counter_ns()
    checked = subprocess.run([core], input=canonical(payload) + b"\n", env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300, check=False)
    elapsed = (time.perf_counter_ns() - started) / 1e6
    if checked.returncode: return False, elapsed
    return json.loads(checked.stdout).get("valid") is True, elapsed


def negative_refresh(holder: ResidentHolder, payload: dict, private: dict, nonce: int, path: Path) -> dict:
    path.write_bytes(canonical(payload))
    private_path=path.with_name(path.stem+"-private.json"); private_path.write_bytes(canonical(private))
    value, elapsed = holder.request(path, private_path, nonce, 150)
    return {"rejected": "error" in value, "error": value.get("error"), "wall_ms": elapsed}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--populations", type=int, nargs="+", default=[16, 128, 1024])
    parser.add_argument("--updates", type=int, nargs="+", default=[1, 8])
    parser.add_argument("--deltas", type=int, nargs="+", default=[0, 5, 15])
    parser.add_argument("--seeds", type=int, nargs="+", default=[1, 2, 3])
    parser.add_argument("--schedule-seed", type=int, default=20261024)
    parser.add_argument("--key-cache", type=Path)
    parser.add_argument("--bootstrap-cache", type=Path)
    parser.add_argument("--lock", type=Path, default=Path("${REMOTE_DATA}/pets2027/results/.experiment.lock"))
    args = parser.parse_args()
    if socket.gethostname() != "experiment-node": raise SystemExit("must run on experiment-node")
    args.out.mkdir(parents=True, exist_ok=False)
    os.chdir(args.source)
    service_dir = args.source / "service"
    sys.path.insert(0, str(service_dir))
    from service import App, CoreVerifier, Store, handler_for

    env = os.environ.copy()
    env.update(PATH=str(Path.home()/".cargo"/"bin") + os.pathsep + env.get("PATH", ""),
               RAYON_NUM_THREADS="10", OMP_NUM_THREADS="1", CARGO_BUILD_JOBS="10", CARGO_TERM_COLOR="never")
    binaries = {name: args.source / "target" / "release" / name for name in (
        "plan_a_agent_cli", "plan_a_service_core", "plan_a_mutation_cli", "plan_a_population_cli", "plan_a_proof_cli")}
    ds, dra, drev = 10, 10, 32
    audience, body, now = "https://service.example", b"payload", 150
    key_dir = args.key_cache if args.key_cache is not None else args.out
    pk, vk = key_dir / "l3-ds10-dra10-drev32.pk", key_dir / "l3-ds10-dra10-drev32.vk"
    rows: list[dict] = []
    failures: list[dict] = []
    cell_schedule: list[dict[str, int]] = []
    with args.lock.open("a+") as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error: raise SystemExit("global lock busy") from error
        rustc, _ = command(["rustc", "--version"], env)
        if rustc.returncode or not rustc.stdout.startswith("rustc 1.95.0 "): raise SystemExit(rustc.stdout)
        build, build_ms = command(["taskset", "-c", "0-9", "cargo", "build", "--locked", "--release", "--bins"], env, 3600)
        (args.out/"BUILD.stdout").write_text(build.stdout); (args.out/"BUILD.stderr").write_text(build.stderr)
        if build.returncode: raise SystemExit("build failed")
        if args.key_cache is None:
            setup, setup_ms = json_command([str(binaries["plan_a_proof_cli"]), "setup", str(pk), str(vk), "3", str(ds), str(dra), str(drev)], env, 3600)
            (args.out/"SETUP.json").write_text(json.dumps(setup, indent=2)+"\n")
        else:
            if not pk.is_file() or not vk.is_file():
                raise SystemExit("key cache is incomplete")
            setup = {
                "reused": True,
                "key_cache": str(args.key_cache),
                "pk_sha256": sha256_file(pk),
                "vk_sha256": sha256_file(vk),
            }
            setup_ms = 0.0
            (args.out/"SETUP_REUSED.json").write_text(json.dumps(setup, indent=2)+"\n")
        if args.bootstrap_cache is None:
            artifact, bootstrap_ms = json_command([str(binaries["plan_a_agent_cli"]), str(pk), str(vk), "3", "2", "10", str(ds), str(dra), str(drev), str(now), audience, body.decode()], env)
            bootstrap_cache = args.out / "BOOTSTRAP_PRIVATE.json"
            bootstrap_cache.write_bytes(canonical(artifact))
            bootstrap_cache.chmod(0o600)
        else:
            artifact = json.loads(args.bootstrap_cache.read_text())
            bootstrap_ms = 0.0
            (args.out / "BOOTSTRAP_REUSED.json").write_text(json.dumps({
                "source": str(args.bootstrap_cache),
                "sha256": sha256_file(args.bootstrap_cache),
            }, indent=2) + "\n")
        env.update(PLAN_A_VK_PATH=str(vk), PLAN_A_VK_ID=artifact["vk_id"], PLAN_A_L="3", PLAN_A_DS=str(ds),
                   PLAN_A_DRA=str(dra), PLAN_A_DREV=str(drev), PLAN_A_REGISTRY_PK_B64=artifact["registry_pk_b64"],
                   PLAN_A_DEPLOYMENT_ID=artifact["bootstrap_admission"]["deployment_id"])
        os.environ.update({
            key: value for key, value in env.items() if key.startswith("PLAN_A_")
        })
        support_h0, _ = json_command([
            str(binaries["plan_a_agent_cli"]), "private-support", "fixed-root-position-0-v1"
        ], env)
        support_h1, _ = json_command([
            str(binaries["plan_a_agent_cli"]), "private-support", "fixed-root-position-1-v1"
        ], env)
        for name, support in (("HOLDER_SUPPORT_H0_PRIVATE.json", support_h0),
                              ("HOLDER_SUPPORT_H1_PRIVATE.json", support_h1)):
            support_path = args.out / name
            support_path.write_bytes(canonical(support))
            support_path.chmod(0o600)
        with tempfile.TemporaryDirectory(dir=args.out) as temporary:
            temp = Path(temporary)
            probe_app = App(
                Store(temp / "direct-enroll-probe.db"),
                CoreVerifier([str(binaries["plan_a_service_core"])], 300),
                0,
                audience,
                Clock(now),
                env["PLAN_A_DEPLOYMENT_ID"],
            )
            probe_status, probe_value = probe_app.enroll(canonical(artifact["bootstrap_admission"]))
            (args.out / "DIRECT_ENROLL_PROBE.json").write_text(
                json.dumps({"status": probe_status, "value": probe_value}, indent=2) + "\n"
            )
            if probe_status != 201:
                raise RuntimeError(("direct-enroll-probe", probe_status, probe_value))
            holder = ResidentHolder(
                str(binaries["plan_a_agent_cli"]), pk, vk, artifact["registry_pk_b64"], ds, dra, drev,
                audience, body, env, args.out / "RESIDENT_HOLDER.stderr",
            )
            (args.out / "RESIDENT_HOLDER_READY.json").write_text(json.dumps(holder.ready, indent=2) + "\n")
            schedule_rng = random.Random(args.schedule_seed)
            base_specs = [(population, seed) for population in args.populations for seed in args.seeds]
            schedule_rng.shuffle(base_specs)
            for base_schedule_index, (population, seed) in enumerate(base_specs):
                    base_db = temp / f"base-n{population}-s{seed}.db"
                    clock = Clock(now)
                    app = App(Store(base_db), CoreVerifier([str(binaries["plan_a_service_core"])], 300), 0, audience, clock, env["PLAN_A_DEPLOYMENT_ID"])
                    server = serve(app, handler_for, args.out / "HTTP_SERVER_ERRORS.log"); port = server.server_port
                    post_ok(port, "/admin/enroll", artifact["bootstrap_admission"])
                    post_ok(port, "/admin/ra-register", artifact["bootstrap_ra_registration"])
                    population_doc, _ = json_command([str(binaries["plan_a_population_cli"]), "population", str(population), str(seed)], env)
                    enroll_ms = 0.0
                    for item in population_doc["background_rows"]:
                        _, elapsed = post_ok(port, "/admin/enroll", item["admission"]); enroll_ms += elapsed
                        _, elapsed = post_ok(port, "/admin/ra-register", item["ra_registration"]); enroll_ms += elapsed
                    roots = app.verifier.response(app.store.materialization_inputs(env["PLAN_A_DEPLOYMENT_ID"]))
                    assert roots and roots["ra_count"] == roots["state_count"] == population and roots["revocation_count"] == 0, roots
                    h0 = dict(artifact["snapshot"])
                    h0.update(tuple_version=1, ra_root=roots["ra_root"], state_root=roots["state_root"], revocation_root=roots["revocation_root"], state_epoch=55, issued_at=now)
                    h0_signature = sign_header(str(binaries["plan_a_mutation_cli"]), h0, env)
                    status, value, _ = http(port, "/admin/header", canonical(h0), {"X-PlanA-Header-Signature":h0_signature})
                    assert status == 201, (status, value)
                    h0_digest = value["snapshot_digest"]
                    status, _, h0_raw = http(port, f"/public/versions/{h0_digest}/leaves"); assert status == 200
                    h0_file = temp / f"h0-n{population}-s{seed}.json"; h0_file.write_bytes(h0_raw)
                    private_h0={"schema":"plan-a-private-holder-v1",
                        "support_model":"explicit-deterministic-signed-synthetic-profile-v1",
                        "holder_profile":"fixed-root-position-0-v1",
                        "complete_support":support_h0,
                        "deployment_id":artifact["bootstrap_admission"]["deployment_id"],
                        "minimum_tuple_version":1,"expected_snapshot_digest":h0_digest,
                        "private_index":{"ra_position":0,"state_position":artifact["bootstrap_admission"]["position"],"grant_position":0},
                        "state":{"owner_commitment":artifact["bootstrap_admission"]["owner_commitment"],
                        "grant_root":artifact["bootstrap_admission"]["initial_opening"]["grant_root"],
                        "state_version":artifact["bootstrap_admission"]["initial_version"],
                        "state_epoch":artifact["bootstrap_admission"]["initial_epoch"],
                        "state_expiry":artifact["bootstrap_admission"]["initial_opening"]["state_expiry"],
                        "active":artifact["bootstrap_admission"]["initial_opening"]["active"],
                        "salt":artifact["bootstrap_admission"]["initial_opening"]["salt"],
                        "position":artifact["bootstrap_admission"]["position"]}}
                    private_h0_file=temp/f"private-h0-n{population}-s{seed}.json"; private_h0_file.write_bytes(canonical(private_h0))
                    old_artifacts = []
                    for suffix in (1, 2):
                        old, _ = holder.request(
                            h0_file, private_h0_file, population*100000 + seed*100 + suffix, now,
                        )
                        if "error" in old: raise RuntimeError(old)
                        old_artifacts.append(old)
                    valid, initial_verify_ms = direct_verify(str(binaries["plan_a_service_core"]), old_artifacts[0], body, env)
                    assert valid
                    server.shutdown(); server.server_close()
                    with sqlite3.connect(base_db) as connection:
                        connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    cell_specs = [(update_count, delta) for update_count in args.updates for delta in args.deltas]
                    schedule_rng.shuffle(cell_specs)
                    updates_cache: dict[int, dict] = {}
                    for update_count, delta in cell_specs:
                            if update_count not in updates_cache:
                                updates_cache[update_count], _ = json_command([
                                    str(binaries["plan_a_population_cli"]), "updates", str(population),
                                    str(seed), str(update_count),
                                ], env)
                            updates_doc = updates_cache[update_count]
                            cell_schedule.append({
                                "trial_order_index": len(cell_schedule),
                                "base_schedule_index": base_schedule_index,
                                "population_n": population,
                                "update_count_per_registry": update_count,
                                "delta_seconds": delta,
                                "seed": seed,
                            })
                            cell_db = temp / f"cell-n{population}-u{update_count}-d{delta}-s{seed}.db"
                            shutil.copy2(base_db, cell_db)
                            cell_clock = Clock(now)
                            cell_app = App(Store(cell_db), CoreVerifier([str(binaries["plan_a_service_core"])], 300), delta, audience, cell_clock, env["PLAN_A_DEPLOYMENT_ID"])
                            cell_server = serve(cell_app, handler_for, args.out / "HTTP_SERVER_ERRORS.log"); cell_port = cell_server.server_port
                            update_timings = {"ra_ms": 0.0, "state_ms": 0.0, "revocation_ms": 0.0}
                            for item in updates_doc["rows"]:
                                _, elapsed = post_ok(cell_port, "/admin/ra-update", item["ra_update"]); update_timings["ra_ms"] += elapsed
                                _, elapsed = post_ok(cell_port, "/admin/state-update", item["state_update"]); update_timings["state_ms"] += elapsed
                                _, elapsed = post_ok(cell_port, "/admin/revoke", item["revocation"]); update_timings["revocation_ms"] += elapsed
                            holder_update, _ = json_command([str(binaries["plan_a_mutation_cli"]), "holder-state-update"], env)
                            holder_profile = holder_update.pop("holder_profile")
                            _, holder_own_state_update_ms = post_ok(cell_port, "/admin/state-update", holder_update)
                            materialize_start = time.perf_counter_ns()
                            updated_roots = cell_app.verifier.response(cell_app.store.materialization_inputs(env["PLAN_A_DEPLOYMENT_ID"]))
                            materialize_ms = (time.perf_counter_ns()-materialize_start)/1e6
                            assert updated_roots and updated_roots["ra_count"] == updated_roots["state_count"] == population
                            assert updated_roots["revocation_count"] == update_count
                            h1 = dict(h0); h1.update(tuple_version=2, ra_root=updated_roots["ra_root"], state_root=updated_roots["state_root"],
                                                         revocation_root=updated_roots["revocation_root"], state_epoch=64,
                                                         revocation_epoch=h0["revocation_epoch"]+update_count)
                            h1_signature = sign_header(str(binaries["plan_a_mutation_cli"]), h1, env)
                            publish_start = time.perf_counter_ns()
                            status, installed, _ = http(cell_port, "/admin/header", canonical(h1), {"X-PlanA-Header-Signature":h1_signature})
                            publish_ms = (time.perf_counter_ns()-publish_start)/1e6
                            assert status == 201, (status, installed)
                            get_start = time.perf_counter_ns(); status, latest, latest_raw = http(cell_port, "/public/versions/latest")
                            latest_ms = (time.perf_counter_ns()-get_start)/1e6; assert status == 200
                            get_start = time.perf_counter_ns(); status, public_doc, public_raw = http(cell_port, f"/public/versions/{latest['snapshot_digest']}/leaves")
                            download_ms = (time.perf_counter_ns()-get_start)/1e6; assert status == 200
                            public_file = temp / f"public-n{population}-u{update_count}-d{delta}-s{seed}.json"; public_file.write_bytes(public_raw)
                            private_h1=copy.deepcopy(private_h0); private_h1.update(minimum_tuple_version=2,expected_snapshot_digest=latest["snapshot_digest"])
                            private_h1.update(holder_profile=holder_profile)
                            private_h1["complete_support"] = support_h1
                            private_h1["private_index"]["grant_position"] = 1
                            private_h1["state"].update(state_version=1,state_epoch=64,state_expiry=holder_update["opening"]["state_expiry"],
                                                       active=holder_update["opening"]["active"],salt=holder_update["opening"]["salt"],
                                                       grant_root=holder_update["opening"]["grant_root"])
                            private_h1_file=temp/f"private-h1-n{population}-u{update_count}-d{delta}-s{seed}.json"; private_h1_file.write_bytes(canonical(private_h1))
                            fresh, holder_total_ms = holder.request(
                                public_file, private_h1_file,
                                population*1000000+update_count*10000+delta*100+seed, now,
                            )
                            if "error" in fresh: raise RuntimeError(fresh)
                            if not (args.out / "PUBLIC_RECONSTRUCTED_PATHS_SAMPLE.json").exists():
                                (args.out / "PUBLIC_RECONSTRUCTED_PATHS_SAMPLE.json").write_bytes(
                                    canonical(fresh["public_reconstructed_paths"])
                                )
                            proof_valid, verify_ms = direct_verify(str(binaries["plan_a_service_core"]), fresh, body, env); assert proof_valid
                            fresh_status, _, fresh_http_ms = invoke(cell_port, fresh, body); assert fresh_status == 200
                            if delta == 0:
                                old_status, _, old_http_ms = invoke(cell_port, old_artifacts[0], body)
                                delta_checks = {"retired_immediate_status": old_status, "expected": 401, "http_ms": old_http_ms}
                                assert old_status == 401
                            else:
                                cell_clock.now = now + delta
                                boundary_status, _, boundary_ms = invoke(cell_port, old_artifacts[0], body); assert boundary_status == 200
                                cell_clock.now = now + delta + 1
                                after_status, _, after_ms = invoke(cell_port, old_artifacts[1], body); assert after_status == 401
                                delta_checks = {"inclusive_boundary_status":boundary_status,"inclusive_boundary_http_ms":boundary_ms,
                                                "after_boundary_status":after_status,"after_boundary_http_ms":after_ms}
                            negative = {}
                            if update_count == 1 and delta == 0:
                                bad_version = copy.deepcopy(private_h1); bad_version["minimum_tuple_version"] = 3
                                negative["bad_version"] = negative_refresh(holder, public_doc, bad_version, 91, temp/"bad-version.json")
                                deleted = copy.deepcopy(public_doc); deleted["state"]["leaves"] = deleted["state"]["leaves"][:-1]
                                negative["deleted_leaf"] = negative_refresh(holder, deleted, private_h1, 92, temp/"deleted.json")
                                mixed = copy.deepcopy(public_doc); mixed["state"]["leaves"] = json.loads(h0_raw)["state"]["leaves"]
                                negative["mixed_root"] = negative_refresh(holder, mixed, private_h1, 93, temp/"mixed.json")
                                old_opening=copy.deepcopy(private_h0); old_opening.update(minimum_tuple_version=2,expected_snapshot_digest=latest["snapshot_digest"])
                                negative["old_private_opening"] = negative_refresh(holder, public_doc, old_opening, 94, temp/"old-opening.json")
                                rollback_doc=json.loads(h0_raw)
                                negative["signed_old_version_rollback"] = negative_refresh(holder, rollback_doc, private_h1, 95, temp/"rollback.json")
                                wrong_deployment=copy.deepcopy(private_h1); wrong_deployment["deployment_id"]="00"*32
                                negative["trusted_deployment_mismatch"] = negative_refresh(holder, public_doc, wrong_deployment, 96, temp/"deployment.json")
                                assert all(item["rejected"] for item in negative.values()), negative
                            row = {"trial_order_index":len(rows),"base_schedule_index":base_schedule_index,
                                   "population_n":population,"update_count_per_registry":update_count,
                                   "background_mutations":3*update_count,"total_mutations":3*update_count+1,
                                   "l_max":3,"actual_enabled_grants":2,
                                   "state_depth":ds,"ra_depth":dra,"revocation_depth":drev,"grant_depth":3,
                                   "delta_seconds":delta,"seed":seed,"actual_ra_rows":updated_roots["ra_count"],"actual_state_rows":updated_roots["state_count"],
                                   "actual_revocations":updated_roots["revocation_count"],"initial_population_http_ms":enroll_ms,
                                   **update_timings,"holder_own_state_update_ms":holder_own_state_update_ms,"materialize_ms":materialize_ms,"publish_ms":publish_ms,"latest_lookup_ms":latest_ms,
                                   "complete_public_version_bytes":len(public_raw),"leaf_download_bytes":len(public_raw),"leaf_download_loopback_ms":download_ms,
                                   "holder_profile_descriptor_bytes":len(canonical({
                                       key:value for key,value in private_h1.items() if key != "complete_support"
                                   })),
                                   "holder_complete_support_bytes":len(canonical(private_h1["complete_support"])),
                                   "holder_private_index_bytes":len(canonical(private_h1["private_index"])),
                                   "public_reconstructed_paths_bytes":fresh["storage"]["public_reconstructed_paths_bytes"],
                                   "pk_bytes":pk.stat().st_size,"vk_bytes":vk.stat().st_size,
                                   "holder_rebuild_ms":fresh["timing"]["public_witness_recompute_ms"],"holder_total_refresh_and_prove_ms":holder_total_ms,
                                   "prove_ms":fresh["timing"]["prove_with_loaded_pk_ms"],"verify_ms":verify_ms,"fresh_http_ms":fresh_http_ms,
                                   "fresh_proof_valid":proof_valid,"fresh_http_status":fresh_status,"delta_checks":delta_checks,"negative_checks":negative,
                                   "initial_direct_verify_ms":initial_verify_ms,"snapshot_digest":latest["snapshot_digest"]}
                            rows.append(row)
                            with (args.out/"TRIALS.jsonl").open("a") as stream: stream.write(json.dumps(row,sort_keys=True)+"\n")
                            cell_server.shutdown(); cell_server.server_close()
            holder.close()
        summary={"schema":"plan-a-e4-real-lifecycle-v1","host":"experiment-node","rustc":rustc.stdout.strip(),"cpu_set":"0-9",
                 "rayon_threads":10,"omp_threads":1,"setup":setup,"setup_wall_ms":setup_ms,
                 "bootstrap_wall_ms":bootstrap_ms,"build_ms":build_ms,
                 "holder_shape":{"l_max":3,"actual_enabled_grants":2},
                 "runner":{"path":str(Path(__file__).resolve()),"sha256":sha256_file(Path(__file__).resolve())},
                 "source_manifest":source_manifest(args.source),
                 "grid":{"population_n":args.populations,"update_count_per_registry":args.updates,"delta_seconds":args.deltas,"seeds":args.seeds},
                 "schedule":{"method":"deterministic shuffled base (N,seed) blocks and shuffled (updates,Delta) cells within each block",
                              "schedule_seed":args.schedule_seed,"cell_order":cell_schedule},
                 "seed_semantics":"seed changes every background owner key, registration salt, state opening, RA admission, and revocation capability/serial, hence public roots; holder profile, PK/VK, and occupied positions remain fixed",
                 "resident_holder_ready":holder.ready,
                 "measurement_boundaries":{"leaf_download":"HTTP loopback bytes and wall time; not production network",
                  "holder_rebuild":"local full public-tree reconstruction plus path/nonmembership refresh; excludes proof; build_tree is dense over fixed dS/dRA capacity, so this is capacity cost rather than N-only sparse-tree complexity",
                  "holder_profile_descriptor":"trusted deployment/version/index/state selector bytes; excludes complete grant/key material",
                  "holder_complete_support":"canonical serialized owner/terminal keys, entitlement and state opening, exact grant messages/signatures, and private grant path for the explicitly supported synthetic holder profile",
                  "holder_private_index":"canonical bytes for RA/state/grant positions inside that private descriptor",
                  "public_reconstructed_paths":"canonical bytes of RA/state paths and indexed-revocation nonmembership witnesses rebuilt from the downloaded public version; excludes the private grant path",
                  "pk":"Groth16 proving key bytes reported separately from holder private support",
                  "verify":"one-shot public verification core subprocess",
                  "total_mutations":"three background registries times update_count, plus one target-holder state update"},
                 "cells":len(rows),"all_fresh_valid":all(row["fresh_proof_valid"] and row["fresh_http_status"]==200 for row in rows),
                 "failures":failures}
        (args.out/"SUMMARY.json").write_text(json.dumps(summary,indent=2)+"\n")
        import statistics
        grouped=[]
        for population in args.populations:
            for updates in args.updates:
                selected=[row for row in rows if row["population_n"]==population and row["update_count_per_registry"]==updates]
                grouped.append({"population_n":population,"update_count_per_registry":updates,
                    **{f"median_{key}":statistics.median(row[key] for row in selected) for key in
                       ("leaf_download_bytes","leaf_download_loopback_ms","holder_rebuild_ms","prove_ms","verify_ms","materialize_ms","publish_ms")}})
        (args.out/"AGGREGATES.json").write_text(json.dumps(grouped,indent=2)+"\n")
        import matplotlib; matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, axes=plt.subplots(1,2,figsize=(9.5,3.8))
        markers = ("o", "s", "^", "D", "v", "P")
        for index, updates in enumerate(args.updates):
            data=[row for row in grouped if row["update_count_per_registry"]==updates]
            marker = markers[index % len(markers)]
            axes[0].plot([row["population_n"] for row in data],[row["median_leaf_download_bytes"] for row in data],marker=marker,label=f"updates={updates}")
            axes[1].plot([row["population_n"] for row in data],[row["median_holder_rebuild_ms"] for row in data],marker=marker,label=f"updates={updates}")
        for axis in axes: axis.set_xscale("log",base=2); axis.grid(alpha=.25); axis.legend(frameon=False)
        axes[0].set(xlabel="Materialized population N",ylabel="Versioned leaf download (bytes)")
        axes[1].set(xlabel="Materialized population N",ylabel="Holder local rebuild (ms)")
        fig.tight_layout(); fig.savefig(args.out/"E4_REAL_LIFECYCLE.pdf"); fig.savefig(args.out/"E4_REAL_LIFECYCLE.svg"); fig.savefig(args.out/"E4_REAL_LIFECYCLE.png",dpi=200); plt.close(fig)
        hashes=[]
        for path in sorted(args.out.iterdir()):
            if path.is_file() and path.name!="ARTIFACT_SHA256.txt": hashes.append(f"{sha256_file(path)}  {path.name}")
        (args.out/"ARTIFACT_SHA256.txt").write_text("\n".join(hashes)+"\n")
        print(json.dumps({"ok":True,"cells":len(rows),"out":str(args.out)}))


if __name__ == "__main__": main()
