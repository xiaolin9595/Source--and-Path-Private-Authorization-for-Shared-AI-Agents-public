#!/usr/bin/env python3
"""R6 component adapter for the audited full-reconstruction implementation.

This is deliberately not an incremental-tree implementation.  It times one
prevalidated SQLite CAS, the existing full materializer subprocess, the
existing synthetic fixture signer, and dense holder path reconstruction.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import resource
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE_DIR = ROOT / "blind_update_impl" / "service"
sys.path.insert(0, str(SERVICE_DIR))
from service import CoreVerifier, Store, canonical, encode_u64  # noqa: E402

DEPLOYMENT_ID = "0" * 63 + "9"
FORMAL_SEEDS = (2026103001, 2026103002, 2026103003, 2026103004, 2026103005)
PILOT_SEED = 2026103099


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def event(log_path: Path, name: str, **fields: object) -> None:
    record = {"event": name, "monotonic_ns": time.monotonic_ns(), **fields}
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def run_json(argv: list[str], *, timeout: float) -> tuple[dict, int, str]:
    started = time.perf_counter_ns()
    completed = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout, check=False)
    elapsed = time.perf_counter_ns() - started
    if completed.returncode != 0:
        raise RuntimeError(f"command-failed:{completed.returncode}:{completed.stderr[-1000:]}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise RuntimeError("command-output-not-object")
    return value, elapsed, completed.stderr


def prepare_database(store: Store, population_file: Path) -> dict:
    with population_file.open(encoding="utf-8") as handle:
        metadata = json.loads(handle.readline())
        with store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            admissions: list[tuple[object, ...]] = []
            states: list[tuple[object, ...]] = []
            for line in handle:
                row = json.loads(line)
                admissions.append((DEPLOYMENT_ID, row["owner"], row["position"],
                                   "synthetic-not-used-by-conditional-cas", "0" * 64,
                                   encode_u64(metadata["expiry_cap"]), encode_u64(0)))
                states.append((DEPLOYMENT_ID, row["owner"], row["position"],
                               encode_u64(row["state_version"]), encode_u64(row["state_epoch"]),
                               1, row["leaf"], 0))
                if len(states) == 4096:
                    db.executemany("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)", admissions)
                    db.executemany("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)", states)
                    admissions.clear(); states.clear()
            if states:
                db.executemany("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)", admissions)
                db.executemany("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)", states)
            db.commit()
    return metadata


def current_row(store: Store, metadata: dict, position: int) -> dict:
    with store.connect() as db:
        row = db.execute("SELECT * FROM owner_states WHERE deployment_id=? AND position=?",
                         (DEPLOYMENT_ID, position)).fetchone()
    if row is None:
        raise RuntimeError("missing-state-row")
    return dict(row)


def materialize(store: Store, verifier: CoreVerifier) -> tuple[dict, int, int]:
    started = time.perf_counter_ns()
    inputs = store.materialization_inputs(DEPLOYMENT_ID)
    db_read_done = time.perf_counter_ns()
    roots = verifier.response(inputs)
    ended = time.perf_counter_ns()
    if roots is None or roots.get("valid") is not True:
        raise RuntimeError("materialization-failed")
    return roots, db_read_done - started, ended - db_read_done


def trial(args: argparse.Namespace) -> dict:
    work = args.output.resolve()
    work.mkdir(parents=True, exist_ok=False)
    events = work / "EVENTS.jsonl"
    population_file = work / "population.jsonl"
    public_file = work / "public.json"
    db_path = work / "state.sqlite"

    tracked = {
        "measurement_design": ROOT / "R6_MEASUREMENT_DESIGN.md",
        "runner": Path(__file__).resolve(),
        "adapter_source": Path(args.adapter_source).resolve(),
        "adapter_cargo_lock": Path(args.adapter_lock).resolve(),
        "adapter_binary": args.adapter.resolve(),
        "service_core_binary": args.service_core.resolve(),
        "mutation_cli_binary": args.mutation_cli.resolve(),
        "audited_service": SERVICE_DIR / "service.py",
    }
    manifest = {
        "schema": "r6-trial-start-manifest-v1", "depth": args.depth, "seed": args.seed,
        "formal_seeds": list(FORMAL_SEEDS), "pilot_seed": PILOT_SEED,
        "files": {name: {"path": str(path), "sha256": sha256_file(path)} for name, path in tracked.items()},
        "environment_allowlist": {name: os.environ.get(name) for name in
            ("PATH", "RAYON_NUM_THREADS", "OMP_NUM_THREADS", "LANG", "LC_ALL")},
    }
    (work / "START_MANIFEST.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    event(events, "trial_started")

    init_started = time.perf_counter_ns()
    generated, _, generator_stderr = run_json(
        [str(args.adapter), "generate", str(args.depth), str(args.seed), str(population_file)],
        timeout=args.timeout)
    if generated.get("valid") is not True:
        raise RuntimeError("population-generation-failed")
    event(events, "population_generated", bytes=population_file.stat().st_size)
    store = Store(db_path)
    metadata = prepare_database(store, population_file)
    init_ns = time.perf_counter_ns() - init_started
    event(events, "database_initialized", population=metadata["population"], initialization_ns=init_ns)

    registry, _, _ = run_json([str(args.adapter), "registry-pk"], timeout=30)
    os.environ.update({
        "PLAN_A_DS": str(args.depth), "PLAN_A_DRA": str(args.depth),
        "PLAN_A_DREV": "32", "PLAN_A_DEPLOYMENT_ID": DEPLOYMENT_ID,
        "PLAN_A_REGISTRY_PK_B64": registry["registry_pk_b64"],
    })
    verifier = CoreVerifier([str(args.service_core)], args.timeout)
    initial_roots, _, _ = materialize(store, verifier)
    event(events, "initial_root_materialized")
    target_before = current_row(store, metadata, metadata["target"])
    unchanged_before = current_row(store, metadata, metadata["unchanged"])
    if target_before["leaf"] == metadata["replacement_leaf"]:
        raise RuntimeError("replacement-leaf-not-distinct")

    statement = {
        "deployment_id": DEPLOYMENT_ID, "owner_commitment": metadata["owner"],
        "position": metadata["target"], "expiry_cap": metadata["expiry_cap"],
        "admission_version": metadata["admission_version"], "old_leaf": target_before["leaf"],
        "old_version": metadata["old_version"], "old_epoch": metadata["old_epoch"],
    }
    verified = {
        "new_leaf": metadata["replacement_leaf"], "old_leaf": target_before["leaf"],
        "new_version": metadata["new_version"], "new_epoch": metadata["new_epoch"],
    }

    maintenance_started = time.perf_counter_ns()
    cas_started = maintenance_started
    cas_status = store.cas_blind_state_update(statement, verified, 1)
    cas_ns = time.perf_counter_ns() - cas_started
    if cas_status != "committed":
        raise RuntimeError(f"accepted-cas-failed:{cas_status}")
    event(events, "conditional_cas_committed", duration_ns=cas_ns)
    roots, db_read_ns, materializer_process_ns = materialize(store, verifier)
    event(events, "updated_root_materialized", database_read_ns=db_read_ns,
          materializer_process_ns=materializer_process_ns)

    signing_started = time.perf_counter_ns()
    snapshot = {
        "deployment_id": DEPLOYMENT_ID, "tuple_version": 1,
        "ra_root": roots["ra_root"], "state_epoch": metadata["new_epoch"],
        "state_root": roots["state_root"], "revocation_epoch": 0,
        "revocation_root": roots["revocation_root"], "issued_at": 1,
    }
    signer_output, signer_process_ns, signer_stderr = run_json(
        [str(args.mutation_cli), "sign-header", canonical(snapshot).decode("utf-8")],
        timeout=args.timeout)
    signing_total_ns = time.perf_counter_ns() - signing_started
    maintenance_ns = time.perf_counter_ns() - maintenance_started
    event(events, "snapshot_signed", signing_total_ns=signing_total_ns,
          complete_maintenance_ns=maintenance_ns)

    stale_status = store.cas_blind_state_update(statement, verified, 2)
    if stale_status != "state-cas-mismatch":
        raise RuntimeError(f"stale-cas-not-rejected:{stale_status}")
    target_after = current_row(store, metadata, metadata["target"])
    unchanged_after = current_row(store, metadata, metadata["unchanged"])
    if target_after["leaf"] != metadata["replacement_leaf"]:
        raise RuntimeError("target-leaf-not-replaced")
    if unchanged_after["leaf"] != unchanged_before["leaf"]:
        raise RuntimeError("unchanged-row-mutated")
    if roots["state_root"] == initial_roots["state_root"]:
        raise RuntimeError("root-did-not-change")

    header_verify_started = time.perf_counter_ns()
    verified_header = verifier.response({"command": "header-verify", "snapshot": snapshot,
                                         "signature_b64": signer_output["signature_b64"]})
    header_verify_ns = time.perf_counter_ns() - header_verify_started
    if verified_header is None or verified_header.get("valid") is not True:
        raise RuntimeError("header-signature-verification-failed")
    event(events, "header_verified", duration_ns=header_verify_ns)

    public_payload = {
        "schema": "plan-a-public-leaves-v1", "snapshot": snapshot,
        "header_signature_b64": signer_output["signature_b64"],
        "state": {"leaves": store.materialization_inputs(DEPLOYMENT_ID)["states"]},
        "ra": {"leaves": []}, "revocation": {"inserted_serials": [], "leaves": []},
    }
    public_bytes = canonical(public_payload)
    public_file.write_bytes(public_bytes)
    dense, dense_process_ns, dense_stderr = run_json(
        [str(args.adapter), "dense-refresh", str(public_file), str(args.depth),
         str(metadata["target"]), str(metadata["unchanged"])], timeout=args.timeout)
    if dense.get("valid") is not True or dense.get("state_root") != roots["state_root"]:
        raise RuntimeError("holder-refresh-failed")
    event(events, "holder_paths_refreshed", duration_ns=dense_process_ns,
          public_bytes=len(public_bytes), path_encoding_bytes=dense["path_encoding_bytes"],
          path_raw=dense["path_raw"])
    full_refresh_ns = header_verify_ns + dense_process_ns

    self_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    child_rss = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    result = {
        "schema": "r6-full-reconstruction-trial-v2", "valid": True,
        "scope": "component measurement; conditional prevalidated CAS; full root and dense holder reconstruction; no HTTP; no Groth16",
        "depth": args.depth, "population": 1 << args.depth, "seed": args.seed,
        "target": metadata["target"], "unchanged_holder": metadata["unchanged"],
        "unrelated_ra_population": 0, "unrelated_revocation_population": 0,
        "timing_ns": {
            "initial_population_outside_update": init_ns, "conditional_cas": cas_ns,
            "database_read": db_read_ns, "materializer_process_including_json_and_startup": materializer_process_ns,
            "snapshot_construct_and_fixture_sign_total": signing_total_ns,
            "fixture_signer_process": signer_process_ns, "complete_maintenance_stages_1_to_3": maintenance_ns,
            "receiver_header_verify_process_including_startup": header_verify_ns,
            "holder_dense_refresh_process_including_file_io_json_and_startup": dense_process_ns,
            "full_refresh_header_verify_plus_holder": full_refresh_ns,
            "holder_internal_read_parse_build_path": dense["holder_refresh_ns"],
        },
        "bytes": {"serialized_public_state": len(public_bytes),
                  "path_encoding": dense["path_encoding_bytes"], "path_raw": dense["path_raw"]},
        "correctness": {"stale_cas_rejected": True, "updated_leaf_differs": True,
                        "root_differs": True, "unchanged_row_intact": True,
                        "header_signature_verified": True, "target_path_verified": True,
                        "unchanged_holder_path_verified": True},
        "rss": {"self_ru_maxrss_raw": self_rss, "children_ru_maxrss_raw": child_rss,
                "units": "KiB on Linux; bytes on macOS; whole-process maxima, not stage-specific"},
        "process": {"platform": platform.platform(), "python": sys.version,
                    "generator_stderr": generator_stderr, "signer_stderr": signer_stderr,
                    "dense_stderr": dense_stderr},
    }
    (work / "RESULT.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    event(events, "trial_complete")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--depth", type=int, required=True, choices=range(1, 21))
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--adapter", type=Path, required=True)
    parser.add_argument("--service-core", type=Path, required=True)
    parser.add_argument("--mutation-cli", type=Path, required=True)
    parser.add_argument("--adapter-source", type=Path, required=True)
    parser.add_argument("--adapter-lock", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=1800.0)
    args = parser.parse_args()
    try:
        print(json.dumps(trial(args), sort_keys=True))
    except Exception as error:
        if args.output.exists():
            (args.output / "FAILURE.json").write_text(json.dumps({
                "schema": "r6-trial-failure-v1", "error_type": type(error).__name__,
                "error": str(error)}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        raise


if __name__ == "__main__":
    main()

