#!/usr/bin/env python3
"""Matched Joint/DAC HTTP service with a trusted semantic-manifest boundary.

The proof envelope is untrusted.  Expected public inputs are reconstructed from
the locally installed manifest, route/body, installed header, terminal map and
trusted clock.  The verifier is a resident JSON-lines process so its opaque
read ticket remains live until the SQLite writer transaction commits.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import sqlite3
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

SHA256 = re.compile(r"^[0-9a-f]{64}$")
BACKENDS = {"joint-bls12-381", "dac-bw6-761"}
SCHEMA = "plan-a-paired-semantic-records-v2"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def strict_json(data: bytes | str) -> object:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate-json-key")
            result[key] = value
        return result
    def bad_number(_value):
        raise ValueError("non-integer-json-number")
    return json.loads(data, object_pairs_hook=pairs, parse_float=bad_number,
                      parse_constant=bad_number)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ResidentVerifier:
    """Serialized request/response channel to one stateful verifier process."""
    def __init__(self, argv: list[str], timeout_seconds: float):
        self.timeout_seconds = timeout_seconds
        self.lock = threading.Lock()
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0)

    def call(self, value: dict) -> dict:
        with self.lock:
            if self.process.poll() is not None:
                raise RuntimeError("verifier-not-running")
            assert self.process.stdin is not None and self.process.stdout is not None
            self.process.stdin.write(canonical(value) + b"\n")
            self.process.stdin.flush()
            selector = selectors.DefaultSelector()
            selector.register(self.process.stdout, selectors.EVENT_READ)
            ready = selector.select(self.timeout_seconds)
            selector.close()
            if not ready:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=2)
                raise TimeoutError("verifier-response-timeout")
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("verifier-closed-output")
            response = strict_json(line)
            if not isinstance(response, dict):
                raise RuntimeError("verifier-non-object-response")
            return response


class TrustedConfig:
    def __init__(self, path: Path):
        raw = path.read_bytes()
        value = strict_json(raw)
        if not isinstance(value, dict) or set(value) != {
            "schema", "canonical_manifest", "audience", "resource_path",
            "terminal_keys", "backend_profiles", "semantic_input_sha256"
        }:
            raise ValueError("bad-trusted-config-schema")
        manifest = value["canonical_manifest"]
        if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
            raise ValueError("bad-semantic-manifest")
        self.manifest = manifest
        # Rust owns the typed canonical serializer.  Python deliberately does
        # not invent another key-ordering rule; each verifier recomputes this
        # trusted value from the supplied typed manifest before doing work.
        self.semantic_input_sha256 = value["semantic_input_sha256"]
        if not isinstance(self.semantic_input_sha256, str) or not SHA256.fullmatch(self.semantic_input_sha256):
            raise ValueError("bad-semantic-input-sha256")
        self.audience = value["audience"]
        self.resource_path = value["resource_path"]
        self.terminal_keys = value["terminal_keys"]
        self.backend_profiles = value["backend_profiles"]
        if set(self.backend_profiles) != BACKENDS or set(self.terminal_keys) != BACKENDS:
            raise ValueError("both-backends-required")
        if not isinstance(self.audience, str) or not self.audience or not isinstance(self.resource_path, str):
            raise ValueError("bad-trusted-route")
        if not all(isinstance(value, str) and value for value in self.terminal_keys.values()):
            raise ValueError("bad-terminal-key-map")
        if manifest["profile"]["l_max"] != 2:
            raise ValueError("matched-profile-requires-lmax2")
        issued = [update["issued_at"] for update in manifest["updates"]]
        policy_anchor = manifest["request"]["now"]
        if (not issued or any(not isinstance(item, int) or isinstance(item, bool) for item in issued)
                or issued != sorted(issued) or not isinstance(policy_anchor, int)
                or isinstance(policy_anchor, bool) or max(issued) < policy_anchor):
            raise ValueError("bad-trusted-clock-mapping")
        self.header_epoch_offset = max(issued) - policy_anchor

    def expected_request(self, backend: str, update_index: int, method: str,
                         path: str, body: bytes, now: int, header: dict) -> dict:
        request = self.manifest["request"]
        operation = strict_json(body)
        if not isinstance(operation, dict) or set(operation) != {"nonce_u64", "operation"} or operation["operation"] != "read":
            raise ValueError("bad-resource-body")
        if body != canonical(operation):
            raise ValueError("noncanonical-resource-body")
        nonce_u64 = operation["nonce_u64"]
        if not isinstance(nonce_u64, int) or isinstance(nonce_u64, bool) or not 0 <= nonce_u64 <= 2**64 - 1:
            raise ValueError("bad-operational-nonce")
        update = self.manifest["updates"][update_index]
        if update["tuple_version"] != header["tuple_version"]:
            raise ValueError("installed-header-update-mismatch")
        return {
            "semantic_input_sha256": self.semantic_input_sha256,
            "backend": backend,
            "deployment_id": self.manifest["deployment_id"],
            "logical_id_mapping_version": self.manifest["logical_id_mapping_version"],
            "policy_version": self.manifest["policy_version"],
            "schema_version": self.manifest["schema_version"],
            "profile": self.manifest["profile"],
            "update_index": update_index,
            "installed_header": header,
            "terminal": request["terminal"],
            "terminal_key": self.terminal_keys[backend],
            "resource": request["resource"],
            "one_hot_action_u16": request["one_hot_action_u16"],
            "interval_lo": request["interval_lo"],
            "interval_hi": request["interval_hi"],
            "nonce_u64": nonce_u64,
            "trusted_now": now,
            "http": {"method": method.upper(), "path": urlsplit(path).path,
                     "body_sha256": sha256(body), "audience": self.audience},
            "backend_profile": self.backend_profiles[backend],
        }


class MatchedStore:
    def __init__(self, path: Path):
        self.path = path
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS matched_headers(
              backend TEXT NOT NULL, tuple_version INTEGER NOT NULL,
              semantic_input_sha256 TEXT NOT NULL, update_index INTEGER NOT NULL,
              header_json TEXT NOT NULL, installed_at INTEGER NOT NULL,
              retired_at INTEGER, PRIMARY KEY(backend,tuple_version));
            CREATE TABLE IF NOT EXISTS matched_nonce_commits(
              backend TEXT NOT NULL, audience TEXT NOT NULL,
              terminal_key TEXT NOT NULL, nonce_u64 INTEGER NOT NULL,
              semantic_input_sha256 TEXT NOT NULL, request_sha256 TEXT NOT NULL,
              output_json TEXT NOT NULL, committed_at INTEGER NOT NULL,
              PRIMARY KEY(backend,audience,terminal_key,nonce_u64));
            """)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    def install_header(self, backend: str, semantic_hash: str, update_index: int,
                       header: dict, now: int):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            latest = db.execute("SELECT tuple_version FROM matched_headers WHERE backend=? "
                                "ORDER BY tuple_version DESC LIMIT 1", (backend,)).fetchone()
            if latest and header["tuple_version"] <= latest["tuple_version"]:
                db.rollback(); raise ValueError("tuple-version-not-increasing")
            db.execute("UPDATE matched_headers SET retired_at=? WHERE backend=? AND retired_at IS NULL",
                       (now, backend))
            db.execute("INSERT INTO matched_headers VALUES(?,?,?,?,?,?,NULL)",
                       (backend, header["tuple_version"], semantic_hash, update_index,
                        canonical(header).decode(), now))
            db.commit()

    @staticmethod
    def current(db, backend: str):
        row = db.execute("SELECT * FROM matched_headers WHERE backend=? AND retired_at IS NULL",
                         (backend,)).fetchone()
        if not row:
            return None
        return {"row": row, "header": strict_json(row["header_json"])}


class MatchedApp:
    def __init__(self, store: MatchedStore, config: TrustedConfig,
                 verifiers: dict[str, ResidentVerifier], clock=lambda: int(time.time())):
        self.store, self.config, self.verifiers = store, config, verifiers
        self.clock = clock
        # The synthetic policy clock and signed-header epoch use one underlying
        # clock with this manifest-bound fixed offset. Both backends share it.
        self.header_epoch_offset = config.header_epoch_offset
        barrier = os.environ.get("MATCHED_READ_BARRIER_DIR")
        self.read_barrier = Path(barrier) if barrier else None

    def install_header(self, backend: str, update_index: int, envelope: dict):
        if (backend not in BACKENDS or not isinstance(update_index, int)
                or isinstance(update_index, bool)
                or not 0 <= update_index < len(self.config.manifest["updates"])):
            raise ValueError("bad-header-request")
        response = self.verifiers[backend].call({"command": "materialize-and-verify-header",
            "canonical_manifest": self.config.manifest, "semantic_input_sha256": self.config.semantic_input_sha256,
            "update_index": update_index, "header_envelope": envelope,
            "backend_profile": self.config.backend_profiles[backend]})
        if set(response) != {"valid", "header"} or response["valid"] is not True:
            print(canonical({"audit":"resident-reject","backend":backend,"phase":"materialize",
                             "error":response.get("error","invalid-response")}).decode(), file=sys.stderr, flush=True)
            raise PermissionError("invalid-header")
        header = response["header"]
        if not isinstance(header, dict):
            raise PermissionError("invalid-header-object")
        if header.get("semantic_input_sha256") != self.config.semantic_input_sha256:
            raise PermissionError("header-semantic-input-mismatch")
        update = self.config.manifest["updates"][update_index]
        for field in ("tuple_version", "state_epoch", "revocation_epoch", "issued_at"):
            if header.get(field) != update[field]:
                raise PermissionError("header-semantic-update-mismatch")
        header_now = self.clock() + self.header_epoch_offset
        if header["issued_at"] > header_now:
            raise PermissionError("future-header")
        self.store.install_header(backend, self.config.semantic_input_sha256,
                                  update_index, header, header_now)
        return header

    def invoke(self, authorization: dict, method: str, path: str, body: bytes):
        if not isinstance(authorization, dict) or set(authorization) != {"backend", "envelope"}:
            return 400, {"error": "bad-authorization-schema"}
        backend = authorization["backend"]
        if backend not in BACKENDS or path != self.config.resource_path:
            return 400, {"error": "backend-or-route"}
        with self.store.connect() as db:
            current = self.store.current(db, backend)
        if current is None:
            return 401, {"error": "no-installed-header"}
        if current["row"]["semantic_input_sha256"] != self.config.semantic_input_sha256:
            return 401, {"error": "installed-semantic-input-mismatch"}
        now = self.clock()
        try:
            expected = self.config.expected_request(backend, current["row"]["update_index"],
                                                    method, path, body, now, current["header"])
        except (KeyError, ValueError) as exc:
            return 400, {"error": str(exc)}
        response = self.verifiers[backend].call({"command": "verify-at-read",
            "canonical_manifest": self.config.manifest, "expected": expected,
            "envelope": authorization["envelope"]})
        if set(response) != {"valid", "ticket"} or response["valid"] is not True:
            print(canonical({"audit":"resident-reject","backend":backend,"phase":"verify-at-read",
                             "error":response.get("error","invalid-response")}).decode(), file=sys.stderr, flush=True)
            return 403, {"error": "invalid-proof"}
        ticket = response["ticket"]
        if self.read_barrier is not None and (self.read_barrier / "enabled").exists():
            self.read_barrier.mkdir(parents=True, exist_ok=True)
            (self.read_barrier / f"reached-{backend}").write_text("1", encoding="ascii")
            deadline = time.monotonic() + 30
            while not (self.read_barrier / "release").exists():
                if time.monotonic() >= deadline:
                    return 503, {"error": "read-barrier-timeout"}
                time.sleep(0.01)
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            commit_now = self.clock()
            locked = self.store.current(db, backend)
            if locked is None or locked["row"]["tuple_version"] != current["row"]["tuple_version"]:
                db.rollback(); return 409, {"error": "stale-after-verification"}
            commit_expected = self.config.expected_request(backend, locked["row"]["update_index"],
                                                           method, path, body, commit_now, locked["header"])
            committed = self.verifiers[backend].call({"command": "commit", "ticket": ticket,
                "canonical_manifest": self.config.manifest, "expected": commit_expected,
                "envelope": authorization["envelope"]})
            if set(committed) != {"valid"} or committed["valid"] is not True:
                print(canonical({"audit":"resident-reject","backend":backend,"phase":"commit",
                                 "error":committed.get("error","invalid-response")}).decode(), file=sys.stderr, flush=True)
                db.rollback(); return 409, {"error": "commit-recheck-failed"}
            request_hash = sha256(canonical(commit_expected))
            output = {"ok": True, "backend": backend,
                      "semantic_input_sha256": self.config.semantic_input_sha256,
                      "request_sha256": request_hash}
            try:
                db.execute("INSERT INTO matched_nonce_commits VALUES(?,?,?,?,?,?,?,?)", (
                    backend, self.config.audience, self.config.terminal_keys[backend],
                    commit_expected["nonce_u64"], self.config.semantic_input_sha256,
                    request_hash, canonical(output).decode(), commit_now))
            except sqlite3.IntegrityError:
                db.rollback(); return 409, {"error": "nonce-replay"}
            db.commit()
        return 200, output


def handler_for(app: MatchedApp):
    class Handler(BaseHTTPRequestHandler):
        def reply(self, status, value):
            data = canonical(value); self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            if self.path == "/admin/matched-header":
                try:
                    auth = strict_json(self.headers.get("X-PlanA-Authorization", ""))
                    header = app.install_header(auth["backend"], auth["update_index"], auth["envelope"])
                    self.reply(201, {"header": header}); return
                except PermissionError as exc: self.reply(403, {"error": str(exc)}); return
                except Exception as exc: self.reply(400, {"error": str(exc)}); return
            try: auth = strict_json(self.headers.get("X-PlanA-Authorization", ""))
            except Exception: self.reply(400, {"error": "bad-authorization-json"}); return
            status, value = app.invoke(auth, "POST", self.path, body); self.reply(status, value)
        def log_message(self, _format, *_args): pass
    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--trusted-config", type=Path, required=True)
    parser.add_argument("--joint-cli", nargs="+", required=True)
    parser.add_argument("--dac-cli", nargs="+", required=True)
    parser.add_argument("--fixed-now", type=int)
    parser.add_argument("--clock-file", type=Path)
    parser.add_argument("--host", default="127.0.0.1"); parser.add_argument("--port", type=int, default=8788)
    args = parser.parse_args()
    config = TrustedConfig(args.trusted_config)
    verifiers = {"joint-bls12-381": ResidentVerifier(args.joint_cli, 120),
                 "dac-bw6-761": ResidentVerifier(args.dac_cli, 120)}
    if args.fixed_now is not None and args.clock_file is not None:
        parser.error("choose at most one of --fixed-now and --clock-file")
    if args.clock_file is not None:
        clock = lambda: int(args.clock_file.read_text(encoding="ascii").strip())
    else:
        clock = (lambda: args.fixed_now) if args.fixed_now is not None else (lambda: int(time.time()))
    app = MatchedApp(MatchedStore(args.db), config, verifiers, clock=clock)
    ThreadingHTTPServer((args.host, args.port), handler_for(app)).serve_forever()


if __name__ == "__main__":
    main()
