#!/usr/bin/env python3
"""Plan A HTTP/T4 service prototype using a real external proof CLI.

No mock verifier is accepted in normal mode. The service is an HTTP prototype,
not a claim of MCP 2026-07-28 compatibility.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import sqlite3
import subprocess
import selectors
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_HTTP_BODY_BYTES = 1_048_576
U64_MAX = 2**64 - 1
U64_TEXT = re.compile(r"^[0-9]{20}$")


def encode_u64(value: object) -> str:
    """Canonical SQLite representation; never rely on SQL text ordering."""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= U64_MAX:
        raise ValueError("not-u64")
    return f"{value:020d}"


def decode_u64(value: object) -> int:
    """Read canonical TEXT plus legacy nonnegative signed-INTEGER rows."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2**63 - 1:
        return value
    # SQLite may coerce a legacy INTEGER inserted into a newly declared TEXT
    # affinity column into its unpadded decimal spelling.
    if isinstance(value, str) and value.isascii() and value.isdigit() and not value.startswith("0"):
        parsed = int(value, 10)
        if parsed <= 2**63 - 1:
            return parsed
    if isinstance(value, str) and U64_TEXT.fullmatch(value):
        parsed = int(value, 10)
        if parsed <= U64_MAX and encode_u64(parsed) == value:
            return parsed
    raise ValueError("noncanonical-stored-u64")


def canonical(obj: object) -> bytes:
    # Restricted protocol canonical JSON; this is not a full RFC 8785 implementation.
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def strict_json(data: bytes | str) -> object:
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out: raise ValueError("duplicate-json-key")
            out[key] = value
        return out
    def bad_number(value): raise ValueError("non-integer-json-number")
    return json.loads(data, object_pairs_hook=pairs, parse_float=bad_number, parse_constant=bad_number)


def tagged_digest(tag: bytes, obj: object) -> str:
    return hashlib.sha256(tag + b"\0" + canonical(obj)).hexdigest()


def exactly_one_u16(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 65536 and value & (value - 1) == 0


def valid_nonce(value: object) -> bool:
    if not isinstance(value, str) or "=" in value:
        return False
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception:
        return False
    return 16 <= len(raw) <= 64 and base64.urlsafe_b64encode(raw).decode().rstrip("=") == value


class Store:
    def __init__(self, path: Path):
        self.path = path
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS headers(
              snapshot_digest TEXT PRIMARY KEY,
              tuple_version TEXT NOT NULL,
              ra_root TEXT NOT NULL,
              state_epoch TEXT NOT NULL,
              state_root TEXT NOT NULL,
              revocation_epoch TEXT NOT NULL,
              revocation_root TEXT NOT NULL,
              issued_at TEXT NOT NULL,
              retired_at INTEGER,
              installed_at INTEGER NOT NULL,
              UNIQUE(tuple_version)
            );
            CREATE TABLE IF NOT EXISTS nonce_commits(
              audience TEXT NOT NULL,
              terminal_agent_pk TEXT NOT NULL,
              nonce TEXT NOT NULL,
              request_digest TEXT NOT NULL,
              committed_at INTEGER NOT NULL,
              resource_output TEXT NOT NULL,
              PRIMARY KEY(audience,terminal_agent_pk,nonce)
            );
            CREATE TABLE IF NOT EXISTS owner_states(
              deployment_id TEXT NOT NULL, owner_commitment TEXT NOT NULL,
              position INTEGER NOT NULL, state_version TEXT NOT NULL,
              state_epoch TEXT NOT NULL, active INTEGER,
              leaf TEXT NOT NULL, updated_at INTEGER NOT NULL,
              PRIMARY KEY(deployment_id,owner_commitment,position)
            );
            CREATE TABLE IF NOT EXISTS admissions(
              deployment_id TEXT NOT NULL, owner_commitment TEXT NOT NULL,
              position INTEGER NOT NULL, owner_public_key TEXT NOT NULL,
              registration_salt TEXT NOT NULL, max_expiry TEXT NOT NULL,
              admission_version TEXT NOT NULL DEFAULT '00000000000000000000',
              PRIMARY KEY(deployment_id,owner_commitment),
              UNIQUE(deployment_id,position)
            );
            CREATE TABLE IF NOT EXISTS ra_leaves(
              deployment_id TEXT NOT NULL, position INTEGER NOT NULL,
              leaf TEXT NOT NULL, updated_at INTEGER NOT NULL,
              PRIMARY KEY(deployment_id,position),
              UNIQUE(deployment_id,leaf)
            );
            CREATE TABLE IF NOT EXISTS revoked_serials(
              serial TEXT PRIMARY KEY, counter INTEGER NOT NULL,
              inserted_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS transition_receipts(
              snapshot_digest TEXT PRIMARY KEY, ra_root TEXT NOT NULL,
              state_root TEXT NOT NULL,
              revocation_root TEXT NOT NULL, state_count INTEGER NOT NULL,
              ra_count INTEGER NOT NULL, revocation_count INTEGER NOT NULL,
              committed_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS public_versions(
              snapshot_digest TEXT PRIMARY KEY, tuple_version TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL, published_at INTEGER NOT NULL
            );
            """)
            self._migrate_blind_u64_tables(db)

    @staticmethod
    def _migrate_blind_u64_tables(db: sqlite3.Connection) -> None:
        """One-time in-place migration from the legacy signed-INTEGER schema."""
        state_info={r[1]:r for r in db.execute("PRAGMA table_info(owner_states)")}
        admission_info={r[1]:r for r in db.execute("PRAGMA table_info(admissions)")}
        header_info={r[1]:r for r in db.execute("PRAGMA table_info(headers)")}
        public_info={r[1]:r for r in db.execute("PRAGMA table_info(public_versions)")}
        state_ok=(state_info.get("state_version",(None,None,""))[2].upper()=="TEXT" and
                  state_info.get("state_epoch",(None,None,""))[2].upper()=="TEXT" and
                  state_info.get("active",(None,None,None,1))[3]==0)
        admission_ok=(admission_info.get("max_expiry",(None,None,""))[2].upper()=="TEXT" and
                      admission_info.get("admission_version",(None,None,""))[2].upper()=="TEXT")
        header_ok=all(header_info.get(name,(None,None,""))[2].upper()=="TEXT" for name in
                      ("tuple_version","state_epoch","revocation_epoch","issued_at"))
        public_ok=public_info.get("tuple_version",(None,None,""))[2].upper()=="TEXT"
        if state_ok and admission_ok and header_ok and public_ok: return
        db.execute("BEGIN IMMEDIATE")
        if not state_ok:
            rows=[dict(r) for r in db.execute("SELECT * FROM owner_states")]
            db.execute("ALTER TABLE owner_states RENAME TO owner_states_r3_legacy")
            db.execute("""CREATE TABLE owner_states(
              deployment_id TEXT NOT NULL, owner_commitment TEXT NOT NULL,
              position INTEGER NOT NULL, state_version TEXT NOT NULL,
              state_epoch TEXT NOT NULL, active INTEGER,
              leaf TEXT NOT NULL, updated_at INTEGER NOT NULL,
              PRIMARY KEY(deployment_id,owner_commitment,position))""")
            for row in rows:
                db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",(
                    row["deployment_id"],row["owner_commitment"],row["position"],
                    encode_u64(decode_u64(row["state_version"])),encode_u64(decode_u64(row["state_epoch"])),
                    row["active"],row["leaf"],row["updated_at"]))
            db.execute("DROP TABLE owner_states_r3_legacy")
        if not admission_ok:
            has_version="admission_version" in admission_info
            columns="deployment_id,owner_commitment,position,owner_public_key,registration_salt,max_expiry"+(",admission_version" if has_version else "")
            rows=[dict(r) for r in db.execute(f"SELECT {columns} FROM admissions")]
            db.execute("ALTER TABLE admissions RENAME TO admissions_r3_legacy")
            db.execute("""CREATE TABLE admissions(
              deployment_id TEXT NOT NULL, owner_commitment TEXT NOT NULL,
              position INTEGER NOT NULL, owner_public_key TEXT NOT NULL,
              registration_salt TEXT NOT NULL, max_expiry TEXT NOT NULL,
              admission_version TEXT NOT NULL DEFAULT '00000000000000000000',
              PRIMARY KEY(deployment_id,owner_commitment), UNIQUE(deployment_id,position))""")
            for row in rows:
                db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",(
                    row["deployment_id"],row["owner_commitment"],row["position"],row["owner_public_key"],
                    row["registration_salt"],encode_u64(decode_u64(row["max_expiry"])),
                    encode_u64(decode_u64(row["admission_version"])) if has_version else encode_u64(0)))
            db.execute("DROP TABLE admissions_r3_legacy")
        if not header_ok:
            rows=[dict(r) for r in db.execute("SELECT * FROM headers")]
            db.execute("ALTER TABLE headers RENAME TO headers_r3_legacy")
            db.execute("""CREATE TABLE headers(
              snapshot_digest TEXT PRIMARY KEY, tuple_version TEXT NOT NULL,
              ra_root TEXT NOT NULL, state_epoch TEXT NOT NULL, state_root TEXT NOT NULL,
              revocation_epoch TEXT NOT NULL, revocation_root TEXT NOT NULL,
              issued_at TEXT NOT NULL, retired_at INTEGER, installed_at INTEGER NOT NULL,
              UNIQUE(tuple_version))""")
            for row in rows:
                db.execute("INSERT INTO headers VALUES(?,?,?,?,?,?,?,?,?,?)",(
                    row["snapshot_digest"],encode_u64(decode_u64(row["tuple_version"])),row["ra_root"],
                    encode_u64(decode_u64(row["state_epoch"])),row["state_root"],
                    encode_u64(decode_u64(row["revocation_epoch"])),row["revocation_root"],
                    encode_u64(decode_u64(row["issued_at"])),row["retired_at"],row["installed_at"]))
            db.execute("DROP TABLE headers_r3_legacy")
        if not public_ok:
            rows=[dict(r) for r in db.execute("SELECT * FROM public_versions")]
            db.execute("ALTER TABLE public_versions RENAME TO public_versions_r3_legacy")
            db.execute("""CREATE TABLE public_versions(
              snapshot_digest TEXT PRIMARY KEY, tuple_version TEXT NOT NULL UNIQUE,
              payload_json TEXT NOT NULL, published_at INTEGER NOT NULL)""")
            for row in rows:
                db.execute("INSERT INTO public_versions VALUES(?,?,?,?)",(
                    row["snapshot_digest"],encode_u64(decode_u64(row["tuple_version"])),
                    row["payload_json"],row["published_at"]))
            db.execute("DROP TABLE public_versions_r3_legacy")
        db.commit()

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        return db

    def materialization_inputs(self, deployment_id: str) -> dict:
        with self.connect() as db:
            ra=[dict(r) for r in db.execute("SELECT position,leaf FROM ra_leaves WHERE deployment_id=? ORDER BY position",(deployment_id,))]
            states=[dict(r) for r in db.execute("SELECT position,leaf FROM owner_states WHERE deployment_id=? ORDER BY position",(deployment_id,))]
            serials=[r["serial"] for r in db.execute("SELECT serial FROM revoked_serials ORDER BY rowid")]
        return {"command":"materialize-roots","ra_leaves":ra,"states":states,"revoked_serials":serials}

    def install_header(self, snapshot: dict, signature_b64: str, requested_now: int, clock, verifier, deployment_id: str) -> str:
        digest = tagged_digest(b"plan-a-snapshot-v1", snapshot)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            now=clock() if deployment_id else requested_now
            if snapshot["issued_at"]>now: db.rollback(); raise ValueError("future-header")
            ra=[dict(r) for r in db.execute("SELECT position,leaf FROM ra_leaves WHERE deployment_id=? ORDER BY position",(deployment_id,))]
            states=[dict(r) for r in db.execute("SELECT position,leaf FROM owner_states WHERE deployment_id=? ORDER BY position",(deployment_id,))]
            serials=[r["serial"] for r in db.execute("SELECT serial FROM revoked_serials ORDER BY rowid")]
            roots=verifier.response({"command":"materialize-roots","ra_leaves":ra,"states":states,"revoked_serials":serials}) if deployment_id else {"valid":True,"ra_root":snapshot["ra_root"],"state_root":snapshot["state_root"],"revocation_root":snapshot["revocation_root"],"ra_count":0,"state_count":0,"revocation_count":0,"revocation_leaves":[]}
            expected_roots={"valid","ra_root","state_root","revocation_root","ra_count","state_count","revocation_count","revocation_leaves"}
            if roots is None or roots.get("valid") is not True or set(roots)!=expected_roots:
                db.rollback(); raise ValueError("root-materialization-failed")
            if roots["ra_root"]!=snapshot["ra_root"] or roots["state_root"]!=snapshot["state_root"] or roots["revocation_root"]!=snapshot["revocation_root"]:
                db.rollback(); raise ValueError("header-root-does-not-match-registry")
            epoch_rows=db.execute("SELECT state_epoch FROM owner_states WHERE deployment_id=?",(deployment_id,)).fetchall() if deployment_id else []
            max_epoch=max((decode_u64(r["state_epoch"]) for r in epoch_rows),default=None)
            if max_epoch is not None and snapshot["state_epoch"]!=max_epoch:
                db.rollback(); raise ValueError("header-state-epoch-does-not-match-registry")
            latest = db.execute("SELECT * FROM headers ORDER BY installed_at DESC, rowid DESC LIMIT 1").fetchone()
            duplicate = db.execute("SELECT issued_at FROM headers WHERE snapshot_digest=?", (digest,)).fetchone()
            if duplicate:
                db.rollback(); raise ValueError("header-republication")
            if latest and snapshot["tuple_version"] <= decode_u64(latest["tuple_version"]):
                db.rollback(); raise ValueError("tuple-version-not-increasing")
            if latest and (snapshot["state_epoch"] < decode_u64(latest["state_epoch"]) or snapshot["revocation_epoch"] < decode_u64(latest["revocation_epoch"])):
                db.rollback(); raise ValueError("epoch-rollback")
            if latest and snapshot["issued_at"] < decode_u64(latest["issued_at"]):
                db.rollback(); raise ValueError("issued-at-rollback")
            if latest:
                db.execute("UPDATE headers SET retired_at=? WHERE snapshot_digest=? AND retired_at IS NULL", (now, latest["snapshot_digest"]))
            db.execute("INSERT INTO headers VALUES(?,?,?,?,?,?,?,?,?,?)", (
                digest, encode_u64(snapshot["tuple_version"]), snapshot["ra_root"], encode_u64(snapshot["state_epoch"]), snapshot["state_root"], encode_u64(snapshot["revocation_epoch"]),
                snapshot["revocation_root"], encode_u64(snapshot["issued_at"]), None, now,
            ))
            public_payload={"schema":"plan-a-public-leaves-v1","snapshot_digest":digest,"snapshot":snapshot,"header_signature_b64":signature_b64,"ra":{"leaves":ra},"state":{"leaves":states},"revocation":{"inserted_serials":serials,"leaves":roots["revocation_leaves"]}}
            db.execute("INSERT INTO transition_receipts VALUES(?,?,?,?,?,?,?,?)",(digest,roots["ra_root"],roots["state_root"],roots["revocation_root"],roots["state_count"],roots["ra_count"],roots["revocation_count"],now))
            db.execute("INSERT INTO public_versions VALUES(?,?,?,?)",(digest,encode_u64(snapshot["tuple_version"]),canonical(public_payload).decode("utf-8"),now))
            db.commit()
        return digest

    def accepted_snapshot(self, digest: str, now: int, delta: int) -> dict | None:
        with self.connect() as db:
            row = db.execute("SELECT * FROM headers WHERE snapshot_digest=?", (digest,)).fetchone()
            latest = db.execute("SELECT snapshot_digest FROM headers ORDER BY installed_at DESC, rowid DESC LIMIT 1").fetchone()
        if not row or not latest:
            return None
        # Current remains valid until replaced. Retired tuples have an inclusive grace boundary.
        if digest != latest["snapshot_digest"]:
            if delta == 0 or row["retired_at"] is None or now > row["retired_at"] + delta: return None
        out={k: row[k] for k in ("tuple_version", "ra_root", "state_epoch", "state_root", "revocation_epoch", "revocation_root", "issued_at")}
        for key in ("tuple_version","state_epoch","revocation_epoch","issued_at"):
            out[key]=decode_u64(out[key])
        return out

    def commit_once(self, request: dict, request_digest: str, output: dict, clock, delta: int) -> str:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Read trusted time only after acquiring the writer lock. Lock wait
            # is part of the authorization-to-resource commit interval.
            now = clock()
            row=db.execute("SELECT * FROM headers WHERE snapshot_digest=?",(request["snapshot_digest"],)).fetchone()
            latest=db.execute("SELECT snapshot_digest FROM headers ORDER BY installed_at DESC,rowid DESC LIMIT 1").fetchone()
            stale = (not row or not latest or now < request["request_time"] or now > request["expires_at"] or
                     (row["snapshot_digest"] != latest["snapshot_digest"] and
                      (delta == 0 or row["retired_at"] is None or now > row["retired_at"] + delta)))
            if stale: db.rollback(); return "stale-after-verification"
            try:
                db.execute("INSERT INTO nonce_commits VALUES(?,?,?,?,?,?)", (
                    request["audience"], request["terminal_agent_pk"], request["nonce"], request_digest,
                    now, canonical(output).decode("utf-8"),
                ))
            except sqlite3.IntegrityError:
                db.rollback(); return "nonce-replay"
            db.commit(); return "committed"

    def cas_state_update(self, update: dict, verified: dict, now: int) -> str:
        key=(update["deployment_id"],update["owner_commitment"],update["position"])
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            admission=db.execute("SELECT owner_public_key,registration_salt,max_expiry FROM admissions WHERE deployment_id=? AND owner_commitment=? AND position=?",key).fetchone()
            if not admission or admission["owner_public_key"]!=update["owner_public_key"] or admission["registration_salt"]!=update["registration_salt"] or decode_u64(admission["max_expiry"])!=update["max_expiry"]:
                db.rollback(); return "admission-mismatch"
            row=db.execute("SELECT state_version,state_epoch,active FROM owner_states WHERE deployment_id=? AND owner_commitment=? AND position=?",key).fetchone()
            if row is None or row["active"] is None:
                db.rollback(); return "blind-mode"
            if (decode_u64(row["state_version"]) != update["expected_version"] or decode_u64(row["state_epoch"]) != update["current_epoch"] or bool(row["active"]) != update["current_active"]):
                db.rollback(); return "state-cas-mismatch"
            db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(deployment_id,owner_commitment,position) DO UPDATE SET state_version=excluded.state_version,state_epoch=excluded.state_epoch,active=excluded.active,leaf=excluded.leaf,updated_at=excluded.updated_at",key+(encode_u64(verified["new_version"]),encode_u64(verified["new_epoch"]),int(verified["active"]),verified["new_leaf"],now))
            db.commit(); return "committed"

    def cas_blind_state_update(self, statement: dict, verified: dict, now: int) -> str:
        key=(statement["deployment_id"],statement["owner_commitment"],statement["position"])
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            admission=db.execute("SELECT max_expiry,admission_version FROM admissions WHERE deployment_id=? AND owner_commitment=? AND position=?",key).fetchone()
            if (not admission or decode_u64(admission["max_expiry"])!=statement["expiry_cap"] or
                    decode_u64(admission["admission_version"])!=statement["admission_version"]):
                db.rollback(); return "admission-mismatch"
            row=db.execute("SELECT leaf,state_version,state_epoch FROM owner_states WHERE deployment_id=? AND owner_commitment=? AND position=?",key).fetchone()
            if (row is None or row["leaf"]!=statement["old_leaf"] or
                    decode_u64(row["state_version"])!=statement["old_version"] or decode_u64(row["state_epoch"])!=statement["old_epoch"]):
                db.rollback(); return "state-cas-mismatch"
            changed=db.execute("UPDATE owner_states SET leaf=?,state_version=?,state_epoch=?,active=NULL,updated_at=? WHERE deployment_id=? AND owner_commitment=? AND position=? AND leaf=? AND state_version=? AND state_epoch=?",
                (verified["new_leaf"],encode_u64(verified["new_version"]),encode_u64(verified["new_epoch"]),now)+key+
                (verified["old_leaf"],row["state_version"],row["state_epoch"])).rowcount
            if changed!=1: db.rollback(); return "state-cas-mismatch"
            db.commit(); return "committed"

    def enroll(self, request: dict, verified: dict, now: int) -> str:
        key=(verified["owner_commitment"],verified["position"],request["owner_public_key"],request["registration_salt"],verified["max_expiry"])
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",(request["deployment_id"],)+key[:-1]+(encode_u64(key[-1]),encode_u64(0)))
                db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",(request["deployment_id"],verified["owner_commitment"],verified["position"],encode_u64(verified["initial_version"]),encode_u64(verified["initial_epoch"]),int(verified["active"]),verified["initial_leaf"],now))
            except sqlite3.IntegrityError: db.rollback(); return "admission-conflict"
            db.commit(); return "committed"

    def admitted_state(self, deployment: str, owner: str, position: int) -> dict | None:
        with self.connect() as db:
            row=db.execute("SELECT a.owner_public_key,a.registration_salt,a.max_expiry,s.state_epoch AS current_epoch,s.active AS current_active FROM admissions a JOIN owner_states s USING(deployment_id,owner_commitment,position) WHERE deployment_id=? AND owner_commitment=? AND position=?",(deployment,owner,position)).fetchone()
        # Once a blind update erases the active hint, do not permit downgrade to
        # the legacy visible-opening update endpoint.
        if not row or row["current_active"] is None: return None
        out=dict(row);out["max_expiry"]=decode_u64(out["max_expiry"]);out["current_epoch"]=decode_u64(out["current_epoch"]);out["current_active"]=bool(out["current_active"]);return out

    def blind_admission(self, deployment: str, owner: str, position: int) -> dict | None:
        with self.connect() as db:
            row=db.execute("SELECT owner_public_key,max_expiry AS expiry_cap,admission_version FROM admissions WHERE deployment_id=? AND owner_commitment=? AND position=?",(deployment,owner,position)).fetchone()
        if not row: return None
        out=dict(row);out["expiry_cap"]=decode_u64(out["expiry_cap"]);out["admission_version"]=decode_u64(out["admission_version"])
        return {"owner_commitment":owner,"position":position,**out}

    def insert_revocation(self, serial: str, counter: int, now: int) -> str:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try: db.execute("INSERT INTO revoked_serials VALUES(?,?,?)",(serial,counter,now))
            except sqlite3.IntegrityError: db.rollback(); return "serial-already-revoked"
            db.commit(); return "committed"

    def insert_ra_leaf(self, deployment_id: str, position: int, leaf: str, now: int) -> str:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            try: db.execute("INSERT INTO ra_leaves VALUES(?,?,?,?)",(deployment_id,position,leaf,now))
            except sqlite3.IntegrityError: db.rollback(); return "ra-conflict"
            db.commit(); return "committed"

    def update_ra_leaf(self, deployment_id: str, position: int, expected_leaf: str, leaf: str, now: int) -> str:
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row=db.execute("SELECT leaf FROM ra_leaves WHERE deployment_id=? AND position=?",(deployment_id,position)).fetchone()
            if row is None or row["leaf"]!=expected_leaf: db.rollback(); return "ra-cas-mismatch"
            try:
                changed=db.execute("UPDATE ra_leaves SET leaf=?,updated_at=? WHERE deployment_id=? AND position=? AND leaf=?",(leaf,now,deployment_id,position,expected_leaf)).rowcount
            except sqlite3.IntegrityError: db.rollback(); return "ra-conflict"
            if changed!=1: db.rollback(); return "ra-cas-mismatch"
            db.commit(); return "committed"

    def public_latest(self) -> dict | None:
        with self.connect() as db:
            row=db.execute("SELECT snapshot_digest,tuple_version,published_at FROM public_versions ORDER BY tuple_version DESC LIMIT 1").fetchone()
        if not row: return None
        out=dict(row);out["tuple_version"]=decode_u64(out["tuple_version"]);return out

    def public_version(self, digest: str) -> dict | None:
        with self.connect() as db:
            row=db.execute("SELECT payload_json FROM public_versions WHERE snapshot_digest=?",(digest,)).fetchone()
        return strict_json(row["payload_json"]) if row else None


class CoreVerifier:
    def __init__(self, argv: list[str], timeout: float):
        if not argv:
            raise ValueError("real proof CLI is required")
        self.argv, self.timeout = argv, timeout

    def response(self, payload: dict) -> dict | None:
        started = time.perf_counter_ns()
        result = subprocess.run(self.argv, input=canonical(payload) + b"\n", stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=self.timeout, check=False)
        self.last_wall_ns = time.perf_counter_ns() - started
        if result.returncode != 0:
            return None
        try:
            response = strict_json(result.stdout)
        except Exception:
            return None
        self.last_private_timing = {}
        if isinstance(response,dict) and "_e2_pure_proof_verify_ns" in response:
            response = dict(response)
            self.last_private_timing["pure_proof_verify_ns"] = response.pop("_e2_pure_proof_verify_ns")
        return response if isinstance(response,dict) else None

    def call(self, payload: dict) -> bool:
        response=self.response(payload)
        return response is not None and response.get("valid") is True

    def close(self) -> None:
        pass


class ResidentCheckedVerifier:
    """Fail-closed serialized channel to an explicitly checked resident core."""
    def __init__(self, argv: list[str], startup_timeout: float, request_timeout: float):
        if not argv:
            raise ValueError("checked resident proof CLI is required")
        self.argv, self.request_timeout = argv, request_timeout
        self.lock = threading.Lock()
        self._stdout_buffer = bytearray()
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, bufsize=0)
        assert self.process.stdin is not None and self.process.stdout is not None
        os.set_blocking(self.process.stdin.fileno(), False)
        os.set_blocking(self.process.stdout.fileno(), False)
        try:
            ready = self._read_line_until(time.monotonic()+startup_timeout, "verifier-startup-timeout")
            if (not isinstance(ready, dict) or ready.get("event") != "ready"
                    or ready.get("profile") != "r4-checked-v5"
                    or not isinstance(ready.get("receipt_sha256"), str)
                    or not isinstance(ready.get("relations"), list)
                    or ready.get("validation_count") != len(ready["relations"])
                    or ready.get("validation_count", 0) < 1):
                raise RuntimeError("invalid-checked-verifier-ready-record")
        except Exception:
            self.close()
            raise
        self.ready = ready

    def _read_line_until(self, deadline: float, timeout_error: str) -> dict:
        if self.process.poll() is not None or self.process.stdout is None:
            raise RuntimeError("checked-verifier-not-running")
        while b"\n" not in self._stdout_buffer:
            if len(self._stdout_buffer) > MAX_HTTP_BODY_BYTES:
                raise RuntimeError("checked-verifier-response-too-large")
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError(timeout_error)
            selector = selectors.DefaultSelector()
            try:
                selector.register(self.process.stdout, selectors.EVENT_READ)
                if not selector.select(remaining): raise TimeoutError(timeout_error)
            finally:
                selector.close()
            chunk = os.read(self.process.stdout.fileno(), min(65536, MAX_HTTP_BODY_BYTES + 1 - len(self._stdout_buffer)))
            if not chunk: raise RuntimeError("checked-verifier-closed-output")
            self._stdout_buffer.extend(chunk)
        line, _, rest = self._stdout_buffer.partition(b"\n")
        self._stdout_buffer = bytearray(rest)
        value = strict_json(line)
        if not isinstance(value, dict):
            raise RuntimeError("checked-verifier-non-object-response")
        return value

    def _write_until(self, data: bytes, deadline: float) -> None:
        if self.process.poll() is not None or self.process.stdin is None:
            raise RuntimeError("checked-verifier-not-running")
        view=memoryview(data)
        while view:
            remaining=deadline-time.monotonic()
            if remaining<=0: raise TimeoutError("verifier-response-timeout")
            selector=selectors.DefaultSelector()
            try:
                selector.register(self.process.stdin,selectors.EVENT_WRITE)
                if not selector.select(remaining): raise TimeoutError("verifier-response-timeout")
            finally: selector.close()
            try: written=os.write(self.process.stdin.fileno(),view)
            except BlockingIOError: continue
            if written<=0: raise RuntimeError("checked-verifier-closed-input")
            view=view[written:]

    def response(self, payload: dict) -> dict | None:
        with self.lock:
            if self.process.poll() is not None or self.process.stdin is None:
                return None
            started=time.perf_counter_ns();deadline=time.monotonic()+self.request_timeout
            try:
                self._write_until(canonical(payload)+b"\n",deadline)
                response = self._read_line_until(deadline,"verifier-response-timeout")
            except Exception:
                self.close()
                return None
            self.last_wall_ns=time.perf_counter_ns()-started
            self.last_private_timing={}
            if "_e2_pure_proof_verify_ns" in response:
                self.last_private_timing["pure_proof_verify_ns"]=response.pop("_e2_pure_proof_verify_ns")
            # Every response proves it came from the retained checked context.
            if response.pop("_r4_receipt_sha256", None) != self.ready["receipt_sha256"]:
                self.close()
                return None
            return response

    def call(self, payload: dict) -> bool:
        response = self.response(payload)
        return response is not None and response.get("valid") is True

    def close(self) -> None:
        process = getattr(self, "process", None)
        if process is None or process.poll() is not None:
            return
        try:
            if process.stdin is not None:
                process.stdin.close()
            process.wait(timeout=2)
        except Exception:
            process.terminate()
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=2)


class App:
    def __init__(self, store: Store, verifier: CoreVerifier, delta: int, audience: str, clock=lambda: int(time.time()), deployment_id: str="", sr_verifier: CoreVerifier | None=None):
        self.store, self.verifier, self.delta, self.audience, self.clock, self.deployment_id, self.sr_verifier = store, verifier, delta, audience, clock, deployment_id, sr_verifier

    def install_header(self, body: bytes, signature: str, now: int) -> str:
        snapshot = strict_json(body)
        if set(snapshot) != {"deployment_id","tuple_version", "ra_root", "state_epoch", "state_root", "revocation_epoch", "revocation_root", "issued_at"}:
            raise ValueError("bad-snapshot-schema")
        if snapshot["deployment_id"]!=self.deployment_id: raise PermissionError("wrong-deployment")
        if not all(isinstance(snapshot[x], int) and not isinstance(snapshot[x], bool) and 0 <= snapshot[x] <= U64_MAX for x in ("tuple_version", "state_epoch", "revocation_epoch", "issued_at")):
            raise ValueError("bad-snapshot-number")
        if not all(HEX64.fullmatch(snapshot[x]) for x in ("ra_root", "state_root", "revocation_root")):
            raise ValueError("bad-root")
        if not self.verifier.call({"command":"header-verify","snapshot":snapshot,"signature_b64":signature}):
            raise PermissionError("bad-header-signature")
        return self.store.install_header(snapshot, signature, now, self.clock, self.verifier, self.deployment_id)

    def invoke(self, envelope: dict, method: str, path: str, body: bytes, now: int) -> tuple[int, dict]:
        sr = envelope.get("proof_scheme") == "sr-bbs23-cdl-v1"
        required = ({"protocol_version","proof_scheme","config_id","deployment_id","audience","resource","action_onehot","nonce","request_time","expires_at","terminal_agent_pk","circuit_id","snapshot_digest","showing_b64","signature_b64"} if sr else {"protocol_version","deployment_id","audience","resource","action_onehot","nonce","request_time","expires_at","terminal_agent_pk","circuit_id","vk_id","snapshot_digest","relation_request_digest","proof_b64","signature_b64"})
        if set(envelope) != required:
            return 400, {"error":"bad-envelope-schema"}
        if sr and self.sr_verifier is None: return 400,{"error":"proof-scheme-not-enabled"}
        string_fields=required-{"action_onehot","request_time","expires_at"}
        # The empty deployment is retained only for the in-process legacy logic
        # harness. The service CLI requires a non-empty trusted deployment ID.
        if not all(
            isinstance(envelope[x], str)
            and (
                (x == "deployment_id" and envelope[x] == self.deployment_id == "")
                or 0 < len(envelope[x]) <= (1_000_000 if x in ("proof_b64", "showing_b64") else 4096)
            )
            for x in string_fields
        ):
            return 400, {"error":"bad-string-field"}
        if envelope["protocol_version"] != "plan-a-http-v1" or envelope["deployment_id"] != self.deployment_id or envelope["audience"] != self.audience:
            return 400, {"error":"protocol-or-audience"}
        if not exactly_one_u16(envelope["action_onehot"]) or not valid_nonce(envelope["nonce"]):
            return 400, {"error":"action-or-nonce"}
        if not all(isinstance(envelope[x],int) and not isinstance(envelope[x],bool) for x in ("request_time","expires_at")) or not (envelope["request_time"] <= now <= envelope["expires_at"]):
            return 401, {"error":"expired"}
        snapshot = self.store.accepted_snapshot(envelope["snapshot_digest"], now, self.delta)
        if snapshot is not None: snapshot={"deployment_id":self.deployment_id,**snapshot}
        if snapshot is None or tagged_digest(b"plan-a-snapshot-v1", snapshot) != envelope["snapshot_digest"]:
            return 401, {"error":"snapshot-not-accepted"}
        request_fields = (("protocol_version","proof_scheme","config_id","deployment_id","audience","resource","action_onehot","nonce","request_time","expires_at","terminal_agent_pk","circuit_id","snapshot_digest") if sr else ("protocol_version","deployment_id","audience","resource","action_onehot","nonce","request_time","expires_at","terminal_agent_pk","circuit_id","vk_id","snapshot_digest"))
        request = {k: envelope[k] for k in request_fields}
        request.update({"method":method.upper(), "path":urlsplit(path).path, "body_sha256":hashlib.sha256(body).hexdigest()})
        request_digest = tagged_digest(b"plan-a-request-v1", request)
        statement = {"snapshot": snapshot, "request": request, "canonical_request_sha256": request_digest}
        if not sr: statement["relation_request_digest"]=envelope["relation_request_digest"]
        proof_ok=(self.sr_verifier.call({"command":"sr-verify","config_id":envelope["config_id"],"proof_scheme":envelope["proof_scheme"],"public_statement":statement,"showing_b64":envelope["showing_b64"]}) if sr else self.verifier.call({"command":"verify","vk_id":envelope["vk_id"],"public_statement":statement,"proof_b64":envelope["proof_b64"]}))
        if not proof_ok:
            return 403, {"error":"invalid-proof"}
        terminal_payload={"command":"sr-terminal-verify" if sr else "terminal-verify","deployment_id":envelope["deployment_id"],"terminal_agent_pk":envelope["terminal_agent_pk"],"canonical_request_sha256":request_digest,"snapshot_digest":envelope["snapshot_digest"],"circuit_id":envelope["circuit_id"],"signature_b64":envelope["signature_b64"]}
        if sr: terminal_payload.update({"config_id":envelope["config_id"],"proof_scheme":envelope["proof_scheme"],"showing_b64":envelope["showing_b64"]})
        else: terminal_payload["proof_b64"]=envelope["proof_b64"]
        if not (self.sr_verifier if sr else self.verifier).call(terminal_payload):
            return 403, {"error":"invalid-terminal-signature"}
        output = {"ok":True,"resource":envelope["resource"],"payload":"synthetic-file-payload-v1","request_digest":request_digest}
        commit_status = self.store.commit_once(request, request_digest, output, self.clock, self.delta)
        if commit_status != "committed":
            return 409, {"error":commit_status}
        return 200, output

    def state_update(self, body: bytes) -> tuple[int,dict]:
        try: update=strict_json(body)
        except Exception: return 400,{"error":"bad-state-update-json"}
        required={"command","deployment_id","owner_commitment","position","expected_version","new_epoch","opening","signature_b64"}
        if not isinstance(update,dict) or set(update)!=required or update.get("command")!="state-update-verify": return 400,{"error":"bad-state-update-schema"}
        if update["deployment_id"]!=self.deployment_id: return 403,{"error":"wrong-deployment"}
        trusted=self.store.admitted_state(update["deployment_id"],update["owner_commitment"],update["position"])
        if trusted is None: return 403,{"error":"owner-not-admitted"}
        update.update(trusted)
        response=self.verifier.response(update)
        if response is None or response.get("valid") is not True: return 403,{"error":"invalid-state-update"}
        if set(response)!={"valid","new_leaf","new_version","new_epoch","active"}: return 502,{"error":"bad-core-state-response"}
        status=self.store.cas_state_update(update,response,self.clock())
        return (201,{**response,"publication_status":"pending"}) if status=="committed" else (409,{"error":status})

    def blind_state_update(self, body: bytes) -> tuple[int,dict]:
        server_started = time.perf_counter_ns()
        try: request=strict_json(body)
        except Exception: return 400,{"error":"bad-blind-update-json"}
        required={"command","statement","proof_b64","signature_b64"}
        if not isinstance(request,dict) or set(request)!=required or request.get("command")!="blind-state-update-verify": return 400,{"error":"bad-blind-update-schema"}
        statement=request.get("statement")
        statement_fields={"config_digest","deployment_id","circuit_id","owner_commitment","position","expiry_cap","admission_version","old_leaf","new_leaf","old_version","new_version","old_epoch","new_epoch"}
        if not isinstance(statement,dict) or set(statement)!=statement_fields: return 400,{"error":"bad-blind-statement-schema"}
        if statement["deployment_id"]!=self.deployment_id: return 403,{"error":"wrong-deployment"}
        if not all(isinstance(statement[x],int) and not isinstance(statement[x],bool) and 0<=statement[x]<=2**64-1 for x in ("expiry_cap","admission_version","old_version","new_version","old_epoch","new_epoch")): return 400,{"error":"bad-blind-u64"}
        if not isinstance(statement["position"],int) or isinstance(statement["position"],bool) or not 0<=statement["position"]<=2**32-1: return 400,{"error":"bad-position"}
        if not all(isinstance(statement[x],str) and HEX64.fullmatch(statement[x]) for x in ("config_digest","deployment_id","circuit_id","owner_commitment","old_leaf","new_leaf")): return 400,{"error":"bad-blind-field"}
        if not all(isinstance(request[x],str) and 0<len(request[x])<=1_000_000 for x in ("proof_b64","signature_b64")): return 400,{"error":"bad-blind-encoding"}
        trusted=self.store.blind_admission(statement["deployment_id"],statement["owner_commitment"],statement["position"])
        if trusted is None: return 403,{"error":"owner-not-admitted"}
        verifier_request={**request,"trusted_admission":trusted}
        verify_started = time.perf_counter_ns()
        response=self.verifier.response(verifier_request)
        verify_finished = time.perf_counter_ns()
        expected={"valid","owner_commitment","position","old_leaf","new_leaf","old_version","new_version","old_epoch","new_epoch","expiry_cap","admission_version"}
        if response is None or response.get("valid") is not True or set(response)!=expected: return 403,{"error":"invalid-blind-update"}
        if any(response[x]!=statement[x] for x in expected-{"valid"}): return 502,{"error":"blind-core-echo-mismatch"}
        cas_started = time.perf_counter_ns()
        status=self.store.cas_blind_state_update(statement,response,self.clock())
        cas_finished = time.perf_counter_ns()
        self.last_blind_timing = {
            "external_verifier_ns": getattr(self.verifier,"last_wall_ns",None),
            "server_verification_ns": verify_finished-verify_started,
            "atomic_cas_ns": cas_finished-cas_started,
            "server_application_ns": cas_finished-server_started,
            "pure_proof_verify_ns": getattr(self.verifier,"last_private_timing",{}).get("pure_proof_verify_ns"),
        }
        # Deliberately return only public transition metadata. No opening is accepted,
        # persisted, logged, or echoed by this endpoint.
        return (201,{"valid":True,"new_leaf":response["new_leaf"],"new_version":response["new_version"],"new_epoch":response["new_epoch"],"publication_status":"pending"}) if status=="committed" else (409,{"error":status})

    def enroll(self, body: bytes) -> tuple[int,dict]:
        try: request=strict_json(body)
        except Exception: return 400,{"error":"bad-admission-json"}
        required={"command","deployment_id","owner_commitment","position","owner_public_key","registration_salt","max_expiry","initial_opening","initial_version","initial_epoch","signature_b64"}
        if not isinstance(request,dict) or set(request)!=required or request.get("command")!="admission-verify": return 400,{"error":"bad-admission-schema"}
        if request["deployment_id"]!=self.deployment_id: return 403,{"error":"wrong-deployment"}
        response=self.verifier.response(request)
        expected={"valid","owner_commitment","position","initial_leaf","initial_version","initial_epoch","active","max_expiry"}
        if response is None or response.get("valid") is not True or set(response)!=expected: return 403,{"error":"invalid-admission"}
        if response["owner_commitment"]!=request["owner_commitment"] or response["position"]!=request["position"] or response["max_expiry"]!=request["max_expiry"]: return 502,{"error":"core-admission-echo-mismatch"}
        status=self.store.enroll(request,response,self.clock())
        return (201,{**response,"publication_status":"pending"}) if status=="committed" else (409,{"error":status})

    def revoke(self, body: bytes) -> tuple[int,dict]:
        try: request=strict_json(body)
        except Exception: return 400,{"error":"bad-revoke-json"}
        if not isinstance(request,dict) or set(request)!={"command","rk_b64","counter","sn"} or request.get("command")!="revoke-authorize": return 400,{"error":"bad-revoke-schema"}
        response=self.verifier.response(request)
        if response is None or response.get("valid") is not True or set(response)!={"valid","serial"}: return 403,{"error":"invalid-revocation-capability"}
        status=self.store.insert_revocation(response["serial"],request["counter"],self.clock())
        return (201,{**response,"publication_status":"pending"}) if status=="committed" else (409,{"error":status})

    def register_ra(self, body: bytes) -> tuple[int,dict]:
        try: request=strict_json(body)
        except Exception: return 400,{"error":"bad-ra-json"}
        required={"command","deployment_id","position","owner_commitment","resource","action_mask","interval_lo","interval_hi","permit_expiry","admission_id","signature_b64"}
        if not isinstance(request,dict) or set(request)!=required or request.get("command")!="ra-register-verify": return 400,{"error":"bad-ra-schema"}
        if request["deployment_id"]!=self.deployment_id: return 403,{"error":"wrong-deployment"}
        response=self.verifier.response(request)
        if response is None or response.get("valid") is not True or set(response)!={"valid","position","leaf"}: return 403,{"error":"invalid-ra-registration"}
        if response["position"]!=request["position"]: return 502,{"error":"core-ra-echo-mismatch"}
        status=self.store.insert_ra_leaf(request["deployment_id"],response["position"],response["leaf"],self.clock())
        return (201,{**response,"publication_status":"pending"}) if status=="committed" else (409,{"error":status})

    def update_ra(self, body: bytes) -> tuple[int,dict]:
        try: request=strict_json(body)
        except Exception: return 400,{"error":"bad-ra-json"}
        expected=request.pop("expected_leaf",None) if isinstance(request,dict) else None
        required={"command","deployment_id","position","owner_commitment","resource","action_mask","interval_lo","interval_hi","permit_expiry","admission_id","signature_b64"}
        if not isinstance(request,dict) or set(request)!=required or request.get("command")!="ra-register-verify" or not isinstance(expected,str) or not HEX64.fullmatch(expected): return 400,{"error":"bad-ra-update-schema"}
        if request["deployment_id"]!=self.deployment_id: return 403,{"error":"wrong-deployment"}
        response=self.verifier.response(request)
        if response is None or response.get("valid") is not True or set(response)!={"valid","position","leaf"}: return 403,{"error":"invalid-ra-registration"}
        status=self.store.update_ra_leaf(request["deployment_id"],response["position"],expected,response["leaf"],self.clock())
        return (201,{**response,"publication_status":"pending"}) if status=="committed" else (409,{"error":status})


def handler_for(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "PlanAHTTP/1"
        def reply(self, status: int, value: dict):
            data = canonical(value); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(data))); self.end_headers(); self.wfile.write(data)
        def read_body(self) -> bytes:
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length) if raw_length is not None else 0
            except ValueError as exc:
                raise ValueError("bad-content-length") from exc
            if length < 0:
                raise ValueError("bad-content-length")
            if length > MAX_HTTP_BODY_BYTES:
                raise OverflowError("body-too-large")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("truncated-body")
            return body
        def do_GET(self):
            if self.path == "/public/versions/latest":
                value=app.store.public_latest();self.reply(200,value) if value else self.reply(404,{"error":"no-public-version"});return
            match=re.fullmatch(r"/public/versions/([0-9a-f]{64})/leaves",self.path)
            if match:
                value=app.store.public_version(match.group(1));self.reply(200,value) if value else self.reply(404,{"error":"unknown-public-version"});return
            self.reply(404,{"error":"not-found"})
        def do_POST(self):
            try:
                body = self.read_body()
            except OverflowError as exc:
                self.reply(413,{"error":str(exc)});return
            except ValueError as exc:
                self.reply(400,{"error":str(exc)});return
            if self.path == "/admin/header":
                try: digest = app.install_header(body, self.headers.get("X-PlanA-Header-Signature", ""), app.clock())
                except PermissionError as e: self.reply(403,{"error":str(e)}); return
                except Exception as e: self.reply(400,{"error":str(e)}); return
                self.reply(201,{"snapshot_digest":digest}); return
            if self.path == "/admin/state-update":
                status,value=app.state_update(body);self.reply(status,value);return
            if self.path == "/state/blind-update":
                status,value=app.blind_state_update(body);self.reply(status,value);return
            if self.path == "/admin/enroll":
                status,value=app.enroll(body);self.reply(status,value);return
            if self.path == "/admin/revoke":
                status,value=app.revoke(body);self.reply(status,value);return
            if self.path == "/admin/ra-register":
                status,value=app.register_ra(body);self.reply(status,value);return
            if self.path == "/admin/ra-update":
                status,value=app.update_ra(body);self.reply(status,value);return
            if self.path != "/resource/read": self.reply(404,{"error":"not-found"}); return
            try: envelope = strict_json(self.headers.get("X-PlanA-Authorization", ""))
            except Exception: self.reply(400,{"error":"bad-authorization-json"}); return
            status, value = app.invoke(envelope, "POST", self.path, body, app.clock()); self.reply(status,value)
        def log_message(self, fmt, *args): pass
    return Handler


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--db", type=Path, required=True); p.add_argument("--proof-cli", nargs="+", required=True)
    p.add_argument("--host", default="127.0.0.1"); p.add_argument("--port", type=int, default=8787)
    p.add_argument("--delta-seconds", type=int, default=30); p.add_argument("--audience", required=True)
    p.add_argument("--deployment-id", required=True)
    p.add_argument("--verify-timeout", type=float, default=120.0)
    p.add_argument("--sr-proof-cli", nargs="+")
    p.add_argument("--checked-profile", action="store_true")
    p.add_argument("--startup-timeout", type=float, default=1800.0)
    args = p.parse_args()
    sr_verifier=CoreVerifier(args.sr_proof_cli,args.verify_timeout) if args.sr_proof_cli else None
    verifier = (ResidentCheckedVerifier(args.proof_cli, args.startup_timeout, args.verify_timeout)
                if args.checked_profile else CoreVerifier(args.proof_cli, args.verify_timeout))
    app = App(Store(args.db), verifier, args.delta_seconds, args.audience, deployment_id=args.deployment_id, sr_verifier=sr_verifier)
    server = ThreadingHTTPServer((args.host,args.port), handler_for(app))
    try: server.serve_forever()
    finally:
        server.server_close(); verifier.close()


if __name__ == "__main__": main()

