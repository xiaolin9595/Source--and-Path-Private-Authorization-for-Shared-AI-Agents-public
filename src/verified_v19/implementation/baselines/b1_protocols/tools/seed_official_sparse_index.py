#!/usr/bin/env python3
"""Seed audited crates.io sparse-index responses into Cargo's local cache.

The input bundle contains the verbatim HTTP response body and headers from
https://index.crates.io.  Cargo's sparse cache is a small binary envelope over
those JSON lines.  This tool never resolves versions and never changes a crate
manifest; it only makes already audited index metadata available to an offline
Cargo invocation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path


MAGIC = b"\x03\x02\x00\x00\x00"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sparse_path(name: str) -> Path:
    name = name.lower()
    if len(name) == 1:
        return Path("1") / name
    if len(name) == 2:
        return Path("2") / name
    if len(name) == 3:
        return Path("3") / name[0] / name
    return Path(name[:2]) / name[2:4] / name


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--cargo-index-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--allow-audited-update",
        action="store_true",
        help="replace a stale cache entry with the audited official response",
    )
    parser.add_argument(
        "--backup-dir",
        type=Path,
        help="required with --allow-audited-update; retains every replaced entry",
    )
    args = parser.parse_args()
    if args.allow_audited_update and args.backup_dir is None:
        raise SystemExit("--backup-dir is required with --allow-audited-update")

    provenance_path = args.bundle / "PROVENANCE.json"
    provenance = json.loads(provenance_path.read_text())
    if provenance.get("schema") != "plan-a-b1-official-sparse-index-bundle-v1":
        raise SystemExit("unexpected sparse-index bundle schema")

    results = []
    for entry in provenance["entries"]:
        if entry.get("status") != 200 or "sha256" not in entry:
            raise SystemExit(f"bundle entry did not download successfully: {entry}")
        name = entry["name"]
        raw_path = args.bundle / f"{name}.index"
        headers_path = args.bundle / f"{name}.headers.json"
        raw = raw_path.read_bytes()
        if sha256(raw) != entry["sha256"]:
            raise SystemExit(f"raw sparse-index hash mismatch for {name}")
        headers = json.loads(headers_path.read_text())
        etag = headers.get("etag") or headers.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise SystemExit(f"missing HTTP ETag for {name}")

        records = []
        for line in raw.splitlines():
            record = json.loads(line)
            if record.get("name", "").lower() != name.lower():
                raise SystemExit(f"record name mismatch in {name}")
            version = record.get("vers")
            checksum = record.get("cksum")
            if not isinstance(version, str) or not version:
                raise SystemExit(f"missing version in {name}")
            if not isinstance(checksum, str) or len(checksum) != 64:
                raise SystemExit(f"invalid checksum in {name} {version}")
            records.append((version, line))
        if not records:
            raise SystemExit(f"empty sparse-index response for {name}")

        cache = bytearray(MAGIC)
        cache.extend(f"etag: {etag}".encode())
        cache.append(0)
        for version, line in records:
            cache.extend(version.encode())
            cache.append(0)
            cache.extend(line)
            cache.append(0)
        cache_bytes = bytes(cache)

        target = args.cargo_index_root / ".cache" / sparse_path(name)
        target.parent.mkdir(parents=True, exist_ok=True)
        action = "created"
        old_sha = None
        if target.exists():
            old = target.read_bytes()
            old_sha = sha256(old)
            if old == cache_bytes:
                action = "already_identical"
            elif args.allow_audited_update:
                backup = args.backup_dir / sparse_path(name)
                backup.parent.mkdir(parents=True, exist_ok=True)
                if backup.exists():
                    raise SystemExit(f"refusing to overwrite cache backup {backup}")
                shutil.copyfile(target, backup)
                target.write_bytes(cache_bytes)
                action = "updated_from_audited_official_response"
            else:
                raise SystemExit(
                    f"refusing to overwrite nonidentical Cargo cache entry {target}"
                )
        else:
            target.write_bytes(cache_bytes)

        results.append(
            {
                "name": name,
                "relative_index_path": str(sparse_path(name)),
                "raw_sha256": sha256(raw),
                "http_etag": etag,
                "record_count": len(records),
                "cache_path": str(target),
                "cache_sha256": sha256(cache_bytes),
                "previous_cache_sha256": old_sha,
                "action": action,
            }
        )

    report = {
        "schema": "plan-a-b1-cargo-sparse-cache-seed-v1",
        "official_source": "https://index.crates.io",
        "version_selection_performed": False,
        "manifest_modified": False,
        "bundle_provenance_sha256": sha256(provenance_path.read_bytes()),
        "entries": results,
    }
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
