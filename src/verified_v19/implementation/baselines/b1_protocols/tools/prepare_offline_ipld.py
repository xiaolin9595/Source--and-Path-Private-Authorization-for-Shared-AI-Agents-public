#!/usr/bin/env python3
"""Vendor the exact official ipld-core crate into a disposable runner copy."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

NAME = "ipld-core"
VERSION = "0.4.3"
EXPECTED_SHA256 = "090f624976d72f0b0bb71b86d58dc16c15e069193067cb3a3a09d655246cbbda"
URL = f"https://static.crates.io/crates/{NAME}/{NAME}-{VERSION}.crate"
PQ_NAME = "pq-ucan"
PQ_VERSION = "0.1.2"
PQ_EXPECTED_SHA256 = "c4f26f4e23e6a928ec6dafd6be3839af162b48e6fdf1fc15af6718f514da014e"
PQ_URL = f"https://static.crates.io/crates/{PQ_NAME}/{PQ_NAME}-{PQ_VERSION}.crate"
CID_NAME = "cid"
CID_VERSION = "0.11.3"
CID_EXPECTED_SHA256 = "21a304f95f84d169a6f31c4d0a30d784643aaa0bbc9c1e449a2c23e963ec4971"
CID_URL = f"https://static.crates.io/crates/{CID_NAME}/{CID_NAME}-{CID_VERSION}.crate"


def download(url: str, destination: Path, attempts: int) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "plan-a-artifact/1"})
            with urllib.request.urlopen(request, timeout=90) as response:
                with destination.open("wb") as output:
                    shutil.copyfileobj(response, output)
            return
        except Exception as error:
            last_error = error
            if destination.exists():
                destination.unlink()
            if attempt != attempts:
                time.sleep(min(2**attempt, 20))
    raise SystemExit(f"download failed after {attempts} attempts: {last_error}")


def safe_extract(archive: Path, destination: Path) -> None:
    destination_resolved = destination.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            target = (destination / member.name).resolve()
            if destination_resolved not in target.parents and target != destination_resolved:
                raise SystemExit(f"unsafe archive path: {member.name}")
            if member.issym() or member.islnk():
                raise SystemExit(f"archive link rejected: {member.name}")
        bundle.extractall(destination)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate-root", type=Path, required=True)
    parser.add_argument("--provenance-out", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument(
        "--archive",
        type=Path,
        help="pre-transferred official crate archive; disables network download",
    )
    parser.add_argument(
        "--pq-ucan-archive",
        type=Path,
        help="pre-transferred official pq-ucan crate archive",
    )
    parser.add_argument(
        "--cid-archive",
        type=Path,
        help="pre-transferred cid archive matching the crates.io registry checksum",
    )
    args = parser.parse_args()
    manifest = args.crate_root / "Cargo.toml"
    original = manifest.read_text()
    expected_line = f'{NAME} = "={VERSION}"'
    if expected_line not in original:
        raise SystemExit(f"expected pinned dependency missing: {expected_line}")
    pq_expected_line = (
        f'{PQ_NAME} = {{ version = "={PQ_VERSION}", default-features = false, '
        'features = ["std", "ed25519"] }'
    )
    if pq_expected_line not in original:
        raise SystemExit(f"expected pinned dependency missing: {pq_expected_line}")
    vendor = args.crate_root / "vendor"
    target = vendor / f"{NAME}-{VERSION}"
    if target.exists():
        raise SystemExit(f"refusing to overwrite {target}")
    vendor.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=vendor) as temporary:
        archive = Path(temporary) / f"{NAME}-{VERSION}.crate"
        if args.archive is None:
            download(URL, archive, args.attempts)
            transport = "direct-official-static-download"
        else:
            supplied = args.archive.resolve()
            if not supplied.is_file():
                raise SystemExit(f"supplied archive missing: {supplied}")
            shutil.copyfile(supplied, archive)
            transport = "pre-transferred-official-static-archive"
        actual = hashlib.sha256(archive.read_bytes()).hexdigest()
        if actual != EXPECTED_SHA256:
            raise SystemExit(f"crate checksum mismatch: {actual}")
        safe_extract(archive, vendor)
        archive_copy = vendor / f"{NAME}-{VERSION}.crate"
        shutil.copyfile(archive, archive_copy)
    if not target.is_dir() or not (target / "Cargo.toml").is_file():
        raise SystemExit("official crate archive did not contain expected root")
    pq_target = vendor / f"{PQ_NAME}-{PQ_VERSION}"
    if pq_target.exists():
        raise SystemExit(f"refusing to overwrite {pq_target}")
    if args.pq_ucan_archive is None:
        raise SystemExit("--pq-ucan-archive is required for the offline bootstrap")
    supplied_pq = args.pq_ucan_archive.resolve()
    if not supplied_pq.is_file():
        raise SystemExit(f"supplied pq-ucan archive missing: {supplied_pq}")
    pq_actual = hashlib.sha256(supplied_pq.read_bytes()).hexdigest()
    if pq_actual != PQ_EXPECTED_SHA256:
        raise SystemExit(f"pq-ucan crate checksum mismatch: {pq_actual}")
    safe_extract(supplied_pq, vendor)
    shutil.copyfile(supplied_pq, vendor / f"{PQ_NAME}-{PQ_VERSION}.crate")
    if not pq_target.is_dir() or not (pq_target / "Cargo.toml").is_file():
        raise SystemExit("official pq-ucan archive did not contain expected root")
    cid_target = vendor / f"{CID_NAME}-{CID_VERSION}"
    if cid_target.exists():
        raise SystemExit(f"refusing to overwrite {cid_target}")
    if args.cid_archive is None:
        raise SystemExit("--cid-archive is required for the offline bootstrap")
    supplied_cid = args.cid_archive.resolve()
    if not supplied_cid.is_file():
        raise SystemExit(f"supplied cid archive missing: {supplied_cid}")
    cid_actual = hashlib.sha256(supplied_cid.read_bytes()).hexdigest()
    if cid_actual != CID_EXPECTED_SHA256:
        raise SystemExit(f"cid crate checksum mismatch: {cid_actual}")
    safe_extract(supplied_cid, vendor)
    shutil.copyfile(supplied_cid, vendor / f"{CID_NAME}-{CID_VERSION}.crate")
    if not cid_target.is_dir() or not (cid_target / "Cargo.toml").is_file():
        raise SystemExit("cid archive did not contain expected root")
    patched = original.replace(
        expected_line,
        f'{NAME} = {{ version = "={VERSION}", path = "vendor/{NAME}-{VERSION}" }}',
        1,
    )
    patched = patched.replace(
        pq_expected_line,
        f'{PQ_NAME} = {{ version = "={PQ_VERSION}", path = "vendor/{PQ_NAME}-{PQ_VERSION}", default-features = false, features = ["std", "ed25519"] }}',
        1,
    )
    if "[patch.crates-io]" in patched:
        raise SystemExit("manifest already contains [patch.crates-io]")
    patched += (
        f'\n[patch.crates-io]\n{NAME} = {{ path = "vendor/{NAME}-{VERSION}" }}\n'
        f'{PQ_NAME} = {{ path = "vendor/{PQ_NAME}-{PQ_VERSION}" }}\n'
        f'{CID_NAME} = {{ path = "vendor/{CID_NAME}-{CID_VERSION}" }}\n'
    )
    manifest.write_text(patched)
    args.provenance_out.parent.mkdir(parents=True, exist_ok=True)
    args.provenance_out.write_text(
        json.dumps(
            {
                "schema": "plan-a-official-crate-bootstrap-v1",
                "name": NAME,
                "version": VERSION,
                "url": URL,
                "expected_sha256": EXPECTED_SHA256,
                "actual_sha256": EXPECTED_SHA256,
                "transport": transport,
                "supplied_archive": str(args.archive.resolve())
                if args.archive is not None
                else None,
                "source_modified": False,
                "manifest_patch_scope": "runner work copy only; exact registry-checksummed ipld-core, pq-ucan and cid archives are path patched without source edits",
                "pq_ucan": {
                    "name": PQ_NAME,
                    "version": PQ_VERSION,
                    "url": PQ_URL,
                    "expected_sha256": PQ_EXPECTED_SHA256,
                    "actual_sha256": pq_actual,
                    "supplied_archive": str(supplied_pq),
                    "source_modified": False,
                },
                "cid": {
                    "name": CID_NAME,
                    "version": CID_VERSION,
                    "canonical_registry_url": CID_URL,
                    "expected_sha256": CID_EXPECTED_SHA256,
                    "actual_sha256": cid_actual,
                    "supplied_archive": str(supplied_cid),
                    "transport_note": "archive transferred from a crates.io mirror; bytes match the exact crates.io registry checksum from the publisher lock",
                    "source_modified": False,
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
