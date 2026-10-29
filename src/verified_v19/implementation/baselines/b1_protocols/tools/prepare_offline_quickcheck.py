#!/usr/bin/env python3
"""Install an exact official quickcheck archive into a disposable B1 copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import tarfile
from pathlib import Path

NAME = "quickcheck"
VERSION = "1.0.3"
SHA256 = "588f6378e4dd99458b60ec275b4477add41ce4fa9f64dcba6f15adccb19b50d6"
URL = f"https://static.crates.io/crates/{NAME}/{NAME}-{VERSION}.crate"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--crate-root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--provenance-out", type=Path, required=True)
    args = parser.parse_args()

    root = args.crate_root.resolve()
    archive = args.archive.resolve()
    manifest = root / "Cargo.toml"
    vendor = root / "vendor"
    target = vendor / f"{NAME}-{VERSION}"
    if not manifest.is_file() or not archive.is_file():
        raise SystemExit("manifest or official archive missing")
    actual = sha256(archive)
    if actual != SHA256:
        raise SystemExit(f"quickcheck archive SHA-256 mismatch: {actual}")
    if target.exists():
        raise SystemExit(f"refusing to overwrite {target}")

    vendor.mkdir(parents=True, exist_ok=True)
    vendor_resolved = vendor.resolve()
    expected_root = f"{NAME}-{VERSION}"
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise SystemExit("quickcheck archive is empty")
        for member in members:
            parts = Path(member.name).parts
            if not parts or parts[0] != expected_root:
                raise SystemExit(f"unexpected archive root: {member.name}")
            destination = (vendor / member.name).resolve()
            if vendor_resolved not in destination.parents:
                raise SystemExit(f"unsafe archive path: {member.name}")
            if member.issym() or member.islnk():
                raise SystemExit(f"archive link rejected: {member.name}")
        bundle.extractall(vendor)
    if not (target / "Cargo.toml").is_file():
        raise SystemExit("extracted quickcheck manifest missing")

    text = manifest.read_text()
    patch_header = "[patch.crates-io]"
    patch_line = f'{NAME} = {{ path = "vendor/{NAME}-{VERSION}" }}'
    if patch_line in text:
        raise SystemExit("quickcheck patch already present")
    if patch_header not in text:
        text = text.rstrip() + f"\n\n{patch_header}\n{patch_line}\n"
    else:
        before, after = text.split(patch_header, 1)
        text = before + patch_header + "\n" + patch_line + after
    manifest.write_text(text)

    record = {
        "schema": "plan-a-official-quickcheck-bootstrap-v1",
        "name": NAME,
        "version": VERSION,
        "canonical_registry_url": URL,
        "expected_sha256": SHA256,
        "actual_sha256": actual,
        "source_modified": False,
        "manifest_patch_scope": "disposable runner copy only",
        "path_patch": patch_line,
        "archive": str(archive),
    }
    args.provenance_out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
