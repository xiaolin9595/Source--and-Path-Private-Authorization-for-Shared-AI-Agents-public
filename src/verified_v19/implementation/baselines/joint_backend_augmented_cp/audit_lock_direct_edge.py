#!/usr/bin/env python3
"""Apply and audit the single Cargo.lock direct edge required by ark-ec-old.

This intentionally does not resolve dependencies.  The retained lock already contains
the exact legacy ark-ec package selected by the path dependency.  Cargo's offline
resolver cannot regenerate the lock because an unrelated unpinned git dependency has
no cached origin/HEAD.  This helper permits one textual change and rejects everything
else; the subsequent `cargo check --locked --offline` remains the authoritative Cargo
validation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


EXPECTED_BEFORE_SHA256 = (
    "3c82016c4e8ec10d53723ece56bca008fa5eeb0eb5b84676107e7a9c33a207ff"
)
LEGACY_PACKAGE = """[[package]]
name = "ark-ec"
version = "0.1.0"
source = "git+https://github.com/arkworks-rs/algebra#8d09ec4525c2f7697a3cd80dae88bdc84afaa6a2"
"""
ROOT_ANCHOR = """name = "joint-backend-augmented-cp"
version = "0.1.0"
dependencies = [
 "accumulator",
 "ark-bls12-381 0.1.0",
 "ark-bls12-381 0.4.0",
"""
ROOT_REPLACEMENT = ROOT_ANCHOR + ' "ark-ec 0.1.0",\n'


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=Path("Cargo.lock"))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    before = args.lock.read_bytes()
    before_text = before.decode("utf-8")
    before_sha = digest(before)
    legacy_count = before_text.count(LEGACY_PACKAGE)
    old_edge_count = before_text.count(ROOT_REPLACEMENT)
    anchor_count = before_text.count(ROOT_ANCHOR)

    if legacy_count != 1:
        raise SystemExit(f"expected one exact legacy ark-ec package, found {legacy_count}")

    if old_edge_count == 1:
        after = before
        status = "already-applied"
    else:
        if before_sha != EXPECTED_BEFORE_SHA256:
            raise SystemExit(
                f"unexpected pre-edit Cargo.lock sha256 {before_sha}; "
                f"expected {EXPECTED_BEFORE_SHA256}"
            )
        if old_edge_count != 0 or anchor_count != 1:
            raise SystemExit(
                f"edge={old_edge_count}, exact root anchor={anchor_count}; refusing edit"
            )
        after_text = before_text.replace(ROOT_ANCHOR, ROOT_REPLACEMENT, 1)
        after = after_text.encode("utf-8")
        status = "applied"

    after_text = after.decode("utf-8")
    if after_text.count(LEGACY_PACKAGE) != 1:
        raise SystemExit("legacy ark-ec package changed")
    if after_text.count(ROOT_REPLACEMENT) != 1:
        raise SystemExit("expected exactly one legacy ark-ec root edge after edit")

    expected_after = before_text.replace(ROOT_ANCHOR, ROOT_REPLACEMENT, 1).encode("utf-8")
    if status == "applied" and after != expected_after:
        raise SystemExit("candidate lock differs from the single permitted replacement")

    changed_line_count = 0 if status == "already-applied" else 1
    report = {
        "schema": "plan-a-e8-cargo-lock-direct-edge-audit-v1",
        "passed": True,
        "status": status,
        "lock_path": str(args.lock),
        "before_sha256": before_sha,
        "after_sha256": digest(after),
        "changed_line_count": changed_line_count,
        "only_change": 'root dependency list adds "ark-ec 0.1.0"',
        "legacy_package": {
            "name": "ark-ec",
            "version": "0.1.0",
            "source": "git+https://github.com/arkworks-rs/algebra#8d09ec4525c2f7697a3cd80dae88bdc84afaa6a2",
            "exact_record_present": True,
        },
        "cargo_validation_required": "cargo check --release --locked --offline --all-targets",
    }

    if args.apply and after != before:
        args.lock.write_bytes(after)
    elif after != before:
        report["status"] = "validated-not-applied"

    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
