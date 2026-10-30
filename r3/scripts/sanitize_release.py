#!/usr/bin/env python3
"""Fail closed on common anonymity, secret, and oversized-artifact hazards."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


MAX_BYTES = 50 * 1024 * 1024
TEXT_LIMIT = 8 * 1024 * 1024
SKIP_CONTENT = {"FILELIST.sha256", "SANITIZATION_REPORT.json", "sanitize_release.py"}
BAD_NAMES = re.compile(
    r"(^\._|\.pem$|\.key$|id_rsa|id_ed25519|known_hosts|authorized_keys|"
    r"proving[_-]?key|(^|[_.-])pk\.(bin|dat|raw)$|failure\.log$)", re.I
)
BAD_TEXT = [
    ("macOS user path", re.compile(rb"/Users/[A-Za-z0-9._-]+/")),
    ("mounted personal path", re.compile(rb"/Volumes/[A-Za-z0-9._-]+/")),
    ("Unix home path", re.compile(rb"/home/[A-Za-z0-9._-]+/")),
    ("private key", re.compile(rb"BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY")),
    ("GitHub token", re.compile(rb"(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]+)")),
    ("AWS access key", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("WeChat identifier", re.compile(rb"wxid_[A-Za-z0-9]+")),
    ("private host alias", re.compile(rb"206160G")),
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--report")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    findings: list[dict[str, object]] = []
    checked = 0
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            findings.append({"path": rel, "kind": "symlink"})
            continue
        if not path.is_file():
            continue
        checked += 1
        size = path.stat().st_size
        if BAD_NAMES.search(path.name):
            findings.append({"path": rel, "kind": "sensitive filename"})
        if size > MAX_BYTES:
            findings.append({"path": rel, "kind": "oversized file", "bytes": size})
        if path.name in SKIP_CONTENT or size > TEXT_LIMIT:
            continue
        data = path.read_bytes()
        if b"\0" in data[:4096]:
            continue
        for label, pattern in BAD_TEXT:
            if pattern.search(data):
                findings.append({"path": rel, "kind": label})
    result = {
        "schema": "anonymous-release-sanitization-v1",
        "status": "PASS" if not findings else "FAIL",
        "files_checked": checked,
        "max_file_bytes": MAX_BYTES,
        "findings": findings,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.report:
        (root / args.report).write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
