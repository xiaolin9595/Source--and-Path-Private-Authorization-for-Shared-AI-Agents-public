#!/usr/bin/env python3
"""Recompute included E1, R2, R3/E2, and R4 timing analyses."""

from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


with tempfile.TemporaryDirectory(prefix="joint-analysis-") as tmp_name:
    tmp = Path(tmp_name)
    e1_out = tmp / "e1.json"
    r2_out = tmp / "r2.json"
    e2_out = tmp / "e2.json"
    r4_out = tmp / "r4.json"
    run(
        [
            sys.executable,
            "results/e1/analysis/analyze_e1.py",
            *[str(path) for path in sorted(ROOT.glob("results/e1/raw/session*/records.jsonl"))],
            "--output",
            str(e1_out),
        ]
    )
    run(
        [
            sys.executable,
            "results/r4/analysis/recompute_included_r4_timings.py",
            "--included-run",
            "results/r4/formal_v5",
            "--expected-analysis",
            "results/r4/formal_v5/ANALYSIS.json",
            "--output",
            str(r4_out),
        ]
    )
    run(
        [
            sys.executable,
            "results/r2/analysis/analyze_r2.py",
            "--validation-manifest",
            "results/r2/raw/analysis_input_manifest.json",
            "--calibration",
            "results/r2/raw/calibration_joined.jsonl",
            "--formal",
            "results/r2/raw/formal_joined.jsonl",
            "--output",
            str(r2_out),
        ]
    )
    run(
        [
            sys.executable,
            "results/r3_e2/analysis/analyze_e2.py",
            "results/r3_e2/raw/observations.jsonl",
            str(e2_out),
        ]
    )
    expected = [
        (e1_out, ROOT / "results/e1/ANALYSIS_REPRODUCED.json"),
        (r2_out, ROOT / "results/r2/ANALYSIS_REPRODUCED.json"),
        (e2_out, ROOT / "results/r3_e2/ANALYSIS_REPRODUCED.json"),
        (r4_out, ROOT / "results/r4/formal_v5/ANALYSIS.json"),
    ]
    for actual, frozen in expected:
        if actual.read_bytes() != frozen.read_bytes():
            raise SystemExit(f"analysis mismatch: {frozen.relative_to(ROOT)}")
        print(f"MATCH {frozen.relative_to(ROOT)} {digest(frozen)}")

print("RECOMPUTE_PASS")
run([sys.executable, "scripts/recompute_historical.py"])
run([sys.executable, "scripts/recompute_r6.py"])
print("UNIFIED_RECOMPUTE_PASS")
