#!/usr/bin/env python3
"""Re-run the frozen R6 analyzer over the ten included compact observations."""
from pathlib import Path
import hashlib
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
R6 = ROOT / "results" / "r6"
rows = sorted((R6 / "formal").glob("depth*/seed_*/RESULT.json"))
if len(rows) != 10:
    raise SystemExit(f"expected 10 R6 observations, found {len(rows)}")
with tempfile.TemporaryDirectory(prefix="r6-analysis-") as td:
    out = Path(td) / "ANALYSIS.json"
    subprocess.run([sys.executable, str(R6 / "analysis" / "analyze_r6.py"),
                    "--results", *map(str, rows), "--output", str(out)], check=True)
    expected = R6 / "ANALYSIS.json"
    if out.read_bytes() != expected.read_bytes():
        raise SystemExit("R6 analysis byte mismatch")
    print("R6_ANALYSIS_MATCH", hashlib.sha256(expected.read_bytes()).hexdigest())
