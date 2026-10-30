#!/usr/bin/env python3
"""Render the public four-panel E3 figure from aggregate summary rows only."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

from analyze_e3 import plot_summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("summary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    with args.summary.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 80:
        raise SystemExit(f"expected 80 aggregate rows, got {len(rows)}")
    args.output.mkdir(parents=True, exist_ok=True)
    plot_summary(rows, args.output)


if __name__ == "__main__":
    main()
