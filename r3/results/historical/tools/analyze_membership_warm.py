#!/usr/bin/env python3
"""Analyze a retained native E8 paired result without changing raw data."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
from pathlib import Path


def percentile(sorted_values: list[float], probability: float) -> float:
    position = (len(sorted_values) - 1) * probability
    lower = int(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("raw", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--resamples", type=int, default=100_000)
    parser.add_argument("--seed", type=int, default=0xE820261025)
    args = parser.parse_args()
    raw_bytes = args.raw.read_bytes()
    raw = json.loads(raw_bytes)
    samples = raw["samples"]
    if len(samples) < 10:
        raise SystemExit("refusing analysis: fewer than 10 paired setups")
    ratios = [float(row["paired_inline_over_linked_prove_ratio"]) for row in samples]
    rng = random.Random(args.seed)
    boot = sorted(
        statistics.median(ratios[rng.randrange(len(ratios))] for _ in ratios)
        for _ in range(args.resamples)
    )
    analysis = {
        "schema": "plan-a-e8-native-paired-analysis-v1",
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "pairs": len(ratios),
        "ratio": "native_inline_prove_ms / lego_total_prove_ms",
        "median_paired_ratio": statistics.median(ratios),
        "paired_bootstrap_95_percentile_interval": [
            percentile(boot, 0.025),
            percentile(boot, 0.975),
        ],
        "bootstrap_resamples": args.resamples,
        "bootstrap_seed": args.seed,
        "raw_paired_ratios": ratios,
        "g2_old_vs_new": "not_comparable",
    }
    args.output.write_text(json.dumps(analysis, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
