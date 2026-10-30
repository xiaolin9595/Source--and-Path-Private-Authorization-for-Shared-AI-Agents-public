#!/usr/bin/env python3
"""Fail-closed analysis for the formal 18-cell x 10-seed E4 lifecycle grid."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import random
import statistics
from pathlib import Path


EXPECTED_N = (16, 128, 1024)
EXPECTED_UPDATES = (1, 8)
EXPECTED_DELTA = (0, 5, 15)
EXPECTED_SEEDS = tuple(range(1, 11))
METRICS = (
    "complete_public_version_bytes",
    "leaf_download_loopback_ms",
    "holder_rebuild_ms",
    "prove_ms",
    "verify_ms",
    "holder_total_refresh_and_prove_ms",
    "fresh_http_ms",
    "materialize_ms",
    "publish_ms",
    "ra_ms",
    "state_ms",
    "revocation_ms",
    "holder_own_state_update_ms",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quantile(sorted_values: list[float], probability: float) -> float:
    position = (len(sorted_values) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    weight = position - lower
    return sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight


def bootstrap_median_ci(values: list[float], reps: int, seed_material: str) -> tuple[float, float]:
    seed = int.from_bytes(hashlib.sha256(seed_material.encode()).digest()[:8], "big")
    rng = random.Random(seed)
    n = len(values)
    medians = sorted(
        statistics.median(values[rng.randrange(n)] for _ in range(n))
        for _ in range(reps)
    )
    return quantile(medians, 0.025), quantile(medians, 0.975)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--bootstrap-reps", type=int, default=10_000)
    args = parser.parse_args()
    if args.bootstrap_reps < 1_000:
        raise SystemExit("bootstrap-reps must be at least 1000")

    trials_path = args.result / "TRIALS.jsonl"
    rows = [json.loads(line) for line in trials_path.read_text().splitlines() if line.strip()]
    summary = json.loads((args.result / "SUMMARY.json").read_text())
    expected = {
        (n, updates, delta, seed)
        for n in EXPECTED_N
        for updates in EXPECTED_UPDATES
        for delta in EXPECTED_DELTA
        for seed in EXPECTED_SEEDS
    }
    observed = {
        (row["population_n"], row["update_count_per_registry"], row["delta_seconds"], row["seed"])
        for row in rows
    }
    if len(rows) != 180 or observed != expected:
        raise SystemExit(
            f"formal grid mismatch rows={len(rows)} missing={sorted(expected-observed)} "
            f"extra={sorted(observed-expected)}"
        )
    if [row["trial_order_index"] for row in rows] != list(range(180)):
        raise SystemExit("trial order index is not a complete ordered range")
    scheduled = summary.get("schedule", {}).get("cell_order")
    observed_schedule = [
        {key: row[key] for key in (
            "trial_order_index", "base_schedule_index", "population_n",
            "update_count_per_registry", "delta_seconds", "seed",
        )}
        for row in rows
    ]
    if scheduled != observed_schedule:
        raise SystemExit("SUMMARY schedule does not match raw trial order")
    base_order = []
    for row in rows:
        pair = (row["population_n"], row["seed"])
        if not base_order or pair != base_order[-1]:
            base_order.append(pair)
    if len(base_order) != 30 or len(set(base_order)) != 30:
        raise SystemExit("base workload schedule is not 30 distinct shuffled blocks")
    n_transitions = sum(a[0] != b[0] for a, b in zip(base_order, base_order[1:]))
    if n_transitions < 10:
        raise SystemExit("population order is insufficiently interleaved")

    if not all(row["fresh_proof_valid"] and row["fresh_http_status"] == 200 for row in rows):
        raise SystemExit("fresh proof/access predicate failed")
    for row in rows:
        checks = row["delta_checks"]
        if row["delta_seconds"] == 0:
            if checks["retired_immediate_status"] != 401:
                raise SystemExit("Delta=0 predicate failed")
        elif checks["inclusive_boundary_status"] != 200 or checks["after_boundary_status"] != 401:
            raise SystemExit("positive Delta boundary predicate failed")
    negative_rows = [row for row in rows if row["negative_checks"]]
    if len(negative_rows) != 30 or not all(
        len(row["negative_checks"]) == 6
        and all(check["rejected"] for check in row["negative_checks"].values())
        for row in negative_rows
    ):
        raise SystemExit("negative predicate failed")
    if any(
        row["actual_ra_rows"] != row["population_n"]
        or row["actual_state_rows"] != row["population_n"]
        for row in rows
    ):
        raise SystemExit("population is metadata rather than materialized rows")
    if any(
        (row["l_max"], row["actual_enabled_grants"], row["state_depth"],
         row["ra_depth"], row["revocation_depth"], row["grant_depth"])
        != (3, 2, 10, 10, 32, 3)
        for row in rows
    ):
        raise SystemExit("relation/profile dimensions changed within the formal grid")
    for n in EXPECTED_N:
        for updates in EXPECTED_UPDATES:
            selected = [
                row for row in rows
                if row["population_n"] == n and row["update_count_per_registry"] == updates
            ]
            by_seed = {}
            for row in selected:
                by_seed.setdefault(row["seed"], set()).add(row["snapshot_digest"])
            if set(by_seed) != set(EXPECTED_SEEDS) or any(len(digests) != 1 for digests in by_seed.values()):
                raise SystemExit("Delta variants do not share one workload snapshot per seed")
            if len({next(iter(digests)) for digests in by_seed.values()}) != 10:
                raise SystemExit("background seeds did not produce ten distinct workload snapshots")

    summaries = []
    for n in EXPECTED_N:
        for updates in EXPECTED_UPDATES:
            for delta in EXPECTED_DELTA:
                selected = [
                    row for row in rows
                    if (row["population_n"], row["update_count_per_registry"], row["delta_seconds"])
                    == (n, updates, delta)
                ]
                item: dict[str, object] = {
                    "population_n": n,
                    "update_count_per_registry": updates,
                    "delta_seconds": delta,
                    "replicates": len(selected),
                }
                for metric in METRICS:
                    values = [float(row[metric]) for row in selected]
                    low, high = bootstrap_median_ci(
                        values, args.bootstrap_reps, f"{n}/{updates}/{delta}/{metric}/{sha256(trials_path)}"
                    )
                    item[f"median_{metric}"] = statistics.median(values)
                    item[f"ci95_low_{metric}"] = low
                    item[f"ci95_high_{metric}"] = high
                    item[f"min_{metric}"] = min(values)
                    item[f"max_{metric}"] = max(values)
                summaries.append(item)

    summary_json = args.result / "E4_FORMAL_CELL_SUMMARY.json"
    summary_csv = args.result / "E4_FORMAL_CELL_SUMMARY.csv"
    summary_json.write_text(json.dumps(summaries, indent=2) + "\n")
    with summary_csv.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2))
    plotted_rows = []
    colors = {0: "#0072B2", 5: "#D55E00", 15: "#009E73"}
    markers = {1: "o", 8: "s"}
    for updates in EXPECTED_UPDATES:
        for delta in EXPECTED_DELTA:
            selected = [
                item for item in summaries
                if item["update_count_per_registry"] == updates and item["delta_seconds"] == delta
            ]
            selected.sort(key=lambda item: item["population_n"])
            label = f"u={updates}, Delta={delta}s"
            for axis, metric in zip(axes, ("complete_public_version_bytes", "holder_rebuild_ms")):
                x = [item["population_n"] for item in selected]
                y = [item[f"median_{metric}"] for item in selected]
                low = [item[f"ci95_low_{metric}"] for item in selected]
                high = [item[f"ci95_high_{metric}"] for item in selected]
                axis.errorbar(
                    x, y,
                    yerr=[[value - lower for value, lower in zip(y, low)],
                          [upper - value for value, upper in zip(y, high)]],
                    marker=markers[updates], color=colors[delta],
                    linestyle="-" if updates == 1 else "--", capsize=2, label=label,
                )
            plotted_rows.extend(selected)
    for axis in axes:
        axis.set_xscale("log", base=2)
        axis.grid(alpha=0.25)
    axes[0].set(xlabel="Materialized population N", ylabel="Complete public version (bytes)")
    axes[1].set(xlabel="Materialized population N", ylabel="Holder rebuild (ms)")
    axes[1].legend(frameon=False, fontsize=8, ncol=2)
    fig.tight_layout()
    for suffix in ("pdf", "svg", "png"):
        kwargs = {"dpi": 200} if suffix == "png" else {}
        fig.savefig(args.result / f"E4_FORMAL_SCALING.{suffix}", **kwargs)
    plt.close(fig)

    validation = {
        "schema": "plan-a-e4-formal-grid-validation-v2",
        "trials_sha256": sha256(trials_path),
        "summary_json_sha256": sha256(summary_json),
        "summary_csv_sha256": sha256(summary_csv),
        "analyzer_sha256": sha256(Path(__file__)),
        "rows": len(rows),
        "groups": len(summaries),
        "replicates_per_group": 10,
        "replicate_semantics": "distinct deterministic background workload seeds with fixed PK and fixed synthetic holder profile; not independent cryptographic setup ceremonies",
        "exact_grid": True,
        "all_fresh_proof_valid": True,
        "all_fresh_http_200": True,
        "all_delta_rules_valid": True,
        "negative_cells": len(negative_rows),
        "negative_checks_per_cell": 6,
        "all_negative_checks_rejected": True,
        "materialized_population_matches_n": True,
        "profile_dimensions_constant": True,
        "distinct_snapshot_seeds_per_n_update": 10,
        "schedule_seed": summary["schedule"]["schedule_seed"],
        "base_workload_blocks": len(base_order),
        "population_transitions_between_blocks": n_transitions,
        "bootstrap_repetitions": args.bootstrap_reps,
        "statistics": "median, deterministic nonparametric 95% bootstrap CI, and observed raw min/max over ten distinct background workload seeds; one same-host batch and no deployment-generalization claim",
    }
    (args.result / "E4_FORMAL_GRID_VALIDATION.json").write_text(json.dumps(validation, indent=2) + "\n")
    print(json.dumps(validation, indent=2))


if __name__ == "__main__":
    main()
