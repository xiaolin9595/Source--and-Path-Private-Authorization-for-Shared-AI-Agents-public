#!/usr/bin/env python3
"""Strict analysis for frozen R6 full-reconstruction trials."""
from __future__ import annotations

import argparse
import json
import math
import statistics
from pathlib import Path
from typing import Iterable

EXPECTED_SEEDS = {2026103001, 2026103002, 2026103003, 2026103004, 2026103005}
EXPECTED = {16: 65_536, 20: 1_048_576}
CORRECTNESS_KEYS = {
    "stale_cas_rejected", "updated_leaf_differs", "root_differs",
    "unchanged_row_intact", "header_signature_verified",
    "target_path_verified", "unchanged_holder_path_verified",
}
TIMING_KEYS = {
    "initial_population_outside_update", "conditional_cas", "database_read",
    "materializer_process_including_json_and_startup",
    "snapshot_construct_and_fixture_sign_total", "fixture_signer_process",
    "complete_maintenance_stages_1_to_3",
    "receiver_header_verify_process_including_startup",
    "holder_dense_refresh_process_including_file_io_json_and_startup",
    "full_refresh_header_verify_plus_holder", "holder_internal_read_parse_build_path",
}


def require_nonnegative_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label}:expected-nonnegative-int")
    return value


def summary(values: Iterable[float | int]) -> dict[str, float]:
    checked = [float(value) for value in values]
    if len(checked) != 5 or not all(math.isfinite(value) for value in checked):
        raise ValueError("summary-requires-five-finite-values")
    return {"median": statistics.median(checked), "min": min(checked), "max": max(checked)}


def validate_trial(row: dict) -> None:
    if row.get("schema") != "r6-full-reconstruction-trial-v2" or row.get("valid") is not True:
        raise ValueError("bad-trial-schema-or-validity")
    depth = require_nonnegative_int(row.get("depth"), "depth")
    if depth not in EXPECTED or row.get("population") != EXPECTED[depth]:
        raise ValueError("bad-depth-population")
    if row.get("seed") not in EXPECTED_SEEDS:
        raise ValueError("unexpected-seed")
    if row.get("unrelated_ra_population") != 0 or row.get("unrelated_revocation_population") != 0:
        raise ValueError("unfrozen-unrelated-population")
    correctness = row.get("correctness")
    if not isinstance(correctness, dict) or set(correctness) != CORRECTNESS_KEYS \
            or not all(value is True for value in correctness.values()):
        raise ValueError("correctness-gate-failed")

    timing = row.get("timing_ns")
    if not isinstance(timing, dict) or set(timing) != TIMING_KEYS:
        raise ValueError("bad-timing-schema")
    for name, value in timing.items():
        require_nonnegative_int(value, f"timing.{name}")
    if timing["complete_maintenance_stages_1_to_3"] <= 0:
        raise ValueError("zero-complete-maintenance")
    # These are containment checks only. Nested timers are never summed by analysis.
    for contained in ("conditional_cas", "database_read",
                      "materializer_process_including_json_and_startup",
                      "snapshot_construct_and_fixture_sign_total"):
        if timing["complete_maintenance_stages_1_to_3"] < timing[contained]:
            raise ValueError(f"maintenance-does-not-contain:{contained}")
    if timing["full_refresh_header_verify_plus_holder"] != (
        timing["receiver_header_verify_process_including_startup"]
        + timing["holder_dense_refresh_process_including_file_io_json_and_startup"]
    ):
        raise ValueError("full-refresh-definition-mismatch")
    if timing["holder_dense_refresh_process_including_file_io_json_and_startup"] \
            < timing["holder_internal_read_parse_build_path"]:
        raise ValueError("holder-nesting-invalid")
    if timing["snapshot_construct_and_fixture_sign_total"] < timing["fixture_signer_process"]:
        raise ValueError("signer-nesting-invalid")

    sizes = row.get("bytes")
    if not isinstance(sizes, dict) or set(sizes) != {"serialized_public_state", "path_encoding", "path_raw"}:
        raise ValueError("bad-byte-schema")
    require_nonnegative_int(sizes["serialized_public_state"], "serialized-public-state")
    encoding = sizes["path_encoding"]
    raw = sizes["path_raw"]
    if not isinstance(encoding, dict) or set(encoding) != {"target_json", "unchanged_json", "two_path_object_json"}:
        raise ValueError("bad-path-encoding-schema")
    if not isinstance(raw, dict) or set(raw) != {
        "target_sibling_bytes", "unchanged_sibling_bytes", "two_path_sibling_bytes",
        "target_direction_count", "unchanged_direction_count", "two_path_direction_count",
        "target_directions_json_bytes", "unchanged_directions_json_bytes",
    }:
        raise ValueError("bad-path-raw-schema")
    for name, value in {**encoding, **raw}.items():
        require_nonnegative_int(value, f"path.{name}")
    expected_siblings = depth * 32
    if (raw["target_sibling_bytes"], raw["unchanged_sibling_bytes"], raw["two_path_sibling_bytes"]) \
            != (expected_siblings, expected_siblings, 2 * expected_siblings):
        raise ValueError("raw-sibling-byte-mismatch")
    if (raw["target_direction_count"], raw["unchanged_direction_count"], raw["two_path_direction_count"]) \
            != (depth, depth, 2 * depth):
        raise ValueError("direction-count-mismatch")
    if encoding["two_path_object_json"] <= encoding["target_json"] + encoding["unchanged_json"]:
        raise ValueError("two-path-json-framing-missing")

    rss = row.get("rss")
    if not isinstance(rss, dict) or set(rss) != {"self_ru_maxrss_raw", "children_ru_maxrss_raw", "units"}:
        raise ValueError("bad-rss-schema")
    require_nonnegative_int(rss["self_ru_maxrss_raw"], "self-rss")
    require_nonnegative_int(rss["children_ru_maxrss_raw"], "children-rss")
    if rss["units"] not in {"KiB on Linux; bytes on macOS; whole-process maxima, not stage-specific"}:
        raise ValueError("bad-rss-units")
    process = row.get("process")
    if not isinstance(process, dict) or not isinstance(process.get("platform"), str):
        raise ValueError("bad-process-platform")
    if not process["platform"].startswith("Linux-"):
        raise ValueError("formal-rss-requires-linux-platform")


def analyze(rows: list[dict]) -> dict:
    if len(rows) != 10:
        raise ValueError("expected-exactly-ten-trials")
    for row in rows:
        validate_trial(row)
    cells = {(row["depth"], row["seed"]) for row in rows}
    expected_cells = {(depth, seed) for depth in EXPECTED for seed in EXPECTED_SEEDS}
    if cells != expected_cells or len(cells) != len(rows):
        raise ValueError("missing-or-duplicate-depth-seed-cell")
    units = {row["rss"]["units"] for row in rows}
    if len(units) != 1:
        raise ValueError("rss-units-differ")

    populations: dict[str, dict] = {}
    for depth, population in EXPECTED.items():
        group = sorted((row for row in rows if row["depth"] == depth), key=lambda row: row["seed"])
        observations = []
        for row in group:
            complete_ns = row["timing_ns"]["complete_maintenance_stages_1_to_3"]
            rate = 1_000_000_000.0 / complete_ns
            observations.append({
                "seed": row["seed"], "complete_maintenance_ns": complete_ns,
                "reciprocal_sequential_rate_per_second": rate,
            })
        timing_summary = {name: summary(row["timing_ns"][name] for row in group) for name in sorted(TIMING_KEYS)}
        rate_summary = summary(item["reciprocal_sequential_rate_per_second"] for item in observations)
        bytes_summary = {
            "serialized_public_state": summary(row["bytes"]["serialized_public_state"] for row in group),
            "target_path_json": summary(row["bytes"]["path_encoding"]["target_json"] for row in group),
            "unchanged_path_json": summary(row["bytes"]["path_encoding"]["unchanged_json"] for row in group),
            "two_path_object_json": summary(row["bytes"]["path_encoding"]["two_path_object_json"] for row in group),
            "target_raw_sibling_bytes": summary(row["bytes"]["path_raw"]["target_sibling_bytes"] for row in group),
            "unchanged_raw_sibling_bytes": summary(row["bytes"]["path_raw"]["unchanged_sibling_bytes"] for row in group),
            "two_path_raw_sibling_bytes": summary(row["bytes"]["path_raw"]["two_path_sibling_bytes"] for row in group),
            "target_direction_count": summary(row["bytes"]["path_raw"]["target_direction_count"] for row in group),
            "unchanged_direction_count": summary(row["bytes"]["path_raw"]["unchanged_direction_count"] for row in group),
            "two_path_direction_count": summary(row["bytes"]["path_raw"]["two_path_direction_count"] for row in group),
            "target_directions_json_bytes": summary(row["bytes"]["path_raw"]["target_directions_json_bytes"] for row in group),
            "unchanged_directions_json_bytes": summary(row["bytes"]["path_raw"]["unchanged_directions_json_bytes"] for row in group),
        }
        rss_summary = {
            "scope": "whole-process peak only; not attributable to stages",
            "units": "KiB (resource.ru_maxrss on verified Linux platform)",
            "self_ru_maxrss_kib": summary(row["rss"]["self_ru_maxrss_raw"] for row in group),
            "children_ru_maxrss_kib": summary(row["rss"]["children_ru_maxrss_raw"] for row in group),
        }
        populations[str(population)] = {
            "depth": depth, "trial_count": 5, "seeds": [row["seed"] for row in group],
            "observations": observations,
            "reciprocal_sequential_latency_rate_per_second": rate_summary,
            "timing_ns": timing_summary, "bytes": bytes_summary, "rss": rss_summary,
        }
    return {
        "schema": "r6-full-reconstruction-analysis-v1", "valid": True,
        "rate_definition": "per trial: 1 / complete_maintenance_seconds; then median/min/max over five trial rates; not 1/mean latency",
        "timing_rule": "each named timer summarized independently; nested timers are not summed",
        "inference": "five deterministic synthetic workloads; median and min-max only; no bootstrap CI",
        "populations": populations,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", type=Path, nargs="+", required=True,
                        help="exactly ten RESULT.json files: five seeds at each depth")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    rows = [json.loads(path.read_text(encoding="utf-8")) for path in args.results]
    output = analyze(rows)
    args.output.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

