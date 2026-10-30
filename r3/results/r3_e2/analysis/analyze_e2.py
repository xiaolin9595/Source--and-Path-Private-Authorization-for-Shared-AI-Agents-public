#!/usr/bin/env python3
"""Frozen E2 completeness checks and setup-cluster descriptive analysis."""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "e2-observation-v1"
SETUPS = 10
WARMUPS = 3
FORMAL = 30
REPLICATES = 10_000
SEED = 20_261_029
HEX64 = re.compile(r"[0-9a-f]{64}")

UPDATE_METRICS = (
    "witness_prepare",
    "proof_generate_loaded_pk",
    "owner_sign_serialize",
    "pure_proof_verify",
    "server_verify_external",
    "atomic_replace",
    "http_request_to_committed_response",
    "client_prepare_to_response",
    "publication",
)
REQUIRED_UPDATE_METRICS = (
    "witness_prepare",
    "proof_generate_loaded_pk",
    "owner_sign_serialize",
    "pure_proof_verify",
    "server_verify_external",
    "atomic_replace",
    "http_request_to_committed_response",
    "client_prepare_to_response",
)
SETUP_METRICS = ("setup", "pk_load", "vk_load_prepare")
GLOBAL_IDENTITIES = (
    "source_manifest_sha256",
    "driver_sha256",
    "analyzer_sha256",
    "protocol_sha256",
    "gate_manifest_sha256",
    "config_sha256",
    "matrix_sha256",
    "config_digest",
)
PER_SETUP_IDENTITIES = (
    "deployment_id",
    "pk_sha256",
    "vk_sha256",
    "circuit_id",
    "owner_sha256",
    "db_sha256",
)


class AnalysisError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AnalysisError(message)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            require(bool(line.strip()), f"blank line {number}")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise AnalysisError(f"invalid JSON line {number}: {error}") from error
            require(isinstance(value, dict), f"line {number} is not an object")
            rows.append(value)
    return rows


def sha(value: Any, field: str) -> str:
    require(isinstance(value, str) and HEX64.fullmatch(value) is not None, f"bad {field}")
    return value


def integer(value: Any, field: str, minimum: int = 0) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value >= minimum, f"bad {field}")
    return value


def timing(value: Any, field: str, required: bool) -> int | None:
    if value is None:
        require(not required, f"required timing {field} is null")
        return None
    # A recorded zero is indistinguishable from a placeholder. Unavailable phases use null.
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0, f"bad timing {field}")
    return value


def type7(values: Iterable[float], probability: float) -> float:
    ordered = sorted(values)
    require(bool(ordered), "percentile of empty sample")
    require(0.0 <= probability <= 1.0, "bad percentile probability")
    if len(ordered) == 1:
        return float(ordered[0])
    index = (len(ordered) - 1) * probability
    lower = math.floor(index)
    fraction = index - lower
    if lower + 1 == len(ordered):
        return float(ordered[lower])
    return float(ordered[lower] + fraction * (ordered[lower + 1] - ordered[lower]))


def interval(values: list[float]) -> dict[str, float | int]:
    return {
        "p2_5": type7(values, 0.025),
        "p97_5": type7(values, 0.975),
        "replicates": len(values),
    }


def identity(row: dict[str, Any], field: str) -> str:
    return sha(row.get(field), field)


def analyze(rows: list[dict[str, Any]]) -> dict[str, Any]:
    require(len(rows) == 1 + SETUPS * (1 + WARMUPS + FORMAL), "wrong total row count")
    setup_rows: dict[int, dict[str, Any]] = {}
    updates: dict[int, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    globals_seen: dict[str, str] = {}
    collection_rows = 0

    for row in rows:
        require(row.get("schema") == SCHEMA, "wrong schema")
        for field in GLOBAL_IDENTITIES:
            value = identity(row, field)
            previous = globals_seen.setdefault(field, value)
            require(value == previous, f"global identity drift: {field}")
        event = row.get("event")
        require(event in {"collection", "setup", "update"}, "bad event")
        if event == "collection":
            collection_rows += 1
            require(row.get("setups") == SETUPS, "wrong collection setup count")
            require(row.get("updates") == FORMAL, "wrong collection formal count")
            require(row.get("warmups") == WARMUPS, "wrong collection warmup count")
            continue
        setup_id = integer(row.get("setup_id"), "setup_id", 1)
        require(setup_id <= SETUPS, "setup_id out of range")
        if event == "setup":
            require(setup_id not in setup_rows, "duplicate setup row")
            for field in PER_SETUP_IDENTITIES:
                identity(row, field)
            for field in ("formal_initial_leaf",):
                sha(row.get(field), field)
            for field in ("formal_initial_version", "formal_initial_epoch"):
                integer(row.get(field), field)
            for field in ("constraints", "instance_variables", "witness_variables", "pk_bytes", "vk_bytes"):
                integer(row.get(field), field, 1)
            times = row.get("timings_ns")
            require(isinstance(times, dict) and set(times) == set(SETUP_METRICS), "bad setup timing schema")
            timing(times["setup"], "setup", True)
            timing(times["pk_load"], "pk_load", False)
            timing(times["vk_load_prepare"], "vk_load_prepare", False)
            setup_rows[setup_id] = row
            continue

        phase = row.get("phase")
        require(phase in {"warmup", "formal"}, "bad update phase")
        position = integer(row.get("position"), "position", 1)
        maximum = WARMUPS if phase == "warmup" else FORMAL
        require(position <= maximum, "position out of range")
        require(row.get("accepted") is True and row.get("error") is None, "non-accepted update")
        for field in PER_SETUP_IDENTITIES:
            identity(row, field)
        for field in ("old_leaf", "new_leaf", "proof_sha256", "request_sha256"):
            sha(row.get(field), field)
        require(row["old_leaf"] != row["new_leaf"], "unchanged leaf")
        for field in ("old_version", "new_version", "old_epoch", "new_epoch"):
            integer(row.get(field), field)
        require(row["new_version"] == row["old_version"] + 1, "version discontinuity within row")
        require(row["new_epoch"] > row["old_epoch"], "epoch did not increase")
        integer(row.get("proof_bytes"), "proof_bytes", 1)
        integer(row.get("request_bytes"), "request_bytes", 1)
        times = row.get("timings_ns")
        require(isinstance(times, dict) and set(times) == set(UPDATE_METRICS), "bad update timing schema")
        for field in UPDATE_METRICS:
            timing(times[field], field, field in REQUIRED_UPDATE_METRICS)
        updates[setup_id][phase].append(row)

    require(collection_rows == 1, "missing or duplicate collection row")
    require(set(setup_rows) == set(range(1, SETUPS + 1)), "missing setup row")
    require(set(updates) == set(range(1, SETUPS + 1)), "missing setup updates")

    seen_per_setup: dict[str, set[str]] = {field: set() for field in PER_SETUP_IDENTITIES}
    formal_by_setup: dict[int, list[dict[str, Any]]] = {}
    for setup_id in range(1, SETUPS + 1):
        setup = setup_rows[setup_id]
        warmup = sorted(updates[setup_id]["warmup"], key=lambda row: row["position"])
        formal = sorted(updates[setup_id]["formal"], key=lambda row: row["position"])
        require([row["position"] for row in warmup] == list(range(1, WARMUPS + 1)), "warmup gap/duplicate")
        require([row["position"] for row in formal] == list(range(1, FORMAL + 1)), "formal gap/duplicate")
        for field in PER_SETUP_IDENTITIES:
            expected = setup[field]
            require(all(row[field] == expected for row in formal), f"formal setup identity drift: {field}")
            seen_per_setup[field].add(expected)
        for field in ("pk_sha256", "vk_sha256", "circuit_id"):
            require(all(row[field] == setup[field] for row in warmup), f"warmup setup identity drift: {field}")
        require(len({row["owner_sha256"] for row in warmup}) == 1, "warmup owner drift")
        require(len({row["db_sha256"] for row in warmup}) == 1, "warmup database drift")
        require(warmup[0]["owner_sha256"] != setup["owner_sha256"], "warmup reused formal owner")
        require(warmup[0]["db_sha256"] != setup["db_sha256"], "warmup reused formal database")
        for previous, current in zip(warmup, warmup[1:]):
            require(previous["new_leaf"] == current["old_leaf"], "warmup leaf chain discontinuity")
            require(previous["new_version"] == current["old_version"], "warmup version chain discontinuity")
            require(previous["new_epoch"] == current["old_epoch"], "warmup epoch chain discontinuity")
        require(formal[0]["old_leaf"] == setup["formal_initial_leaf"], "position 1 initial leaf mismatch")
        require(formal[0]["old_version"] == setup["formal_initial_version"], "position 1 initial version mismatch")
        require(formal[0]["old_epoch"] == setup["formal_initial_epoch"], "position 1 initial epoch mismatch")
        for previous, current in zip(formal, formal[1:]):
            require(previous["new_leaf"] == current["old_leaf"], "leaf chain discontinuity")
            require(previous["new_version"] == current["old_version"], "version chain discontinuity")
            require(previous["new_epoch"] == current["old_epoch"], "epoch chain discontinuity")
        require(len({row["new_leaf"] for row in formal}) == FORMAL, "reused successor leaf")
        require(len({row["proof_sha256"] for row in formal}) == FORMAL, "reused proof")
        require(len({row["request_sha256"] for row in formal}) == FORMAL, "reused request")
        formal_by_setup[setup_id] = formal

    for field in ("deployment_id", "pk_sha256", "vk_sha256", "circuit_id", "owner_sha256", "db_sha256"):
        require(len(seen_per_setup[field]) == SETUPS, f"{field} not fresh across setups")
    for field in ("constraints", "instance_variables", "witness_variables", "pk_bytes", "vk_bytes"):
        require(len({setup_rows[s][field] for s in setup_rows}) == 1, f"setup shape drift: {field}")

    setup_ids = list(range(1, SETUPS + 1))
    rng = random.Random(SEED)
    cluster_index_vectors = [tuple(rng.randrange(SETUPS) for _ in range(SETUPS)) for _ in range(REPLICATES)]
    pooled: dict[str, Any] = {}
    per_setup: dict[str, Any] = {}
    for metric in UPDATE_METRICS:
        observed = [row["timings_ns"][metric] for s in setup_ids for row in formal_by_setup[s] if row["timings_ns"][metric] is not None]
        if not observed:
            pooled[metric] = None
            per_setup[metric] = None
            continue
        require(len(observed) == SETUPS * FORMAL, f"partially unavailable timing: {metric}")
        per_setup_values = {str(s): statistics.median(row["timings_ns"][metric] for row in formal_by_setup[s]) for s in setup_ids}
        replicates: list[float] = []
        for vector in cluster_index_vectors:
            selected = [setup_ids[index] for index in vector]
            sample = [row["timings_ns"][metric] for s in selected for row in formal_by_setup[s]]
            replicates.append(float(statistics.median(sample)))
        pooled[metric] = {
            "n": len(observed),
            "median_ns": float(statistics.median(observed)),
            "min_ns": min(observed),
            "max_ns": max(observed),
            "whole_setup_bootstrap_95pct": interval(replicates),
        }
        per_setup[metric] = per_setup_values

    setup_costs: dict[str, Any] = {}
    for metric in SETUP_METRICS:
        values = [setup_rows[s]["timings_ns"][metric] for s in setup_ids]
        available = [value for value in values if value is not None]
        if not available:
            setup_costs[metric] = None
            continue
        require(len(available) == SETUPS, f"partially unavailable setup timing: {metric}")
        replicates = [float(statistics.median(available[index] for index in vector)) for vector in cluster_index_vectors]
        setup_costs[metric] = {
            "n": SETUPS,
            "median_ns": float(statistics.median(available)),
            "min_ns": min(available),
            "max_ns": max(available),
            "ten_observation_bootstrap_95pct": interval(replicates),
        }

    growth: dict[str, Any] = {}
    for metric in ("http_request_to_committed_response", "client_prepare_to_response"):
        differences = [
            formal_by_setup[s][-1]["timings_ns"][metric] - formal_by_setup[s][0]["timings_ns"][metric]
            for s in setup_ids
        ]
        replicates = [float(statistics.median(differences[index] for index in vector)) for vector in cluster_index_vectors]
        growth[metric] = {
            "n_pairs": SETUPS,
            "position30_minus_position1_by_setup_ns": {str(s): differences[s - 1] for s in setup_ids},
            "median_paired_difference_ns": float(statistics.median(differences)),
            "paired_setup_bootstrap_95pct": interval(replicates),
        }

    formal_rows = [row for s in setup_ids for row in formal_by_setup[s]]
    require(len({row["proof_sha256"] for row in formal_rows}) == SETUPS * FORMAL, "proof reused across setups")
    require(len({row["request_sha256"] for row in formal_rows}) == SETUPS * FORMAL, "request reused across setups")
    position_by_setup = {
        str(s): {
            str(row["position"]): {metric: row["timings_ns"][metric] for metric in UPDATE_METRICS}
            for row in formal_by_setup[s]
        }
        for s in setup_ids
    }
    return {
        "schema": "e2-analysis-v1",
        "complete": True,
        "seed": SEED,
        "bootstrap_replicates": REPLICATES,
        "bootstrap_prng": "Python random.Random (MT19937), randrange(10)",
        "bootstrap_index_vectors_shared_across_metrics": True,
        "setups": SETUPS,
        "warmups": SETUPS * WARMUPS,
        "formal_updates": len(formal_rows),
        "accepted_formal_updates": sum(row["accepted"] is True for row in formal_rows),
        "errors": 0,
        "identities": {
            "global": globals_seen,
            "pk_sha256_by_setup": {str(s): setup_rows[s]["pk_sha256"] for s in setup_ids},
            "vk_sha256_by_setup": {str(s): setup_rows[s]["vk_sha256"] for s in setup_ids},
            "circuit_id_by_setup": {str(s): setup_rows[s]["circuit_id"] for s in setup_ids},
        },
        "shape": {field: setup_rows[1][field] for field in ("constraints", "instance_variables", "witness_variables", "pk_bytes", "vk_bytes")},
        "sizes": {
            "proof_bytes": {"min": min(row["proof_bytes"] for row in formal_rows), "max": max(row["proof_bytes"] for row in formal_rows)},
            "request_bytes": {"min": min(row["request_bytes"] for row in formal_rows), "max": max(row["request_bytes"] for row in formal_rows)},
        },
        "pooled_timing": pooled,
        "per_setup_medians_ns": per_setup,
        "position_by_setup_ns": position_by_setup,
        "setup_costs": setup_costs,
        "within_chain_growth": growth,
        "percentile_method": "Python-equivalent type-7 linear interpolation on deterministic bootstrap replicates",
        "limitations": "Descriptive setup-cluster intervals on one shared host; thirty updates are a chain, not independent users.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    result = analyze(load_jsonl(args.input))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
