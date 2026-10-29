#!/usr/bin/env python3
"""Fail-closed validator and deterministic bootstrap summary for B1 formal trials."""

import argparse
import hashlib
import json
import math
import random
from pathlib import Path

PROTOCOLS = (
    "JWT-RFC8693-local-profile",
    "UCAN-1.0-DAG-CBOR-local-profile",
)
LENGTHS = (1, 2, 3)
TIMING_METRICS = (
    "setup_us",
    "initial_issuance_us",
    "attenuation_refresh_us",
    "issuance_us",
    "presentation_us",
    "verification_us",
    "revocation_update_us",
)
BYTE_METRICS = (
    "signed_artifacts_total_bytes",
    "presentation_bytes",
    "terminal_binding_bytes",
    "revocation_state_bytes",
)
RESAMPLES = 10_000


def median(values):
    ordered = sorted(values)
    n = len(ordered)
    middle = n // 2
    return ordered[middle] if n % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def percentile(values, probability):
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    fraction = position - lower
    return ordered[lower] * (1 - fraction) + ordered[upper] * fraction


def bootstrap_ci(values, seed):
    rng = random.Random(seed)
    n = len(values)
    estimates = [median([values[rng.randrange(n)] for _ in range(n)]) for _ in range(RESAMPLES)]
    return {
        "median": median(values),
        "bootstrap_95ci_low": percentile(estimates, 0.025),
        "bootstrap_95ci_high": percentile(estimates, 0.975),
        "bootstrap_resamples": RESAMPLES,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("raw_json", type=Path)
    parser.add_argument("summary_json", type=Path)
    args = parser.parse_args()
    raw_bytes = args.raw_json.read_bytes()
    document = json.loads(raw_bytes)
    assert document["schema"] == "plan-a-b1-formal-trials-v1"
    assert document["trial_count_per_protocol_length"] >= 10
    assert document["fresh_setup_each_trial"] is True
    assert document["provenance_private"] is False
    assert document["same_privacy_comparator"] is False
    rows = document["raw_trials"]
    assert len(rows) == len(PROTOCOLS) * len(LENGTHS) * document["trial_count_per_protocol_length"]
    for length in LENGTHS:
        for paired_trial in range(document["trial_count_per_protocol_length"]):
            pair = [
                row
                for row in rows
                if row["semantic_length"] == length
                and row["paired_trial"] == paired_trial
            ]
            assert len(pair) == 2
            assert {row["protocol"] for row in pair} == set(PROTOCOLS)
            assert {row["order_position"] for row in pair} == {0, 1}
            assert len({row["order"] for row in pair}) == 1
            declared_order = pair[0]["order"].split(",")
            assert declared_order in (["JWT", "UCAN"], ["UCAN", "JWT"])
            expected_protocols = [
                "JWT-RFC8693-local-profile" if name == "JWT" else "UCAN-1.0-DAG-CBOR-local-profile"
                for name in declared_order
            ]
            assert len(expected_protocols) == 2
            assert all(
                expected_protocols[row["order_position"]] == row["protocol"]
                for row in pair
            )
            assert len({(row["request_lo"], row["request_hi"]) for row in pair}) == 1

    summaries = []
    for protocol in PROTOCOLS:
        for length in LENGTHS:
            group = [row for row in rows if row["protocol"] == protocol and row["semantic_length"] == length]
            assert len(group) == document["trial_count_per_protocol_length"]
            assert sorted(row["paired_trial"] for row in group) == list(range(len(group)))
            assert sum(row["order_position"] == 0 for row in group) == len(group) // 2
            assert sum(row["order_position"] == 1 for row in group) == len(group) // 2
            assert all(
                row["accepted"]
                and row["revoked_path_rejected"]
                and row["independent_path_survives"]
                and row["visible_chain_length"] == length
                and len(row["signed_artifact_bytes_by_level"]) == length
                for row in group
            )
            peer_protocol = PROTOCOLS[1] if protocol == PROTOCOLS[0] else PROTOCOLS[0]
            peer_group = [
                row
                for row in rows
                if row["protocol"] == peer_protocol and row["semantic_length"] == length
            ]
            paired_intervals = {
                row["paired_trial"]: (row["request_lo"], row["request_hi"])
                for row in peer_group
            }
            assert all(
                paired_intervals[row["paired_trial"]]
                == (row["request_lo"], row["request_hi"])
                for row in group
            )
            metrics = {}
            for metric in TIMING_METRICS + BYTE_METRICS:
                values = [row[metric] for row in group]
                assert all(isinstance(value, (int, float)) and value >= 0 for value in values)
                seed_material = f"plan-a-b1-bootstrap-v1:{protocol}:{length}:{metric}".encode()
                seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:8], "big")
                metrics[metric] = bootstrap_ci(values, seed)
            summaries.append(
                {
                    "protocol": protocol,
                    "semantic_length": length,
                    "n": len(group),
                    "all_functional_predicates_true": True,
                    "metrics": metrics,
                }
            )

    result = {
        "schema": "plan-a-b1-formal-summary-v1",
        "raw_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "confidence_interval": "two-sided percentile bootstrap interval for the sample median",
        "confidence_level": 0.95,
        "bootstrap_resamples": RESAMPLES,
        "formal_gate_complete": True,
        "same_privacy_comparator": False,
        "summaries": summaries,
    }
    args.summary_json.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
