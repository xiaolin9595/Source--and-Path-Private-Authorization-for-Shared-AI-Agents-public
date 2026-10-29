#!/usr/bin/env python3
"""Fail-closed validation for the B1 functional and formal artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


JWT_TRUE = {
    "accepted",
    "adapter_nonce_replay_rejected",
    "atomic_commit_accepted",
    "bad_terminal_pop_rejected",
    "changed_artifact_rejected",
    "commit_clock_expiry_rejected",
    "delta0_commit_rejected",
    "expired_rejected",
    "external_terminal_ed25519_pop_accepted",
    "inactive_parent_exchange_rejected",
    "local_nested_act_profile_gate_complete",
    "replay_rejected",
    "request_mutation_rejected",
    "retired_header_delta0_rejected",
    "reversed_request_rejected",
    "revoked_ancestor_introspection_rejected",
    "revoked_between_read_and_commit_rejected",
    "same_joint_commit_contract_complete",
    "unauthorized_exchange_rejected",
    "widening_exchange_rejected",
    "wrong_policy_version_rejected",
}

UCAN_TRUE = {
    "accepted",
    "active_registry_installed",
    "adapter_registry_installed",
    "authenticated_cid_revocation_registry_extension",
    "expired_rejected",
    "independent_path_survives",
    "local_ucan_delegation_invocation_gate_complete",
    "missing_proof_rejected",
    "policy_widening_rejected",
    "registry_rollback_rejected",
    "replay_rejected",
    "resolver_denied_ancestor_rejected",
    "revoked_between_read_and_commit_rejected",
    "revoked_commit_active_registry_installed",
    "revoked_commit_registry_advanced",
    "revoked_registry_installed",
    "same_joint_commit_contract_complete",
    "signed_registry_accepts",
    "signed_registry_independent_path_survives",
    "signed_registry_revoked_ancestor_rejected",
    "tampered_registry_rejected",
    "ucan_adapter_replay_rejected",
    "ucan_atomic_commit_accepted",
    "ucan_changed_artifact_rejected",
    "ucan_commit_clock_rejected",
    "ucan_delta0_commit_rejected",
    "wrong_executor_rejected",
}


def load(path: Path):
    return json.loads(path.read_text())


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jwt", type=Path, required=True)
    parser.add_argument("--ucan", type=Path, required=True)
    parser.add_argument("--raw", type=Path, required=True)
    parser.add_argument("--summary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    jwt = load(args.jwt)
    ucan = load(args.ucan)
    raw = load(args.raw)
    summary = load(args.summary)

    require(all(jwt.get(key) is True for key in JWT_TRUE), "JWT predicate failed")
    require(jwt.get("rfc8693_profile_complete") is False, "JWT scope flag changed")
    require(jwt.get("provenance_private") is False, "JWT provenance scope changed")
    require(all(ucan.get(key) is True for key in UCAN_TRUE), "UCAN predicate failed")
    require(
        ucan.get("signed_revocation_subspec_implemented") is False,
        "UCAN revocation scope flag changed",
    )
    require(ucan.get("provenance_private") is False, "UCAN provenance scope changed")

    require(raw.get("schema") == "plan-a-b1-formal-trials-v1", "raw schema")
    require(raw.get("fresh_setup_each_trial") is True, "fresh setup declaration")
    require(raw.get("same_privacy_comparator") is False, "privacy scope")
    require(raw.get("trial_count_per_protocol_length") == 10, "trial count declaration")
    require(raw.get("semantic_lengths") == [1, 2, 3], "semantic lengths")
    rows = raw.get("raw_trials")
    require(isinstance(rows, list) and len(rows) == 60, "expected 60 raw rows")

    protocols = {
        "JWT-RFC8693-local-profile",
        "UCAN-1.0-DAG-CBOR-local-profile",
    }
    counts = Counter((row.get("protocol"), row.get("semantic_length")) for row in rows)
    require(
        counts == Counter({(protocol, length): 10 for protocol in protocols for length in (1, 2, 3)}),
        "formal grid mismatch",
    )
    pairs = defaultdict(list)
    for row in rows:
        require(row.get("accepted") is True, "current path not accepted")
        require(row.get("revoked_path_rejected") is True, "revoked path accepted")
        require(row.get("independent_path_survives") is True, "independent path lost")
        length = row["semantic_length"]
        require(row.get("visible_chain_length") == length, "visible length mismatch")
        levels = row.get("signed_artifact_bytes_by_level")
        require(isinstance(levels, list) and len(levels) == length, "artifact level count")
        require(sum(levels) == row.get("signed_artifacts_total_bytes"), "artifact byte sum")
        require(row.get("terminal_binding_bytes") == 88, "terminal binding definition")
        order = row.get("order")
        require(order in {"JWT,UCAN", "UCAN,JWT"}, "invalid order token")
        expected_protocol = (
            "JWT-RFC8693-local-profile"
            if order.split(",")[row.get("order_position")] == "JWT"
            else "UCAN-1.0-DAG-CBOR-local-profile"
        )
        require(row.get("protocol") == expected_protocol, "order position mismatch")
        pairs[(length, row.get("paired_trial"))].append(row)

    for length in (1, 2, 3):
        order_counts = Counter(
            pair_rows[0]["order"]
            for (pair_length, _), pair_rows in pairs.items()
            if pair_length == length
        )
        require(order_counts == Counter({"JWT,UCAN": 5, "UCAN,JWT": 5}), "unbalanced order")
    require(len(pairs) == 30, "expected 30 paired workloads")
    for pair_rows in pairs.values():
        require(len(pair_rows) == 2, "paired workload does not have two protocols")
        require({row["protocol"] for row in pair_rows} == protocols, "protocol pair mismatch")
        require(len({(row["request_lo"], row["request_hi"]) for row in pair_rows}) == 1, "request mismatch")
        require(len({row["order"] for row in pair_rows}) == 1, "order label mismatch")
        require({row["order_position"] for row in pair_rows} == {0, 1}, "order positions")

    require(summary.get("schema") == "plan-a-b1-formal-summary-v1", "summary schema")
    require(summary.get("formal_gate_complete") is True, "formal summary gate")
    require(summary.get("bootstrap_resamples") == 10000, "bootstrap count")
    require(summary.get("raw_sha256") == digest(args.raw), "summary raw hash")
    cells = summary.get("summaries")
    require(isinstance(cells, list) and len(cells) == 6, "summary cell count")
    require(
        {(cell.get("protocol"), cell.get("semantic_length")) for cell in cells}
        == {(protocol, length) for protocol in protocols for length in (1, 2, 3)},
        "summary grid mismatch",
    )
    require(all(cell.get("n") == 10 for cell in cells), "summary cell n")
    require(all(cell.get("all_functional_predicates_true") is True for cell in cells), "summary predicates")

    result = {
        "schema": "plan-a-b1-formal-validation-v1",
        "gate_passed": True,
        "functional_profiles_passed": 2,
        "raw_trial_count": 60,
        "paired_workload_count": 30,
        "configuration_count": 6,
        "trials_per_configuration": 10,
        "balanced_order_each_length": True,
        "bootstrap_resamples": 10000,
        "fresh_protocol_setup_each_trial": True,
        "same_privacy_comparator": False,
        "rfc8693_profile_complete": False,
        "signed_revocation_subspec_implemented": False,
        "source_sha256": {
            "jwt": digest(args.jwt),
            "ucan": digest(args.ucan),
            "raw": digest(args.raw),
            "summary": digest(args.summary),
        },
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
