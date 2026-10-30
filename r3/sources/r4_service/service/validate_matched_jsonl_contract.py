#!/usr/bin/env python3
"""Proof-free fail-closed check for the agreed Joint/DAC JSONL wire."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

COMMANDS = {"materialize-and-verify-header", "verify-at-read", "commit"}
EXPECTED_FIELDS = {
    "semantic_input_sha256", "backend", "deployment_id",
    "logical_id_mapping_version", "policy_version", "schema_version",
    "profile", "update_index", "installed_header", "terminal",
    "terminal_key", "resource", "one_hot_action_u16", "interval_lo",
    "interval_hi", "nonce_u64", "trusted_now", "http", "backend_profile",
}
HEADER_FIELDS = {
    "semantic_input_sha256", "tuple_version", "state_epoch",
    "revocation_epoch", "issued_at",
}
HTTP_FIELDS = {"audience", "body_sha256", "method", "path"}


def load(path: Path) -> tuple[dict, str]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path}: top level must be an object")
    return value, hashlib.sha256(raw).hexdigest()


def exact(label: str, value: dict, fields: set[str]) -> None:
    if set(value) != fields:
        raise ValueError(f"{label}: fields {sorted(value)} != {sorted(fields)}")


def check_expected(label: str, expected: dict, backend: str) -> None:
    exact(label, expected, EXPECTED_FIELDS)
    if expected["backend"] != backend:
        raise ValueError(f"{label}: backend mismatch")
    if not HEADER_FIELDS <= set(expected["installed_header"]):
        raise ValueError(f"{label}: incomplete installed header")
    exact(f"{label}.http", expected["http"], HTTP_FIELDS)
    if expected["http"]["method"] != "POST":
        raise ValueError(f"{label}: method must be POST")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--joint", type=Path, required=True)
    parser.add_argument("--dac", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    joint, joint_sha = load(args.joint)
    dac, dac_sha = load(args.dac)
    if (joint.get("wire_version") != "plan-a-matched-jsonl-v1"
            or dac.get("wire_version") != "plan-a-matched-jsonl-v1"):
        raise ValueError("wire version mismatch")

    joint_commands = joint["commands"]
    if set(joint_commands) != COMMANDS:
        raise ValueError("Joint command set mismatch")
    check_expected("joint.verify.expected", joint_commands["verify-at-read"]["expected"],
                   "joint-bls12-381")
    if "actual" in joint_commands["verify-at-read"]["envelope"]:
        raise ValueError("Joint envelope leaks actual depth")

    templates = dac["commands"]
    if {item["command"] for item in templates} != COMMANDS:
        raise ValueError("DAC command set mismatch")
    check_expected("dac.expected", dac["expected"], "dac-bw6-761")
    if "actual" in dac["proof_envelope"]:
        raise ValueError("DAC envelope leaks actual depth")
    if any(key in dac["proof_envelope"] for key in ("verifying_key", "vk", "params")):
        raise ValueError("DAC caller envelope selects trusted verifier material")

    materialized_headers = {
        "joint": joint_commands["materialize-and-verify-header"]["header_envelope"]["header"],
        "dac": dac["header_envelope"]["header"],
    }
    for label, fixture in (("joint", joint), ("dac", dac)):
        header = materialized_headers[label]
        if not HEADER_FIELDS <= set(header):
            raise ValueError(f"{label}: incomplete materialized header")
        responses = fixture["success_responses"]
        if set(responses) != COMMANDS:
            raise ValueError(f"{label}: response set mismatch")
        if set(responses["verify-at-read"]) != {"valid", "ticket"}:
            raise ValueError(f"{label}: verify response shape mismatch")
        if set(responses["commit"]) != {"valid"}:
            raise ValueError(f"{label}: commit response shape mismatch")

    result = {
        "valid": True,
        "wire_version": "plan-a-matched-jsonl-v1",
        "commands": sorted(COMMANDS),
        "expected_fields": sorted(EXPECTED_FIELDS),
        "joint_fixture_sha256": joint_sha,
        "dac_fixture_sha256": dac_sha,
        "actual_depth_absent_from_envelopes": True,
        "trusted_now_location": "expected-only",
        "proof_or_setup_executed": False,
    }
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
