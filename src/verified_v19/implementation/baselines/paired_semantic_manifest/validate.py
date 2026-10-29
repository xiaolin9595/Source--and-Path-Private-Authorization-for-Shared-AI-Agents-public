#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path


def canonical_json_bytes(value):
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=False
    ).encode("utf-8")


def request_authorized(grant, request):
    return (
        grant["subject"] == request["terminal"]
        and grant["resource"] == request["resource"]
        and grant["actions"] & request["one_hot_action_u16"]
        == request["one_hot_action_u16"]
        and grant["lo"] <= request["interval_lo"] <= request["interval_hi"] <= grant["hi"]
        and grant["not_before"] <= request["now"] <= grant["expiry"]
        and grant["policy_version"] == request["policy_version"]
        and grant["schema_version"] == request["schema_version"]
    )


path = Path(sys.argv[1])
result_bytes = path.read_bytes()
doc = json.loads(result_bytes)
assert doc["schema"] == "plan-a-paired-semantic-manifest-result-v2"
raw = doc["canonical_raw_manifest"]
assert raw["schema"] == "plan-a-paired-semantic-records-v2"
raw_sha = hashlib.sha256(canonical_json_bytes(raw)).hexdigest()
assert raw_sha == doc["canonical_raw_manifest_sha256"]
bound_metadata = {
    "schema": raw["schema"],
    "profile": raw["profile"],
    "deployment_id": raw["deployment_id"],
    "logical_id_mapping_version": raw["logical_id_mapping_version"],
    "policy_version": raw["policy_version"],
    "schema_version": raw["schema_version"],
    "entitlement_visibility": raw["entitlement"]["visibility"],
    "state_visibility": raw["state"]["visibility"],
}
metadata_digest = hashlib.sha256(canonical_json_bytes(bound_metadata)).digest()
metadata_sha = metadata_digest.hex()
metadata_limbs = [
    int.from_bytes(metadata_digest[index : index + 8], "little")
    for index in range(0, 32, 8)
]
canonical_http_body = canonical_json_bytes(
    {
        "action": raw["request"]["one_hot_action_u16"],
        "interval_hi": raw["request"]["interval_hi"],
        "interval_lo": raw["request"]["interval_lo"],
        "resource": raw["request"]["resource"],
    }
)
canonical_http = {
    "audience": "plan-a-resource-service",
    "body_sha256": hashlib.sha256(canonical_http_body).hexdigest(),
    "method": "POST",
    "path": "/v1/read-resource",
}
request_digest = hashlib.sha256(
    b"plan-a-matched-http-v1\0" + canonical_json_bytes(canonical_http)
).digest()
request_limbs = [
    int.from_bytes(request_digest[index : index + 8], "little")
    for index in range(0, 32, 8)
]
assert doc["projection_contract"]["bound_metadata"] == bound_metadata
assert doc["projection_contract"]["bound_metadata_sha256"] == metadata_sha
assert doc["projection_contract"]["canonical_http"] == canonical_http
assert doc["projection_contract"]["canonical_http_body_utf8"].encode() == canonical_http_body
assert doc["projection_contract"]["canonical_http_sha256"] == request_digest.hex()

updates = raw["updates"]
assert [item["tuple_version"] for item in updates] == [1, 2, 3]
assert [item["state_epoch"] for item in updates] == [55, 56, 56]
assert [item["revocation_epoch"] for item in updates] == [9, 9, 10]
assert [item["issued_at"] for item in updates] == [1792700000, 1792700001, 1792700002]
assert updates[0]["active_root_grants"] == ["root-a", "root-b", "root-c"]
assert updates[1]["active_root_grants"] == ["root-b", "root-c"]
assert updates[2]["active_root_grants"] == ["root-b", "root-c"]
assert updates[0]["revoked_serials"] == []
assert updates[1]["revoked_serials"] == []
assert updates[2]["revoked_serials"] == ["child-b"]

grants = {item["id"]: item for item in raw["grants"]}
root_ids = [item["id"] for item in raw["grants"] if item["parent"] is None]
assert root_ids == ["root-a", "root-b", "root-c"]
request = raw["request"]
assert request["terminal"] == raw["logical_ids"]["terminal"]

expected_membership = []
expected_b = []
expected_c = []
revoked = set()
for update in updates:
    active = set(update["active_root_grants"])
    revoked.update(update["revoked_serials"])
    expected_membership.append([item in active for item in root_ids])
    expected_b.append(
        "root-b" in active
        and "child-b" not in revoked
        and grants["child-b"]["parent"] == "root-b"
        and request_authorized(grants["child-b"], request)
    )
    expected_c.append(
        "root-c" in active
        and "root-c" not in revoked
        and request_authorized(grants["root-c"], request)
    )

assert expected_membership == [[True, True, True], [False, True, True], [False, True, True]]
assert expected_b == [True, True, False]
assert expected_c == [True, True, True]

revoked = set()
for index, update in enumerate(updates):
    revoked.update(update["revoked_serials"])
    for backend_name in ("joint381", "dac377"):
        backend = doc[backend_name]
        projection = backend["consumed_projection"]
        projection_sha = hashlib.sha256(canonical_json_bytes(projection)).hexdigest()
        assert projection == raw
        assert projection_sha == raw_sha
        assert backend["consumed_projection_sha256"] == projection_sha
        assert backend["native_metadata_binding_limbs_u64_le"] == metadata_limbs
        assert backend["metadata_binding_matches"] is True
        assert backend["native_request_binding_limbs_u64_le"] == request_limbs
        assert backend["request_binding_matches"] is True
        assert backend["registration_salt_owner_commitment_opening_matches"] is True
        assert projection["request"] == request
        assert projection["updates"] == updates
        assert backend["original_b_c_credential_bytes_unchanged"] is True
        assert backend["credential_b_before_sha256"] == backend["credential_b_after_sha256"]
        assert backend["credential_c_before_sha256"] == backend["credential_c_after_sha256"]
        assert len(backend["credential_b_before_sha256"]) == 64
        assert len(backend["credential_c_before_sha256"]) == 64
        phases = backend["phases"]
        assert len(phases) == len(updates)
        phase = phases[index]
        assert phase["consumed_update"] == update
        assert phase["tuple_version"] == update["tuple_version"]
        assert phase["state_epoch"] == update["state_epoch"]
        assert phase["revocation_epoch"] == update["revocation_epoch"]
        assert phase["grant_path_depth"] == raw["profile"]["grant_depth"]
        assert phase["state_path_depth"] == raw["profile"]["state_depth"]
        assert phase["root_membership_abc"] == expected_membership[index]
        assert phase["revocation_nonmember_b"] == ("child-b" not in revoked)
        assert phase["revocation_nonmember_c"] is True
        assert phase["request_acceptance_b"] == expected_b[index]
        assert phase["request_acceptance_c"] == expected_c[index]
        assert phase["grant_root"]
        assert phase["state_root"]

logical_ids = set(raw["logical_ids"].values())
assert len(logical_ids) == 4
assert all(
    item["issuer"] in logical_ids and item["subject"] in logical_ids
    for item in raw["grants"]
)
assert doc["mapping_contract"]["same_raw_records_and_update_order"] is True
assert doc["mapping_contract"]["trusted_mapper_added"] is False

matched = doc["matched_dac_fixture"]
assert matched["semantic_input_sha256"] == raw_sha
assert matched["selected_update_index"] == 1
assert matched["selected_tuple_version"] == updates[1]["tuple_version"]
assert matched["canonical_http"] == canonical_http
assert matched["canonical_http_sha256"] == request_digest.hex()
assert matched["same_manifest_circuit_built"] is True
assert matched["expected_request_from_same_manifest_matches_statement"] is True
expected = matched["expected_request"]
assert expected["semantic_input_sha256"] == raw_sha
assert expected["canonical_http"] == canonical_http
assert expected["canonical_http_sha256"] == request_digest.hex()
assert expected["tuple_version"] == updates[1]["tuple_version"]
assert expected["canonical_request_lo"] == request_limbs[:2]
assert expected["canonical_request_hi"] == request_limbs[2:]
assert expected["terminal"] == request["terminal"]
assert expected["resource"] == request["resource"]
assert expected["one_hot_action"] == request["one_hot_action_u16"]
assert expected["request_lo"] == request["interval_lo"]
assert expected["request_hi"] == request["interval_hi"]
assert expected["now"] == request["now"]
assert expected["policy_version"] == request["policy_version"]
assert expected["schema_version"] == request["schema_version"]
assert matched["expected_request_sha256"] == hashlib.sha256(
    canonical_json_bytes(expected)
).hexdigest()
assert doc["required_predicates"]["full_proof_claimed"] == (
    matched["proof_envelope_exported"] and matched["proof_verified"]
)

required = doc["required_predicates"]
for key in (
    "canonical_manifest_hashed",
    "typed_roundtrip_is_backend_input",
    "initial_membership_abc_true_both",
    "delete_a_preserve_b_c_both",
    "revoke_b_preserve_c_both",
    "heterogeneous_root_encodings",
    "same_request_terminal_updates",
    "request_outcomes_match",
    "original_b_c_credential_bytes_unchanged_both",
    "classified_metadata_bound_in_native_requests_both",
    "canonical_request_bound_in_native_requests_both",
    "registration_salt_opening_matches_both",
    "same_manifest_dac_circuit_built",
    "same_manifest_expected_request_built",
    "no_trusted_mapper",
):
    assert required[key] is True, key
assert required["service_acceptance_claimed"] is False

print(
    json.dumps(
        {
            "validation_passed": True,
            "canonical_raw_manifest_sha256_recomputed": raw_sha,
            "result_sha256": hashlib.sha256(result_bytes).hexdigest(),
        },
        sort_keys=True,
    )
)
