//! JSON/stdin smoke boundary for the exported fixed-policy service envelope.
//!
//! This is a synthetic integration profile. A production service should call
//! the public `service_wire` and `DeltaZeroAdapter` APIs in process and retain
//! adapter state across requests.

use plan_a_dac_fixed_wrapper::{
    service_adapter::{AdapterError, DeltaZeroAdapter},
    service_wire::{ExpectedServiceRequest, ServiceEnvelope},
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read};

#[derive(Deserialize)]
struct CliRequest {
    envelope: ServiceEnvelope,
    /// Must be independently derived from trusted route/body/policy/clock
    /// values. It must never be copied from `envelope.statement` by a service.
    expected: ExpectedServiceRequest,
    trusted_now: u64,
}

#[derive(Serialize)]
struct CliResponse {
    schema: &'static str,
    statement_binding_accepted: bool,
    header_accepted: bool,
    proof_and_terminal_accepted: bool,
    delta0_commit_accepted: bool,
    nonce_replay_rejected: bool,
    synthetic_profile: bool,
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let request: CliRequest = serde_json::from_str(&input).unwrap();
    let decoded = request.envelope.decode().unwrap();
    assert_eq!(
        request.expected.semantic_input_sha256,
        decoded.semantic_input_sha256
    );
    assert!(request
        .expected
        .matches_public_statement(&decoded.statement));
    let mut adapter = DeltaZeroAdapter::new(
        decoded.generator,
        decoded.registry_public_key,
        decoded.statement.deployment_id,
    );
    adapter
        .install_header(&decoded.statement, &decoded.header_signature)
        .unwrap();
    let ticket = adapter
        .verify_at_read(
            &decoded.verifying_key,
            &decoded.statement,
            decoded.relation_version,
            &decoded.proof,
            &decoded.proof_bytes,
            &decoded.terminal_signature,
        )
        .unwrap();
    adapter
        .commit(
            &ticket,
            &decoded.statement,
            decoded.relation_version,
            &decoded.proof_bytes,
            &decoded.terminal_signature,
            request.trusted_now,
        )
        .unwrap();
    let nonce_replay_rejected = matches!(
        adapter.commit(
            &ticket,
            &decoded.statement,
            decoded.relation_version,
            &decoded.proof_bytes,
            &decoded.terminal_signature,
            request.trusted_now,
        ),
        Err(AdapterError::ReplayedNonce)
    );
    assert!(nonce_replay_rejected);

    println!(
        "{}",
        serde_json::to_string_pretty(&CliResponse {
            schema: "plan-a-dac-fixed-policy-adapter-cli-result-v1",
            statement_binding_accepted: true,
            header_accepted: true,
            proof_and_terminal_accepted: true,
            delta0_commit_accepted: true,
            nonce_replay_rejected,
            synthetic_profile: true,
        })
        .unwrap()
    );
}
