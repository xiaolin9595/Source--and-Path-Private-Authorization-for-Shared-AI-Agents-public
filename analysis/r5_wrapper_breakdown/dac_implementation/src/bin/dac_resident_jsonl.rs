//! Persistent synthetic DAC verifier for the matched service gate.
//!
//! The process loads one trusted deployment file at startup. Requests cannot
//! supply a verifying key, generator, registry key, or deployment id.

use plan_a_dac_fixed_wrapper::{
    semantic_schema::manifest_sha256,
    service_adapter::{DeltaZeroAdapter, VerificationTicket},
    service_wire::{
        DacInstalledHeader, ExpectedServiceRequest, ResidentCommand, ResidentProofEnvelope,
        ServiceWireError, TrustedDacConfigWire,
    },
};
use rand::{rngs::OsRng, RngCore};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, BufRead},
};

#[derive(Serialize)]
struct Response {
    valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ticket: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn reject(error: impl Into<String>) -> Response {
    Response {
        valid: false,
        header: None,
        ticket: None,
        error: Some(error.into()),
    }
}

struct ResidentTicket {
    inner: VerificationTicket,
    expected: ExpectedServiceRequest,
    envelope: ResidentProofEnvelope,
}

fn same_expected_except_clock(
    left: &ExpectedServiceRequest,
    right: &ExpectedServiceRequest,
) -> bool {
    let mut left = left.clone();
    let mut right = right.clone();
    left.trusted_now = 0;
    right.trusted_now = 0;
    left == right
}

fn main() {
    let config_path = env::var("DAC_TRUSTED_CONFIG_PATH")
        .expect("DAC_TRUSTED_CONFIG_PATH must name the producer-owned trusted config");
    let config_wire: TrustedDacConfigWire =
        serde_json::from_slice(&fs::read(config_path).expect("read trusted DAC config"))
            .expect("parse trusted DAC config");
    let trusted = config_wire.decode().expect("decode trusted DAC config");
    let mut adapter = DeltaZeroAdapter::new(
        trusted.generator,
        trusted.registry_public_key,
        trusted.deployment_id,
    );
    let mut tickets: BTreeMap<String, ResidentTicket> = BTreeMap::new();

    for line in io::stdin().lock().lines() {
        let response = match line {
            Err(error) => reject(format!("read command: {error}")),
            Ok(line) => match serde_json::from_str::<ResidentCommand>(&line) {
                Err(error) => reject(format!("parse command: {error}")),
                Ok(ResidentCommand::MaterializeAndVerifyHeader {
                    canonical_manifest,
                    semantic_input_sha256,
                    update_index,
                    header_envelope,
                    backend_profile,
                }) => {
                    let manifest_hash = manifest_sha256(&canonical_manifest);
                    let update_matches = canonical_manifest
                        .updates
                        .get(update_index as usize)
                        .is_some_and(|update| {
                            update.tuple_version == header_envelope.header.tuple_version
                                && update.state_epoch == header_envelope.header.state_epoch
                                && update.revocation_epoch
                                    == header_envelope.header.revocation_epoch
                                && update.issued_at == header_envelope.header.issued_at
                        });
                    let trusted_statement = config_wire.trusted_statements.iter().find(|wire| {
                        wire.decode().is_ok_and(|statement| {
                            DacInstalledHeader::from_statement(
                                trusted.semantic_input_sha256.clone(),
                                &statement,
                            ) == header_envelope.header
                        })
                    });
                    if manifest_hash != semantic_input_sha256
                        || semantic_input_sha256 != trusted.semantic_input_sha256
                        || header_envelope.header.semantic_input_sha256 != semantic_input_sha256
                        || trusted_statement.is_none()
                        || backend_profile != trusted.backend_profile
                        || !update_matches
                    {
                        reject("trusted manifest/header/profile binding mismatch")
                    } else {
                        match header_envelope
                            .decode(trusted_statement.expect("checked above"))
                            .and_then(|header| {
                                adapter
                                    .install_header(&header.statement, &header.registry_signature)
                                    .map_err(ServiceWireError::from)
                            }) {
                            Ok(()) => Response {
                                valid: true,
                                header: Some(
                                    serde_json::to_value(&header_envelope.header).unwrap(),
                                ),
                                ticket: None,
                                error: None,
                            },
                            Err(error) => reject(error.to_string()),
                        }
                    }
                }
                Ok(ResidentCommand::VerifyAtRead {
                    canonical_manifest,
                    expected,
                    envelope,
                }) => {
                    if manifest_sha256(&canonical_manifest) != trusted.semantic_input_sha256
                        || expected.semantic_input_sha256 != trusted.semantic_input_sha256
                        || envelope.semantic_input_sha256 != trusted.semantic_input_sha256
                        || envelope.relation_version != trusted.relation_version
                        || envelope.update_index != expected.update_index
                        || !config_wire.trusted_statements.contains(&envelope.statement)
                        || expected.trusted_now < expected.interval_lo
                        || expected.trusted_now > expected.interval_hi
                    {
                        reject("trusted read binding mismatch")
                    } else {
                        match envelope.decode() {
                            Err(error) => reject(error.to_string()),
                            Ok(proof)
                                if !expected.matches_statement(
                                    &canonical_manifest,
                                    &trusted.backend_profile,
                                    &proof.statement,
                                ) =>
                            {
                                reject("expected request mismatch")
                            }
                            Ok(proof) => match adapter.verify_at_read(
                                &trusted.verifying_key,
                                &proof.statement,
                                proof.relation_version,
                                &proof.proof,
                                &proof.proof_bytes,
                                &proof.terminal_signature,
                            ) {
                                Err(error) => reject(format!("verify-at-read: {error:?}")),
                                Ok(ticket) => {
                                    let mut token = [0u8; 32];
                                    OsRng.fill_bytes(&mut token);
                                    let token: String =
                                        token.iter().map(|b| format!("{b:02x}")).collect();
                                    tickets.insert(
                                        token.clone(),
                                        ResidentTicket {
                                            inner: ticket,
                                            expected,
                                            envelope,
                                        },
                                    );
                                    Response {
                                        valid: true,
                                        header: None,
                                        ticket: Some(token),
                                        error: None,
                                    }
                                }
                            },
                        }
                    }
                }
                Ok(ResidentCommand::Commit {
                    canonical_manifest,
                    expected,
                    envelope,
                    ticket,
                }) => {
                    if manifest_sha256(&canonical_manifest) != trusted.semantic_input_sha256
                        || expected.semantic_input_sha256 != trusted.semantic_input_sha256
                        || envelope.semantic_input_sha256 != trusted.semantic_input_sha256
                        || envelope.relation_version != trusted.relation_version
                        || envelope.update_index != expected.update_index
                        || !config_wire.trusted_statements.contains(&envelope.statement)
                        || expected.trusted_now < expected.interval_lo
                        || expected.trusted_now > expected.interval_hi
                    {
                        reject("trusted commit binding mismatch")
                    } else {
                        match (tickets.remove(&ticket), envelope.decode()) {
                            (Some(ticket), Ok(proof))
                                if ticket.envelope == envelope
                                    && same_expected_except_clock(&ticket.expected, &expected)
                                    && expected.matches_statement(
                                        &canonical_manifest,
                                        &trusted.backend_profile,
                                        &proof.statement,
                                    ) =>
                            {
                                match adapter.commit(
                                    &ticket.inner,
                                    &proof.statement,
                                    proof.relation_version,
                                    &proof.proof_bytes,
                                    &proof.terminal_signature,
                                    expected.trusted_now,
                                ) {
                                    Ok(()) => Response {
                                        valid: true,
                                        header: None,
                                        ticket: None,
                                        error: None,
                                    },
                                    Err(error) => reject(format!("commit: {error:?}")),
                                }
                            }
                            (None, _) => reject("unknown or already consumed ticket"),
                            (_, Err(error)) => reject(error.to_string()),
                            _ => reject("expected request mismatch"),
                        }
                    }
                }
            },
        };
        println!("{}", serde_json::to_string(&response).unwrap());
    }
}
