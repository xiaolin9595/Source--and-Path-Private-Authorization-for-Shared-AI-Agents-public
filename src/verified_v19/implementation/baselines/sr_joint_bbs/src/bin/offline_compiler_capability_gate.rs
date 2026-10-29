#![recursion_limit = "256"]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use hrada_sr_full_f_bbs::{
    encode_complete_q, present, verify, FullFError, Issuer, PublicCredentialFields, RequestContext,
};
use plan_a_joint_circuit::{
    contract::Grant,
    fixture::{offline_child_to_new_terminal, public_inputs},
    joint::{grant_digest, snapshot_digest},
    signature::PublicKey,
};
use plan_a_sr_joint_bbs::compile;
use rand::rngs::OsRng;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::error::Error;

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_bytes<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

fn json_sha256<T: Serialize>(value: &T) -> Result<String, Box<dyn Error>> {
    Ok(sha256_hex(&serde_json::to_vec(value)?))
}

fn terminal_sha256(terminal: &PublicKey) -> Result<String, Box<dyn Error>> {
    Ok(sha256_hex(&canonical_bytes(&terminal.0)?))
}

fn limbs_le(bytes: &[u8; 32]) -> (Fr, Fr) {
    (
        Fr::from_le_bytes_mod_order(&bytes[..16]),
        Fr::from_le_bytes_mod_order(&bytes[16..]),
    )
}

fn public_fields_differ_only_in_terminal(
    old: &PublicCredentialFields,
    new: &PublicCredentialFields,
) -> bool {
    old.system == new.system
        && old.circuit_version == new.circuit_version
        && old.global_epoch == new.global_epoch
        && old.resource == new.resource
        && old.action_one_hot == new.action_one_hot
        && old.terminal_key != new.terminal_key
}

fn signed_grant_bytes(grant: &Grant) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    grant.issuer.0.serialize_compressed(&mut bytes)?;
    grant.subject.0.serialize_compressed(&mut bytes)?;
    grant.resource.serialize_compressed(&mut bytes)?;
    bytes.extend_from_slice(&grant.action_mask.to_le_bytes());
    bytes.extend_from_slice(&grant.interval_lo.to_le_bytes());
    bytes.extend_from_slice(&grant.interval_hi.to_le_bytes());
    bytes.extend_from_slice(&grant.not_before.to_le_bytes());
    bytes.extend_from_slice(&grant.expiry.to_le_bytes());
    bytes.push(grant.depth_remaining);
    grant.serial.serialize_compressed(&mut bytes)?;
    grant.parent_digest.serialize_compressed(&mut bytes)?;
    grant.signature.r.serialize_compressed(&mut bytes)?;
    grant.signature.s.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

fn snapshot_record_bytes(
    snapshot: &plan_a_joint_circuit::contract::Snapshot,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&snapshot.tuple_version.to_le_bytes());
    snapshot.root_ra.serialize_compressed(&mut bytes)?;
    snapshot.root_state.serialize_compressed(&mut bytes)?;
    snapshot.root_rev.serialize_compressed(&mut bytes)?;
    bytes.extend_from_slice(&snapshot.state_epoch.to_le_bytes());
    bytes.extend_from_slice(&snapshot.revocation_epoch.to_le_bytes());
    bytes.extend_from_slice(&snapshot.issued_at.to_le_bytes());
    Ok(bytes)
}

fn main() -> Result<(), Box<dyn Error>> {
    let (initial, child) = offline_child_to_new_terminal();
    let snapshot_fields_equal = initial.snapshot.tuple_version == child.snapshot.tuple_version
        && initial.snapshot.root_ra == child.snapshot.root_ra
        && initial.snapshot.root_state == child.snapshot.root_state
        && initial.snapshot.root_rev == child.snapshot.root_rev
        && initial.snapshot.state_epoch == child.snapshot.state_epoch
        && initial.snapshot.revocation_epoch == child.snapshot.revocation_epoch
        && initial.snapshot.issued_at == child.snapshot.issued_at;
    let initial_snapshot_digest = snapshot_digest(&initial.snapshot);
    let child_snapshot_digest = snapshot_digest(&child.snapshot);
    let snapshot_digest_equal = initial_snapshot_digest == child_snapshot_digest;
    let initial_root_digest = grant_digest(&initial.grants[0].grant);
    let child_root_digest = grant_digest(&child.grants[0].grant);
    let root_grant_digest_equal = initial_root_digest == child_root_digest;
    let initial_root_bytes = signed_grant_bytes(&initial.grants[0].grant)?;
    let child_root_bytes = signed_grant_bytes(&child.grants[0].grant)?;
    let root_grant_signed_bytes_equal = initial_root_bytes == child_root_bytes;
    let terminal_changed = initial.request.terminal != child.request.terminal;
    let initial_active_depth = initial
        .grants
        .iter()
        .take_while(|slot| slot.enabled)
        .count();
    let child_active_depth = child.grants.iter().take_while(|slot| slot.enabled).count();

    assert!(snapshot_fields_equal);
    assert!(snapshot_digest_equal);
    assert!(root_grant_digest_equal);
    assert!(root_grant_signed_bytes_equal);
    assert!(terminal_changed);
    assert_eq!(initial_active_depth, 1);
    assert_eq!(child_active_depth, 2);

    let mut rng = OsRng;
    let (joint_pk, joint_vk) = Groth16::<Bls12_381>::setup(initial.clone(), &mut rng)?;
    let initial_proof = Groth16::<Bls12_381>::prove(&joint_pk, initial.clone(), &mut rng)?;
    let child_proof = Groth16::<Bls12_381>::prove(&joint_pk, child.clone(), &mut rng)?;
    let initial_public_inputs = public_inputs(&initial);
    let child_public_inputs = public_inputs(&child);
    let joint_same_pk_initial_accepted =
        Groth16::<Bls12_381>::verify(&joint_vk, &initial_public_inputs, &initial_proof)?;
    let joint_same_pk_offline_child_accepted =
        Groth16::<Bls12_381>::verify(&joint_vk, &child_public_inputs, &child_proof)?;
    assert!(joint_same_pk_initial_accepted);
    assert!(joint_same_pk_offline_child_accepted);

    let old_batch = compile(&[initial.clone()])?;
    let new_batch = compile(&[child.clone()])?;
    assert_eq!(old_batch.valid_paths, 1);
    assert_eq!(old_batch.invalid_paths, 0);
    assert_eq!(old_batch.issuance.credentials.len(), 1);
    assert_eq!(new_batch.valid_paths, 1);
    assert_eq!(new_batch.invalid_paths, 0);
    assert_eq!(new_batch.issuance.credentials.len(), 1);
    let old_input = &old_batch.issuance.credentials[0];
    let new_input = &new_batch.issuance.credentials[0];
    let old_public = old_input.public_fields()?;
    let new_public = new_input.public_fields()?;
    let compiler_initial_terminal_matches_request =
        old_input.key.terminal == canonical_bytes(&initial.request.terminal.0)?;
    let compiler_ingested_child_terminal_matches_request =
        new_input.key.terminal == canonical_bytes(&child.request.terminal.0)?;
    assert!(compiler_initial_terminal_matches_request);
    assert!(compiler_ingested_child_terminal_matches_request);
    let sr_public_fields_differ_only_in_terminal =
        public_fields_differ_only_in_terminal(&old_public, &new_public);
    assert!(sr_public_fields_differ_only_in_terminal);

    let issuer = Issuer::generate(&mut rng);
    let prover = issuer.prover_params();
    let verifier = issuer.verifier_params();
    let old_credential = issuer.issue(
        &mut rng,
        old_public.clone(),
        old_input.not_before,
        old_input.upper(),
    )?;

    // Build the current T1 request only after the compiler has ingested the
    // offline child. Both the old and new showings below use this exact Q16,
    // header, nonce, and interval. Therefore the old-credential rejection
    // cannot be explained by replaying an old showing under a changed context.
    let initial_snapshot_record_bytes = snapshot_record_bytes(&initial.snapshot)?;
    let child_snapshot_record_bytes = snapshot_record_bytes(&child.snapshot)?;
    let current_header_digest: [u8; 32] = Sha256::digest(
        [
            b"plan-a-offline-child-current-header-v1\0".as_slice(),
            child_snapshot_record_bytes.as_slice(),
        ]
        .concat(),
    )
    .into();
    let t1_current_request_digest: [u8; 32] = Sha256::digest(
        [
            b"plan-a-offline-child-t1-current-request-v1\0".as_slice(),
            canonical_bytes(&child_public_inputs)?.as_slice(),
        ]
        .concat(),
    )
    .into();
    let deployment_digest: [u8; 32] = Sha256::digest(
        [
            b"plan-a-offline-child-deployment-v1\0".as_slice(),
            canonical_bytes(&child.request.circuit_id)?.as_slice(),
        ]
        .concat(),
    )
    .into();
    let (header_lo, header_hi) = limbs_le(&current_header_digest);
    let (request_lo, request_hi) = limbs_le(&t1_current_request_digest);
    let (deployment_lo, deployment_hi) = limbs_le(&deployment_digest);
    let verifier_nonce_u64 = 0x0ff1_1e01_u64;
    let q16_fields = [
        header_lo,
        header_hi,
        Fr::from(new_public.global_epoch),
        Fr::from(new_public.system),
        Fr::from(new_public.circuit_version),
        request_lo,
        request_hi,
        Fr::from(new_public.resource),
        Fr::from(new_public.action_one_hot as u64),
        Fr::from(child.request.interval_lo),
        Fr::from(verifier_nonce_u64),
        Fr::from(child.request.interval_hi),
        deployment_lo,
        deployment_hi,
        child.request.terminal.0.x,
        child.request.terminal.0.y,
    ];
    let t1_current_q16 = encode_complete_q(&q16_fields)?;
    let child_terminal_bytes = canonical_bytes(&child.request.terminal.0)?;
    let (request, t1_current_public) = RequestContext::from_q16(
        t1_current_q16,
        current_header_digest,
        issuer.params_digest()?,
        &child_terminal_bytes,
        verifier_nonce_u64,
    )?;
    let t1_current_public_matches_compiler_child = t1_current_public == new_public;
    assert!(t1_current_public_matches_compiler_child);
    let old_showing_request = request.clone();
    let new_showing_request = request.clone();
    let old_and_new_showings_use_identical_t1_request_context =
        old_showing_request == new_showing_request;
    assert!(old_and_new_showings_use_identical_t1_request_context);

    // This is a fresh showing made from the old credential specifically for
    // the new/current T1 request. First verify it against the old credential's
    // public fields under that request, then change only the expected terminal
    // public field and require the exact mismatch error.
    let old_showing = present(&mut rng, &prover, &old_credential, &old_showing_request)?;
    let sr_old_credential_initial_terminal_accepted = verify(
        &mut rng,
        &verifier,
        &old_public,
        &old_showing_request,
        &old_showing,
    )
    .is_ok();
    let old_against_new = verify(
        &mut rng,
        &verifier,
        &t1_current_public,
        &old_showing_request,
        &old_showing,
    );
    let sr_old_credential_new_terminal_rejected =
        matches!(old_against_new, Err(FullFError::PublicFieldsMismatch));
    assert!(sr_old_credential_initial_terminal_accepted);
    assert!(sr_old_credential_new_terminal_rejected);

    let new_credential = issuer.issue(
        &mut rng,
        new_public.clone(),
        new_input.not_before,
        new_input.upper(),
    )?;
    let new_showing = present(&mut rng, &prover, &new_credential, &new_showing_request)?;
    let sr_new_credential_after_compiler_ingest_accepted = verify(
        &mut rng,
        &verifier,
        &t1_current_public,
        &new_showing_request,
        &new_showing,
    )
    .is_ok();
    assert!(sr_new_credential_after_compiler_ingest_accepted);

    let gate_passed = snapshot_fields_equal
        && snapshot_digest_equal
        && root_grant_digest_equal
        && root_grant_signed_bytes_equal
        && terminal_changed
        && joint_same_pk_initial_accepted
        && joint_same_pk_offline_child_accepted
        && compiler_initial_terminal_matches_request
        && compiler_ingested_child_terminal_matches_request
        && sr_public_fields_differ_only_in_terminal
        && t1_current_public_matches_compiler_child
        && old_and_new_showings_use_identical_t1_request_context
        && sr_old_credential_initial_terminal_accepted
        && sr_old_credential_new_terminal_rejected
        && sr_new_credential_after_compiler_ingest_accepted;
    assert!(gate_passed);

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "plan-a-offline-child-compiler-capability-gate-v1",
            "scope": "standalone correctness gate; no timing claim and no service/HTTP claim",
            "rng": "OsRng for Joint setup/proofs and SR setup/showings",
            "snapshot_fields_equal": snapshot_fields_equal,
            "snapshot_digest_equal": snapshot_digest_equal,
            "snapshot_digest_hex": hex::encode(canonical_bytes(&initial_snapshot_digest)?),
            "initial_snapshot_record_sha256": sha256_hex(&initial_snapshot_record_bytes),
            "child_snapshot_record_sha256": sha256_hex(&child_snapshot_record_bytes),
            "root_grant_digest_equal": root_grant_digest_equal,
            "root_grant_signed_bytes_equal": root_grant_signed_bytes_equal,
            "initial_root_grant_signed_sha256": sha256_hex(&initial_root_bytes),
            "child_root_grant_signed_sha256": sha256_hex(&child_root_bytes),
            "terminal_changed": terminal_changed,
            "initial_terminal_sha256": terminal_sha256(&initial.request.terminal)?,
            "child_terminal_sha256": terminal_sha256(&child.request.terminal)?,
            "initial_active_depth": initial_active_depth,
            "child_active_depth": child_active_depth,
            "joint_same_pk_initial_accepted": joint_same_pk_initial_accepted,
            "joint_same_pk_offline_child_accepted": joint_same_pk_offline_child_accepted,
            "joint_initial_public_inputs_sha256": sha256_hex(&canonical_bytes(&initial_public_inputs)?),
            "joint_child_public_inputs_sha256": sha256_hex(&canonical_bytes(&child_public_inputs)?),
            "joint_initial_proof_sha256": sha256_hex(&canonical_bytes(&initial_proof)?),
            "joint_child_proof_sha256": sha256_hex(&canonical_bytes(&child_proof)?),
            "sr_initial_compiler_valid_paths": old_batch.valid_paths,
            "sr_initial_compiler_invalid_paths": old_batch.invalid_paths,
            "sr_child_compiler_valid_paths": new_batch.valid_paths,
            "sr_child_compiler_invalid_paths": new_batch.invalid_paths,
            "compiler_initial_terminal_matches_request": compiler_initial_terminal_matches_request,
            "compiler_ingested_child_terminal_matches_request": compiler_ingested_child_terminal_matches_request,
            "sr_public_fields_differ_only_in_terminal": sr_public_fields_differ_only_in_terminal,
            "sr_old_public_fields_sha256": json_sha256(&old_public)?,
            "sr_new_public_fields_sha256": json_sha256(&new_public)?,
            "t1_current_public_matches_compiler_child": t1_current_public_matches_compiler_child,
            "t1_current_request_digest_sha256": hex::encode(t1_current_request_digest),
            "t1_current_q16_sha256": sha256_hex(&old_showing_request.complete_q),
            "t1_current_request_context_sha256": json_sha256(&old_showing_request)?,
            "t1_current_header_digest_sha256": hex::encode(current_header_digest),
            "t1_deployment_digest_sha256": hex::encode(deployment_digest),
            "t1_verifier_nonce_u64": verifier_nonce_u64,
            "t1_verifier_nonce_sha256": sha256_hex(&old_showing_request.verifier_nonce),
            "sr_old_credential_sha256": sha256_hex(&old_credential.canonical_bytes()?),
            "sr_new_credential_sha256": sha256_hex(&new_credential.canonical_bytes()?),
            "fresh_old_showing_for_t1_request_sha256": sha256_hex(&old_showing.canonical_bytes()?),
            "new_showing_for_t1_request_sha256": sha256_hex(&new_showing.canonical_bytes()?),
            "old_and_new_showings_use_identical_t1_request_context": old_and_new_showings_use_identical_t1_request_context,
            "old_public_t1_request_primitive_control_accepted": sr_old_credential_initial_terminal_accepted,
            "old_public_t1_request_control_scope": "primitive-only diagnostic; not service Accept; the HTTP verifier derives expected public fields, including terminal, from the trusted canonical request Q16",
            "sr_old_credential_initial_terminal_accepted": sr_old_credential_initial_terminal_accepted,
            "sr_old_credential_new_terminal_rejected": sr_old_credential_new_terminal_rejected,
            "sr_old_credential_new_terminal_rejection": "PublicFieldsMismatch",
            "sr_new_credential_after_compiler_ingest_accepted": sr_new_credential_after_compiler_ingest_accepted,
            "gate_passed": gate_passed
        }))?
    );
    Ok(())
}
