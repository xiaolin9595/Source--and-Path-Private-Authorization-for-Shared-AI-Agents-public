#![recursion_limit = "256"]

use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use hrada_sr_full_f_bbs::{
    present, verify, AtomicCredential, Issuer, PublicCredentialFields, RequestContext,
};
use plan_a_joint_circuit::{contract::Grant, joint::snapshot_digest};
use plan_a_sr_joint_bbs::{
    compile_timed,
    portfolio::{
        build, revocation_target, revoke_support, unique_owner_count, unique_signed_path_count,
        IntervalShape,
    },
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::Instant;

fn signed_grant_hash(g: &Grant) -> [u8; 32] {
    let mut bytes = Vec::new();
    g.issuer.0.serialize_compressed(&mut bytes).unwrap();
    g.subject.0.serialize_compressed(&mut bytes).unwrap();
    g.resource.serialize_compressed(&mut bytes).unwrap();
    bytes.extend_from_slice(&g.action_mask.to_le_bytes());
    bytes.extend_from_slice(&g.interval_lo.to_le_bytes());
    bytes.extend_from_slice(&g.interval_hi.to_le_bytes());
    bytes.extend_from_slice(&g.not_before.to_le_bytes());
    bytes.extend_from_slice(&g.expiry.to_le_bytes());
    bytes.push(g.depth_remaining);
    g.serial.serialize_compressed(&mut bytes).unwrap();
    g.parent_digest.serialize_compressed(&mut bytes).unwrap();
    g.signature.r.serialize_compressed(&mut bytes).unwrap();
    g.signature.s.serialize_compressed(&mut bytes).unwrap();
    Sha256::digest(bytes).into()
}

fn request(
    issuer: &Issuer,
    trial: usize,
    credential: usize,
    lower: u64,
    upper: u64,
) -> RequestContext {
    RequestContext {
        current_header_digest: [0x56; 32],
        params_digest: issuer.params_digest().unwrap(),
        complete_q: format!("portfolio-sweep-v1:{trial}:{credential}:{lower}:{upper}:single-atom")
            .into_bytes(),
        verifier_nonce: ((trial as u64) << 32 | credential as u64)
            .to_le_bytes()
            .to_vec(),
        tq: lower,
        te: upper,
    }
}

fn cell(size: usize, shape: IntervalShape, trials: usize) -> Value {
    let portfolio = build(size, shape);
    let snapshot = snapshot_digest(&portfolio.sources[0].snapshot);
    assert!(portfolio
        .sources
        .iter()
        .all(|c| snapshot_digest(&c.snapshot) == snapshot));
    let target = revocation_target(shape);
    let before_hashes = portfolio
        .sources
        .iter()
        .map(|c| signed_grant_hash(&c.grants[0].grant))
        .collect::<Vec<_>>();
    let mut samples = Vec::with_capacity(trials);
    for trial in 0..trials {
        let seed =
            0x5052_5446_0000u64 + (size as u64) * 0x100 + (shape as u64) * 0x10 + trial as u64;
        let mut rng = StdRng::seed_from_u64(seed);
        let setup_start = Instant::now();
        let issuer = Issuer::generate(&mut rng);
        let setup_ns = setup_start.elapsed().as_nanos();
        let prover = issuer.prover_params();
        let verifier = issuer.verifier_params();

        let (compiled, stages) = compile_timed(&portfolio.sources).unwrap();
        compiled.issuance.validate().unwrap();
        let issued_intervals = compiled
            .issuance
            .credentials
            .iter()
            .map(|x| [x.not_before, x.upper()])
            .collect::<Vec<_>>();
        let ledger_bytes = serde_json::to_vec(&compiled.dependencies).unwrap().len();
        let mut issuance_ns = 0u128;
        let mut credential_bytes = 0usize;
        let mut showing_bytes = 0usize;
        let mut accepted = true;
        let mut first_credential: Option<(AtomicCredential, PublicCredentialFields)> = None;
        for (credential_index, input) in compiled.issuance.credentials.iter().enumerate() {
            let public = input.public_fields().unwrap();
            let started = Instant::now();
            let credential = issuer
                .issue(&mut rng, public.clone(), input.not_before, input.upper())
                .unwrap();
            if credential_index == 0 {
                first_credential = Some((credential.clone(), public.clone()));
            }
            issuance_ns += started.elapsed().as_nanos();
            credential_bytes += credential.canonical_bytes().unwrap().len();
            let q = request(
                &issuer,
                trial,
                credential_index,
                input.not_before,
                input.upper(),
            );
            let showing = present(&mut rng, &prover, &credential, &q).unwrap();
            showing_bytes += showing.canonical_bytes().unwrap().len();
            accepted &= verify(&mut rng, &verifier, &public, &q, &showing).is_ok();
        }

        let state_update_start = Instant::now();
        let successor_sources = revoke_support(&portfolio, target);
        let state_update_ns = state_update_start.elapsed().as_nanos();
        let after_hashes = successor_sources
            .iter()
            .map(|c| signed_grant_hash(&c.grants[0].grant))
            .collect::<Vec<_>>();
        assert_eq!(before_hashes, after_hashes);
        let (successor, refresh_stages) = compile_timed(&successor_sources).unwrap();
        successor.issuance.validate().unwrap();
        let reissued_intervals = successor
            .issuance
            .credentials
            .iter()
            .map(|x| [x.not_before, x.upper()])
            .collect::<Vec<_>>();
        let refresh_ledger_bytes = serde_json::to_vec(&successor.dependencies).unwrap().len();
        let mut reissuance_ns = 0u128;
        let mut reissued_bytes = 0usize;
        let mut refresh_accepted = true;
        for (credential_index, input) in successor.issuance.credentials.iter().enumerate() {
            let public = input.public_fields().unwrap();
            let started = Instant::now();
            let credential = issuer
                .issue(&mut rng, public.clone(), input.not_before, input.upper())
                .unwrap();
            reissuance_ns += started.elapsed().as_nanos();
            reissued_bytes += credential.canonical_bytes().unwrap().len();
            let q = request(
                &issuer,
                trial + trials,
                credential_index,
                input.not_before,
                input.upper(),
            );
            let showing = present(&mut rng, &prover, &credential, &q).unwrap();
            refresh_accepted &= verify(&mut rng, &verifier, &public, &q, &showing).is_ok();
        }

        let mut cross_verify_calls = 0usize;
        let cross_boundary_rejected = if shape == IntervalShape::Noncontained {
            let (credential, public) = first_credential.as_ref().unwrap();
            let cross = request(
                &issuer,
                trial + 2 * trials,
                0,
                compiled.issuance.credentials.first().unwrap().not_before,
                compiled.issuance.credentials.last().unwrap().upper(),
            );
            match present(&mut rng, &prover, credential, &cross) {
                Err(_) => true,
                Ok(showing) => {
                    cross_verify_calls += 1;
                    verify(&mut rng, &verifier, public, &cross, &showing).is_err()
                }
            }
        } else {
            true
        };

        samples.push(json!({
            "trial": trial,
            "rng": "StdRng_seed_from_u64",
            "seed_u64": seed,
            "fresh_issuer_setup_ns": setup_ns,
            "native_path_validation_ns": stages.native_path_validation_ns,
            "support_derivation_ns": stages.support_derivation_ns,
            "maximal_containment_dedup_ns": stages.maximal_containment_dedup_ns,
            "issuance_ns": issuance_ns,
            "revocation_state_update_ns": state_update_ns,
            "refresh_native_path_validation_ns": refresh_stages.native_path_validation_ns,
            "refresh_support_derivation_ns": refresh_stages.support_derivation_ns,
            "refresh_maximal_containment_dedup_ns": refresh_stages.maximal_containment_dedup_ns,
            "reissuance_ns": reissuance_ns,
            "verify_accepted": accepted,
            "refresh_verify_accepted": refresh_accepted,
            "cross_boundary_rejected": cross_boundary_rejected,
            "scanned_supports": compiled.scanned_paths,
            "valid_supports": compiled.valid_paths,
            "invalid_supports": compiled.invalid_paths,
            "exact_duplicates": compiled.exact_duplicates,
            "dominated_supports": compiled.dominated,
            "issued_credentials": compiled.issuance.credentials.len(),
            "issued_intervals": issued_intervals,
            "private_ledger_bytes": ledger_bytes,
            "credential_bytes_total": credential_bytes,
            "showing_bytes_total": showing_bytes,
            "refresh_scanned_supports": successor.scanned_paths,
            "refresh_valid_supports": successor.valid_paths,
            "refresh_invalid_supports": successor.invalid_paths,
            "refresh_exact_duplicates": successor.exact_duplicates,
            "refresh_dominated_supports": successor.dominated,
            "reissued_credentials": successor.issuance.credentials.len(),
            "reissued_intervals": reissued_intervals,
            "dominated_support_becomes_maximal_after_refresh": shape != IntervalShape::Contained ||
                (successor.issuance.credentials.len() == 1 &&
                 successor.issuance.credentials[0].not_before == 101 &&
                 successor.issuance.credentials[0].upper() == 299),
            "refresh_private_ledger_bytes": refresh_ledger_bytes,
            "reissued_credential_bytes_total": reissued_bytes,
            "signed_grant_bytes_hashes_unchanged": before_hashes == after_hashes,
            "configuration": {
                "lmax": 3,
                "actual_grants_per_support": 1,
                "state_tree_depth": 6,
                "ra_tree_depth": 6,
                "revocation_tree_depth": 6,
                "action_atoms_compiled_per_support": 1,
                "primary_request": "each credential's complete maximal closed interval"
            },
            "exposure_counts": {
                "fresh_issuer_setups": 1,
                "compiler_invocations": 2,
                "native_support_validations": compiled.scanned_paths + successor.scanned_paths,
                "issuance_calls": compiled.issuance.credentials.len() + successor.issuance.credentials.len(),
                "presentation_attempts": compiled.issuance.credentials.len() + successor.issuance.credentials.len() + usize::from(shape == IntervalShape::Noncontained),
                "verification_calls": compiled.issuance.credentials.len() + successor.issuance.credentials.len() + cross_verify_calls
            }
        }));
    }
    json!({
        "portfolio_size": size,
        "interval_shape": shape.label(),
        "input_rows": portfolio.sources.len(),
        "unique_signed_paths": unique_signed_path_count(&portfolio.sources),
        "unique_owners": unique_owner_count(&portfolio.sources),
        "revoked_source_index": target,
        "request_atom_count": 1,
        "lmax": 3,
        "actual_grants_per_support": 1,
        "primary_request_selection": "one full maximal interval per issued credential; one additional convex-hull rejection attempt for noncontained",
        "fixture_reuse": "trusted deterministic portfolio reused across fresh issuer trials; all measured issuer setups are fresh",
        "samples": samples
    })
}

fn main() {
    let trials = std::env::args()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(10usize);
    assert!(trials > 0);
    let mut cells = Vec::new();
    for size in [2usize, 8, 32] {
        for shape in [
            IntervalShape::Duplicate,
            IntervalShape::Contained,
            IntervalShape::Noncontained,
        ] {
            cells.push(cell(size, shape, trials));
        }
    }
    println!("{}", serde_json::to_string_pretty(&json!({
        "schema": "plan-a-sr-real-portfolio-sweep-v1",
        "backend": "BBS23-CDL real issuance/presentation/verification",
        "trial_count_per_cell": trials,
        "sizes": [2, 8, 32],
        "interval_shapes": ["duplicate", "contained", "noncontained"],
        "refresh_policy": "global successor reissuance candidate",
        "measurement_status": "measured by this executable; source contains no populated benchmark results",
        "cells": cells
    })).unwrap());
}
