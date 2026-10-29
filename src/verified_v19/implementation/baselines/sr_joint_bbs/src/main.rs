use ark_std::rand::{rngs::StdRng, SeedableRng};
use hrada_sr_full_f_bbs::{present, verify, Issuer, RequestContext};
use plan_a_joint_circuit::contract::Grant;
use plan_a_joint_circuit::joint::{grant_digest, request_digest, snapshot_digest};
use plan_a_sr_joint_bbs::{
    compile,
    fixtures::{offline_child_to_new_terminal, revoke_source_b, two_source_same_terminal},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Instant;

fn median(mut xs: Vec<u128>) -> u128 {
    xs.sort();
    xs[xs.len() / 2]
}
fn signed_grant_hash(g: &Grant) -> [u8; 32] {
    use ark_serialize::CanonicalSerialize;
    let mut b = Vec::new();
    g.issuer.0.serialize_compressed(&mut b).unwrap();
    g.subject.0.serialize_compressed(&mut b).unwrap();
    g.resource.serialize_compressed(&mut b).unwrap();
    b.extend_from_slice(&g.action_mask.to_le_bytes());
    b.extend_from_slice(&g.interval_lo.to_le_bytes());
    b.extend_from_slice(&g.interval_hi.to_le_bytes());
    b.extend_from_slice(&g.not_before.to_le_bytes());
    b.extend_from_slice(&g.expiry.to_le_bytes());
    b.push(g.depth_remaining);
    g.serial.serialize_compressed(&mut b).unwrap();
    g.parent_digest.serialize_compressed(&mut b).unwrap();
    g.signature.r.serialize_compressed(&mut b).unwrap();
    g.signature.s.serialize_compressed(&mut b).unwrap();
    Sha256::digest(b).into()
}
fn main() {
    let reps = std::env::args()
        .nth(1)
        .and_then(|x| x.parse().ok())
        .unwrap_or(10usize);
    let fresh_setups = std::env::args()
        .nth(2)
        .and_then(|x| x.parse().ok())
        .unwrap_or(10usize);
    let [source_a, source_b] = two_source_same_terminal();
    assert_eq!(
        snapshot_digest(&source_a.snapshot),
        snapshot_digest(&source_b.snapshot)
    );
    assert_eq!(
        request_digest(&source_a.request, snapshot_digest(&source_a.snapshot)),
        request_digest(&source_b.request, snapshot_digest(&source_b.snapshot))
    );
    let original_grant_digests = [
        source_a.grants.each_ref().map(|s| grant_digest(&s.grant)),
        source_b.grants.each_ref().map(|s| grant_digest(&s.grant)),
    ];
    let original_signed_grant_hashes = [
        source_a
            .grants
            .each_ref()
            .map(|s| signed_grant_hash(&s.grant)),
        source_b
            .grants
            .each_ref()
            .map(|s| signed_grant_hash(&s.grant)),
    ];
    let t = Instant::now();
    let compiled = compile(&[source_a.clone(), source_b.clone()]).unwrap();
    let compile_ns = t.elapsed().as_nanos();
    let successor_sources = revoke_source_b(source_a.clone(), source_b.clone());
    let successor_grant_digests = [
        successor_sources[0]
            .grants
            .each_ref()
            .map(|s| grant_digest(&s.grant)),
        successor_sources[1]
            .grants
            .each_ref()
            .map(|s| grant_digest(&s.grant)),
    ];
    let successor_signed_grant_hashes = [
        successor_sources[0]
            .grants
            .each_ref()
            .map(|s| signed_grant_hash(&s.grant)),
        successor_sources[1]
            .grants
            .each_ref()
            .map(|s| signed_grant_hash(&s.grant)),
    ];
    assert_eq!(original_grant_digests, successor_grant_digests);
    assert_eq!(original_signed_grant_hashes, successor_signed_grant_hashes);
    let t = Instant::now();
    let successor = compile(&successor_sources).unwrap();
    let refresh_compile_ns = t.elapsed().as_nanos();
    let removed = compile::<3>(&[]).unwrap();
    assert_eq!(compiled.valid_paths, 2);
    assert_eq!(compiled.issuance.credentials.len(), 1);
    assert_eq!(compiled.dependencies.values().next().unwrap().len(), 2);
    assert_eq!(successor.valid_paths, 1);
    assert_eq!(successor.invalid_paths, 1);
    assert_eq!(successor.issuance.credentials.len(), 1);
    assert_eq!(successor.dependencies.values().next().unwrap().len(), 1);
    assert!(removed.issuance.credentials.is_empty());
    let input = &compiled.issuance.credentials[0];
    let public = input.public_fields().unwrap();
    let upper = input.upper();
    let mut rng = StdRng::seed_from_u64(0x5352_4a42);
    let setup = Instant::now();
    let issuer = Issuer::generate(&mut rng);
    let setup_ns = setup.elapsed().as_nanos();
    let prover = issuer.prover_params();
    let verifier = issuer.verifier_params();
    let mut issue: Vec<u128> = Vec::new();
    let mut show: Vec<u128> = Vec::new();
    let mut check: Vec<u128> = Vec::new();
    let mut sizes: Vec<usize> = Vec::new();
    for rep in 0..reps {
        let start = Instant::now();
        let credential = issuer
            .issue(&mut rng, public.clone(), input.not_before, upper)
            .unwrap();
        issue.push(start.elapsed().as_nanos());
        let request = RequestContext {
            current_header_digest: [7; 32],
            params_digest: issuer.params_digest().unwrap(),
            complete_q: format!("plan-a-joint-base-request-v1:{rep}").into_bytes(),
            verifier_nonce: (rep as u64).to_le_bytes().to_vec(),
            tq: source_a.request.interval_lo,
            te: source_a.request.interval_hi,
        };
        let start = Instant::now();
        let showing = present(&mut rng, &prover, &credential, &request).unwrap();
        show.push(start.elapsed().as_nanos());
        sizes.push(showing.canonical_bytes().unwrap().len());
        let start = Instant::now();
        verify(&mut rng, &verifier, &public, &request, &showing).unwrap();
        check.push(start.elapsed().as_nanos());
    }
    let (t0, t1) = offline_child_to_new_terminal();
    let old_batch = compile(&[t0.clone()]).unwrap();
    let old_input = &old_batch.issuance.credentials[0];
    let old_public = old_input.public_fields().unwrap();
    let old_credential = issuer
        .issue(
            &mut rng,
            old_public.clone(),
            old_input.not_before,
            old_input.upper(),
        )
        .unwrap();
    let old_request = RequestContext {
        current_header_digest: [8; 32],
        params_digest: issuer.params_digest().unwrap(),
        complete_q: b"offline-delegation-t1-request".to_vec(),
        verifier_nonce: b"old-batch".to_vec(),
        tq: t1.request.interval_lo,
        te: t1.request.interval_hi,
    };
    let old_showing = present(&mut rng, &prover, &old_credential, &old_request).unwrap();
    let start = Instant::now();
    let new_batch = compile(&[t1]).unwrap();
    let new_delegation_compile_ns = start.elapsed().as_nanos();
    let new_input = &new_batch.issuance.credentials[0];
    let new_public = new_input.public_fields().unwrap();
    assert!(verify(&mut rng, &verifier, &new_public, &old_request, &old_showing).is_err());
    let start = Instant::now();
    let new_credential = issuer
        .issue(
            &mut rng,
            new_public.clone(),
            new_input.not_before,
            new_input.upper(),
        )
        .unwrap();
    let new_delegation_issuance_ns = start.elapsed().as_nanos();
    let new_showing = present(&mut rng, &prover, &new_credential, &old_request).unwrap();
    verify(&mut rng, &verifier, &new_public, &old_request, &new_showing).unwrap();
    let mut fresh_samples = Vec::new();
    for sample in 0..fresh_setups {
        let seed = 0x4652_4553_4800 + sample as u64;
        let mut fresh_rng = StdRng::seed_from_u64(seed);
        let start = Instant::now();
        let fresh_issuer = Issuer::generate(&mut fresh_rng);
        let fresh_setup_ns = start.elapsed().as_nanos();
        let fresh_prover = fresh_issuer.prover_params();
        let fresh_verifier = fresh_issuer.verifier_params();
        let start = Instant::now();
        let credential = fresh_issuer
            .issue(&mut fresh_rng, public.clone(), input.not_before, upper)
            .unwrap();
        let fresh_issuance_ns = start.elapsed().as_nanos();
        let request = RequestContext {
            current_header_digest: [9; 32],
            params_digest: fresh_issuer.params_digest().unwrap(),
            complete_q: format!("fresh-setup-request-{sample}").into_bytes(),
            verifier_nonce: (sample as u64).to_le_bytes().to_vec(),
            tq: source_a.request.interval_lo,
            te: source_a.request.interval_hi,
        };
        let context_bytes = request.complete_q.len();
        let nonce_bytes = request.verifier_nonce.len();
        let start = Instant::now();
        let showing = present(&mut fresh_rng, &fresh_prover, &credential, &request).unwrap();
        let fresh_show_ns = start.elapsed().as_nanos();
        let start = Instant::now();
        verify(&mut fresh_rng, &fresh_verifier, &public, &request, &showing).unwrap();
        let fresh_verify_ns = start.elapsed().as_nanos();
        fresh_samples.push(json!({"sample":sample,"rng":"StdRng_seed_from_u64","seed_u64":seed,"setup_including_signature_and_bound_crs_ns":fresh_setup_ns,"issuance_ns":fresh_issuance_ns,"show_ns":fresh_show_ns,"verify_ns":fresh_verify_ns,"verify_accepted":true,"complete_q_bytes":context_bytes,"verifier_nonce_bytes":nonce_bytes,"prover_material_bytes":fresh_prover.canonical_bytes().unwrap().len(),"verifier_material_bytes":fresh_verifier.canonical_bytes().unwrap().len(),"showing_bytes":showing.canonical_bytes().unwrap().len()}));
    }
    println!("{}",serde_json::to_string_pretty(&json!({"schema":"plan-a-sr-joint-bbs-component-v3","scope":"two distinct owner/source Joint paths under one exact RA/state/rev snapshot and one terminal/Q -> containment dedup -> real BBS23-CDL issuance/show/verify; excludes terminal signature, Delta service and resource commit","repetitions":reps,"fresh_setup_count":fresh_setups,"fresh_setup_samples":fresh_samples,"compile_two_distinct_sources_ns":compile_ns,"successor_compile_after_source_b_middle_grant_revocation_ns":refresh_compile_ns,"original_grant_relation_digests_unchanged_across_refresh":original_grant_digests==successor_grant_digests,"canonical_signed_grant_sha256_unchanged_across_refresh":original_signed_grant_hashes==successor_signed_grant_hashes,"canonical_signed_grant_sha256_before":original_signed_grant_hashes.map(|source|source.map(hex::encode)),"canonical_signed_grant_sha256_after":successor_signed_grant_hashes.map(|source|source.map(hex::encode)),"exact_duplicates":compiled.exact_duplicates,"credentials_after_dedup":compiled.issuance.credentials.len(),"dependencies_before_revocation":compiled.dependencies.values().next().unwrap().len(),"valid_paths_after_source_b_revocation":successor.valid_paths,"invalid_paths_after_source_b_revocation":successor.invalid_paths,"dependencies_after_source_b_revocation":successor.dependencies.values().next().unwrap().len(),"independent_source_revocation_retains_credential":successor.issuance.credentials.len()==1,"last_support_removal_credentials":removed.issuance.credentials.len(),"offline_new_terminal_old_compiled_credential_rejected":true,"new_delegation_compile_ns":new_delegation_compile_ns,"new_delegation_issuance_ns":new_delegation_issuance_ns,"setup_ns":setup_ns,"issuance_median_ns":median(issue),"show_median_ns":median(show),"verify_median_ns":median(check),"showing_bytes":sizes[0],"global_reissue_policy":"candidate, not unavoidable"})).unwrap());
}
