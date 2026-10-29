//! Prepare a source-neutral full-F issuance lifecycle for the native anonymous
//! credential backend.  This binary stops at the serialized crypto boundary:
//! the BBS prover/verifier consumes this manifest and returns proof bytes, after
//! which the existing Agent key signs `terminal_binding_digest`.

use ark_bls12_381::Fr;
use ark_ff::{One, PrimeField};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_admission::{AdmissionAuthority, BusinessEntitlement, InMemoryEntitlementLedger},
    hrada_auth::AuthFixture,
    hrada_sr_f_compiler::{
        compile_portfolio, encode_complete_q, CredentialIssuanceBatch, TrustedSnapshotRegistry,
    },
};
use serde::Serialize;
use std::{env, fs, path::PathBuf, time::Instant};

type Hash = [u8; 32];

#[derive(Serialize)]
struct RequestContext {
    complete_q_encoding: &'static str,
    complete_q_hex: String,
    current_header_digest_hex: String,
    native_params_digest_hex: Option<String>,
    native_params_digest_requirement: &'static str,
    verifier_nonce: u64,
    tq: u64,
    te: u64,
}

#[derive(Serialize)]
struct LifecycleStage {
    name: &'static str,
    issuance: CredentialIssuanceBatch,
    stats: cpsnarks_set::protocols::hrada_sr_f_compiler::CompileStats,
    private_dependency_entries: usize,
    public_compiler_digest_hex: String,
    private_ledger_digest_hex: String,
    state_update_ns: u128,
    compile_total_ns: u128,
    issuance_serialization_ns: u128,
    request: RequestContext,
}

#[derive(Serialize)]
struct LifecycleManifest {
    format: &'static str,
    scope: &'static str,
    terminal_public_key_hex: String,
    terminal_binding_domain: &'static str,
    benchmark_setup_id: Option<String>,
    benchmark_seed: u64,
    benchmark_pair_id: Option<String>,
    benchmark_side: Option<String>,
    shared_grant_preparation_ns: u128,
    original_grant_portfolio_digest_hex: String,
    stages: Vec<LifecycleStage>,
    gates: LifecycleGates,
}

#[derive(Serialize)]
struct LifecycleGates {
    original_grants_unchanged_across_epoch: bool,
    original_grants_unchanged_after_last_support_removal: bool,
    issuer_signing_keys_offline_during_refresh: bool,
    old_snapshot_rejected_by_successor_registry: bool,
    independent_support_survives_revocation: bool,
    last_support_removal_has_no_eligible_credential: bool,
    issuance_contains_source_identifiers: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn canonical_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = Vec::new();
    value.serialize(&mut bytes).expect("vec serialization");
    hex(&bytes)
}

fn digest(domain: &[u8], payload: &[u8]) -> Hash {
    let mut hasher = Blake2s::new();
    hasher.update(domain);
    hasher.update(payload);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn digest_limbs(value: &Hash) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&value[..16]),
        Fr::from_le_bytes_mod_order(&value[16..]),
    ]
}

fn set_request(
    fixture: &mut AuthFixture,
    header: Hash,
    epoch: u64,
    nonce: u64,
    tq: u64,
    te: u64,
) -> Vec<Fr> {
    let header_limbs = digest_limbs(&header);
    // The application context is the same externally expected export job used
    // by the PC control. The request nonce remains independently bound in Q[10].
    let context = digest(
        b"HRADA-SYNTHETIC-EXPORT-JOB-V1",
        b"project-document-export-001",
    );
    let context_limbs = digest_limbs(&context);
    let terminal = fixture.keys[5].0;
    let q = vec![
        header_limbs[0],
        header_limbs[1],
        Fr::from(epoch),
        Fr::from(1u64),
        Fr::from(1u64),
        Fr::from(17u64),
        Fr::from(18u64),
        Fr::from(42u64),
        Fr::from(1u64),
        Fr::from(tq),
        Fr::from(nonce),
        Fr::from(te),
        context_limbs[0],
        context_limbs[1],
        terminal.x,
        terminal.y,
    ];
    fixture.base.request.fields.copy_from_slice(&q);
    q
}

fn entitlement(fixture: &AuthFixture) -> BusinessEntitlement {
    BusinessEntitlement {
        user_commitment: fixture.base.user_commitment(),
        system: 1,
        resource: 42,
        action_mask: 3,
        not_before: 0,
        not_after: 2_000,
        active: true,
        max_delegation_depth: 2,
    }
}

fn stage(
    name: &'static str,
    registry: &TrustedSnapshotRegistry,
    authority: &AdmissionAuthority,
    ledger: &InMemoryEntitlementLedger,
    q: &[Fr],
    header: Hash,
    nonce: u64,
    tq: u64,
    te: u64,
    target_terminal: &[u8],
    state_update_ns: u128,
) -> Result<(LifecycleStage, usize), String> {
    let compile_start = Instant::now();
    let compiled =
        compile_portfolio(authority, ledger, registry, tq)?.select_terminal(target_terminal);
    let compile_total_ns = compile_start.elapsed().as_nanos();
    let credential_count = compiled.credentials.len();
    let serialization_start = Instant::now();
    let public_compiler_digest = digest(
        b"HRADA-SR-F-PUBLIC-COMPILER-V1",
        &serde_json::to_vec(&compiled.issuance_batch()).map_err(|error| error.to_string())?,
    );
    let private_ledger_wire = compiled
        .dependencies
        .iter()
        .map(|(authority, supports)| (hex(authority), supports))
        .collect::<Vec<_>>();
    let private_ledger_digest = digest(
        b"HRADA-SR-F-PRIVATE-LEDGER-V1",
        &serde_json::to_vec(&private_ledger_wire).map_err(|error| error.to_string())?,
    );
    let issuance_serialization_ns = serialization_start.elapsed().as_nanos();
    Ok((
        LifecycleStage {
            name,
            issuance: compiled.issuance_batch(),
            stats: compiled.stats,
            private_dependency_entries: compiled.dependencies.len(),
            public_compiler_digest_hex: hex(&public_compiler_digest),
            private_ledger_digest_hex: hex(&private_ledger_digest),
            state_update_ns,
            compile_total_ns,
            issuance_serialization_ns,
            request: RequestContext {
                complete_q_encoding: "HRADA-Q16-V1/canonical-field-length-prefix",
                complete_q_hex: hex(&encode_complete_q(q)?),
                current_header_digest_hex: hex(&header),
                native_params_digest_hex: None,
                native_params_digest_requirement:
                    "native backend must bind issuer key, proof parameters, schema and version",
                verifier_nonce: nonce,
                tq,
                te,
            },
        },
        credential_count,
    ))
}

fn run(output: PathBuf) -> Result<(), String> {
    let benchmark_seed = env::var("BENCHMARK_SEED")
        .ok()
        .map(|value| value.parse::<u64>().map_err(|_| "invalid_benchmark_seed"))
        .transpose()?
        .unwrap_or(0);
    let first_seed = 2026102301u64
        .checked_add(benchmark_seed)
        .ok_or("benchmark_seed_overflow")?;
    let grant_prep_start = Instant::now();
    let mut first = AuthFixture::new(first_seed);
    let mut second = first.second_user(first_seed.checked_add(1).ok_or("benchmark_seed_overflow")?);
    let shared_grant_preparation_ns = grant_prep_start.elapsed().as_nanos();
    let terminal_public_key_hex = canonical_hex(&first.keys[5].0);
    let mut target_terminal = Vec::new();
    first.keys[5]
        .0
        .serialize(&mut target_terminal)
        .expect("vec serialization");
    let authority = AdmissionAuthority::new(
        first.base.params.clone(),
        first.base.ra_pk,
        first.base.sr_pk,
        1,
        1,
    );
    let ledger = InMemoryEntitlementLedger {
        records: vec![entitlement(&first), entitlement(&second)],
    };
    let mut original_grant_ids = Vec::new();
    for fixture in [&first, &second] {
        for grant in &fixture.all_grants {
            original_grant_ids.extend_from_slice(&grant.id());
        }
    }
    let original_grant_portfolio_digest_hex = hex(&digest(
        b"HRADA-F-ORIGINAL-GRANT-PORTFOLIO-V1",
        &original_grant_ids,
    ));
    let header1 = digest(b"HRADA-SR-F-HEADER-V1", &1u64.to_le_bytes());
    let q1 = set_request(&mut first, header1, 1, 1001, 500, 550);
    set_request(&mut second, header1, 1, 1001, 500, 550);
    let old_first = first.base.clone();
    let original_grants = first.all_grants.iter().map(|g| g.id()).collect::<Vec<_>>();
    let original_second_grants = second
        .all_grants
        .iter()
        .map(|grant| grant.id())
        .collect::<Vec<_>>();
    let registry1 = TrustedSnapshotRegistry::install_under(
        1,
        digest_limbs(&header1),
        &[
            (&first.base, first.all_grants.as_slice()),
            (&second.base, second.all_grants.as_slice()),
        ],
    )?;
    let (initial, initial_count) = stage(
        "initial",
        &registry1,
        &authority,
        &ledger,
        &q1,
        header1,
        1001,
        500,
        550,
        &target_terminal,
        0,
    )?;

    first.close_issuers();
    second.close_issuers();

    // Revoke the middle grant of one source. Original grant records remain in
    // its archive; the independent source and independent local path survive.
    let update_start = Instant::now();
    first.revoke_middle(first.base.prime + Fr::one());
    let header2 = digest(b"HRADA-SR-F-HEADER-V1", &2u64.to_le_bytes());
    let q2 = set_request(&mut first, header2, 2, 2001, 501, 551);
    set_request(&mut second, header2, 2, 2001, 501, 551);
    // Q is not part of the signed per-user state. Refreshing the second state is
    // unnecessary; the registry pins its exact unchanged signed identity.
    let registry2 = TrustedSnapshotRegistry::install_under(
        2,
        digest_limbs(&header2),
        &[
            (&first.base, first.all_grants.as_slice()),
            (&second.base, second.all_grants.as_slice()),
        ],
    )?;
    let middle_update_ns = update_start.elapsed().as_nanos();
    let (successor, successor_count) = stage(
        "after_middle_revocation",
        &registry2,
        &authority,
        &ledger,
        &q2,
        header2,
        2001,
        501,
        551,
        &target_terminal,
        middle_update_ns,
    )?;

    // Remove all remaining leaves for the selected terminal in both sources.
    // Grant archives and issuer signatures remain byte-identical.
    let last_support_update_start = Instant::now();
    for fixture in [&mut first, &mut second] {
        for index in [2usize, 6, 7] {
            fixture.all_grants[index].active = false;
        }
        fixture.base.state_version += 1;
        fixture.base.transition = [3u8; 32];
        fixture.refresh_state(fixture.base.prime + Fr::one());
    }
    let header3 = digest(b"HRADA-SR-F-HEADER-V1", &3u64.to_le_bytes());
    let q3 = set_request(&mut first, header3, 3, 3001, 502, 552);
    set_request(&mut second, header3, 3, 3001, 502, 552);
    let registry3 = TrustedSnapshotRegistry::install_under(
        3,
        digest_limbs(&header3),
        &[
            (&first.base, first.all_grants.as_slice()),
            (&second.base, second.all_grants.as_slice()),
        ],
    )?;
    let last_support_update_ns = last_support_update_start.elapsed().as_nanos();
    let (no_support, no_support_count) = stage(
        "after_last_support_removal",
        &registry3,
        &authority,
        &ledger,
        &q3,
        header3,
        3001,
        502,
        552,
        &target_terminal,
        last_support_update_ns,
    )?;

    let serialized_issuance =
        serde_json::to_vec(&[&initial.issuance, &successor.issuance, &no_support.issuance])
            .map_err(|error| error.to_string())?;
    let manifest = LifecycleManifest {
        format: "HRADA-SR-F-LIFECYCLE-MANIFEST-V1",
        scope: "local synthetic honest-SR native validation and source-neutral issuance export",
        terminal_public_key_hex,
        terminal_binding_domain: "HRADA-SR-F-TERMINAL-V1",
        benchmark_setup_id: env::var("BENCHMARK_SETUP_ID").ok(),
        benchmark_seed,
        benchmark_pair_id: env::var("BENCHMARK_PAIR_ID").ok(),
        benchmark_side: env::var("BENCHMARK_SIDE").ok(),
        shared_grant_preparation_ns,
        original_grant_portfolio_digest_hex,
        stages: vec![initial, successor, no_support],
        gates: LifecycleGates {
            original_grants_unchanged_across_epoch: original_grants
                == first.all_grants.iter().map(|g| g.id()).collect::<Vec<_>>(),
            original_grants_unchanged_after_last_support_removal: original_second_grants
                == second
                    .all_grants
                    .iter()
                    .map(|grant| grant.id())
                    .collect::<Vec<_>>(),
            issuer_signing_keys_offline_during_refresh: first.issuers_closed
                && second.issuers_closed,
            old_snapshot_rejected_by_successor_registry: !registry2.snapshot_is_current(&old_first),
            independent_support_survives_revocation: initial_count > 0 && successor_count > 0,
            last_support_removal_has_no_eligible_credential: no_support_count == 0,
            issuance_contains_source_identifiers: [
                b"path_id".as_slice(),
                b"grant_ids",
                b"dependencies",
            ]
            .iter()
            .any(|needle| {
                serialized_issuance
                    .windows(needle.len())
                    .any(|w| w == *needle)
            }),
        },
    };
    if !manifest.gates.original_grants_unchanged_across_epoch
        || !manifest
            .gates
            .original_grants_unchanged_after_last_support_removal
        || !manifest.gates.issuer_signing_keys_offline_during_refresh
        || !manifest.gates.old_snapshot_rejected_by_successor_registry
        || !manifest.gates.independent_support_survives_revocation
        || !manifest
            .gates
            .last_support_removal_has_no_eligible_credential
        || manifest.gates.issuance_contains_source_identifiers
    {
        return Err("lifecycle_gate_failed".into());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(
        &output,
        serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    println!("{}", output.display());
    Ok(())
}

fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("sr_full_f_lifecycle.json"));
    if let Err(error) = run(output) {
        eprintln!("hrada_sr_f_lifecycle: {}", error);
        std::process::exit(1);
    }
}
