//! Native anonymous-credential adverse cell for the authenticated overlap
//! portfolio.  This intentionally stops at BBS23/Lego show and verify; it does
//! not claim Agent control, nonce commit, permit creation, or resource ACK.

use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake2::{Blake2s256, Digest};
use hrada_sr_full_f_bbs::{
    present, q16_with_nonce, verify, CredentialIssuanceBatch, Issuer, RequestContext,
};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf, time::Instant};

const CELL_ID: &str = "overlap_fragmentation";
const FORMAT: &str = "HRADA-SR-F-BBS-ADVERSE-V1";

#[derive(Deserialize)]
struct ScalingOutput {
    format: String,
    benchmark_seed: u64,
    cells: Vec<ScalingCell>,
    accepted: bool,
}

#[derive(Deserialize)]
struct ScalingCell {
    cell_id: String,
    target_terminal_k: usize,
    intervals: Vec<(u64, u64)>,
    issuance: CredentialIssuanceBatch,
    request: Option<PublicRequest>,
}

#[derive(Deserialize)]
struct PublicRequest {
    complete_q_hex: String,
    current_header_digest_hex: String,
    terminal_public_key_hex: String,
    context_digest_hex: String,
    verifier_nonce: u64,
    tq: u64,
    te: u64,
}

#[derive(Serialize)]
struct Output {
    format: &'static str,
    scope: &'static str,
    input_format: &'static str,
    input_blake2s_hex: String,
    scaling_benchmark_seed: u64,
    setup_seed: u64,
    cell_id: &'static str,
    compiled_k: usize,
    issued: usize,
    receipt_verified: usize,
    matching_credentials: usize,
    selected_credential_index: usize,
    repetitions: usize,
    setup_ns: u128,
    issue_total_ns: u128,
    issue_observations: Vec<OperationObservation>,
    receipt_total_ns: u128,
    receipt_observations: Vec<OperationObservation>,
    credential_bytes: usize,
    credential_hex: Vec<String>,
    params_digest_hex: String,
    prover_material_hex: String,
    verifier_material_hex: String,
    public_request: PublicRequestOutput,
    warmup: ShowingObservation,
    observations: Vec<ShowingObservation>,
    accepted: bool,
}

#[derive(Serialize)]
struct OperationObservation {
    index: usize,
    elapsed_ns: u128,
    accepted: bool,
}

#[derive(Serialize)]
struct PublicRequestOutput {
    complete_q_hex: String,
    current_header_digest_hex: String,
    terminal_public_key_hex: String,
    context_digest_hex: String,
    verifier_nonce: u64,
    tq: u64,
    te: u64,
}

#[derive(Serialize)]
struct ShowingObservation {
    kind: &'static str,
    rep: usize,
    credential_index: usize,
    nonce: u64,
    complete_q_hex: String,
    show_ns: u128,
    verify_ns: u128,
    proof_bytes: usize,
    showing_bytes: usize,
    anonymous_proof_hex: String,
    showing_hex: String,
    accepted: bool,
}

fn arg_value(args: &[String], flag: &str) -> Result<String, String> {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| format!("missing {flag}"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn fixed32(text: &str, label: &str) -> Result<[u8; 32], String> {
    hex::decode(text)
        .map_err(|error| format!("{label}: {error}"))?
        .try_into()
        .map_err(|_| format!("{label}: expected 32 bytes"))
}

fn observe_showing(
    kind: &'static str,
    rep: usize,
    credential_index: usize,
    nonce: u64,
    base_q: &[u8],
    header: [u8; 32],
    params_digest: [u8; 32],
    terminal: &[u8],
    issuer_prover: &hrada_sr_full_f_bbs::ProverParams,
    issuer_verifier: &hrada_sr_full_f_bbs::VerifierParams,
    credential: &hrada_sr_full_f_bbs::AtomicCredential,
    rng: &mut StdRng,
) -> Result<ShowingObservation, String> {
    let complete_q = q16_with_nonce(base_q, nonce).map_err(|error| error.to_string())?;
    let (request, expected_public) = RequestContext::from_q16(
        complete_q.clone(),
        header,
        params_digest,
        terminal,
        nonce,
    )
    .map_err(|error| error.to_string())?;
    if credential.public != expected_public
        || credential.lower > request.tq
        || credential.upper < request.te
    {
        return Err("selected credential does not cover the public request".into());
    }
    let show_start = Instant::now();
    let showing = present(rng, issuer_prover, credential, &request)
        .map_err(|error| error.to_string())?;
    let show_ns = show_start.elapsed().as_nanos();
    let verify_start = Instant::now();
    let anonymous_proof = verify(
        rng,
        issuer_verifier,
        &expected_public,
        &request,
        &showing,
    )
    .map_err(|error| error.to_string())?;
    let verify_ns = verify_start.elapsed().as_nanos();
    let showing_bytes = showing.canonical_bytes().map_err(|error| error.to_string())?;
    Ok(ShowingObservation {
        kind,
        rep,
        credential_index,
        nonce,
        complete_q_hex: hex::encode(complete_q),
        show_ns,
        verify_ns,
        proof_bytes: anonymous_proof.len(),
        showing_bytes: showing_bytes.len(),
        anonymous_proof_hex: hex::encode(anonymous_proof),
        showing_hex: hex::encode(showing_bytes),
        accepted: true,
    })
}

fn run(args: &[String]) -> Result<(), String> {
    let scaling_path = PathBuf::from(arg_value(args, "--scaling")?);
    let output_path = PathBuf::from(arg_value(args, "--output")?);
    let repetitions: usize = arg_value(args, "--repetitions")?
        .parse()
        .map_err(|_| "invalid repetitions")?;
    if repetitions != 3 {
        return Err("adverse protocol requires exactly 3 measured repetitions".into());
    }
    let input_bytes = fs::read(&scaling_path).map_err(|error| error.to_string())?;
    let input_digest = Blake2s256::digest(&input_bytes);
    let scaling: ScalingOutput =
        serde_json::from_slice(&input_bytes).map_err(|error| error.to_string())?;
    if scaling.format != "HRADA-SR-F-COMPILE-SCALING-V1" || !scaling.accepted {
        return Err("scaling input is not an accepted compiler output".into());
    }
    let cell = scaling
        .cells
        .into_iter()
        .find(|cell| cell.cell_id == CELL_ID)
        .ok_or("overlap cell missing")?;
    if cell.target_terminal_k != 8
        || cell.intervals.len() != 8
        || cell.issuance.credentials.len() != 8
    {
        return Err("overlap oracle mismatch: expected k=8".into());
    }
    cell.issuance.validate().map_err(|error| error.to_string())?;
    let issuance_intervals = cell
        .issuance
        .credentials
        .iter()
        .map(|input| (input.not_before, input.upper()))
        .collect::<Vec<_>>();
    if issuance_intervals != cell.intervals {
        return Err("overlap interval list does not match issuance".into());
    }
    for left in 0..cell.intervals.len() {
        for right in left + 1..cell.intervals.len() {
            let a = cell.intervals[left];
            let b = cell.intervals[right];
            let contains = (a.0 <= b.0 && a.1 >= b.1) || (b.0 <= a.0 && b.1 >= a.1);
            let overlaps = a.0.max(b.0) <= a.1.min(b.1);
            if contains || !overlaps {
                return Err("overlap oracle requires 8 noncontained overlapping intervals".into());
            }
        }
    }
    let public_request = cell.request.ok_or("overlap public request missing")?;
    if public_request.tq > public_request.te {
        return Err("invalid public request interval".into());
    }
    let base_q = hex::decode(&public_request.complete_q_hex).map_err(|e| e.to_string())?;
    let header = fixed32(&public_request.current_header_digest_hex, "header")?;
    let terminal = hex::decode(&public_request.terminal_public_key_hex)
        .map_err(|error| error.to_string())?;

    let setup_seed = env::var("BENCHMARK_SEED")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(scaling.benchmark_seed);
    let mut rng = StdRng::seed_from_u64(setup_seed);
    let setup_start = Instant::now();
    let issuer = Issuer::generate(&mut rng);
    let prover = issuer.prover_params();
    let verifier = issuer.verifier_params();
    let params_digest = verifier.params_digest().map_err(|error| error.to_string())?;
    let setup_ns = setup_start.elapsed().as_nanos();
    let (base_request, expected_public) = RequestContext::from_q16(
        base_q.clone(),
        header,
        params_digest,
        &terminal,
        public_request.verifier_nonce,
    )
    .map_err(|error| error.to_string())?;
    if base_request.tq != public_request.tq || base_request.te != public_request.te {
        return Err("public request metadata mismatch".into());
    }
    for input in &cell.issuance.credentials {
        if input.public_fields().map_err(|error| error.to_string())? != expected_public
            || input.not_before > base_request.tq
            || input.upper() < base_request.te
        {
            return Err("public Q does not match every overlap issuance record".into());
        }
    }

    let issue_total_start = Instant::now();
    let mut credentials = Vec::with_capacity(8);
    let mut issue_observations = Vec::with_capacity(8);
    for (index, input) in cell.issuance.credentials.iter().enumerate() {
        let start = Instant::now();
        let credential = issuer
            .issue(
                &mut rng,
                input.public_fields().map_err(|error| error.to_string())?,
                input.not_before,
                input.upper(),
            )
            .map_err(|error| error.to_string())?;
        issue_observations.push(OperationObservation {
            index,
            elapsed_ns: start.elapsed().as_nanos(),
            accepted: true,
        });
        credentials.push(credential);
    }
    let issue_total_ns = issue_total_start.elapsed().as_nanos();

    let receipt_total_start = Instant::now();
    let mut receipt_observations = Vec::with_capacity(8);
    for (index, credential) in credentials.iter().enumerate() {
        let start = Instant::now();
        verifier
            .verify_credential(credential)
            .map_err(|error| error.to_string())?;
        receipt_observations.push(OperationObservation {
            index,
            elapsed_ns: start.elapsed().as_nanos(),
            accepted: true,
        });
    }
    let receipt_total_ns = receipt_total_start.elapsed().as_nanos();

    let matching = credentials
        .iter()
        .enumerate()
        .filter(|(_, credential)| {
            credential.public == expected_public
                && credential.lower <= base_request.tq
                && credential.upper >= base_request.te
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if matching.len() != 8 {
        return Err("overlap oracle mismatch: all 8 credentials must cover the request".into());
    }
    let selected_credential_index = matching[0];
    let selected = &credentials[selected_credential_index];
    let warmup_nonce = public_request
        .verifier_nonce
        .checked_add(repetitions as u64)
        .ok_or("warmup nonce overflow")?;
    let warmup = observe_showing(
        "warmup",
        usize::MAX,
        selected_credential_index,
        warmup_nonce,
        &base_q,
        header,
        params_digest,
        &terminal,
        &prover,
        &verifier,
        selected,
        &mut rng,
    )?;
    let mut observations = Vec::with_capacity(repetitions);
    for rep in 0..repetitions {
        let nonce = public_request
            .verifier_nonce
            .checked_add(rep as u64)
            .ok_or("measurement nonce overflow")?;
        observations.push(observe_showing(
            "measured",
            rep,
            selected_credential_index,
            nonce,
            &base_q,
            header,
            params_digest,
            &terminal,
            &prover,
            &verifier,
            selected,
            &mut rng,
        )?);
    }

    let credential_hex = credentials
        .iter()
        .map(|credential| {
            credential
                .canonical_bytes()
                .map(hex::encode)
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let credential_bytes = credential_hex.iter().map(|value| value.len() / 2).sum();
    let output = Output {
        format: FORMAT,
        scope: "native anonymous credential issue, receipt, show, and verify only; no Agent or commit/ACK",
        input_format: "HRADA-SR-F-COMPILE-SCALING-V1",
        input_blake2s_hex: hex::encode(input_digest),
        scaling_benchmark_seed: scaling.benchmark_seed,
        setup_seed,
        cell_id: CELL_ID,
        compiled_k: cell.target_terminal_k,
        issued: credentials.len(),
        receipt_verified: receipt_observations.len(),
        matching_credentials: matching.len(),
        selected_credential_index,
        repetitions,
        setup_ns,
        issue_total_ns,
        issue_observations,
        receipt_total_ns,
        receipt_observations,
        credential_bytes,
        credential_hex,
        params_digest_hex: hex::encode(params_digest),
        prover_material_hex: hex::encode(
            prover.canonical_bytes().map_err(|error| error.to_string())?,
        ),
        verifier_material_hex: hex::encode(
            verifier
                .canonical_bytes()
                .map_err(|error| error.to_string())?,
        ),
        public_request: PublicRequestOutput {
            complete_q_hex: public_request.complete_q_hex,
            current_header_digest_hex: public_request.current_header_digest_hex,
            terminal_public_key_hex: public_request.terminal_public_key_hex,
            context_digest_hex: public_request.context_digest_hex,
            verifier_nonce: public_request.verifier_nonce,
            tq: public_request.tq,
            te: public_request.te,
        },
        warmup,
        observations,
        accepted: true,
    };
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(
        output_path,
        serde_json::to_vec_pretty(&output).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("run") => run(&args),
        _ => Err(
            "usage: sr_adverse_bbs run --scaling PATH --output PATH --repetitions 3".into(),
        ),
    };
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
