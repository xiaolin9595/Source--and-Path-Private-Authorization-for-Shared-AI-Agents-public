use ark_std::rand::{rngs::StdRng, SeedableRng};
use hrada_sr_full_f_bbs::{present, q16_with_nonce, verify, CredentialIssuanceBatch, Issuer, RequestContext};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf, time::Instant};

#[derive(Deserialize)]
struct Manifest { format: String, terminal_public_key_hex: String, stages: Vec<Stage>, gates: Gates }
#[derive(Deserialize)]
struct Gates {
    original_grants_unchanged_across_epoch: bool,
    original_grants_unchanged_after_last_support_removal: bool,
    issuer_signing_keys_offline_during_refresh: bool,
    old_snapshot_rejected_by_successor_registry: bool,
    independent_support_survives_revocation: bool,
    last_support_removal_has_no_eligible_credential: bool,
    issuance_contains_source_identifiers: bool,
}
#[derive(Deserialize)]
struct Stage { name: String, issuance: CredentialIssuanceBatch, request: Request }
#[derive(Deserialize)]
struct Request { complete_q_hex: String, current_header_digest_hex: String, verifier_nonce: u64 }

#[derive(Serialize, Deserialize)]
struct Output {
    format: String,
    backend: String,
    proof_variant: String,
    setup_seed: u64,
    repetitions: usize,
    params_digest_hex: String,
    verifier_material_hex: String,
    prover_material_hex: String,
    setup_ns: u128,
    stages: Vec<StageOutput>,
    accepted: bool,
}
#[derive(Serialize, Deserialize)]
struct StageOutput {
    name: String, issued: usize, matching_credentials: usize, expected_available: bool,
    issue_ns: u128, receipt_verify_ns: u128, show_ns: u128, verify_ns: u128,
    credential_bytes: usize, proof_bytes: usize, showing_bytes: usize,
    anonymous_proof_hex: Option<String>, accepted: bool,
    credential_hex: Vec<String>,
    warmup: Option<Observation>,
    observations: Vec<Observation>,
}
#[derive(Serialize, Deserialize)]
struct Observation { rep: usize, nonce: u64, complete_q_hex: String, show_ns: u128, verify_ns: u128, proof_bytes: usize, showing_bytes: usize, anonymous_proof_hex: String, showing_hex: String, accepted: bool }

#[derive(Serialize)]
struct VerifyOutput { format: &'static str, stage: String, rep: usize, nonce: u64, params_digest_hex: String, complete_q_hex: String, proof_bytes: usize, verify_ns: u128, accepted: bool }

#[derive(Serialize, Deserialize)]
struct VerifyPackage {
    format: String, stage: String, rep: usize, nonce: u64,
    complete_q_hex: String, current_header_digest_hex: String, terminal_public_key_hex: String,
    params_digest_hex: String, verifier_material_hex: String, showing_hex: String, anonymous_proof_hex: String,
}

fn fixed32(hex_text: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(hex_text).map_err(|e| format!("{what}: {e}"))?;
    bytes.try_into().map_err(|_| format!("{what}: expected 32 bytes"))
}

fn arg_value(args: &[String], flag: &str) -> Result<String, String> {
    let i = args.iter().position(|a| a == flag).ok_or_else(|| format!("missing {flag}"))?;
    args.get(i + 1).cloned().ok_or_else(|| format!("missing value for {flag}"))
}

fn run(args: &[String]) -> Result<(), String> {
    if !args.iter().any(|a| a == "--require-gates") { return Err("--require-gates is mandatory".into()); }
    let manifest_path = PathBuf::from(arg_value(&args, "--manifest")?);
    let output_path = PathBuf::from(arg_value(&args, "--output")?);
    let repetitions: usize = arg_value(&args, "--repetitions")?.parse().map_err(|_| "invalid repetitions")?;
    if repetitions == 0 { return Err("repetitions must be positive".into()); }
    let manifest: Manifest = serde_json::from_slice(&fs::read(manifest_path).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if manifest.format != "HRADA-SR-F-LIFECYCLE-MANIFEST-V1" { return Err("manifest format mismatch".into()); }
    let gates = &manifest.gates;
    if !(gates.original_grants_unchanged_across_epoch
        && gates.original_grants_unchanged_after_last_support_removal
        && gates.issuer_signing_keys_offline_during_refresh
        && gates.old_snapshot_rejected_by_successor_registry
        && gates.independent_support_survives_revocation
        && gates.last_support_removal_has_no_eligible_credential
        && !gates.issuance_contains_source_identifiers) { return Err("lifecycle acceptance gates failed".into()); }
    let terminal = hex::decode(&manifest.terminal_public_key_hex).map_err(|e| e.to_string())?;
    let seed = env::var("BENCHMARK_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(20261023);
    let mut rng = StdRng::seed_from_u64(seed);
    let setup_start = Instant::now();
    let issuer = Issuer::generate(&mut rng);
    let prover = issuer.prover_params();
    let verifier = issuer.verifier_params();
    let params_digest = verifier.params_digest().map_err(|e| e.to_string())?;
    let setup_ns = setup_start.elapsed().as_nanos();
    let mut stages = Vec::new();
    let mut all_accepted = true;
    if manifest.stages.len() != 3 || manifest.stages.iter().map(|s| s.issuance.credentials.len()).collect::<Vec<_>>() != [2, 2, 0] {
        return Err("fixture oracle mismatch: expected issuance k=2,2,0".into());
    }
    for stage in manifest.stages {
        stage.issuance.validate().map_err(|e| format!("{}: {e}", stage.name))?;
        let q = hex::decode(&stage.request.complete_q_hex).map_err(|e| e.to_string())?;
        let header = fixed32(&stage.request.current_header_digest_hex, "header")?;
        let (base_request, expected_public) = RequestContext::from_q16(q.clone(), header, params_digest, &terminal, stage.request.verifier_nonce).map_err(|e| format!("{}: {e}", stage.name))?;
        let issue_start = Instant::now();
        let mut credentials = Vec::new();
        for input in &stage.issuance.credentials {
            let public = input.public_fields().map_err(|e| e.to_string())?;
            credentials.push(issuer.issue(&mut rng, public, input.not_before, input.upper()).map_err(|e| e.to_string())?);
        }
        let issue_ns = issue_start.elapsed().as_nanos();
        let receipt_start = Instant::now();
        for credential in &credentials { verifier.verify_credential(credential).map_err(|e| e.to_string())?; }
        let receipt_verify_ns = receipt_start.elapsed().as_nanos();
        let candidates: Vec<_> = credentials.iter().filter(|c| c.public == expected_public && c.lower <= base_request.tq && c.upper >= base_request.te).collect();
        let expected_available = !candidates.is_empty();
        let mut show_ns = 0; let mut verify_ns = 0; let mut proof_bytes = Vec::new(); let mut showing_bytes = 0; let mut observations = Vec::new(); let mut warmup = None;
        if let Some(credential) = candidates.first() {
            let warmup_nonce = stage.request.verifier_nonce.checked_add(repetitions as u64).ok_or("warmup nonce overflow")?;
            let warmup_q = q16_with_nonce(&q, warmup_nonce).map_err(|e| e.to_string())?;
            let (warmup_request, warmup_public) = RequestContext::from_q16(warmup_q.clone(), header, params_digest, &terminal, warmup_nonce).map_err(|e| e.to_string())?;
            let showing = present(&mut rng, &prover, credential, &warmup_request).map_err(|e| e.to_string())?;
            let warmup_proof = verify(&mut rng, &verifier, &warmup_public, &warmup_request, &showing).map_err(|e| e.to_string())?;
            let warmup_showing = showing.canonical_bytes().map_err(|e| e.to_string())?;
            warmup = Some(Observation { rep: usize::MAX, nonce: warmup_nonce, complete_q_hex: hex::encode(warmup_q), show_ns: 0, verify_ns: 0, proof_bytes: warmup_proof.len(), showing_bytes: warmup_showing.len(), anonymous_proof_hex: hex::encode(warmup_proof), showing_hex: hex::encode(warmup_showing), accepted: true });
            for rep in 0..repetitions {
                let nonce = stage.request.verifier_nonce.checked_add(rep as u64).ok_or("measurement nonce overflow")?;
                let rep_q = q16_with_nonce(&q, nonce).map_err(|e| e.to_string())?;
                let (request, rep_public) = RequestContext::from_q16(rep_q.clone(), header, params_digest, &terminal, nonce).map_err(|e| e.to_string())?;
                let start = Instant::now();
                let showing = present(&mut rng, &prover, credential, &request).map_err(|e| e.to_string())?;
                let one_show_ns = start.elapsed().as_nanos(); show_ns += one_show_ns;
                let start = Instant::now();
                proof_bytes = verify(&mut rng, &verifier, &rep_public, &request, &showing).map_err(|e| e.to_string())?;
                let one_verify_ns = start.elapsed().as_nanos(); verify_ns += one_verify_ns;
                let showing_encoded = showing.canonical_bytes().map_err(|e| e.to_string())?; showing_bytes = showing_encoded.len();
                observations.push(Observation { rep, nonce, complete_q_hex: hex::encode(rep_q), show_ns: one_show_ns, verify_ns: one_verify_ns, proof_bytes: proof_bytes.len(), showing_bytes, anonymous_proof_hex: hex::encode(&proof_bytes), showing_hex: hex::encode(showing_encoded), accepted: true });
            }
        }
        let accepted = if expected_available { !proof_bytes.is_empty() } else { proof_bytes.is_empty() };
        all_accepted &= accepted;
        let credential_bytes = credentials.iter().map(|c| c.canonical_bytes().map(|b| b.len()).unwrap_or(0)).sum();
        let credential_hex = credentials.iter().map(|c| c.canonical_bytes().map(hex::encode).unwrap_or_default()).collect();
        stages.push(StageOutput { name: stage.name, issued: credentials.len(), matching_credentials: candidates.len(), expected_available, issue_ns, receipt_verify_ns, show_ns, verify_ns, credential_bytes, proof_bytes: proof_bytes.len(), showing_bytes, anonymous_proof_hex: (!proof_bytes.is_empty()).then(|| hex::encode(&proof_bytes)), accepted, credential_hex, warmup, observations });
    }
    let output = Output { format: "HRADA-SR-F-BBS-RUN-V1".into(), backend: "docknetwork-crypto@224f195bb8babc2d0de5256135120e0aca9fbd19".into(), proof_variant: "BBS23-CDL+LegoGroth16".into(), setup_seed: seed, repetitions, params_digest_hex: hex::encode(params_digest), verifier_material_hex: hex::encode(verifier.canonical_bytes().map_err(|e| e.to_string())?), prover_material_hex: hex::encode(prover.canonical_bytes().map_err(|e| e.to_string())?), setup_ns, stages, accepted: all_accepted };
    fs::write(output_path, serde_json::to_vec_pretty(&output).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    if !all_accepted { return Err("acceptance gate failed".into()); }
    Ok(())
}

fn verify_retained(args: &[String]) -> Result<(), String> {
    let manifest_path=PathBuf::from(arg_value(args,"--manifest")?); let native_path=PathBuf::from(arg_value(args,"--native-output")?); let output_path=PathBuf::from(arg_value(args,"--output")?);
    let stage_name=arg_value(args,"--stage")?; let rep:usize=arg_value(args,"--rep")?.parse().map_err(|_|"invalid rep")?;
    let manifest:Manifest=serde_json::from_slice(&fs::read(manifest_path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let native:Output=serde_json::from_slice(&fs::read(native_path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let manifest_stage=manifest.stages.iter().find(|s|s.name==stage_name).ok_or("stage absent from manifest")?;
    let native_stage=native.stages.iter().find(|s|s.name==stage_name).ok_or("stage absent from native output")?;
    let observation=native_stage.observations.iter().find(|o|o.rep==rep).ok_or("rep absent")?;
    let base_q=hex::decode(&manifest_stage.request.complete_q_hex).map_err(|e|e.to_string())?;
    let expected_nonce=manifest_stage.request.verifier_nonce.checked_add(rep as u64).ok_or("nonce overflow")?;
    let expected_q=q16_with_nonce(&base_q,expected_nonce).map_err(|e|e.to_string())?;
    if observation.nonce!=expected_nonce || observation.complete_q_hex!=hex::encode(&expected_q) { return Err("observation Q/nonce mismatch".into()); }
    let terminal=hex::decode(&manifest.terminal_public_key_hex).map_err(|e|e.to_string())?; let header=fixed32(&manifest_stage.request.current_header_digest_hex,"header")?;
    let verifier=hrada_sr_full_f_bbs::VerifierParams::from_canonical_bytes(&hex::decode(&native.verifier_material_hex).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let params_digest=verifier.params_digest().map_err(|e|e.to_string())?; if native.params_digest_hex!=hex::encode(params_digest) { return Err("params digest mismatch".into()); }
    let (request,public)=RequestContext::from_q16(expected_q.clone(),header,params_digest,&terminal,expected_nonce).map_err(|e|e.to_string())?;
    let showing=hrada_sr_full_f_bbs::Showing::from_canonical_bytes(&hex::decode(&observation.showing_hex).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let mut rng=StdRng::seed_from_u64(native.setup_seed ^ (expected_nonce.rotate_left(17)));
    let start=Instant::now(); let proof=verify(&mut rng,&verifier,&public,&request,&showing).map_err(|e|e.to_string())?; let verify_ns=start.elapsed().as_nanos();
    if hex::encode(&proof)!=observation.anonymous_proof_hex { return Err("retained proof mismatch".into()); }
    let result=VerifyOutput { format:"HRADA-SR-F-BBS-VERIFY-V1",stage:stage_name,rep,nonce:expected_nonce,params_digest_hex:hex::encode(params_digest),complete_q_hex:hex::encode(expected_q),proof_bytes:proof.len(),verify_ns,accepted:true };
    fs::write(output_path,serde_json::to_vec_pretty(&result).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?; Ok(())
}

fn verify_package(args:&[String])->Result<(),String>{
    let input=PathBuf::from(arg_value(args,"--input")?); let output=PathBuf::from(arg_value(args,"--output")?);
    let package:VerifyPackage=serde_json::from_slice(&fs::read(input).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    if package.format!="HRADA-SR-F-BBS-VERIFY-PACKAGE-V1" { return Err("verify package format".into()); }
    let verifier=hrada_sr_full_f_bbs::VerifierParams::from_canonical_bytes(&hex::decode(&package.verifier_material_hex).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let params=verifier.params_digest().map_err(|e|e.to_string())?; if package.params_digest_hex!=hex::encode(params){return Err("params digest mismatch".into());}
    let q=hex::decode(&package.complete_q_hex).map_err(|e|e.to_string())?; let header=fixed32(&package.current_header_digest_hex,"header")?; let terminal=hex::decode(&package.terminal_public_key_hex).map_err(|e|e.to_string())?;
    let(request,public)=RequestContext::from_q16(q.clone(),header,params,&terminal,package.nonce).map_err(|e|e.to_string())?;
    let showing=hrada_sr_full_f_bbs::Showing::from_canonical_bytes(&hex::decode(&package.showing_hex).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
    let mut rng=StdRng::seed_from_u64(package.nonce.rotate_left(17)); let start=Instant::now(); let proof=verify(&mut rng,&verifier,&public,&request,&showing).map_err(|e|e.to_string())?; let verify_ns=start.elapsed().as_nanos();
    if hex::encode(&proof)!=package.anonymous_proof_hex{return Err("proof mismatch".into());}
    let result=VerifyOutput{format:"HRADA-SR-F-BBS-VERIFY-V1",stage:package.stage,rep:package.rep,nonce:package.nonce,params_digest_hex:hex::encode(params),complete_q_hex:hex::encode(q),proof_bytes:proof.len(),verify_ns,accepted:true};
    fs::write(output,serde_json::to_vec_pretty(&result).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?; Ok(())
}

fn main() {
    let args:Vec<String>=env::args().collect();
    let result=match args.get(1).map(String::as_str) { Some("run")=>run(&args), Some("verify-retained")=>verify_retained(&args), Some("verify-package")=>verify_package(&args), _=>Err("usage: sr_full_f_bbs <run|verify-package> ...".into()) };
    if let Err(error)=result { eprintln!("{error}"); std::process::exit(1); }
}
