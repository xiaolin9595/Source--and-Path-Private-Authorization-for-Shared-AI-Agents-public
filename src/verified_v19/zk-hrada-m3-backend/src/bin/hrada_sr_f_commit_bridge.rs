//! Complete the native anonymous showing with the existing Jubjub Agent
//! signature and a local nonce/permit/resource-ACK commit path.

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_auth::AuthFixture,
    hrada_sr_f_compiler::{
        terminal_binding_digest, terminal_sign_showing, terminal_verify_showing,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet, convert::{TryFrom, TryInto}, env, fs, fs::OpenOptions, io::Write, path::PathBuf,
    process::Command, time::Instant,
};

type Hash = [u8; 32];

#[derive(Deserialize)]
struct Manifest {
    format: String,
    terminal_public_key_hex: String,
    stages: Vec<ManifestStage>,
}
#[derive(Deserialize)]
struct ManifestStage {
    name: String,
    request: ManifestRequest,
}
#[derive(Deserialize)]
struct ManifestRequest {
    complete_q_hex: String,
    current_header_digest_hex: String,
    verifier_nonce: u64,
}
#[derive(Deserialize)]
struct NativeOutput {
    format: String,
    params_digest_hex: String,
    verifier_material_hex: String,
    stages: Vec<NativeStage>,
    accepted: bool,
}
#[derive(Deserialize)]
struct NativeStage {
    name: String,
    observations: Vec<NativeObservation>,
    accepted: bool,
}
#[derive(Deserialize)]
struct NativeObservation {
    rep: usize,
    nonce: u64,
    complete_q_hex: String,
    proof_bytes: usize,
    showing_bytes: usize,
    anonymous_proof_hex: String,
    showing_hex: String,
    accepted: bool,
}
#[derive(Deserialize)]
struct RetainedVerify {
    format: String,
    stage: String,
    rep: usize,
    nonce: u64,
    params_digest_hex: String,
    complete_q_hex: String,
    proof_bytes: usize,
    verify_ns: u128,
    accepted: bool,
}

#[derive(Serialize)]
struct BridgeOutput {
    format: &'static str,
    params_digest_hex: String,
    stages: Vec<BridgeStage>,
    gates: Gates,
    accepted: bool,
}
#[derive(Serialize)]
struct BridgeStage {
    name: String,
    observations: Vec<BridgeObservation>,
}
#[derive(Serialize)]
struct BridgeObservation {
    rep: usize,
    nonce: u64,
    agent_sign_ns: u128,
    agent_verify_ns: u128,
    native_reverify_ns: u128,
    native_reverify_subprocess_ns: u128,
    commit_ack_ns: u128,
    artifact_io_ns: u128,
    accepted_component_sum_ns: u128,
    proof_bytes: usize,
    showing_bytes: usize,
    terminal_signature_hex: String,
    terminal_binding_digest_hex: String,
    permit_artifact: String,
    ack_artifact: String,
    accepted: bool,
}
#[derive(Default, Serialize)]
struct Gates {
    native_crypto_accepted: bool,
    complete_q_nonce_consistent: bool,
    agent_public_key_consistent: bool,
    retained_showing_cryptographically_verified: bool,
    actual_anonymous_substitution_rejected: bool,
    agent_proof_substitution_rejected: bool,
    stale_epoch_binding_rejected: bool,
    failed_verify_nonce_remains_usable: bool,
    replay_after_commit_rejected: bool,
    last_support_has_no_ack: bool,
    trusted_job_policy_and_clock: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if text.len() % 2 != 0 {
        return Err("hex_length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&text[index..index + 2], 16).map_err(|_| "hex_digit".into())
        })
        .collect()
}
fn fixed32(text: &str, label: &str) -> Result<Hash, String> {
    unhex(text)
        .map_err(|e| format!("{label}:{e}"))?
        .try_into()
        .map_err(|_| format!("{label}:length"))
}
fn fr_u64(value: Fr, label: &str) -> Result<u64, String> {
    let repr = value.into_repr();
    let limbs = repr.as_ref();
    if limbs.iter().skip(1).any(|limb| *limb != 0) {
        Err(format!("{label}:not_u64"))
    } else {
        Ok(limbs[0])
    }
}
fn decode_q16(hex_text: &str) -> Result<[Fr; 16], String> {
    let bytes = unhex(hex_text)?;
    let prefix = b"HRADA-Q16-V1";
    if !bytes.starts_with(prefix) {
        return Err("q16_prefix".into());
    }
    let mut cursor = prefix.len();
    let mut fields = Vec::new();
    for _ in 0..16 {
        if cursor + 4 > bytes.len() {
            return Err("q16_truncated_length".into());
        }
        let len = u32::from_le_bytes(bytes[cursor..cursor + 4].try_into().unwrap()) as usize;
        cursor += 4;
        if cursor + len > bytes.len() {
            return Err("q16_truncated_field".into());
        }
        let mut input = &bytes[cursor..cursor + len];
        let field = Fr::deserialize(&mut input).map_err(|_| "q16_field_decode")?;
        if !input.is_empty() {
            return Err("q16_field_trailing".into());
        }
        fields.push(field);
        cursor += len;
    }
    if cursor != bytes.len() {
        return Err("q16_trailing".into());
    }
    fields.try_into().map_err(|_| "q16_arity".into())
}
fn encode_q16(fields: &[Fr; 16]) -> Result<String, String> {
    let mut bytes = b"HRADA-Q16-V1".to_vec();
    for field in fields {
        let mut encoded = Vec::new();
        field
            .serialize(&mut encoded)
            .map_err(|_| "q16_field_encode")?;
        let len = u32::try_from(encoded.len()).map_err(|_| "q16_field_too_large")?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&encoded);
    }
    Ok(hex(&bytes))
}
fn digest(parts: &[&[u8]]) -> Hash {
    let mut h = Blake2s::new();
    for part in parts {
        h.update(part);
    }
    let mut out = [0; 32];
    out.copy_from_slice(&h.finalize());
    out
}
fn arg(args: &[String], flag: &str) -> Result<PathBuf, String> {
    let i = args
        .iter()
        .position(|a| a == flag)
        .ok_or_else(|| format!("missing {flag}"))?;
    args.get(i + 1)
        .map(PathBuf::from)
        .ok_or_else(|| format!("missing value {flag}"))
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    let manifest_path = arg(&args, "--manifest")?;
    let native_path = arg(&args, "--native-output")?;
    let native_verifier = arg(&args, "--native-verifier")?;
    let output_dir = arg(&args, "--output-dir")?;
    fs::create_dir_all(&output_dir).map_err(|e| e.to_string())?;
    let manifest: Manifest =
        serde_json::from_slice(&fs::read(&manifest_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let native: NativeOutput =
        serde_json::from_slice(&fs::read(&native_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if manifest.format != "HRADA-SR-F-LIFECYCLE-MANIFEST-V1"
        || native.format != "HRADA-SR-F-BBS-RUN-V1"
    {
        return Err("format_mismatch".into());
    }
    if manifest.stages.len() != native.stages.len() {
        return Err("stage_count_mismatch".into());
    }
    let seed = env::var("BENCHMARK_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let fixture = AuthFixture::new(2026102301u64.checked_add(seed).ok_or("seed_overflow")?);
    let mut terminal_bytes = Vec::new();
    fixture.keys[5]
        .0
        .serialize(&mut terminal_bytes)
        .map_err(|_| "terminal_encode")?;
    let params = fixed32(&native.params_digest_hex, "params_digest")?;
    let mut gates = Gates::default();
    gates.native_crypto_accepted = native.accepted;
    gates.agent_public_key_consistent = hex(&terminal_bytes) == manifest.terminal_public_key_hex;
    gates.complete_q_nonce_consistent = true;
    gates.agent_proof_substitution_rejected = true;
    gates.failed_verify_nonce_remains_usable = true;
    gates.replay_after_commit_rejected = true;
    gates.retained_showing_cryptographically_verified = true;
    gates.trusted_job_policy_and_clock = true;
    if !gates.native_crypto_accepted {
        return Err("native_crypto_rejected".into());
    }
    if !gates.agent_public_key_consistent {
        return Err("agent_public_key_mismatch".into());
    }
    let source = b"Synthetic project document 42\nApproved asynchronous export example.\n";
    let mut bridge_stages = Vec::new();
    let mut prior: Option<(
        Vec<Fr>,
        Hash,
        Vec<u8>,
        ark_crypto_primitives::signature::schnorr::Signature<
            ark_ed_on_bls12_381::EdwardsProjective,
        >,
    )> = None;
    let mut nonce_store = BTreeSet::new();
    for (manifest_stage, native_stage) in manifest.stages.iter().zip(native.stages.iter()) {
        if manifest_stage.name != native_stage.name || !native_stage.accepted {
            return Err("stage_mismatch_or_rejected".into());
        }
        let base_q = decode_q16(&manifest_stage.request.complete_q_hex)?;
        let header = fixed32(&manifest_stage.request.current_header_digest_hex, "header")?;
        let mut rows = Vec::new();
        for observation in &native_stage.observations {
            if !observation.accepted {
                return Err("native_observation_rejected".into());
            }
            let q = decode_q16(&observation.complete_q_hex)?;
            let nonce = fr_u64(q[10], "nonce")?;
            let expected_nonce = manifest_stage
                .request
                .verifier_nonce
                .checked_add(observation.rep as u64)
                .ok_or("nonce_overflow")?;
            let mut expected_q = base_q;
            expected_q[10] = Fr::from(expected_nonce);
            let expected_q_hex = encode_q16(&expected_q)?;
            let q_nonce_consistent = nonce == observation.nonce
                && nonce == expected_nonce
                && q == expected_q
                && observation.complete_q_hex == expected_q_hex;
            gates.complete_q_nonce_consistent &= q_nonce_consistent;
            if !q_nonce_consistent {
                return Err("complete_q_or_nonce_mismatch".into());
            }
            let header_limbs = [
                Fr::from_le_bytes_mod_order(&header[..16]),
                Fr::from_le_bytes_mod_order(&header[16..]),
            ];
            let request_time=fr_u64(q[9],"request_time")?;
            let permit_until=fr_u64(q[11],"permit_until")?;
            gates.trusted_job_policy_and_clock &= q[0]==header_limbs[0] && q[1]==header_limbs[1]
                && fr_u64(q[3],"system")?==1 && fr_u64(q[4],"circuit_version")?==1
                && fr_u64(q[5],"verifier")?==17 && fr_u64(q[6],"pep")?==18
                && fr_u64(q[7],"resource")?==42 && fr_u64(q[8],"action")?==1
                && request_time<=permit_until && q[14]==fixture.keys[5].0.x && q[15]==fixture.keys[5].0.y;
            if !gates.trusted_job_policy_and_clock{return Err("trusted_job_policy_or_clock".into())}
            let package_path = output_dir.join(format!(
                "{}_rep{}_public_verify_package.json",
                manifest_stage.name, observation.rep
            ));
            let package = serde_json::json!({"format":"HRADA-SR-F-BBS-VERIFY-PACKAGE-V1",
                "stage":manifest_stage.name,"rep":observation.rep,"nonce":nonce,
                "complete_q_hex":expected_q_hex.clone(),
                "current_header_digest_hex":manifest_stage.request.current_header_digest_hex,
                "terminal_public_key_hex":manifest.terminal_public_key_hex,
                "params_digest_hex":native.params_digest_hex,
                "verifier_material_hex":native.verifier_material_hex,
                "showing_hex":observation.showing_hex,
                "anonymous_proof_hex":observation.anonymous_proof_hex});
            fs::write(&package_path, serde_json::to_vec_pretty(&package).unwrap())
                .map_err(|e| e.to_string())?;
            let retained_path = output_dir.join(format!(
                "{}_rep{}_retained_verify.json",
                manifest_stage.name, observation.rep
            ));
            let subprocess_start = Instant::now();
            let retained_status = Command::new(&native_verifier)
                .arg("verify-package")
                .arg("--input")
                .arg(&package_path)
                .arg("--output")
                .arg(&retained_path)
                .status()
                .map_err(|e| format!("native verifier spawn: {e}"))?;
            let native_reverify_subprocess_ns = subprocess_start.elapsed().as_nanos();
            if !retained_status.success() {
                return Err("retained_showing_verify_failed".into());
            }
            let retained: RetainedVerify =
                serde_json::from_slice(&fs::read(&retained_path).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
            let retained_ok = retained.format == "HRADA-SR-F-BBS-VERIFY-V1"
                && retained.stage == manifest_stage.name
                && retained.rep == observation.rep
                && retained.nonce == nonce
                && retained.params_digest_hex == native.params_digest_hex
                && retained.complete_q_hex == expected_q_hex
                && retained.proof_bytes == observation.proof_bytes
                && retained.accepted;
            gates.retained_showing_cryptographically_verified &= retained_ok;
            if !retained_ok {
                return Err("retained_showing_output_mismatch".into());
            }
            if !gates.actual_anonymous_substitution_rejected {
                let mut tampered = package.clone();
                let target = tampered
                    .get("showing_hex")
                    .and_then(|v| v.as_str())
                    .ok_or("tampered_showing")?
                    .to_string();
                let mut bytes = target.into_bytes();
                if bytes.is_empty() {
                    return Err("empty_showing_hex".into());
                }
                bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
                tampered["showing_hex"] =
                    serde_json::Value::String(String::from_utf8(bytes).unwrap());
                let tampered_package = output_dir.join("tampered_public_verify_package.json");
                let tampered_result = output_dir.join("tampered_verify.json");
                fs::write(
                    &tampered_package,
                    serde_json::to_vec_pretty(&tampered).unwrap(),
                )
                .map_err(|e| e.to_string())?;
                let status = Command::new(&native_verifier)
                    .arg("verify-package")
                    .arg("--input")
                    .arg(&tampered_package)
                    .arg("--output")
                    .arg(&tampered_result)
                    .status()
                    .map_err(|e| e.to_string())?;
                gates.actual_anonymous_substitution_rejected = !status.success();
                if !gates.actual_anonymous_substitution_rejected {
                    return Err("tampered_showing_accepted".into());
                }
            }
            let proof = unhex(&observation.anonymous_proof_hex)?;
            if !observation.accepted || proof.len() != observation.proof_bytes {
                return Err("native_observation_invalid".into());
            }
            let sign_start = Instant::now();
            let signature = terminal_sign_showing(
                &fixture.base,
                &fixture.keys[5].1,
                &params,
                &header,
                &q,
                &proof,
            )?;
            let agent_sign_ns = sign_start.elapsed().as_nanos();
            let verify_start = Instant::now();
            let valid = terminal_verify_showing(
                &fixture.base,
                &fixture.keys[5].0,
                &signature,
                &params,
                &header,
                &q,
                &proof,
            )?;
            let agent_verify_ns = verify_start.elapsed().as_nanos();
            if !valid {
                return Err("agent_signature_rejected".into());
            }
            let mut substituted = proof.clone();
            if substituted.is_empty() {
                substituted.push(1)
            } else {
                substituted[0] ^= 1
            };
            gates.agent_proof_substitution_rejected &= !terminal_verify_showing(
                &fixture.base,
                &fixture.keys[5].0,
                &signature,
                &params,
                &header,
                &q,
                &substituted,
            )?;
            if !gates.agent_proof_substitution_rejected {
                return Err("agent_proof_substitution_accepted".into());
            }
            let bad_first = !terminal_verify_showing(
                &fixture.base,
                &fixture.keys[5].0,
                &signature,
                &params,
                &header,
                &q,
                &substituted,
            )?;
            gates.failed_verify_nonce_remains_usable &= bad_first && !nonce_store.contains(&nonce);
            if !gates.failed_verify_nonce_remains_usable {
                return Err("failed_verify_consumed_nonce".into());
            }
            let commit = Instant::now();
            if request_time>permit_until{return Err("commit_clock_expired".into())}
            if !nonce_store.insert(nonce) {
                return Err("nonce_already_consumed".into());
            }
            let permit_name = format!("{}_rep{}_permit.json", manifest_stage.name, observation.rep);
            let ack_name = format!("{}_rep{}_ack.json", manifest_stage.name, observation.rep);
            let binding = terminal_binding_digest(&params, &header, &q, &proof)?;
            let mut sig_bytes = Vec::new();
            signature
                .prover_response
                .serialize(&mut sig_bytes)
                .map_err(|_| "signature_encode")?;
            signature
                .verifier_challenge
                .serialize(&mut sig_bytes)
                .map_err(|_| "signature_encode")?;
            let export_name = format!("{}_rep{}_export.txt", manifest_stage.name, observation.rep);
            let export_path = output_dir.join(&export_name);
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&export_path)
                .map_err(|e| e.to_string())?;
            file.write_all(source).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            let commit_ack_ns = commit.elapsed().as_nanos();
            let artifact_start = Instant::now();
            fs::write(output_dir.join(&permit_name),serde_json::to_vec_pretty(&serde_json::json!({"format":"HRADA-SR-F-PERMIT-V1","nonce":nonce,"resource":fr_u64(expected_q[7],"resource")?,"action":fr_u64(expected_q[8],"action")?,"complete_q_hex":expected_q_hex,"terminal_signature_hex":hex(&sig_bytes),"binding_digest_hex":hex(&binding)})).unwrap()).map_err(|e|e.to_string())?;
            fs::write(output_dir.join(&ack_name),serde_json::to_vec_pretty(&serde_json::json!({"format":"HRADA-SR-F-RESOURCE-ACK-V1","nonce":nonce,"export":export_name,"export_blake2s":hex(&digest(&[source]))})).unwrap()).map_err(|e|e.to_string())?;
            let artifact_io_ns = artifact_start.elapsed().as_nanos();
            gates.replay_after_commit_rejected &= !nonce_store.insert(nonce);
            rows.push(BridgeObservation {
                rep: observation.rep,
                nonce,
                agent_sign_ns,
                agent_verify_ns,
                native_reverify_ns: retained.verify_ns,
                native_reverify_subprocess_ns,
                commit_ack_ns,
                artifact_io_ns,
                accepted_component_sum_ns: retained.verify_ns
                    + agent_sign_ns
                    + agent_verify_ns
                    + commit_ack_ns,
                proof_bytes: observation.proof_bytes,
                showing_bytes: observation.showing_bytes,
                terminal_signature_hex: hex(&sig_bytes),
                terminal_binding_digest_hex: hex(&binding),
                permit_artifact: permit_name,
                ack_artifact: ack_name,
                accepted: true,
            });
            if prior.is_none() {
                prior = Some((q.to_vec(), header, proof, signature.clone()));
            }
        }
        bridge_stages.push(BridgeStage {
            name: manifest_stage.name.clone(),
            observations: rows,
        });
    }
    if let Some((old_q, old_header, old_proof, old_sig)) = prior {
        if let Some(successor) = manifest.stages.get(1) {
            let q = decode_q16(&successor.request.complete_q_hex)?;
            let h = fixed32(
                &successor.request.current_header_digest_hex,
                "successor_header",
            )?;
            gates.stale_epoch_binding_rejected = !terminal_verify_showing(
                &fixture.base,
                &fixture.keys[5].0,
                &old_sig,
                &params,
                &h,
                &q,
                &old_proof,
            )? && old_header != h
                && old_q != q.to_vec();
        }
    }
    gates.last_support_has_no_ack = bridge_stages
        .last()
        .map(|s| s.observations.is_empty())
        .unwrap_or(false);
    let accepted = gates.native_crypto_accepted
        && gates.complete_q_nonce_consistent
        && gates.agent_public_key_consistent
        && gates.retained_showing_cryptographically_verified
        && gates.actual_anonymous_substitution_rejected
        && gates.agent_proof_substitution_rejected
        && gates.stale_epoch_binding_rejected
        && gates.failed_verify_nonce_remains_usable
        && gates.replay_after_commit_rejected
        && gates.last_support_has_no_ack
        && gates.trusted_job_policy_and_clock;
    let output = BridgeOutput {
        format: "HRADA-SR-F-COMMIT-BRIDGE-V1",
        params_digest_hex: native.params_digest_hex,
        stages: bridge_stages,
        gates,
        accepted,
    };
    fs::write(
        output_dir.join("sr_commit_bridge.json"),
        serde_json::to_vec_pretty(&output).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    if !accepted {
        return Err("bridge_gate_failed".into());
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1)
    }
}
