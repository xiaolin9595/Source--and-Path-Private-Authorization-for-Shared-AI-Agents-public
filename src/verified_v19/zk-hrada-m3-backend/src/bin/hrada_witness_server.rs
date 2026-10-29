//! Authenticated loopback state-update service for witness_delivery_v1.
//! It performs the real AuthFixture leaf revocation and publishes one signed epoch-2 response.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Fr, G1Projective};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::{
    protocols::{
        hrada_auth::{AuthCircuit, AuthCircuitWire, AuthFixture},
        hrada_membership::StateSet,
        hrada_poseidon_baseline::PoseidonMerkleState as MerkleState,
    },
    utils::integer_to_bigint_mod_q,
};
use rug::Integer;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env, fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const WIRE_VERSION: &str = "hrada-state-update/1";
const MAX_MESSAGE: usize = 65_536;

#[derive(Deserialize)]
struct FixtureFile {
    fixtures: Vec<Fixture>,
}
#[derive(Deserialize)]
struct Fixture {
    trial: usize,
    auth_seed: u64,
    other_seed: u64,
    initial_prime_hex: Vec<String>,
    replacement_prime_hex: String,
}
#[derive(Deserialize)]
struct Request {
    wire_version: String,
    scheme: String,
    trial: usize,
    current_epoch: u64,
    requested_epoch: u64,
    request_id: String,
    parameter_digest: String,
    user_binding: String,
}
#[derive(Serialize)]
struct BootstrapPayload {
    wire_version: String,
    trial: usize,
    epoch: u64,
    request_id: String,
    response_id: String,
    user_binding: String,
    setup_circuit: AuthCircuitWire,
}
#[derive(Clone, Serialize, Deserialize)]
struct SrStateProofWire {
    auth_root: String,
    state_version: u64,
    state_status: u64,
    state_expiry: u64,
    transition: String,
    sr_sig: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct AuthDeliveryWire {
    pre_primary_q: AuthCircuitWire,
    pre_other_q: AuthCircuitWire,
    post_primary_q: AuthCircuitWire,
    post_primary_p: AuthCircuitWire,
    post_primary_p2: AuthCircuitWire,
    post_other_q: AuthCircuitWire,
    sr_state_proof: SrStateProofWire,
}
#[derive(Clone, Serialize)]
struct Payload {
    wire_version: String,
    scheme: String,
    trial: usize,
    epoch: u64,
    request_id: String,
    response_id: String,
    parameter_digest: String,
    user_binding: String,
    auth_root: String,
    cp_accumulator: String,
    merkle_root: String,
    state_digest: String,
    auth_bundle_digest: String,
    auth_delivery: AuthDeliveryWire,
    body_kind: String,
    changed_slot: usize,
    old_prime_hex: String,
    new_prime_hex: String,
    updated_primes_hex: Vec<String>,
}

fn enc<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut b = vec![];
    x.serialize(&mut b).unwrap();
    b
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn hash(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Blake2s::digest(b));
    out
}
fn fr(p: &Integer) -> Fr {
    integer_to_bigint_mod_q::<G1Projective>(p).unwrap()
}
fn sat(c: AuthCircuit) -> Result<bool, String> {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    let cs = ConstraintSystem::new_ref();
    c.generate_constraints(cs.clone())
        .map_err(|e| format!("{:?}", e))?;
    cs.is_satisfied().map_err(|e| format!("{:?}", e))
}
fn get_arg(args: &[String], key: &str) -> Result<String, String> {
    args.windows(2)
        .find(|w| w[0] == key)
        .map(|w| w[1].clone())
        .ok_or_else(|| format!("missing {}", key))
}
fn read_frame(stream: &mut TcpStream, max: usize) -> Result<Vec<u8>, String> {
    let mut n = [0u8; 4];
    stream.read_exact(&mut n).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(n) as usize;
    if len == 0 || len > max {
        return Err("request_length_out_of_bounds".into());
    }
    let mut b = vec![0u8; len];
    stream.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}
fn write_frame(stream: &mut TcpStream, b: &[u8]) -> Result<(), String> {
    if b.is_empty() || b.len() > MAX_MESSAGE {
        return Err("response_length_out_of_bounds".into());
    }
    stream
        .write_all(&(b.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(b))
        .map_err(|e| e.to_string())
}
fn sign(payload: &[u8], key: &Path, input_path: &Path) -> Result<Vec<u8>, String> {
    fs::write(input_path, payload).map_err(|e| e.to_string())?;
    let out = Command::new("openssl")
        .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
        .arg(key)
        .arg("-in")
        .arg(input_path)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "openssl_sign:{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    if out.stdout.is_empty() || out.stdout.len() > 256 {
        return Err("signature_length_out_of_bounds".into());
    }
    Ok(out.stdout)
}
fn state_digest(
    scheme: &str,
    epoch: u64,
    parameter_digest: &str,
    user_binding: &str,
    auth_root: &str,
    cp_accumulator: &str,
    merkle_root: &str,
    auth_bundle_digest: &str,
    body: &[String],
) -> String {
    let mut b = b"HRADA-STATE-UPDATE-V1".to_vec();
    for s in [
        WIRE_VERSION,
        scheme,
        parameter_digest,
        user_binding,
        auth_root,
        cp_accumulator,
        merkle_root,
        auth_bundle_digest,
    ] {
        b.extend_from_slice(&(s.len() as u64).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    b.extend_from_slice(&epoch.to_be_bytes());
    for s in body {
        b.extend_from_slice(&(s.len() as u64).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    hex(&hash(&b))
}
fn process_provenance() -> Value {
    let pid = std::process::id();
    let pgid = Command::new("ps")
        .args(["-o", "pgid=", "-p", &pid.to_string()])
        .output()
        .ok()
        .map(|x| String::from_utf8_lossy(&x.stdout).trim().to_string());
    let utc_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    json!({
        "utc_unix_ms": utc_unix_ms,
        "pid":pid,"pgid":pgid,"argv":env::args().collect::<Vec<_>>(),
        "environment":{"RUST_BACKTRACE":env::var("RUST_BACKTRACE").ok(),"PATH_sha256":hex(&hash(env::var("PATH").unwrap_or_default().as_bytes()))}
    })
}

fn run() -> Result<(), String> {
    let origin = Instant::now();
    let args = env::args().collect::<Vec<_>>();
    let fixture_path = PathBuf::from(get_arg(&args, "--fixtures")?);
    let trial: usize = get_arg(&args, "--trial")?
        .parse()
        .map_err(|_| "bad_trial")?;
    let addr = get_arg(&args, "--addr")?;
    let key = PathBuf::from(get_arg(&args, "--private-key")?);
    let out_dir = PathBuf::from(get_arg(&args, "--output-dir")?);
    if out_dir.exists() {
        return Err("output_directory_exists".into());
    }
    fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let fixtures: FixtureFile =
        serde_json::from_slice(&fs::read(&fixture_path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let x = fixtures
        .fixtures
        .iter()
        .find(|x| x.trial == trial)
        .ok_or("trial_not_found")?;
    if x.initial_prime_hex.len() != 8 || x.other_seed == x.auth_seed {
        return Err("invalid_fixture".into());
    }
    let primes = x
        .initial_prime_hex
        .iter()
        .map(|p| Integer::from_str_radix(p, 16).unwrap())
        .collect::<Vec<_>>();
    let newp = Integer::from_str_radix(&x.replacement_prime_hex, 16).map_err(|e| e.to_string())?;
    let mut primary = AuthFixture::new(x.auth_seed);
    primary.refresh_state(fr(&primes[0]));
    let mut other = primary.second_user(x.other_seed);
    other.refresh_state(fr(&primes[1]));
    let other_sr = other.sr_signatures;
    if !sat(primary.circuit_for("P"))?
        || !sat(primary.circuit_for("Q"))?
        || !sat(other.circuit_for("Q"))?
    {
        return Err("pre_revocation_authorization_failed".into());
    }
    let original_ids = primary
        .all_grants
        .iter()
        .map(|g| g.id())
        .collect::<Vec<_>>();
    let pre_primary_q = AuthCircuitWire::from_circuit(&primary.circuit_for("Q"));
    let pre_other_q = AuthCircuitWire::from_circuit(&other.circuit_for("Q"));
    let initial_sr = primary.sr_signatures;
    let revoke_start = Instant::now();
    primary.revoke_middle(fr(&newp));
    let revoke_ms = revoke_start.elapsed().as_secs_f64() * 1000.0;
    if sat(primary.circuit_for("P"))?
        || sat(primary.circuit_for("P2"))?
        || !sat(primary.circuit_for("Q"))?
    {
        return Err("post_revocation_authorization_gate_failed".into());
    }
    if primary
        .all_grants
        .iter()
        .map(|g| g.id())
        .collect::<Vec<_>>()
        != original_ids
        || primary.sr_signatures != initial_sr + 1
        || other.sr_signatures != other_sr
    {
        return Err("signature_counter_or_grant_invariant_failed".into());
    }
    let post_primary_q = AuthCircuitWire::from_circuit(&primary.circuit_for("Q"));
    let post_primary_p = AuthCircuitWire::from_circuit(&primary.circuit_for("P"));
    let post_primary_p2 = AuthCircuitWire::from_circuit(&primary.circuit_for("P2"));
    let post_other_q = AuthCircuitWire::from_circuit(&other.circuit_for("Q"));
    let auth_delivery = AuthDeliveryWire {
        sr_state_proof: SrStateProofWire {
            auth_root: hex(&primary.base.auth_root),
            state_version: primary.base.state_version,
            state_status: primary.base.state_status,
            state_expiry: primary.base.state_expiry,
            transition: hex(&primary.base.transition),
            sr_sig: post_primary_q.sr_sig.clone(),
        },
        pre_primary_q: pre_primary_q.clone(),
        pre_other_q,
        post_primary_q,
        post_primary_p,
        post_primary_p2,
        post_other_q,
    };
    let auth_bundle_bytes = serde_json::to_vec(&auth_delivery).map_err(|e| e.to_string())?;
    let auth_bundle_digest = hex(&hash(&auth_bundle_bytes));
    let mut updated = primes.clone();
    updated[0] = newp.clone();
    let state_start = Instant::now();
    let cp = StateSet::rebuild(&updated)?;
    let merkle = MerkleState::with_depth(&updated, 4)?;
    let state_ms = state_start.elapsed().as_secs_f64() * 1000.0;
    let user_binding = hex(&hash(&enc(&primary.base.user_pk)));
    let listener = TcpListener::bind(&addr).map_err(|e| e.to_string())?;
    let bound = listener.local_addr().map_err(|e| e.to_string())?;
    fs::write(
        out_dir.join("ready.json"),
        serde_json::to_vec_pretty(&json!({"addr":bound.to_string(),"pid":std::process::id()}))
            .unwrap(),
    )
    .map_err(|e| e.to_string())?;
    let (mut stream, peer) = listener.accept().map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let bootstrap_request_bytes = read_frame(&mut stream, MAX_MESSAGE)?;
    let bootstrap_req: Request = serde_json::from_slice(&bootstrap_request_bytes)
        .map_err(|_| "bootstrap_request_json_invalid")?;
    if bootstrap_req.wire_version != WIRE_VERSION
        || bootstrap_req.scheme != "auth_public_bootstrap"
        || bootstrap_req.trial != trial
        || bootstrap_req.current_epoch != 1
        || bootstrap_req.requested_epoch != 1
        || bootstrap_req.user_binding != user_binding
        || bootstrap_req.request_id.len() != 64
    {
        return Err("bootstrap_request_binding_invalid".into());
    }
    let bootstrap_response_id = hex(&hash(
        [
            bootstrap_req.request_id.as_bytes(),
            b"/auth-public-bootstrap",
        ]
        .concat()
        .as_slice(),
    ));
    let bootstrap = BootstrapPayload {
        wire_version: WIRE_VERSION.into(),
        trial,
        epoch: 1,
        request_id: bootstrap_req.request_id.clone(),
        response_id: bootstrap_response_id,
        user_binding: user_binding.clone(),
        setup_circuit: pre_primary_q.clone(),
    };
    let bootstrap_bytes = serde_json::to_vec(&bootstrap).map_err(|e| e.to_string())?;
    let bootstrap_signature = sign(
        &bootstrap_bytes,
        &key,
        &out_dir.join("signed_bootstrap_payload.bin"),
    )?;
    write_frame(&mut stream, &bootstrap_bytes)?;
    write_frame(&mut stream, &bootstrap_signature)?;
    stream.flush().map_err(|e| e.to_string())?;
    let request_bytes = read_frame(&mut stream, MAX_MESSAGE)?;
    let req: Request =
        serde_json::from_slice(&request_bytes).map_err(|_| "request_json_invalid")?;
    if req.wire_version != WIRE_VERSION
        || req.trial != trial
        || req.current_epoch != 1
        || req.requested_epoch != 2
    {
        return Err("request_version_or_epoch_mismatch".into());
    }
    if !["cp_rsa_update_log", "poseidon_whole_tree", "both"].contains(&req.scheme.as_str()) {
        return Err("request_scheme_invalid".into());
    }
    if req.user_binding != user_binding
        || req.request_id.len() != 64
        || req.parameter_digest.len() != 64
    {
        return Err("request_binding_invalid".into());
    }
    let cp_accumulator = hex(&Rsa2048::elem_to_bytes(&cp.accumulator));
    let merkle_root = hex(&merkle.root());
    let auth_root = hex(&primary.base.auth_root);
    let body = if req.scheme == "cp_rsa_update_log" {
        vec![
            x.initial_prime_hex[0].clone(),
            x.replacement_prime_hex.clone(),
        ]
    } else {
        updated
            .iter()
            .map(|p| p.to_string_radix(16))
            .collect::<Vec<_>>()
    };
    let sd = state_digest(
        &req.scheme,
        2,
        &req.parameter_digest,
        &user_binding,
        &auth_root,
        &cp_accumulator,
        &merkle_root,
        &auth_bundle_digest,
        &body,
    );
    let response_id = hex(&hash(
        [req.request_id.as_bytes(), sd.as_bytes()]
            .concat()
            .as_slice(),
    ));
    let payload = Payload {
        wire_version: WIRE_VERSION.into(),
        scheme: req.scheme.clone(),
        trial,
        epoch: 2,
        request_id: req.request_id.clone(),
        response_id,
        parameter_digest: req.parameter_digest.clone(),
        user_binding,
        auth_root,
        cp_accumulator,
        merkle_root,
        state_digest: sd,
        auth_bundle_digest,
        auth_delivery,
        body_kind: if req.scheme == "cp_rsa_update_log" {
            "replacement_log_v1"
        } else {
            "whole_tree_v1"
        }
        .into(),
        changed_slot: 0,
        old_prime_hex: x.initial_prime_hex[0].clone(),
        new_prime_hex: x.replacement_prime_hex.clone(),
        updated_primes_hex: if req.scheme == "cp_rsa_update_log" {
            vec![]
        } else {
            body.clone()
        },
    };
    let serialize_start = Instant::now();
    let payload_bytes = serde_json::to_vec(&payload).map_err(|e| e.to_string())?;
    let serialize_ms = serialize_start.elapsed().as_secs_f64() * 1000.0;
    let sign_start = Instant::now();
    let signature = sign(&payload_bytes, &key, &out_dir.join("signed_payload.bin"))?;
    let sign_ms = sign_start.elapsed().as_secs_f64() * 1000.0;
    let mut wrong_root_payload = payload.clone();
    wrong_root_payload.merkle_root.replace_range(
        0..2,
        if &wrong_root_payload.merkle_root[0..2] == "00" {
            "01"
        } else {
            "00"
        },
    );
    wrong_root_payload.state_digest = state_digest(
        &req.scheme,
        2,
        &req.parameter_digest,
        &wrong_root_payload.user_binding,
        &wrong_root_payload.auth_root,
        &wrong_root_payload.cp_accumulator,
        &wrong_root_payload.merkle_root,
        &wrong_root_payload.auth_bundle_digest,
        &body,
    );
    wrong_root_payload.response_id = hex(&hash(
        [
            req.request_id.as_bytes(),
            wrong_root_payload.state_digest.as_bytes(),
            b"/wrong-root",
        ]
        .concat()
        .as_slice(),
    ));
    let wrong_root_bytes = serde_json::to_vec(&wrong_root_payload).map_err(|e| e.to_string())?;
    let wrong_root_signature = sign(
        &wrong_root_bytes,
        &key,
        &out_dir.join("signed_wrong_root_payload.bin"),
    )?;
    let send_start = Instant::now();
    write_frame(&mut stream, &payload_bytes)?;
    write_frame(&mut stream, &signature)?;
    write_frame(&mut stream, &wrong_root_bytes)?;
    write_frame(&mut stream, &wrong_root_signature)?;
    // A byte-identical second delivery exercises replay handling in the real receiver.
    write_frame(&mut stream, &payload_bytes)?;
    write_frame(&mut stream, &signature)?;
    stream.flush().map_err(|e| e.to_string())?;
    let send_ms = send_start.elapsed().as_secs_f64() * 1000.0;
    let result = json!({
        "status":"complete","provenance":process_provenance(),"peer":peer.to_string(),"trial":trial,"scheme":req.scheme,
        "request_id":req.request_id,"response_id":payload.response_id,"epoch":2,
        "checks":{"pre_P_Q_Z":true,"post_P_P2_rejected":true,"post_Q_valid":true,"original_grants_unchanged":true,"one_primary_sr_refresh":true,"sr_state_proof_issued_by_server":true,"client_sr_private_key_transmitted":false},
        "timing_ms":{"revocation":revoke_ms,"state_construct":state_ms,"serialize":serialize_ms,"sign":sign_ms,"send":send_ms,"process_wall":origin.elapsed().as_secs_f64()*1000.0},
        "bytes":{"bootstrap_request":bootstrap_request_bytes.len(),"bootstrap_payload":bootstrap_bytes.len(),"bootstrap_signature":bootstrap_signature.len(),"request_payload":request_bytes.len(),"response_payload":payload_bytes.len(),"signature":signature.len(),"positive_wire_total":8+request_bytes.len()+payload_bytes.len()+signature.len(),"adverse_wrong_root_payload":wrong_root_bytes.len(),"adverse_replay_payload":payload_bytes.len(),"wire_total":bootstrap_request_bytes.len()+bootstrap_bytes.len()+bootstrap_signature.len()+request_bytes.len()+payload_bytes.len()+signature.len()+wrong_root_bytes.len()+wrong_root_signature.len()+payload_bytes.len()+signature.len()+32},
        "digests":{"payload_blake2s":hex(&hash(&payload_bytes)),"state":payload.state_digest,"auth_root":hex(&hash(payload.auth_root.as_bytes())),"cp_accumulator":hex(&hash(payload.cp_accumulator.as_bytes())),"merkle_root":hex(&hash(payload.merkle_root.as_bytes()))}
    });
    fs::write(
        out_dir.join("server.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("FAILED {}", e);
        std::process::exit(1);
    }
}
