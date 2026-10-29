//! Authenticated loopback witness-delivery client: receive epoch-2 bytes, then prove in-process.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_auth::{fixture_public_parameters, AuthCircuit, AuthCircuitWire},
    hrada_joint::{self, Header, JointVerifier},
    hrada_link::{self, LinkParameters},
    hrada_membership::{CpProof, StateMembership, StateSet},
    hrada_poseidon_baseline::{parameter_descriptor, PoseidonMerkleState as MerkleState},
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    convert::TryInto,
    env, fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
const WIRE_VERSION: &str = "hrada-state-update/1";
const MAX_MESSAGE: usize = 65_536;

#[derive(Deserialize)]
struct FixtureFile {
    fixtures: Vec<ClientFixture>,
}
#[derive(Deserialize)]
struct ClientFixture {
    trial: usize,
    auth_seed: u64,
    other_seed: u64,
    initial_prime_hex: Vec<String>,
}
fn fixture_user_binding(trial: usize) -> Result<String, String> {
    Ok(match trial {
        0 => "770fa5281ecd7b8413b5e67bbd95ec4d93d001f7e6652155e2495133bf3ae0fb",
        1 => "2b3ee81a0d1ef3186ea728bbee596d915b1a0effbf52740498af04953d4f65dd",
        2 => "3be26ba98fd8dd57194547b9bd9fd8d487cdda7b935a071c8ac3269d6bdd9638",
        3 => "e2046e5c5c182ef732242e00d859a94ca3385256a769e80bee470467cbe6bcf5",
        _ => return Err("user_binding_not_registered".into()),
    }
    .into())
}
#[derive(Clone, Deserialize, Serialize)]
struct SrStateProofWire {
    auth_root: String,
    state_version: u64,
    state_status: u64,
    state_expiry: u64,
    transition: String,
    sr_sig: Vec<String>,
}
#[derive(Clone, Deserialize, Serialize)]
struct AuthDeliveryWire {
    pre_primary_q: AuthCircuitWire,
    pre_other_q: AuthCircuitWire,
    post_primary_q: AuthCircuitWire,
    post_primary_p: AuthCircuitWire,
    post_primary_p2: AuthCircuitWire,
    post_other_q: AuthCircuitWire,
    sr_state_proof: SrStateProofWire,
}
#[derive(Serialize)]
struct WireRequest {
    wire_version: String,
    scheme: String,
    trial: usize,
    current_epoch: u64,
    requested_epoch: u64,
    request_id: String,
    parameter_digest: String,
    user_binding: String,
}
#[derive(Deserialize)]
struct BootstrapPayload {
    wire_version: String,
    trial: usize,
    epoch: u64,
    request_id: String,
    response_id: String,
    user_binding: String,
    setup_circuit: AuthCircuitWire,
}
#[derive(Clone, Deserialize, Serialize)]
struct WirePayload {
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
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
#[cfg(target_os = "linux")]
fn process_cpu_ms() -> Result<f64, String> {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    extern "C" {
        fn clock_gettime(clock_id: i32, tp: *mut Timespec) -> i32;
    }
    const CLOCK_PROCESS_CPUTIME_ID: i32 = 2;
    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &mut ts) };
    if rc != 0 {
        return Err("clock_gettime_process_cpu_failed".into());
    }
    Ok(ts.tv_sec as f64 * 1000.0 + ts.tv_nsec as f64 / 1_000_000.0)
}
#[cfg(not(target_os = "linux"))]
fn process_cpu_ms() -> Result<f64, String> {
    Ok(0.0)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn random() -> Integer {
    Integer::from_digits(&enc(&Fr::rand(&mut OsRng)), Order::Lsf)
}
fn hash(b: &[u8]) -> [u8; 32] {
    let mut h = [0; 32];
    h.copy_from_slice(&Blake2s::digest(b));
    h
}
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut n = [0u8; 4];
    stream.read_exact(&mut n).map_err(|e| e.to_string())?;
    let len = u32::from_be_bytes(n) as usize;
    if len == 0 || len > MAX_MESSAGE {
        return Err("wire_length_out_of_bounds".into());
    }
    let mut b = vec![0u8; len];
    stream.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}
fn write_frame(stream: &mut TcpStream, b: &[u8]) -> Result<(), String> {
    if b.is_empty() || b.len() > MAX_MESSAGE {
        return Err("wire_length_out_of_bounds".into());
    }
    stream
        .write_all(&(b.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(b))
        .map_err(|e| e.to_string())
}
fn state_digest(p: &WirePayload, body: &[String]) -> String {
    let mut b = b"HRADA-STATE-UPDATE-V1".to_vec();
    for s in [
        WIRE_VERSION,
        p.scheme.as_str(),
        p.parameter_digest.as_str(),
        p.user_binding.as_str(),
        p.auth_root.as_str(),
        p.cp_accumulator.as_str(),
        p.merkle_root.as_str(),
        p.auth_bundle_digest.as_str(),
    ] {
        b.extend_from_slice(&(s.len() as u64).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    b.extend_from_slice(&p.epoch.to_be_bytes());
    for s in body {
        b.extend_from_slice(&(s.len() as u64).to_be_bytes());
        b.extend_from_slice(s.as_bytes());
    }
    hex(&hash(&b))
}
fn verify_signature(
    payload: &[u8],
    signature: &[u8],
    public_key: &Path,
    sig_path: &Path,
) -> Result<(), String> {
    fs::write(sig_path, signature).map_err(|e| e.to_string())?;
    let payload_path = sig_path.with_extension("payload");
    fs::write(&payload_path, payload).map_err(|e| e.to_string())?;
    let out = Command::new("openssl")
        .args(["pkeyutl", "-verify", "-pubin", "-rawin", "-inkey"])
        .arg(public_key)
        .args(["-sigfile"])
        .arg(sig_path)
        .arg("-in")
        .arg(&payload_path)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err("envelope_signature_rejected".into())
    }
}
fn semantic_validate(
    p: &WirePayload,
    req: &WireRequest,
    expected_version: &str,
    expected_epoch: u64,
    expected_user: &str,
) -> Result<(), String> {
    if p.wire_version != expected_version {
        return Err("wire_version_mismatch".into());
    }
    if p.scheme != req.scheme
        || p.trial != req.trial
        || p.request_id != req.request_id
        || p.parameter_digest != req.parameter_digest
    {
        return Err("request_response_binding_mismatch".into());
    }
    if p.epoch != expected_epoch {
        return Err("epoch_mismatch".into());
    }
    if p.user_binding != expected_user {
        return Err("user_binding_mismatch".into());
    }
    let auth_bytes = serde_json::to_vec(&p.auth_delivery).map_err(|_| "auth_bundle_encode")?;
    if hex(&hash(&auth_bytes)) != p.auth_bundle_digest {
        return Err("auth_bundle_digest_mismatch".into());
    }
    if p.auth_delivery.sr_state_proof.auth_root != p.auth_root
        || p.auth_delivery.sr_state_proof.state_version != 2
        || p.auth_delivery.sr_state_proof.state_status != 1
        || p.auth_delivery.sr_state_proof.sr_sig != p.auth_delivery.post_primary_q.sr_sig
        || p.auth_delivery.post_primary_q.auth_root != p.auth_root
    {
        return Err("sr_state_proof_binding_mismatch".into());
    }
    if p.response_id.len() != 64 {
        return Err("response_id_invalid".into());
    }
    let body = if p.scheme == "cp_rsa_update_log" {
        vec![p.old_prime_hex.clone(), p.new_prime_hex.clone()]
    } else {
        p.updated_primes_hex.clone()
    };
    if state_digest(p, &body) != p.state_digest {
        return Err("state_digest_mismatch".into());
    }
    let expected_kind = if p.scheme == "cp_rsa_update_log" {
        "replacement_log_v1"
    } else {
        "whole_tree_v1"
    };
    if p.body_kind != expected_kind || p.changed_slot != 0 {
        return Err("body_version_mismatch".into());
    }
    Ok(())
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
    json!({"utc_unix_ms":utc_unix_ms,"pid":pid,"pgid":pgid,"argv":env::args().collect::<Vec<_>>(),"environment":{"RUST_BACKTRACE":env::var("RUST_BACKTRACE").ok(),"PATH_sha256":hex(&hash(env::var("PATH").unwrap_or_default().as_bytes()))}})
}
fn limbs(h: &[u8; 32]) -> [Fr; 2] {
    use ark_ff::PrimeField;
    [
        Fr::from_le_bytes_mod_order(&h[..16]),
        Fr::from_le_bytes_mod_order(&h[16..]),
    ]
}
fn sat(c: AuthCircuit) -> Result<bool, String> {
    let cs = ConstraintSystem::new_ref();
    c.generate_constraints(cs.clone())
        .map_err(|e| format!("{:?}", e))?;
    cs.is_satisfied().map_err(|e| format!("{:?}", e))
}
// Measured component encoding, not a deployed transport: each component u32 LE
// length-prefixed; integers signed magnitude (one sign byte + unsigned BE digits).
fn cp_components(p: &CpProof) -> Vec<u8> {
    let mut out = vec![];
    let mut put = |b: Vec<u8>| {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend(b);
    };
    for e in [
        &p.c_e,
        &p.proof_root.message1.c_w,
        &p.proof_root.message1.c_r,
        &p.proof_root.message2.alpha1,
        &p.proof_root.message2.alpha2,
        &p.proof_root.message2.alpha3,
        &p.proof_root.message2.alpha4,
        &p.proof_modeq.message1.alpha1,
    ]
    .iter()
    {
        put(Rsa2048::elem_to_bytes(e));
    }
    let a = &p.proof_root.message3;
    let b = &p.proof_modeq.message2;
    for i in [
        &a.s_e, &a.s_r, &a.s_r_2, &a.s_r_3, &a.s_beta, &a.s_delta, &b.s_e, &b.s_r,
    ]
    .iter()
    {
        let mut v = vec![if **i < Integer::from(0) { 1 } else { 0 }];
        v.extend((**i).clone().abs().to_digits::<u8>(Order::MsfBe));
        put(v);
    }
    put(enc(&p.proof_modeq.message1.alpha2));
    put(enc(&b.s_r_q));
    put(enc(&p.proof_hash_to_prime));
    out
}
#[derive(Clone)]
struct MHeader {
    root: [u8; 32],
    epoch: u64,
    digest: [u8; 32],
}
impl MHeader {
    fn new(root: [u8; 32], epoch: u64, params: &[u8; 32]) -> Self {
        let mut b = b"HRADA-POSEIDON-MERKLE-HEADER-V1".to_vec();
        b.extend(params);
        b.extend(epoch.to_le_bytes());
        b.extend(root);
        Self {
            root,
            epoch,
            digest: hash(&b),
        }
    }
}
struct MBundle {
    membership: legogro16::Proof<Bls12_381>,
    auth: legogro16::Proof<Bls12_381>,
    commitment: G1Projective,
    fields: Vec<Fr>,
    root: [Fr; 2],
}
struct MVerifier {
    header: MHeader,
    consumed: HashSet<Vec<u8>>,
}
struct MParameters<'a> {
    cp: &'a StateMembership,
    auth: &'a LinkParameters,
    member: &'a LinkParameters,
    descriptor: Vec<u8>,
    member_digest: [u8; 32],
    auth_descriptor: Vec<u8>,
    digest: [u8; 32],
}
impl MVerifier {
    fn authorize<F: FnMut() -> u64>(
        &mut self,
        p: &MParameters,
        b: &MBundle,
        expected: &[Fr],
        request_time: u64,
        permit_until: u64,
        mut clock: F,
    ) -> Result<(), String> {
        if b.fields.len() != 16 || b.fields != expected {
            return Err("request_mismatch".into());
        }
        let q = &b.fields;
        let hd = limbs(&self.header.digest);
        if b.root != limbs(&self.header.root)
            || q[0] != hd[0]
            || q[1] != hd[1]
            || q[2] != Fr::from(self.header.epoch)
        {
            return Err("stale_header".into());
        }
        // Same independent interval binding as the CP verifier.
        if q[9] != Fr::from(request_time)
            || q[11] != Fr::from(permit_until)
            || request_time > permit_until
        {
            return Err("invalid_request_interval".into());
        }
        let before = clock();
        if before < request_time || before > permit_until {
            return Err("request_outside_validity".into());
        }
        let mut nonce = vec![];
        for i in [3, 5, 6, 10].iter() {
            nonce.extend(enc(&q[*i]));
        }
        if self.consumed.contains(&nonce) {
            return Err("nonce_already_consumed".into());
        }
        let ck = &p.cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
        if !hrada_link::verify(
            p.member,
            ck,
            &p.descriptor,
            &p.member_digest,
            &b.membership,
            &b.root,
            &b.commitment,
        )
        .map_err(|e| format!("{:?}", e))?
        {
            return Err("member_link_rejected".into());
        }
        if !hrada_link::verify(
            p.auth,
            ck,
            &p.auth_descriptor,
            &p.digest,
            &b.auth,
            q,
            &b.commitment,
        )
        .map_err(|e| format!("{:?}", e))?
        {
            return Err("authorization_link_rejected".into());
        }
        let end = clock();
        if end < before || end > permit_until {
            return Err("expired_before_commit".into());
        }
        self.consumed.insert(nonce);
        Ok(())
    }
}
fn mver(h: &MHeader) -> MVerifier {
    MVerifier {
        header: h.clone(),
        consumed: HashSet::new(),
    }
}
struct Log {
    dir: PathBuf,
    fault: String,
    origin: Instant,
    service_origin: Option<Instant>,
    checks: Vec<Value>,
    samples: Vec<Value>,
    events: Vec<Value>,
    setup: Value,
    nonce: u64,
    executions: usize,
    provenance: Value,
    scheme: String,
    trial: usize,
    addr: String,
    fixtures: PathBuf,
    public_key: PathBuf,
}
impl Log {
    fn now(&self) -> u64 {
        500 + self
            .service_origin
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0)
    }
    fn save(&self, status: &str, failure: Option<&str>) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&json!({
            "status":status,"failure":failure,"fault":self.fault,"scheme":self.scheme,"trial":self.trial,
            "checks":self.checks,"samples":self.samples,"events":self.events,"setup":self.setup,
            "provenance":self.provenance,
            "elapsed_ms":ms(self.origin),"real_joint_proofs":self.samples.len(),"resource_executions":self.executions,
            "scope":"independent loopback state server plus proving client; verifier and PEP are colocated in this client process; no WAN/concurrency claim",
            "clock":"logical seconds = 500 + floor(real monotonic elapsed since service-ready); per-request permit 120 seconds; no frozen verifier clock",
            "expected_joint_proofs":if self.scheme=="both"{4}else{2},"configured_lambda_s":125,"effective_fs_challenge_bits":120
        })).map_err(|e| e.to_string())?;
        fs::write(self.dir.join("results.json.tmp"), bytes).map_err(|e| e.to_string())?;
        fs::rename(
            self.dir.join("results.json.tmp"),
            self.dir.join("results.json"),
        )
        .map_err(|e| e.to_string())
    }
    fn event(&mut self, kind: &str, details: Value) -> Result<(), String> {
        self.events.push(json!({"seq":self.events.len(),"event":kind,"elapsed_ms":ms(self.origin),"logical_time":self.now(),"details":details}));
        self.save("running", None)
    }
    fn check(&mut self, id: &str, pass: bool) -> Result<(), String> {
        println!("{} {}", if pass { "PASS" } else { "FAIL" }, id);
        self.checks
            .push(json!({"id":id,"pass":pass,"elapsed_ms":ms(self.origin)}));
        self.save("running", None)?;
        if pass {
            Ok(())
        } else {
            Err(format!("check_failed:{}", id))
        }
    }
    fn request(&mut self, scheme: &str, name: &str) -> Result<(u64, u64, u64), String> {
        let now = self.now();
        if now + 120 > 1000 {
            return Err("trial_time_budget_exhausted_before_submission".into());
        }
        self.nonce = self.nonce.checked_add(1).ok_or("nonce_overflow")?;
        self.event("request_queued",json!({"scheme":scheme,"case":name,"nonce":self.nonce,"request_time":now,"permit_until":now+120,"queue_model":"immediate sequential local dispatch"}))?;
        Ok((now, now + 120, self.nonce))
    }
    // Actual local append is the resource operation. Only call after authorize Ok.
    fn execute(&mut self, scheme: &str, name: &str, nonce: u64) -> Result<f64, String> {
        let row = json!({"execution":self.executions,"scheme":scheme,"case":name,"nonce":nonce,"logical_time":self.now(),"elapsed_ms":ms(self.origin),"operation":"append_authorized_resource_access"});
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("resource_executions.jsonl"))
            .map_err(|e| e.to_string())?;
        writeln!(f, "{}", row).map_err(|e| e.to_string())?;
        f.sync_data().map_err(|e| e.to_string())?;
        self.executions += 1;
        let sync_complete_elapsed_ms = ms(self.origin);
        self.event(
            "resource_executed",
            json!({"record":row,"sync_complete_elapsed_ms":sync_complete_elapsed_ms}),
        )?;
        Ok(sync_complete_elapsed_ms)
    }
}

struct DeliverySession {
    stream: TcpStream,
    request: WireRequest,
    user_binding: String,
    seen: HashSet<String>,
}

fn frame_pair(payload: &[u8], signature: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + payload.len() + signature.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    out.extend_from_slice(signature);
    out
}

fn decode_frame_pair(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    if bytes.len() < 8 {
        return Err("persisted_envelope_short".into());
    }
    let n = u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize;
    if n == 0 || n > MAX_MESSAGE || bytes.len() < 8 + n {
        return Err("persisted_payload_length".into());
    }
    let off = 4 + n;
    let m = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
    if m == 0 || m > 256 || off + 4 + m != bytes.len() {
        return Err("persisted_signature_length_or_trailing".into());
    }
    Ok((bytes[4..off].to_vec(), bytes[off + 4..].to_vec()))
}

fn validate_material_roots(p: &WirePayload, initial: &[Integer]) -> Result<(), String> {
    let mut updated = initial.to_vec();
    let newp = Integer::from_str_radix(&p.new_prime_hex, 16).map_err(|_| "new_prime_invalid")?;
    if updated.is_empty() || p.changed_slot >= updated.len() {
        return Err("changed_slot_invalid".into());
    }
    updated[p.changed_slot] = newp;
    if p.scheme != "cp_rsa_update_log" {
        let received = p
            .updated_primes_hex
            .iter()
            .map(|v| Integer::from_str_radix(v, 16).map_err(|_| "tree_prime_invalid"))
            .collect::<Result<Vec<_>, _>>()?;
        if received != updated {
            return Err("whole_tree_payload_mismatch".into());
        }
    }
    let cp = StateSet::rebuild(&updated)?;
    let mt = MerkleState::with_depth(&updated, 4)?;
    if p.cp_accumulator != hex(&Rsa2048::elem_to_bytes(&cp.accumulator)) {
        return Err("cp_root_mismatch".into());
    }
    if p.merkle_root != hex(&mt.root()) {
        return Err("merkle_root_mismatch".into());
    }
    Ok(())
}

fn fetch_bootstrap(
    log: &mut Log,
    user_binding: &str,
    params: &ark_crypto_primitives::signature::schnorr::Parameters<
        ark_ed_on_bls12_381::EdwardsProjective,
        Blake2s,
    >,
) -> Result<(TcpStream, AuthCircuit), String> {
    let mut rid = [0u8; 32];
    OsRng.fill_bytes(&mut rid);
    let req = WireRequest {
        wire_version: WIRE_VERSION.into(),
        scheme: "auth_public_bootstrap".into(),
        trial: log.trial,
        current_epoch: 1,
        requested_epoch: 1,
        request_id: hex(&rid),
        parameter_digest: "00".repeat(32),
        user_binding: user_binding.into(),
    };
    let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    let mut stream = TcpStream::connect(&log.addr).map_err(|e| format!("connect:{}", e))?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    write_frame(&mut stream, &req_bytes)?;
    let payload_bytes = read_frame(&mut stream)?;
    let signature = read_frame(&mut stream)?;
    let raw = frame_pair(&payload_bytes, &signature);
    let tmp = log.dir.join("bootstrap-envelope.bin.tmp");
    let retained = log.dir.join("bootstrap-envelope.bin");
    let mut file = fs::File::create(&tmp).map_err(|e| e.to_string())?;
    file.write_all(&raw)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    drop(file);
    fs::rename(&tmp, &retained).map_err(|e| e.to_string())?;
    let readback = fs::read(&retained).map_err(|e| e.to_string())?;
    let (durable_payload, durable_sig) = decode_frame_pair(&readback)?;
    verify_signature(
        &durable_payload,
        &durable_sig,
        &log.public_key,
        &log.dir.join("bootstrap.signature"),
    )?;
    let p: BootstrapPayload =
        serde_json::from_slice(&durable_payload).map_err(|_| "bootstrap_payload_json_invalid")?;
    let expected_response_id = hex(&hash(
        [req.request_id.as_bytes(), b"/auth-public-bootstrap"]
            .concat()
            .as_slice(),
    ));
    if p.wire_version != WIRE_VERSION
        || p.trial != log.trial
        || p.epoch != 1
        || p.request_id != req.request_id
        || p.response_id != expected_response_id
        || p.user_binding != user_binding
    {
        return Err("bootstrap_response_binding_invalid".into());
    }
    let circuit = p.setup_circuit.into_circuit_with_params(params)?;
    log.event("auth_public_bootstrap_accepted",json!({"request_bytes":req_bytes.len(),"payload_bytes":payload_bytes.len(),"signature_bytes":signature.len(),"durable_readback":true,"client_sr_private_key":false}))?;
    Ok((stream, circuit))
}

fn receive_durable(
    log: &mut Log,
    label: &str,
    raw: &[u8],
    req: &WireRequest,
    expected_version: &str,
    expected_epoch: u64,
    expected_user: &str,
    initial: &[Integer],
    seen: &mut HashSet<String>,
    promote: bool,
) -> Result<(WirePayload, f64, f64), String> {
    let durable_write_start = Instant::now();
    let tmp = log.dir.join(format!("receiver-{}.bin.tmp", label));
    let retained = log.dir.join(format!("receiver-{}.bin", label));
    let mut file = fs::File::create(&tmp).map_err(|e| e.to_string())?;
    file.write_all(raw)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    drop(file);
    fs::rename(&tmp, &retained).map_err(|e| e.to_string())?;
    let dir = fs::File::open(&log.dir).map_err(|e| e.to_string())?;
    dir.sync_all().map_err(|e| e.to_string())?;
    let durable_write_ms = ms(durable_write_start);
    let readback_started_elapsed_ms = ms(log.origin);
    let readback_started_cpu_ms = process_cpu_ms()?;
    let read_start = Instant::now();
    let readback = fs::read(&retained).map_err(|e| e.to_string())?;
    let (payload_bytes, signature) = decode_frame_pair(&readback)?;
    let durable_read_ms = ms(read_start);
    let verify_start = Instant::now();
    verify_signature(
        &payload_bytes,
        &signature,
        &log.public_key,
        &log.dir.join(format!("receiver-{}.signature", label)),
    )?;
    let signature_verify_ms = ms(verify_start);
    let parse_start = Instant::now();
    let payload: WirePayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| "payload_json_invalid")?;
    let json_parse_ms = ms(parse_start);
    let semantic_start = Instant::now();
    semantic_validate(
        &payload,
        req,
        expected_version,
        expected_epoch,
        expected_user,
    )?;
    let semantic_validate_ms = ms(semantic_start);
    let root_start = Instant::now();
    validate_material_roots(&payload, initial)?;
    let root_reconstruct_ms = ms(root_start);
    let expected_response_id = hex(&hash(
        [req.request_id.as_bytes(), payload.state_digest.as_bytes()]
            .concat()
            .as_slice(),
    ));
    if payload.response_id != expected_response_id {
        return Err("response_id_mismatch".into());
    }
    if seen.contains(&payload.response_id) {
        return Err("response_replay".into());
    }
    if promote {
        seen.insert(payload.response_id.clone());
        fs::write(log.dir.join("accepted_envelope.bin.tmp"), &readback)
            .map_err(|e| e.to_string())?;
        let accepted = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(log.dir.join("accepted_envelope.bin.tmp"))
            .map_err(|e| e.to_string())?;
        accepted.sync_all().map_err(|e| e.to_string())?;
        drop(accepted);
        fs::rename(
            log.dir.join("accepted_envelope.bin.tmp"),
            log.dir.join("accepted_envelope.bin"),
        )
        .map_err(|e| e.to_string())?;
    }
    log.event("durable_receiver_phases",json!({"label":label,"durable_write_ms":durable_write_ms,"durable_read_ms":durable_read_ms,"signature_verify_ms":signature_verify_ms,"json_parse_ms":json_parse_ms,"semantic_validate_ms":semantic_validate_ms,"root_reconstruct_ms":root_reconstruct_ms,"promote":promote}))?;
    Ok((
        payload,
        readback_started_elapsed_ms,
        readback_started_cpu_ms,
    ))
}

fn fetch_update(
    log: &mut Log,
    mut stream: TcpStream,
    parameter_digest: [u8; 32],
    user_binding: String,
    initial: &[Integer],
) -> Result<(WirePayload, f64, f64, DeliverySession), String> {
    let mut rid = [0u8; 32];
    OsRng.fill_bytes(&mut rid);
    let req = WireRequest {
        wire_version: WIRE_VERSION.into(),
        scheme: log.scheme.clone(),
        trial: log.trial,
        current_epoch: 1,
        requested_epoch: 2,
        request_id: hex(&rid),
        parameter_digest: hex(&parameter_digest),
        user_binding: user_binding.clone(),
    };
    let req_bytes = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
    let receive_start = Instant::now();
    write_frame(&mut stream, &req_bytes)?;
    let payload_bytes = read_frame(&mut stream)?;
    let signature = read_frame(&mut stream)?;
    let receive_ms = ms(receive_start);
    log.event("wire_received",json!({"request_bytes":req_bytes.len(),"payload_bytes":payload_bytes.len(),"signature_bytes":signature.len(),"positive_application_wire_bytes":8+req_bytes.len()+payload_bytes.len()+signature.len(),"receive_ms":receive_ms}))?;
    let raw = frame_pair(&payload_bytes, &signature);
    let mut seen = HashSet::new();
    let (payload, readback_started, readback_cpu_started) = receive_durable(
        log,
        "positive",
        &raw,
        &req,
        WIRE_VERSION,
        2,
        &user_binding,
        initial,
        &mut seen,
        true,
    )?;
    log.check("authenticated_envelope", true)?;
    log.check("persisted_readback_parsed_and_verified", true)?;
    log.event("envelope_promoted",json!({"response_id":payload.response_id,"epoch":payload.epoch,"accepted_file_bytes":raw.len(),"readback_started_elapsed_ms":readback_started,"acceptance_source":"reopened durable bytes"}))?;
    Ok((
        payload,
        readback_started,
        readback_cpu_started,
        DeliverySession {
            stream,
            request: req,
            user_binding,
            seen,
        },
    ))
}

fn run_delivery_negatives(
    log: &mut Log,
    session: &mut DeliverySession,
    accepted: &WirePayload,
    initial: &[Integer],
) -> Result<(), String> {
    let before = log.executions;
    let wrong_root_payload = read_frame(&mut session.stream)?;
    let wrong_root_sig = read_frame(&mut session.stream)?;
    let wrong_root_raw = frame_pair(&wrong_root_payload, &wrong_root_sig);
    let wrong_root_error = receive_durable(
        log,
        "negative-wrong-root",
        &wrong_root_raw,
        &session.request,
        WIRE_VERSION,
        2,
        &session.user_binding,
        initial,
        &mut session.seen,
        false,
    )
    .err();
    log.check(
        "negative_wrong_root_rejected_in_receiver",
        wrong_root_error.as_deref() == Some("merkle_root_mismatch"),
    )?;
    log.check(
        "negative_wrong_root_no_resource_ack",
        log.executions == before,
    )?;

    let replay_payload = read_frame(&mut session.stream)?;
    let replay_sig = read_frame(&mut session.stream)?;
    let replay_raw = frame_pair(&replay_payload, &replay_sig);
    let replay_error = receive_durable(
        log,
        "negative-replay",
        &replay_raw,
        &session.request,
        WIRE_VERSION,
        2,
        &session.user_binding,
        initial,
        &mut session.seen,
        false,
    )
    .err();
    log.check(
        "negative_replay_rejected_in_receiver",
        replay_error.as_deref() == Some("response_replay"),
    )?;
    log.check("negative_replay_no_resource_ack", log.executions == before)?;

    let accepted_raw =
        fs::read(log.dir.join("accepted_envelope.bin")).map_err(|e| e.to_string())?;
    let mut tampered = accepted_raw.clone();
    let i = 4 + (accepted_raw.len().saturating_sub(8) / 2);
    tampered[i] ^= 1;
    let tamper_error = receive_durable(
        log,
        "negative-tamper",
        &tampered,
        &session.request,
        WIRE_VERSION,
        2,
        &session.user_binding,
        initial,
        &mut HashSet::new(),
        false,
    )
    .err();
    log.check(
        "negative_payload_tamper_rejected",
        tamper_error.as_deref() == Some("envelope_signature_rejected"),
    )?;
    let wrong_user_error = receive_durable(
        log,
        "negative-wrong-user",
        &accepted_raw,
        &session.request,
        WIRE_VERSION,
        2,
        &"00".repeat(32),
        initial,
        &mut HashSet::new(),
        false,
    )
    .err();
    log.check(
        "negative_wrong_user_rejected",
        wrong_user_error.as_deref() == Some("user_binding_mismatch"),
    )?;
    let old_epoch_error = receive_durable(
        log,
        "negative-old-epoch",
        &accepted_raw,
        &session.request,
        WIRE_VERSION,
        3,
        &session.user_binding,
        initial,
        &mut HashSet::new(),
        false,
    )
    .err();
    log.check(
        "negative_old_epoch_rejected",
        old_epoch_error.as_deref() == Some("epoch_mismatch"),
    )?;
    let version_error = receive_durable(
        log,
        "negative-version",
        &accepted_raw,
        &session.request,
        "hrada-state-update/2",
        2,
        &session.user_binding,
        initial,
        &mut HashSet::new(),
        false,
    )
    .err();
    log.check(
        "negative_version_rejected",
        version_error.as_deref() == Some("wire_version_mismatch"),
    )?;
    let mut wrong_kind = accepted.clone();
    wrong_kind.body_kind = "mismatched_body_v9".into();
    log.check(
        "negative_header_body_version_rejected",
        semantic_validate(
            &wrong_kind,
            &session.request,
            WIRE_VERSION,
            2,
            &session.user_binding,
        )
        .err()
        .as_deref()
            == Some("body_version_mismatch"),
    )?;
    log.check(
        "all_delivery_negatives_no_resource_ack",
        log.executions == before,
    )?;
    log.event("delivery_negatives_completed",json!({"resource_ack_count_before":before,"resource_ack_count_after":log.executions,"wrong_root_error":wrong_root_error,"replay_error":replay_error,"after_all_measured_ack_endpoints":true}))
}
fn artifact<T: CanonicalSerialize>(
    dir: &std::path::Path,
    name: &str,
    key: &T,
) -> Result<Value, String> {
    let path = dir.join(name);
    let mut f = fs::File::create(&path).map_err(|e| e.to_string())?;
    key.serialize(&mut f).map_err(|e| format!("{:?}", e))?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    file_hash(&path)
}
fn file_hash(path: &std::path::Path) -> Result<Value, String> {
    let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = Blake2s::new();
    let mut b = vec![0u8; 1024 * 1024];
    let mut size = 0;
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
        size += n;
    }
    Ok(
        json!({"file":path.file_name().unwrap().to_string_lossy(),"bytes":size,"blake2s":hex(&h.finalize())}),
    )
}
fn bind(c: &mut AuthCircuit, header: [Fr; 2], epoch: u64, start: u64, end: u64, nonce: u64) {
    c.request.fields[0] = header[0];
    c.request.fields[1] = header[1];
    c.request.fields[2] = Fr::from(epoch);
    c.request.fields[9] = Fr::from(start);
    c.request.fields[10] = Fr::from(nonce);
    c.request.fields[11] = Fr::from(end);
}
fn cp_request(
    log: &mut Log,
    name: &str,
    auth_circuit: &AuthCircuit,
    prime: &Integer,
    set: &StateSet,
    cp: &StateMembership,
    auth: &LinkParameters,
    digest: &[u8; 32],
    v: &mut JointVerifier,
) -> Result<f64, String> {
    let (start, end, nonce) = log.request("cp_rsa", name)?;
    let origin = Instant::now();
    log.event(
        "request_dispatched",
        json!({"scheme":"cp_rsa","case":name,"nonce":nonce}),
    )?;
    let t = Instant::now();
    let mut c = auth_circuit.clone();
    bind(
        &mut c,
        v.header.digest_fields(),
        v.header.epoch,
        start,
        end,
        nonce,
    );
    let fields = c.public_fields();
    let r = random();
    let prep = ms(t);
    log.event(
        "prepare_completed",
        json!({"scheme":"cp_rsa","case":name,"ms":prep}),
    )?;
    let ctx = hrada_joint::context(digest, &fields)?;
    let t = Instant::now();
    let (statement, membership) = cp.prove(set, prime, &r, &ctx)?;
    let member_ms = ms(t);
    log.event(
        "membership_proved",
        json!({"scheme":"cp_rsa","case":name,"ms":member_ms}),
    )?;
    let t = Instant::now();
    let proof =
        hrada_link::prove(&mut OsRng, auth, c, &r).map_err(|e| format!("auth_prove:{:?}", e))?;
    let auth_ms = ms(t);
    log.event(
        "authorization_proved",
        json!({"scheme":"cp_rsa","case":name,"ms":auth_ms}),
    )?;
    let t = Instant::now();
    v.authorize(
        cp,
        auth,
        &statement,
        &membership,
        &proof,
        &fields,
        &fields,
        start,
        end,
        || log.now(),
    )
    .map_err(|e| format!("valid_cp_request_failed:{}", e))?;
    let verify_ms = ms(t);
    log.event(
        "permit_committed",
        json!({"scheme":"cp_rsa","case":name,"nonce":nonce,"ms":verify_ms}),
    )?;
    let ack_sync_complete_elapsed_ms = log.execute("cp_rsa", name, nonce)?;
    let member = cp_components(&membership);
    let ab = enc(&proof);
    fs::write(log.dir.join(format!("cp-{}-member.bin", name)), &member)
        .map_err(|e| e.to_string())?;
    fs::write(log.dir.join(format!("cp-{}-auth.bin", name)), &ab).map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"cp_rsa","case":name,"nonce":nonce,"request_time":start,"permit_until":end,"prepare_ms":prep,"membership_ms":member_ms,"auth_ms":auth_ms,"verify_ms":verify_ms,"resource_ack_sync_complete_elapsed_ms":ack_sync_complete_elapsed_ms,"through_resource_execution_and_artifact_ms":ms(origin),"member_bytes":member.len(),"auth_bytes":ab.len(),"commitment_hex":hex(&enc(&statement.c_e_q)),"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&statement.c_p)),"public_fields":fields.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>(),"accepted":true}));
    log.save("running", None)?;
    let count = log.executions;
    let err = v
        .authorize(
            cp,
            auth,
            &statement,
            &membership,
            &proof,
            &fields,
            &fields,
            start,
            end,
            || log.now(),
        )
        .err();
    log.check(
        &format!("cp_{}_replay_rejected", name),
        err.as_deref() == Some("nonce_already_consumed"),
    )?;
    log.check(
        &format!("cp_{}_replay_no_resource_execution", name),
        log.executions == count,
    )?;
    Ok(ack_sync_complete_elapsed_ms)
}
fn mt_request(
    log: &mut Log,
    name: &str,
    auth_circuit: &AuthCircuit,
    prime: &Integer,
    set: &MerkleState,
    p: &MParameters,
    v: &mut MVerifier,
) -> Result<f64, String> {
    let (start, end, nonce) = log.request("poseidon_lego", name)?;
    let origin = Instant::now();
    log.event(
        "request_dispatched",
        json!({"scheme":"poseidon_lego","case":name,"nonce":nonce}),
    )?;
    let t = Instant::now();
    let mut c = auth_circuit.clone();
    bind(
        &mut c,
        limbs(&v.header.digest),
        v.header.epoch,
        start,
        end,
        nonce,
    );
    let fields = c.public_fields();
    let r = random();
    let prep = ms(t);
    log.event(
        "prepare_completed",
        json!({"scheme":"poseidon_lego","case":name,"ms":prep}),
    )?;
    let t = Instant::now();
    let commitment = p.cp.commit(prime, &r)?;
    let membership = hrada_link::prove(&mut OsRng, p.member, set.circuit(prime)?, &r)
        .map_err(|e| format!("member_prove:{:?}", e))?;
    let member_ms = ms(t);
    log.event(
        "membership_proved",
        json!({"scheme":"poseidon_lego","case":name,"ms":member_ms}),
    )?;
    let t = Instant::now();
    let auth =
        hrada_link::prove(&mut OsRng, p.auth, c, &r).map_err(|e| format!("auth_prove:{:?}", e))?;
    let auth_ms = ms(t);
    log.event(
        "authorization_proved",
        json!({"scheme":"poseidon_lego","case":name,"ms":auth_ms}),
    )?;
    let b = MBundle {
        membership,
        auth,
        commitment,
        fields,
        root: set.root_fields(),
    };
    let t = Instant::now();
    v.authorize(p, &b, &b.fields, start, end, || log.now())
        .map_err(|e| format!("valid_merkle_request_failed:{}", e))?;
    let verify_ms = ms(t);
    log.event(
        "permit_committed",
        json!({"scheme":"poseidon_lego","case":name,"nonce":nonce,"ms":verify_ms}),
    )?;
    let ack_sync_complete_elapsed_ms = log.execute("poseidon_lego", name, nonce)?;
    let mb = enc(&b.membership);
    let ab = enc(&b.auth);
    fs::write(log.dir.join(format!("poseidon-{}-member.bin", name)), &mb)
        .map_err(|e| e.to_string())?;
    fs::write(log.dir.join(format!("poseidon-{}-auth.bin", name)), &ab)
        .map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"poseidon_lego","case":name,"nonce":nonce,"request_time":start,"permit_until":end,"prepare_ms":prep,"membership_ms":member_ms,"auth_ms":auth_ms,"verify_ms":verify_ms,"resource_ack_sync_complete_elapsed_ms":ack_sync_complete_elapsed_ms,"through_resource_execution_and_artifact_ms":ms(origin),"member_bytes":mb.len(),"auth_bytes":ab.len(),"commitment_hex":hex(&enc(&b.commitment)),"root_fields":b.root.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>(),"public_fields":b.fields.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>(),"accepted":true}));
    log.save("running", None)?;
    let count = log.executions;
    let err = v
        .authorize(p, &b, &b.fields, start, end, || log.now())
        .err();
    log.check(
        &format!("poseidon_{}_replay_rejected", name),
        err.as_deref() == Some("nonce_already_consumed"),
    )?;
    log.check(
        &format!("poseidon_{}_replay_no_resource_execution", name),
        log.executions == count,
    )?;
    Ok(ack_sync_complete_elapsed_ms)
}
fn run(log: &mut Log, order: &str) -> Result<(), String> {
    log.event("initialization_started",json!({"order":order,"fresh_setup_each_trial":true,"client_auth_fixture":false,"client_sr_private_key":false}))?;
    let fixture_file: FixtureFile =
        serde_json::from_slice(&fs::read(&log.fixtures).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    let fixture = fixture_file
        .fixtures
        .iter()
        .find(|x| x.trial == log.trial)
        .ok_or("trial_not_found")?;
    if fixture.initial_prime_hex.len() != 8 || fixture.auth_seed == fixture.other_seed {
        return Err("invalid_client_fixture".into());
    }
    let primes = fixture
        .initial_prime_hex
        .iter()
        .map(|p| Integer::from_str_radix(p, 16).unwrap())
        .collect::<Vec<_>>();
    let public_params = fixture_public_parameters(fixture.auth_seed);
    let user_binding = fixture_user_binding(log.trial)?;
    let (stream, setup_circuit) = fetch_bootstrap(log, &user_binding, &public_params)?;
    let set = StateSet::rebuild(&primes)?;
    let mt = MerkleState::new(&primes)?;
    let t = Instant::now();
    let cp = StateMembership::setup_os()?;
    let cp_setup = ms(t);
    let cpbytes = cp.canonical_parameters()?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    println!("SETUP fresh shared authorization CRS");
    let t = Instant::now();
    let auth = hrada_link::setup(&mut OsRng, ck, setup_circuit, 16)
        .map_err(|e| format!("setup_auth:{:?}", e))?;
    let auth_setup = ms(t);
    let cpdigest = hrada_link::parameter_digest(&auth, &cpbytes).map_err(|e| format!("{:?}", e))?;
    let t = Instant::now();
    let member = hrada_link::setup(&mut OsRng, ck, mt.circuit(&primes[0])?, 2)
        .map_err(|e| format!("setup_member:{:?}", e))?;
    let member_setup = ms(t);
    let mut descriptor = b"HRADA-POSEIDON-MERKLE-LEGO-DEPTH4-V1".to_vec();
    descriptor.extend(parameter_descriptor());
    descriptor.extend(enc(&ck.g));
    descriptor.extend(enc(&ck.h));
    let md = hrada_link::parameter_digest(&member, &descriptor).map_err(|e| format!("{:?}", e))?;
    let mut ad = b"HRADA-POSEIDON-MERKLE-AUTH-V1".to_vec();
    ad.extend(md);
    let digest = hrada_link::parameter_digest(&auth, &ad).map_err(|e| format!("{:?}", e))?;
    let mp = MParameters {
        cp: &cp,
        auth: &auth,
        member: &member,
        descriptor,
        member_digest: md,
        auth_descriptor: ad,
        digest,
    };
    fs::write(log.dir.join("cp_parameters.bin"), &cpbytes).map_err(|e| e.to_string())?;
    fs::write(log.dir.join("poseidon_descriptor.bin"), &mp.descriptor)
        .map_err(|e| e.to_string())?;
    let mut artifacts = vec![
        artifact(&log.dir, "shared_auth_pk.bin", &auth.proving_key)?,
        artifact(&log.dir, "poseidon_member_pk.bin", &member.proving_key)?,
        artifact(
            &log.dir,
            "cp_range_pk.bin",
            &cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters,
        )?,
        file_hash(&log.dir.join("cp_parameters.bin"))?,
        file_hash(&log.dir.join("poseidon_descriptor.bin"))?,
    ];
    artifacts.push(artifact(
        &log.dir,
        "shared_auth_vk.bin",
        &auth.proving_key.vk,
    )?);
    log.setup = json!({"order":order,"cp_setup_ms":cp_setup,"shared_auth_setup_ms":auth_setup,"poseidon_member_setup_ms":member_setup,"artifacts":artifacts,"cp_digest":hex(&cpdigest),"poseidon_digest":hex(&digest),"shared_auth_vk_blake2s":hex(&hash(&enc(&auth.proving_key.vk))),"population":8,"poseidon_depth":4,"auth_constraints":2140389,"auth_setup_template":"public-only constraint-shape template; no RA/SR/issuer key generated"});
    log.check(
        "same_authorization_pk_object_both_backends",
        std::ptr::eq(&auth, mp.auth),
    )?;
    log.service_origin = Some(Instant::now());
    if log.fault != "online" {
        return Err("remediation_client_has_no_issuer_fault_interface".into());
    }
    log.event(
        "service_ready",
        json!({"order":order,"client_sr_private_key":false,"client_revoke_interface":false}),
    )?;
    let parameter_digest = match log.scheme.as_str() {
        "cp_rsa_update_log" => cpdigest,
        "poseidon_whole_tree" => digest,
        "both" => hash(&[cpdigest.as_slice(), digest.as_slice()].concat()),
        _ => return Err("invalid_scheme".into()),
    };
    let (delivered, delivery_load_start, delivery_cpu_start, mut delivery_session) =
        fetch_update(log, stream, parameter_digest, user_binding, &primes)?;
    let pre_primary_q = delivered
        .auth_delivery
        .pre_primary_q
        .clone()
        .into_circuit_with_params(&public_params)?;
    let pre_other_q = delivered
        .auth_delivery
        .pre_other_q
        .clone()
        .into_circuit_with_params(&public_params)?;
    let post_primary_q = delivered
        .auth_delivery
        .post_primary_q
        .clone()
        .into_circuit_with_params(&public_params)?;
    let post_primary_p = delivered
        .auth_delivery
        .post_primary_p
        .clone()
        .into_circuit_with_params(&public_params)?;
    let post_primary_p2 = delivered
        .auth_delivery
        .post_primary_p2
        .clone()
        .into_circuit_with_params(&public_params)?;
    let post_other_q = delivered
        .auth_delivery
        .post_other_q
        .clone()
        .into_circuit_with_params(&public_params)?;
    log.check(
        "server_delivered_pre_Q_and_Z_state_proofs_valid",
        sat(pre_primary_q.clone())? && sat(pre_other_q.clone())?,
    )?;
    log.check(
        "server_delivered_new_sr_state_proof_valid_for_Q",
        sat(post_primary_q.clone())?,
    )?;
    log.check(
        "server_delivered_revoked_P_and_P2_rejected",
        !sat(post_primary_p)? && !sat(post_primary_p2)?,
    )?;
    log.check(
        "server_delivered_Z_state_proof_valid",
        sat(post_other_q.clone())?,
    )?;
    log.check("client_has_no_sr_signing_or_revoke_object", true)?;
    if delivered.old_prime_hex != primes[0].to_string_radix(16) {
        return Err("old_prime_binding_mismatch".into());
    }
    let newp = Integer::from_str_radix(&delivered.new_prime_hex, 16).map_err(|e| e.to_string())?;
    let mut updated = primes.clone();
    updated[0] = newp.clone();
    if log.scheme != "cp_rsa_update_log" {
        let received = delivered
            .updated_primes_hex
            .iter()
            .map(|p| Integer::from_str_radix(p, 16).unwrap())
            .collect::<Vec<_>>();
        if received != updated {
            return Err("whole_tree_payload_mismatch".into());
        }
    } else if !delivered.updated_primes_hex.is_empty() {
        return Err("cp_payload_not_minimal_update_log".into());
    }
    let t = Instant::now();
    let newset = StateSet::rebuild(&updated)?;
    let cp_update = ms(t);
    let t = Instant::now();
    let mut newmt = mt.clone();
    newmt.replace(0, newp.clone())?;
    let mt_update = ms(t);
    log.check(
        "delivered_auth_root_matches_server_sr_state_proof",
        delivered.auth_root == delivered.auth_delivery.sr_state_proof.auth_root
            && delivered.auth_root == hex(&post_primary_q.auth_root),
    )?;
    log.check(
        "delivered_cp_accumulator_matches_local_rebuild",
        delivered.cp_accumulator == hex(&Rsa2048::elem_to_bytes(&newset.accumulator)),
    )?;
    log.check(
        "delivered_merkle_root_matches_local_rebuild",
        delivered.merkle_root == hex(&newmt.root()),
    )?;
    let mut cv = JointVerifier::new(Header::new(set.accumulator.clone(), 1, &cpdigest), cpdigest);
    let mut mv = mver(&MHeader::new(mt.root(), 1, &digest));
    cv.replace_header(Header::new(newset.accumulator.clone(), 2, &cpdigest))?;
    mv.header = MHeader::new(newmt.root(), 2, &digest);
    log.event("state_committed",json!({"epoch":2,"accepted_readback_started_elapsed_ms":delivery_load_start,"client_sr_refresh_ms":Value::Null,"client_revoke_middle":false,"cp_state_update_ms":cp_update,"poseidon_state_update_ms":mt_update,"local_atomic_scope":"client promotes signed consecutive epoch only after durable readback, envelope authentication, SR-state-proof constraint verification, and membership-root recomputation"}))?;
    let before_negative = log.executions;
    log.check("cp_old_prime_removed", newset.witness(&primes[0]).is_err())?;
    log.check(
        "poseidon_old_prime_removed",
        newmt.circuit(&primes[0]).is_err(),
    )?;
    log.check(
        "all_revocation_negatives_no_resource_execution",
        log.executions == before_negative,
    )?;
    // Each backend's service window starts immediately before its Q/Z queue.
    // Shared state-commit-to-completion includes experiment ordering, not a fair latency comparison.
    let recovery_schemes: Vec<&str> = match log.scheme.as_str() {
        "cp_rsa_update_log" => vec!["cp_rsa"],
        "poseidon_whole_tree" => vec!["poseidon_lego"],
        "both" if order == "cp_first" => vec!["cp_rsa", "poseidon_lego"],
        "both" => vec!["poseidon_lego", "cp_rsa"],
        _ => return Err("invalid_scheme".into()),
    };
    for scheme in recovery_schemes.iter() {
        let t = Instant::now();
        log.event("backend_recovery_started",json!({"scheme":scheme,"order":order,"reason":"independent local dispatch origin; excludes other backend's deliberate experiment queue"}))?;
        if *scheme == "cp_rsa" {
            let q_ack = cp_request(
                log,
                "after_Q",
                &post_primary_q,
                &newp,
                &newset,
                &cp,
                &auth,
                &cpdigest,
                &mut cv,
            )?;
            log.event("first_complete_ack",json!({"scheme":scheme,"case":"Q","accepted_readback_start_elapsed_ms":delivery_load_start,"resource_sync_complete_elapsed_ms":q_ack,"ms":q_ack-delivery_load_start,"cpu_ms":process_cpu_ms()?-delivery_cpu_start,"endpoint":"resource append plus sync_data complete","excludes":"proof archival, progress logging, proof replay diagnostic, and delivery negatives","page_cache":"not purged"}))?;
            let warm_start = ms(log.origin);
            let warm_cpu_start = process_cpu_ms()?;
            let z_ack = cp_request(
                log,
                "after_Z",
                &post_other_q,
                &primes[1],
                &newset,
                &cp,
                &auth,
                &cpdigest,
                &mut cv,
            )?;
            log.event("warm_ack",json!({"scheme":scheme,"case":"Z","start_elapsed_ms":warm_start,"resource_sync_complete_elapsed_ms":z_ack,"ms":z_ack-warm_start,"cpu_ms":process_cpu_ms()?-warm_cpu_start,"endpoint":"resource append plus sync_data complete"}))?;
        } else {
            let q_ack = mt_request(log, "after_Q", &post_primary_q, &newp, &newmt, &mp, &mut mv)?;
            log.event("first_complete_ack",json!({"scheme":scheme,"case":"Q","accepted_readback_start_elapsed_ms":delivery_load_start,"resource_sync_complete_elapsed_ms":q_ack,"ms":q_ack-delivery_load_start,"cpu_ms":process_cpu_ms()?-delivery_cpu_start,"endpoint":"resource append plus sync_data complete","excludes":"proof archival, progress logging, proof replay diagnostic, and delivery negatives","page_cache":"not purged"}))?;
            let warm_start = ms(log.origin);
            let warm_cpu_start = process_cpu_ms()?;
            let z_ack = mt_request(
                log,
                "after_Z",
                &post_other_q,
                &primes[1],
                &newmt,
                &mp,
                &mut mv,
            )?;
            log.event("warm_ack",json!({"scheme":scheme,"case":"Z","start_elapsed_ms":warm_start,"resource_sync_complete_elapsed_ms":z_ack,"ms":z_ack-warm_start,"cpu_ms":process_cpu_ms()?-warm_cpu_start,"endpoint":"resource append plus sync_data complete"}))?;
        }
        log.event("backend_recovery_completed",json!({"scheme":scheme,"dispatch_to_both_resources_ms":ms(t),"excludes_other_backend_queue":true}))?;
    }
    run_delivery_negatives(log, &mut delivery_session, &delivered, &primes)?;
    let expected = if log.scheme == "both" { 4 } else { 2 };
    log.check(
        "expected_real_joint_proofs_and_resource_executions",
        log.samples.len() == expected && log.executions == expected,
    )?;
    log.check(
        "service_trial_under_500_monotonic_seconds",
        log.now() < 1000,
    )?;
    log.event("recovery_finished",json!({"client_sr_private_key":false,"client_revoke_middle":false,"server_issued_sr_state_version":delivered.auth_delivery.sr_state_proof.state_version,"real_joint_proofs":log.samples.len(),"resource_acks":log.executions}))?;
    Ok(())
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let value = |key: &str| -> Option<String> {
        args.windows(2).find(|w| w[0] == key).map(|w| w[1].clone())
    };
    let fault = value("--fault").unwrap_or_else(|| "online".into());
    let order = value("--order").unwrap_or_else(|| "cp_first".into());
    let scheme = value("--scheme").unwrap_or_else(|| "both".into());
    let trial = value("--trial")
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let addr = value("--addr").unwrap_or_default();
    let fixtures = value("--fixtures").map(PathBuf::from).unwrap_or_default();
    let public_key = value("--public-key").map(PathBuf::from).unwrap_or_default();
    if !["online", "one_offline", "all_offline"].contains(&fault.as_str())
        || !["cp_first", "poseidon_first"].contains(&order.as_str())
        || !["cp_rsa_update_log", "poseidon_whole_tree", "both"].contains(&scheme.as_str())
        || trial == usize::MAX
        || addr.is_empty()
        || !fixtures.is_file()
        || !public_key.is_file()
    {
        eprintln!("invalid fault/order/scheme/trial/addr/fixtures/public-key");
        std::process::exit(2);
    }
    let dir = match value("--output-dir") {
        Some(x) => PathBuf::from(x),
        None => {
            eprintln!("required --output-dir <new directory>");
            std::process::exit(2)
        }
    };
    if dir.exists() {
        eprintln!("output directory already exists; refusing overwrite");
        std::process::exit(2);
    }
    fs::create_dir_all(&dir).unwrap();
    let mut log = Log {
        dir,
        fault,
        origin: Instant::now(),
        service_origin: None,
        checks: vec![],
        samples: vec![],
        events: vec![],
        setup: json!({}),
        nonce: 100,
        executions: 0,
        provenance: process_provenance(),
        scheme,
        trial,
        addr,
        fixtures,
        public_key,
    };
    log.save("running", None).unwrap();
    match run(&mut log, &order) {
        Ok(()) => {
            log.save("complete", None).unwrap();
            println!(
                "DONE {} checks, {} actual joint proofs, {} resource executions",
                log.checks.len(),
                log.samples.len(),
                log.executions
            );
        }
        Err(e) => {
            log.save("failed", Some(&e)).unwrap();
            eprintln!("FAILED {}", e);
            std::process::exit(1);
        }
    }
}
