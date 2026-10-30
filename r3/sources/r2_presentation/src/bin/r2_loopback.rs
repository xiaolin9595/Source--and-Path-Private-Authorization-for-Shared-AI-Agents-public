use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::synthesis_patch::Mode;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    contract::{terminal_transcript, Request as CircuitRequest, Snapshot},
    fixture::{fixed, fresh_dummy_slot, public_inputs},
    indexed_revocation::IndexedRevocationTree,
    joint::{request_digest, snapshot_digest},
    phase_groth16::prove_with_randomness_mode,
    signature::{
        decode_public_key, decode_signature, encode_signature, public_key, sign, verify, SecretKey,
    },
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env, fs,
    io::{Cursor, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    thread,
    time::Duration,
};

const CHALLENGE_DOMAIN: &[u8] = b"pets2027-r2-challenge-to-fr-v1\0";
const CIRCUIT_ID: &str = "pets2027-r1-valid-dummy-native-depth20-20-32-grant3-lmax3-v1";
const WIRE_SCHEMA: &str = "pets2027-r2-loopback-envelope-v1";
const MAX_FRAME: usize = 1024 * 1024;
const TIMEOUT_SECS: u64 = 60;

#[derive(Clone, Serialize, Deserialize)]
struct CanonicalSnapshot {
    tuple_version: u64,
    root_ra: String,
    root_state: String,
    root_rev: String,
    state_epoch: u64,
    revocation_epoch: u64,
    issued_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct CanonicalRequest {
    circuit_id: String,
    verifier_id: String,
    pep_id: String,
    resource: String,
    action_onehot: u16,
    interval_lo: u64,
    interval_hi: u64,
    time: u64,
    challenge_b64: String,
    context: String,
    terminal_pk_b64: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Envelope {
    schema: String,
    circuit_id: String,
    challenge_b64: String,
    request: CanonicalRequest,
    snapshot: CanonicalSnapshot,
    public_inputs_b64: String,
    proof_b64: String,
    terminal_pk_b64: String,
    terminal_signature_b64: String,
}

#[derive(Deserialize)]
struct AgentControl {
    addr: String,
    length: usize,
    tpad_ms: u64,
    padded: bool,
    slow_ms: u64,
}

#[derive(Default)]
struct ReplayState {
    used: HashSet<[u8; 32]>,
}

fn monotonic_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    assert_eq!(rc, 0, "clock_gettime failed");
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn field_hex(x: Fr) -> String {
    let mut out = Vec::new();
    x.serialize_compressed(&mut out)
        .expect("field serialization");
    hex::encode(out)
}

fn parse_field(s: &str) -> Result<Fr, String> {
    let bytes = hex::decode(s).map_err(|_| "field hex")?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let out = Fr::deserialize_compressed(&mut cursor).map_err(|_| "field encoding")?;
    if cursor.position() as usize != bytes.len() || field_hex(out) != s {
        return Err("noncanonical field".into());
    }
    Ok(out)
}

fn point_b64(pk: &plan_a_joint_circuit::signature::PublicKey) -> String {
    let mut out = Vec::new();
    pk.0.serialize_compressed(&mut out)
        .expect("point serialization");
    STANDARD.encode(out)
}

fn challenge_field(challenge: &[u8; 32]) -> Fr {
    let mut h = Sha256::new();
    h.update(CHALLENGE_DOMAIN);
    h.update(challenge);
    Fr::from_le_bytes_mod_order(&h.finalize())
}

fn sha_limbs(bytes: &[u8]) -> (Fr, Fr, [u8; 32]) {
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    (
        Fr::from(u128::from_be_bytes(digest[..16].try_into().unwrap())),
        Fr::from(u128::from_be_bytes(digest[16..].try_into().unwrap())),
        digest,
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical_snapshot(snapshot: &Snapshot) -> CanonicalSnapshot {
    CanonicalSnapshot {
        tuple_version: snapshot.tuple_version,
        root_ra: field_hex(snapshot.root_ra),
        root_state: field_hex(snapshot.root_state),
        root_rev: field_hex(snapshot.root_rev),
        state_epoch: snapshot.state_epoch,
        revocation_epoch: snapshot.revocation_epoch,
        issued_at: snapshot.issued_at,
    }
}

fn canonical_request(request: &CircuitRequest, challenge: &[u8; 32]) -> CanonicalRequest {
    CanonicalRequest {
        circuit_id: field_hex(request.circuit_id),
        verifier_id: field_hex(request.verifier_id),
        pep_id: field_hex(request.pep_id),
        resource: field_hex(request.resource),
        action_onehot: request.action_onehot,
        interval_lo: request.interval_lo,
        interval_hi: request.interval_hi,
        time: request.time,
        challenge_b64: STANDARD.encode(challenge),
        context: field_hex(request.context),
        terminal_pk_b64: point_b64(&request.terminal),
    }
}

fn snapshot_from_wire(w: &CanonicalSnapshot) -> Result<Snapshot, String> {
    Ok(Snapshot {
        tuple_version: w.tuple_version,
        root_ra: parse_field(&w.root_ra)?,
        root_state: parse_field(&w.root_state)?,
        root_rev: parse_field(&w.root_rev)?,
        state_epoch: w.state_epoch,
        revocation_epoch: w.revocation_epoch,
        issued_at: w.issued_at,
    })
}

fn request_from_wire(
    w: &CanonicalRequest,
    request_lo: Fr,
    request_hi: Fr,
) -> Result<CircuitRequest, String> {
    let terminal_bytes = STANDARD
        .decode(&w.terminal_pk_b64)
        .map_err(|_| "terminal b64")?;
    Ok(CircuitRequest {
        canonical_request_lo: request_lo,
        canonical_request_hi: request_hi,
        circuit_id: parse_field(&w.circuit_id)?,
        verifier_id: parse_field(&w.verifier_id)?,
        pep_id: parse_field(&w.pep_id)?,
        resource: parse_field(&w.resource)?,
        action_onehot: w.action_onehot,
        interval_lo: w.interval_lo,
        interval_hi: w.interval_hi,
        time: w.time,
        nonce: Fr::from(0u64),
        context: parse_field(&w.context)?,
        terminal: decode_public_key(&terminal_bytes).map_err(|_| "terminal key")?,
    })
}

fn expected_public(snapshot: &Snapshot, request: &CircuitRequest) -> Vec<Fr> {
    let sd = snapshot_digest(snapshot);
    vec![
        Fr::from(snapshot.tuple_version),
        snapshot.root_ra,
        snapshot.root_state,
        snapshot.root_rev,
        Fr::from(snapshot.state_epoch),
        Fr::from(snapshot.revocation_epoch),
        Fr::from(snapshot.issued_at),
        sd,
        request.canonical_request_lo,
        request.canonical_request_hi,
        request.circuit_id,
        request.verifier_id,
        request.pep_id,
        request.resource,
        Fr::from(request.action_onehot as u64),
        Fr::from(request.interval_lo),
        Fr::from(request.interval_hi),
        Fr::from(request.time),
        request.nonce,
        request.context,
        request.terminal.0.x,
        request.terminal.0.y,
        request_digest(request, sd),
    ]
}

fn decode_exact<T: CanonicalDeserialize>(bytes: &[u8], what: &str) -> Result<T, String> {
    let mut cursor = Cursor::new(bytes);
    let value = T::deserialize_compressed(&mut cursor).map_err(|_| format!("bad {what}"))?;
    if cursor.position() as usize != bytes.len() {
        return Err(format!("trailing {what}"));
    }
    Ok(value)
}

fn verify_envelope(
    bytes: &[u8],
    challenge: [u8; 32],
    vk: &VerifyingKey<Bls12_381>,
    expected_terminal: &plan_a_joint_circuit::signature::PublicKey,
    state: &mut ReplayState,
) -> Result<(), String> {
    if bytes.len() > MAX_FRAME {
        return Err("oversize frame".into());
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| "bad envelope json")?;
    if envelope.schema != WIRE_SCHEMA || envelope.circuit_id != CIRCUIT_ID {
        return Err("wrong schema or circuit".into());
    }
    if serde_json::to_vec(&envelope).map_err(|_| "json")? != bytes {
        return Err("noncanonical envelope".into());
    }
    let challenge_wire = STANDARD
        .decode(&envelope.challenge_b64)
        .map_err(|_| "challenge b64")?;
    if challenge_wire.as_slice() != challenge
        || envelope.request.challenge_b64 != envelope.challenge_b64
    {
        return Err("challenge mismatch".into());
    }
    if state.used.contains(&challenge) {
        return Err("replayed challenge".into());
    }
    // All statement configuration is pinned locally.  The wire is evidence, not a
    // source of expected request/snapshot values.
    let mut expected_circuit = fixed::<3>(1, 0, 20, 20, 32);
    expected_circuit.request.nonce = challenge_field(&challenge);
    let expected_request = canonical_request(&expected_circuit.request, &challenge);
    let request_bytes = serde_json::to_vec(&expected_request).map_err(|_| "request json")?;
    let (request_lo, request_hi, request_sha) = sha_limbs(&request_bytes);
    expected_circuit.request.canonical_request_lo = request_lo;
    expected_circuit.request.canonical_request_hi = request_hi;
    let expected_snapshot = canonical_snapshot(&expected_circuit.snapshot);
    if serde_json::to_vec(&envelope.request).map_err(|_| "request json")? != request_bytes {
        return Err("request configuration mismatch".into());
    }
    if serde_json::to_vec(&envelope.snapshot).map_err(|_| "snapshot json")?
        != serde_json::to_vec(&expected_snapshot).map_err(|_| "snapshot json")?
    {
        return Err("snapshot configuration mismatch".into());
    }
    let snapshot_bytes = serde_json::to_vec(&expected_snapshot).map_err(|_| "snapshot json")?;
    let (_, _, snapshot_sha) = sha_limbs(&snapshot_bytes);
    if &expected_circuit.request.terminal != expected_terminal
        || envelope.terminal_pk_b64 != point_b64(expected_terminal)
    {
        return Err("unexpected terminal".into());
    }
    let public_bytes = STANDARD
        .decode(&envelope.public_inputs_b64)
        .map_err(|_| "public b64")?;
    let public: Vec<Fr> = decode_exact(&public_bytes, "public inputs")?;
    if public != expected_public(&expected_circuit.snapshot, &expected_circuit.request) {
        return Err("public statement mismatch".into());
    }
    let proof_bytes = STANDARD
        .decode(&envelope.proof_b64)
        .map_err(|_| "proof b64")?;
    let proof: Proof<Bls12_381> = decode_exact(&proof_bytes, "proof")?;
    if !Groth16::<Bls12_381>::verify(vk, &public, &proof).map_err(|_| "proof verify error")? {
        return Err("proof rejected".into());
    }
    let signature_bytes = STANDARD
        .decode(&envelope.terminal_signature_b64)
        .map_err(|_| "signature b64")?;
    let signature = decode_signature(&signature_bytes).map_err(|_| "bad signature")?;
    if !verify(
        expected_terminal,
        terminal_transcript(request_sha, snapshot_sha, CIRCUIT_ID, &proof_bytes),
        &signature,
    ) {
        return Err("terminal signature rejected".into());
    }
    state.used.insert(challenge);
    Ok(())
}

fn setup(out: &Path) {
    assert!(!out.exists(), "setup output exists");
    fs::create_dir(out).unwrap();
    let (pk, vk) = Groth16::<Bls12_381>::setup(fixed::<3>(3, 0, 20, 20, 32), &mut OsRng).unwrap();
    let mut pb = Vec::new();
    let mut vb = Vec::new();
    pk.serialize_compressed(&mut pb).unwrap();
    vk.serialize_compressed(&mut vb).unwrap();
    fs::write(out.join("pk.compressed"), &pb).unwrap();
    fs::write(out.join("vk.compressed"), &vb).unwrap();
    println!(
        "{}",
        json!({"event":"setup","pk_bytes":pb.len(),"vk_bytes":vb.len(),"challenge_domain":String::from_utf8_lossy(CHALLENGE_DOMAIN),"circuit_id":CIRCUIT_ID})
    );
}

fn make_envelope(
    pk: &ProvingKey<Bls12_381>,
    template: &plan_a_joint_circuit::joint::JointCircuit<3>,
    length: usize,
    challenge: [u8; 32],
    t_agent: u64,
    config_variant: &str,
) -> (Vec<u8>, u64, u64, u64, u64) {
    let mut circuit = template.clone();
    match config_variant {
        "normal" => {}
        "request" => circuit.request.context += Fr::from(1u64),
        "snapshot" => circuit.snapshot.issued_at += 1,
        "fr-circuit" => circuit.request.circuit_id += Fr::from(1u64),
        _ => panic!("unknown config variant"),
    }
    let terminal_secret = SecretKey(Scalar::from(14u64));
    let terminal = public_key(&terminal_secret).unwrap();
    assert_eq!(circuit.request.terminal, terminal);
    circuit.request.nonce = challenge_field(&challenge);
    let preliminary = canonical_request(&circuit.request, &challenge);
    let request_bytes = serde_json::to_vec(&preliminary).unwrap();
    let (request_lo, request_hi, _) = sha_limbs(&request_bytes);
    circuit.request.canonical_request_lo = request_lo;
    circuit.request.canonical_request_hi = request_hi;
    let canonical_request = canonical_request(&circuit.request, &challenge);
    assert_eq!(
        request_bytes,
        serde_json::to_vec(&canonical_request).unwrap()
    );
    let rev = IndexedRevocationTree::new(32).unwrap();
    for slot in circuit.grants.iter_mut().skip(length) {
        *slot = fresh_dummy_slot(3, &rev);
    }
    let t_prepared = monotonic_ns();
    let public = public_inputs(&circuit);
    let r = Fr::rand(&mut OsRng);
    let s = Fr::rand(&mut OsRng);
    let (proof, _) = prove_with_randomness_mode(pk, circuit.clone(), r, s, Mode::Native).unwrap();
    let t_proved = monotonic_ns();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let mut public_bytes = Vec::new();
    public.serialize_compressed(&mut public_bytes).unwrap();
    let snapshot = canonical_snapshot(&circuit.snapshot);
    let request_bytes = serde_json::to_vec(&canonical_request).unwrap();
    let snapshot_bytes = serde_json::to_vec(&snapshot).unwrap();
    let (_, _, request_sha) = sha_limbs(&request_bytes);
    let (_, _, snapshot_sha) = sha_limbs(&snapshot_bytes);
    let mut aux = [0u8; 32];
    OsRng.fill_bytes(&mut aux);
    let signature = sign(
        &terminal_secret,
        terminal_transcript(request_sha, snapshot_sha, CIRCUIT_ID, &proof_bytes),
        aux,
    )
    .unwrap();
    let envelope = Envelope {
        schema: WIRE_SCHEMA.into(),
        circuit_id: CIRCUIT_ID.into(),
        challenge_b64: STANDARD.encode(challenge),
        request: canonical_request,
        snapshot,
        public_inputs_b64: STANDARD.encode(public_bytes),
        proof_b64: STANDARD.encode(proof_bytes),
        terminal_pk_b64: point_b64(&terminal),
        terminal_signature_b64: STANDARD.encode(encode_signature(&signature)),
    };
    let bytes = serde_json::to_vec(&envelope).unwrap();
    assert!(bytes.len() <= MAX_FRAME);
    let t_ready = monotonic_ns();
    (bytes, t_agent, t_prepared, t_proved, t_ready)
}

fn run_agent_request(
    pk: &ProvingKey<Bls12_381>,
    templates: &[plan_a_joint_circuit::joint::JointCircuit<3>; 3],
    addr: &str,
    length: usize,
    tpad_ms: u64,
    padded: bool,
    slow_ms: u64,
) {
    assert!((1..=3).contains(&length));
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .unwrap();
    let mut challenge = [0u8; 32];
    stream.read_exact(&mut challenge).unwrap();
    let t_agent = monotonic_ns();
    let (frame, _, t_prepared, t_proved, mut t_ready) = make_envelope(
        pk,
        &templates[length - 1],
        length,
        challenge,
        t_agent,
        "normal",
    );
    if slow_ms > 0 {
        thread::sleep(Duration::from_millis(slow_ms));
        t_ready = monotonic_ns();
    }
    let elapsed = t_ready - t_agent;
    let tpad_ns = tpad_ms * 1_000_000;
    let k = if padded {
        std::cmp::max(1, (elapsed + tpad_ns - 1) / tpad_ns)
    } else {
        0
    };
    let deadline = if padded {
        t_agent + k * tpad_ns
    } else {
        t_ready
    };
    while monotonic_ns() < deadline {
        thread::sleep(Duration::from_micros(100));
    }
    let t_send_call = monotonic_ns();
    let len = u32::try_from(frame.len()).unwrap().to_be_bytes();
    stream.write_all(&len).unwrap();
    stream.write_all(&frame).unwrap();
    stream.flush().unwrap();
    let t_send_return = monotonic_ns();
    let envelope: Envelope = serde_json::from_slice(&frame).unwrap();
    let proof_bytes = STANDARD.decode(&envelope.proof_b64).unwrap();
    println!(
        "{}",
        json!({"event":"agent_complete","length_private":length,"padded_private":padded,"frame_bytes":frame.len(),"t_agent_ns":t_agent,"t_prepared_ns":t_prepared,"t_proved_ns":t_proved,"t_ready_ns":t_ready,"k":k,"deadline_ns":deadline,"t_send_call_ns":t_send_call,"t_send_return_ns":t_send_return,"overflow":k>1,"overshoot_ns":t_send_call.saturating_sub(deadline),"actual_wait_ns":t_send_call.saturating_sub(t_ready),"challenge_sha256":sha256_hex(&challenge),"proof_sha256":sha256_hex(&proof_bytes),"envelope_sha256":sha256_hex(&frame)})
    );
    std::io::stdout().flush().unwrap();
}

fn prepared_agent(
    pk_path: &Path,
) -> (
    ProvingKey<Bls12_381>,
    [plan_a_joint_circuit::joint::JointCircuit<3>; 3],
) {
    let pk_bytes = fs::read(pk_path).unwrap();
    let pk: ProvingKey<Bls12_381> = decode_exact(&pk_bytes, "proving key").unwrap();
    let templates = [
        fixed::<3>(1, 0, 20, 20, 32),
        fixed::<3>(2, 0, 20, 20, 32),
        fixed::<3>(3, 0, 20, 20, 32),
    ];
    (pk, templates)
}

fn run_agent(addr: &str, pk_path: &Path, length: usize, tpad_ms: u64, padded: bool, slow_ms: u64) {
    let (pk, templates) = prepared_agent(pk_path);
    run_agent_request(&pk, &templates, addr, length, tpad_ms, padded, slow_ms);
}

fn run_agent_serve(pk_path: &Path) {
    use std::io::BufRead;
    let (pk, templates) = prepared_agent(pk_path);
    println!(
        "{}",
        json!({"event":"agent_ready","templates":3,"depths":[20,20,32],"grant_depth":3})
    );
    std::io::stdout().flush().unwrap();
    for line in std::io::stdin().lock().lines() {
        let control: AgentControl =
            serde_json::from_str(&line.unwrap()).expect("bad private control");
        run_agent_request(
            &pk,
            &templates,
            &control.addr,
            control.length,
            control.tpad_ms,
            control.padded,
            control.slow_ms,
        );
    }
}

fn run_receiver(addr: &str, vk_path: &Path, mutation_gate: bool) {
    let vk_bytes = fs::read(vk_path).unwrap();
    let vk: VerifyingKey<Bls12_381> = decode_exact(&vk_bytes, "verifying key").unwrap();
    let terminal = public_key(&SecretKey(Scalar::from(14u64))).unwrap();
    let listener = TcpListener::bind(addr).unwrap();
    println!(
        "{}",
        json!({"event":"receiver_ready","addr":listener.local_addr().unwrap().to_string()})
    );
    std::io::stdout().flush().unwrap();
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(TIMEOUT_SECS)))
        .unwrap();
    let mut challenge = [0u8; 32];
    OsRng.fill_bytes(&mut challenge);
    let t_challenge_send = monotonic_ns();
    stream.write_all(&challenge).unwrap();
    stream.flush().unwrap();
    let mut len = [0u8; 4];
    stream.read_exact(&mut len).unwrap();
    let frame_len = u32::from_be_bytes(len) as usize;
    assert!(frame_len <= MAX_FRAME, "oversize frame");
    let mut frame = vec![0u8; frame_len];
    stream.read_exact(&mut frame).unwrap();
    let t_arrival = monotonic_ns(); // Frozen endpoint: before any proof/signature verification.
    let t_verify_start = monotonic_ns();
    let mut state = ReplayState::default();
    let verified = verify_envelope(&frame, challenge, &vk, &terminal, &mut state).is_ok();
    let t_verify_end = monotonic_ns();
    assert!(verified, "receiver verification failed");
    let mut mutation_results = serde_json::Map::new();
    if mutation_gate {
        let envelope: Envelope = serde_json::from_slice(&frame).unwrap();
        let cases: Vec<(&str, Envelope)> = vec![
            ("wrong_circuit", {
                let mut x = envelope.clone();
                x.circuit_id.push('x');
                x
            }),
            ("wrong_request", {
                let mut x = envelope.clone();
                x.request.context = field_hex(Fr::from(999u64));
                x
            }),
            ("wrong_snapshot", {
                let mut x = envelope.clone();
                x.snapshot.issued_at += 1;
                x
            }),
            ("wrong_signature", {
                let mut x = envelope.clone();
                x.terminal_signature_b64 = STANDARD.encode([0u8; 64]);
                x
            }),
            ("wrong_proof", {
                let mut x = envelope.clone();
                let mut b = STANDARD.decode(&x.proof_b64).unwrap();
                b[0] ^= 1;
                x.proof_b64 = STANDARD.encode(b);
                x
            }),
        ];
        for (name, mutated) in cases {
            let bytes = serde_json::to_vec(&mutated).unwrap();
            let mut fresh = ReplayState::default();
            mutation_results.insert(
                name.into(),
                json!(verify_envelope(&bytes, challenge, &vk, &terminal, &mut fresh).is_err()),
            );
        }
        let mut wrong_challenge = challenge;
        wrong_challenge[0] ^= 1;
        let mut fresh = ReplayState::default();
        mutation_results.insert(
            "wrong_challenge".into(),
            json!(verify_envelope(&frame, wrong_challenge, &vk, &terminal, &mut fresh).is_err()),
        );
        mutation_results.insert(
            "replay".into(),
            json!(verify_envelope(&frame, challenge, &vk, &terminal, &mut state).is_err()),
        );
    }
    let accepted_envelope: Envelope = serde_json::from_slice(&frame).unwrap();
    let accepted_proof = STANDARD.decode(&accepted_envelope.proof_b64).unwrap();
    println!(
        "{}",
        json!({"event":"receiver_complete","frame_bytes":frame_len,"t_challenge_send_ns":t_challenge_send,"t_arrival_ns":t_arrival,"t_verify_start_ns":t_verify_start,"t_verify_end_ns":t_verify_end,"primary_duration_ns":t_arrival-t_challenge_send,"arrival_recorded_before_verification":t_arrival<=t_verify_start && t_verify_start<=t_verify_end,"verified":verified,"proof_verified":verified,"signature_verified":verified,"challenge_sha256":sha256_hex(&challenge),"proof_sha256":sha256_hex(&accepted_proof),"envelope_sha256":sha256_hex(&frame),"mutation_gate":mutation_results})
    );
}

fn wire_equality_gate(pk_path: &Path) {
    let pk_bytes = fs::read(pk_path).unwrap();
    let pk: ProvingKey<Bls12_381> = decode_exact(&pk_bytes, "proving key").unwrap();
    let challenge = [0x5au8; 32];
    let templates = [
        fixed::<3>(1, 0, 20, 20, 32),
        fixed::<3>(2, 0, 20, 20, 32),
        fixed::<3>(3, 0, 20, 20, 32),
    ];
    let mut common: Option<(CanonicalRequest, CanonicalSnapshot, String, usize)> = None;
    let mut frame_lengths = Vec::new();
    for length in 1..=3 {
        let (bytes, ..) = make_envelope(
            &pk,
            &templates[length - 1],
            length,
            challenge,
            monotonic_ns(),
            "normal",
        );
        let text = std::str::from_utf8(&bytes).unwrap();
        for forbidden in [
            "\"length\"",
            "\"arm\"",
            "\"block\"",
            "\"session\"",
            "\"timings\"",
            "\"label\"",
            "\"pA\"",
            "\"pB\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "forbidden receiver-wire field {forbidden}"
            );
        }
        let envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
        let now = (
            envelope.request,
            envelope.snapshot,
            envelope.public_inputs_b64,
            bytes.len(),
        );
        if let Some(expected) = &common {
            assert_eq!(
                serde_json::to_vec(&now.0).unwrap(),
                serde_json::to_vec(&expected.0).unwrap()
            );
            assert_eq!(
                serde_json::to_vec(&now.1).unwrap(),
                serde_json::to_vec(&expected.1).unwrap()
            );
            assert_eq!(now.2, expected.2);
            assert_eq!(now.3, expected.3);
        } else {
            common = Some(now);
        }
        frame_lengths.push(bytes.len());
    }
    println!(
        "{}",
        json!({"event":"wire_equality_gate","same_challenge":true,"canonical_request_equal":true,"canonical_snapshot_equal":true,"public_inputs_equal":true,"fixed_frame_bytes":frame_lengths[0],"frame_lengths":frame_lengths,"forbidden_metadata_absent":true})
    );
}

fn pinned_config_negative_gate(pk_path: &Path, vk_path: &Path) {
    let (pk, templates) = prepared_agent(pk_path);
    let vk_bytes = fs::read(vk_path).unwrap();
    let vk: VerifyingKey<Bls12_381> = decode_exact(&vk_bytes, "verifying key").unwrap();
    let terminal = public_key(&SecretKey(Scalar::from(14u64))).unwrap();
    let challenge = [0x36u8; 32];
    let mut rejected = serde_json::Map::new();
    for variant in ["request", "snapshot", "fr-circuit"] {
        let (bytes, ..) = make_envelope(&pk, &templates[0], 1, challenge, monotonic_ns(), variant);
        let mut state = ReplayState::default();
        rejected.insert(
            variant.into(),
            json!(verify_envelope(&bytes, challenge, &vk, &terminal, &mut state).is_err()),
        );
    }
    assert!(rejected.values().all(|v| v == &json!(true)));
    println!(
        "{}",
        json!({"event":"pinned_config_negative_gate","valid_proof_and_terminal_signature_for_alternate_statement":true,"expected_config_rejected":rejected})
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup") if args.len()==3 => setup(Path::new(&args[2])),
        Some("receiver") if args.len()==5 => run_receiver(&args[2],Path::new(&args[3]),args[4]=="mutation-gate"),
        Some("agent") if args.len()==8 => run_agent(&args[2],Path::new(&args[3]),args[4].parse().unwrap(),args[5].parse().unwrap(),args[6]=="padded",args[7].parse().unwrap()),
        Some("agent-serve") if args.len()==3 => run_agent_serve(Path::new(&args[2])),
        Some("wire-equality-gate") if args.len()==3 => wire_equality_gate(Path::new(&args[2])),
        Some("pinned-config-negative-gate") if args.len()==4 => pinned_config_negative_gate(Path::new(&args[2]),Path::new(&args[3])),
        _ => panic!("usage: setup OUT | receiver ADDR VK mutation-gate|normal | agent ADDR PK LENGTH TPAD_MS padded|unpadded SLOW_MS | agent-serve PK | wire-equality-gate PK | pinned-config-negative-gate PK VK"),
    }
}
