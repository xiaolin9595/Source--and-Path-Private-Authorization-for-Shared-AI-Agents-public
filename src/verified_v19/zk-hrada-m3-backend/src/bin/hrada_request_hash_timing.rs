//! Isolated paired-timing worker for the request-hash Auth experiment.
//! The default Auth relation and proof components are not modified here.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::{
    protocols::{
        hrada_auth::{AuthCircuit, AuthFixture, ExperimentalAuthWithoutRequestHash},
        hrada_joint::{self, Header, JointVerifier},
        hrada_link::{self, LinkParameters},
        hrada_membership::{allocate_prime, CpProof, StateMembership, StateSet},
    },
    utils::integer_to_bigint_mod_q,
};
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Map, Value};
use std::{
    env,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::PathBuf,
    time::Instant,
};

const FIXTURE_SEED: u64 = 20261017;
const REQUEST_FIELDS: usize = 16;
const PROOFS_PER_VARIANT: u64 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Variant {
    Baseline,
    Candidate,
}

impl Variant {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "A" | "baseline" => Ok(Self::Baseline),
            "B" | "candidate" => Ok(Self::Candidate),
            _ => Err(format!("unknown variant: {}", value)),
        }
    }

    fn code(self) -> &'static str {
        match self {
            Self::Baseline => "A",
            Self::Candidate => "B",
        }
    }

    fn relation(self) -> &'static str {
        match self {
            Self::Baseline => "default AuthCircuit with domain-8 request hash",
            Self::Candidate => "ExperimentalAuthWithoutRequestHash",
        }
    }
}

struct Args {
    output: PathBuf,
    trial: u64,
    position: u64,
    variant: Variant,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut output = None;
        let mut trial = None;
        let mut position = None;
        let mut variant = None;
        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("missing value after {}", arg))?;
            match arg.as_str() {
                "--output" => output = Some(PathBuf::from(value)),
                "--trial" => trial = Some(value.parse::<u64>().map_err(|e| e.to_string())?),
                "--position" => position = Some(value.parse::<u64>().map_err(|e| e.to_string())?),
                "--variant" => variant = Some(Variant::parse(&value)?),
                _ => return Err(format!("unknown argument: {}", arg)),
            }
        }
        let args = Self {
            output: output.ok_or("missing --output")?,
            trial: trial.ok_or("missing --trial")?,
            position: position.ok_or("missing --position")?,
            variant: variant.ok_or("missing --variant")?,
        };
        if !(1..=4).contains(&args.trial) || !(1..=2).contains(&args.position) {
            return Err("trial must be 1..=4 and position must be 1..=2".into());
        }
        Ok(args)
    }
}

struct DurableLog {
    file: File,
    sequence: u64,
    trial: u64,
    position: u64,
    variant: Variant,
}

impl DurableLog {
    fn open(args: &Args) -> Result<Self, String> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&args.output)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            file,
            sequence: 0,
            trial: args.trial,
            position: args.position,
            variant: args.variant,
        })
    }

    fn emit(&mut self, stage: &str, status: &str, data: Value) -> Result<(), String> {
        self.sequence = self.sequence.checked_add(1).ok_or("sequence overflow")?;
        let event = json!({
            "schema": "hrada-request-hash-timing-stage-v1",
            "sequence_in_worker": self.sequence,
            "trial": self.trial,
            "position": self.position,
            "variant": self.variant.code(),
            "relation": self.variant.relation(),
            "worker_pid": std::process::id() as u64,
            "stage": stage,
            "status": status,
            "data": data,
        });
        serde_json::to_writer(&mut self.file, &event).map_err(|e| e.to_string())?;
        self.file.write_all(b"\n").map_err(|e| e.to_string())?;
        self.file.flush().map_err(|e| e.to_string())?;
        self.file.sync_data().map_err(|e| e.to_string())
    }
}

struct StageClock {
    wall: Instant,
    cpu_seconds: f64,
}

impl StageClock {
    fn start() -> Result<Self, String> {
        Ok(Self {
            wall: Instant::now(),
            cpu_seconds: process_cpu_seconds()?,
        })
    }

    fn stop(self) -> Result<(f64, f64), String> {
        let cpu = process_cpu_seconds()? - self.cpu_seconds;
        if cpu < 0.0 {
            return Err("process CPU clock moved backwards".into());
        }
        Ok((self.wall.elapsed().as_secs_f64() * 1000.0, cpu))
    }
}

fn process_cpu_seconds() -> Result<f64, String> {
    // POSIX clock(), cumulative process CPU including worker threads. This run
    // is macOS, where CLOCKS_PER_SEC is 1,000,000. The environment record keeps
    // that platform assumption explicit rather than claiming portability/pinning.
    extern "C" {
        fn clock() -> i64;
    }
    let ticks = unsafe { clock() };
    if ticks < 0 {
        return Err("process_cpu_clock_failed".into());
    }
    Ok(ticks as f64 / 1_000_000.0)
}

#[derive(Default)]
struct CountingWriter {
    bytes: u64,
}

impl Write for CountingWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buffer.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "byte count overflow"))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn canonical_sizes<T: CanonicalSerialize>(value: &T) -> Result<(u64, u64), String> {
    let mut compressed = CountingWriter::default();
    value
        .serialize(&mut compressed)
        .map_err(|e| format!("canonical compressed serialization: {:?}", e))?;
    let mut uncompressed = CountingWriter::default();
    value
        .serialize_uncompressed(&mut uncompressed)
        .map_err(|e| format!("canonical uncompressed serialization: {:?}", e))?;
    Ok((compressed.bytes, uncompressed.bytes))
}

fn cp_components_size(proof: &CpProof) -> Result<u64, String> {
    let mut total = 0u64;
    let mut add = |length: usize| -> Result<(), String> {
        total = total
            .checked_add(4)
            .and_then(|v| v.checked_add(length as u64))
            .ok_or_else(|| "CP component size overflow".to_owned())?;
        Ok(())
    };
    for element in [
        &proof.c_e,
        &proof.proof_root.message1.c_w,
        &proof.proof_root.message1.c_r,
        &proof.proof_root.message2.alpha1,
        &proof.proof_root.message2.alpha2,
        &proof.proof_root.message2.alpha3,
        &proof.proof_root.message2.alpha4,
        &proof.proof_modeq.message1.alpha1,
    ]
    .iter()
    {
        add(Rsa2048::elem_to_bytes(element).len())?;
    }
    let root = &proof.proof_root.message3;
    let modeq = &proof.proof_modeq.message2;
    for integer in [
        &root.s_e,
        &root.s_r,
        &root.s_r_2,
        &root.s_r_3,
        &root.s_beta,
        &root.s_delta,
        &modeq.s_e,
        &modeq.s_r,
    ]
    .iter()
    {
        let digits = (**integer).clone().abs().to_digits::<u8>(Order::MsfBe);
        add(1usize
            .checked_add(digits.len())
            .ok_or("CP integer size overflow")?)?;
    }
    add(canonical_sizes(&proof.proof_modeq.message1.alpha2)?.0 as usize)?;
    add(canonical_sizes(&modeq.s_r_q)?.0 as usize)?;
    add(canonical_sizes(&proof.proof_hash_to_prime)?.0 as usize)?;
    Ok(total)
}

fn scalar_integer() -> Integer {
    let mut bytes = Vec::new();
    Fr::rand(&mut OsRng).serialize(&mut bytes).unwrap();
    Integer::from_digits(&bytes, Order::Lsf)
}

fn update_header(fixture: &mut AuthFixture, header: &Header) {
    let digest = header.digest_fields();
    fixture.base.request.fields[0] = digest[0];
    fixture.base.request.fields[1] = digest[1];
    fixture.base.request.fields[2] = Fr::from(header.epoch);
}

fn setup_auth(
    variant: Variant,
    circuit: AuthCircuit,
    cp: &StateMembership,
) -> Result<LinkParameters, String> {
    let commitment = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    match variant {
        Variant::Baseline => hrada_link::setup(&mut OsRng, commitment, circuit, REQUEST_FIELDS),
        Variant::Candidate => hrada_link::setup(
            &mut OsRng,
            commitment,
            ExperimentalAuthWithoutRequestHash(circuit),
            REQUEST_FIELDS,
        ),
    }
    .map_err(|e| format!("Auth setup: {:?}", e))
}

fn prove_auth(
    variant: Variant,
    link: &LinkParameters,
    circuit: AuthCircuit,
    randomness: &Integer,
) -> Result<legogro16::Proof<Bls12_381>, String> {
    match variant {
        Variant::Baseline => hrada_link::prove(&mut OsRng, link, circuit, randomness),
        Variant::Candidate => hrada_link::prove(
            &mut OsRng,
            link,
            ExperimentalAuthWithoutRequestHash(circuit),
            randomness,
        ),
    }
    .map_err(|e| format!("Auth prove: {:?}", e))
}

fn verifier(header: &Header, digest: [u8; 32]) -> JointVerifier {
    JointVerifier::new(
        Header::new(header.accumulator.clone(), header.epoch, &digest),
        digest,
    )
}

fn timed_data(wall_ms: f64, cpu_seconds: f64) -> Map<String, Value> {
    let mut data = Map::new();
    data.insert("wall_ms".into(), json!(wall_ms));
    data.insert("process_cpu_seconds".into(), json!(cpu_seconds));
    data
}

fn run(args: &Args, log: &mut DurableLog) -> Result<(), String> {
    let lifecycle = StageClock::start()?;
    log.emit(
        "worker_start",
        "ok",
        json!({
            "fixture_seed": FIXTURE_SEED,
            "proofs_planned": PROOFS_PER_VARIANT,
            "rayon_num_threads": env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".into()),
            "rayon_thread_count_observation": "configured by RAYON_NUM_THREADS; not queried through a direct rayon dependency",
            "process_cpu_clock": format!("POSIX clock(); CLOCKS_PER_SEC=1,000,000; target_os={}", env::consts::OS),
            "default_protocol_changed": false,
            "auth_boundary": "existing hrada_link::prove adapter including constraint-satisfaction precheck",
            "joint_verify_boundary": "existing JointVerifier::authorize including internal prepared-VK construction",
        }),
    )?;

    let clock = StageClock::start()?;
    let cp = StateMembership::setup_os()?;
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("setup_kind".into(), json!("fresh CP setup"));
    log.emit("cp_setup", "ok", Value::Object(data))?;

    let clock = StageClock::start()?;
    let cp_parameters = cp.canonical_parameters()?;
    let prime = allocate_prime();
    let set = StateSet::rebuild(&[prime.clone()])?;
    let prime_field = integer_to_bigint_mod_q::<G1Projective>(&prime)
        .map_err(|e| format!("prime conversion: {:?}", e))?;
    let mut fixture = AuthFixture::new(FIXTURE_SEED);
    fixture.refresh_state(prime_field);
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("business_fixture".into(), json!("Q path, one-member state"));
    data.insert("prime_bits".into(), json!(prime.significant_bits() as u64));
    data.insert(
        "cp_parameter_bytes".into(),
        json!(cp_parameters.len() as u64),
    );
    log.emit("fixture_and_state", "ok", Value::Object(data))?;

    let clock = StageClock::start()?;
    let link = setup_auth(args.variant, fixture.circuit(), &cp)?;
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("setup_kind".into(), json!("fresh Auth setup"));
    data.insert(
        "h_query_len".into(),
        json!(link.proving_key.h_query.len() as u64),
    );
    data.insert(
        "gamma_abc_len".into(),
        json!(link.proving_key.vk.gamma_abc_g1.len() as u64),
    );
    data.insert(
        "link_bases_len".into(),
        json!(link.proving_key.vk.link_bases.len() as u64),
    );
    log.emit("auth_setup", "ok", Value::Object(data))?;

    let clock = StageClock::start()?;
    let (pk_compressed, pk_uncompressed) = canonical_sizes(&link.proving_key)?;
    let (vk_compressed, vk_uncompressed) = canonical_sizes(&link.proving_key.vk)?;
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert(
        "method".into(),
        json!("streaming counting writer; no key bytes retained or written"),
    );
    data.insert("before_proof_1".into(), json!(true));
    data.insert(
        "auth_pk_canonical_compressed_bytes".into(),
        json!(pk_compressed),
    );
    data.insert(
        "auth_pk_canonical_uncompressed_bytes".into(),
        json!(pk_uncompressed),
    );
    data.insert(
        "auth_vk_canonical_compressed_bytes".into(),
        json!(vk_compressed),
    );
    data.insert(
        "auth_vk_canonical_uncompressed_bytes".into(),
        json!(vk_uncompressed),
    );
    log.emit("key_serialization", "ok", Value::Object(data))?;

    let digest = hrada_link::parameter_digest(&link, &cp_parameters)
        .map_err(|e| format!("parameter digest: {:?}", e))?;
    let header = Header::new(set.accumulator.clone(), 1, &digest);
    update_header(&mut fixture, &header);
    let mut joint = verifier(&header, digest);

    for proof_index in 1..=PROOFS_PER_VARIANT {
        fixture.base.request.fields[10] = Fr::from(98 + proof_index);
        let circuit = fixture.circuit();
        let fields = circuit.public_fields();
        let context = hrada_joint::context(&digest, &fields)?;
        let randomness = scalar_integer();

        let cp_clock = StageClock::start()?;
        let (statement, cp_proof) = cp.prove(&set, &prime, &randomness, &context)?;
        let (cp_wall_ms, cp_cpu_seconds) = cp_clock.stop()?;
        let mut data = timed_data(cp_wall_ms, cp_cpu_seconds);
        data.insert("proof_index".into(), json!(proof_index));
        data.insert(
            "phase".into(),
            json!(if proof_index == 1 { "first" } else { "later" }),
        );
        log.emit("cp_prove", "ok", Value::Object(data))?;

        let auth_clock = StageClock::start()?;
        let auth_proof = prove_auth(args.variant, &link, circuit, &randomness)?;
        let (auth_wall_ms, auth_cpu_seconds) = auth_clock.stop()?;
        let mut data = timed_data(auth_wall_ms, auth_cpu_seconds);
        data.insert("proof_index".into(), json!(proof_index));
        data.insert(
            "phase".into(),
            json!(if proof_index == 1 { "first" } else { "later" }),
        );
        data.insert(
            "boundary".into(),
            json!("hrada_link::prove including constraint-satisfaction precheck"),
        );
        log.emit("auth_prove", "ok", Value::Object(data))?;

        let serialization_clock = StageClock::start()?;
        let (auth_compressed, auth_uncompressed) = canonical_sizes(&auth_proof)?;
        let cp_custom_bytes = cp_components_size(&cp_proof)?;
        let (statement_commitment_compressed, statement_commitment_uncompressed) =
            canonical_sizes(&statement.c_e_q)?;
        let statement_accumulator_bytes = Rsa2048::elem_to_bytes(&statement.c_p).len() as u64;
        let (serialization_wall_ms, serialization_cpu_seconds) = serialization_clock.stop()?;
        let mut data = timed_data(serialization_wall_ms, serialization_cpu_seconds);
        data.insert("proof_index".into(), json!(proof_index));
        data.insert(
            "auth_proof_canonical_compressed_bytes".into(),
            json!(auth_compressed),
        );
        data.insert(
            "auth_proof_canonical_uncompressed_bytes".into(),
            json!(auth_uncompressed),
        );
        data.insert(
            "cp_proof_component_encoding_bytes".into(),
            json!(cp_custom_bytes),
        );
        data.insert(
            "cp_proof_encoding".into(),
            json!("existing experiment component encoding; CP proof type has no CanonicalSerialize implementation"),
        );
        data.insert(
            "cp_statement_accumulator_bytes".into(),
            json!(statement_accumulator_bytes),
        );
        data.insert(
            "cp_statement_commitment_canonical_compressed_bytes".into(),
            json!(statement_commitment_compressed),
        );
        data.insert(
            "cp_statement_commitment_canonical_uncompressed_bytes".into(),
            json!(statement_commitment_uncompressed),
        );
        log.emit("proof_serialization", "ok", Value::Object(data))?;

        let joint_clock = StageClock::start()?;
        let result = joint.authorize(
            &cp,
            &link,
            &statement,
            &cp_proof,
            &auth_proof,
            &fields,
            &fields,
            500,
            550,
            || 500,
        );
        let (joint_wall_ms, joint_cpu_seconds) = joint_clock.stop()?;
        let accepted = result.is_ok();
        let mut data = timed_data(joint_wall_ms, joint_cpu_seconds);
        data.insert("proof_index".into(), json!(proof_index));
        data.insert("accepted".into(), json!(accepted));
        data.insert(
            "boundary".into(),
            json!("one JointVerifier::authorize call; includes CP verify and Auth verify with internal VK preparation"),
        );
        if let Err(error) = &result {
            data.insert("error".into(), json!(error));
        }
        log.emit(
            "joint_verify",
            if accepted { "ok" } else { "rejected" },
            Value::Object(data),
        )?;
        result.map_err(|error| format!("joint verification rejected: {}", error))?;

        let subtotal_wall_ms = cp_wall_ms + auth_wall_ms + joint_wall_ms;
        let subtotal_cpu_seconds = cp_cpu_seconds + auth_cpu_seconds + joint_cpu_seconds;
        log.emit(
            "request_subtotal",
            "ok",
            json!({
                "proof_index": proof_index,
                "phase": if proof_index == 1 { "first" } else { "later" },
                "wall_ms": subtotal_wall_ms,
                "process_cpu_seconds": subtotal_cpu_seconds,
                "formula": "cp_prove + auth_prove + one joint_verify",
                "excluded": "fixture construction, witness preparation outside called CP prove API, setup, serialization, durable logging, network, and other I/O",
                "not_end_to_end": true,
            }),
        )?;
    }

    let (wall_ms, cpu_seconds) = lifecycle.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("proofs_completed".into(), json!(PROOFS_PER_VARIANT));
    data.insert("all_joint_accepted".into(), json!(true));
    data.insert("lifecycle_includes_logging".into(), json!(true));
    log.emit("worker_end", "ok", Value::Object(data))
}

fn serialization_smoke() -> Result<(), String> {
    let event = json!({
        "schema": "hrada-request-hash-timing-stage-v1",
        "sequence_in_worker": 1u64,
        "trial": 1u64,
        "position": 1u64,
        "variant": "A",
        "stage": "schema_smoke",
        "status": "ok",
        "data": {
            "wall_ms": 1.25f64,
            "process_cpu_seconds": 0.5f64,
            "bytes": 42u64,
            "accepted": true,
        }
    });
    let encoded = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
    let decoded: Value = serde_json::from_slice(&encoded).map_err(|e| e.to_string())?;
    for path in ["sequence_in_worker", "trial", "position"] {
        if decoded.get(path).and_then(Value::as_u64).is_none() {
            return Err(format!("smoke expected u64 at {}", path));
        }
    }
    let data = decoded.get("data").ok_or("smoke missing data")?;
    if data.get("wall_ms").and_then(Value::as_f64).is_none()
        || data
            .get("process_cpu_seconds")
            .and_then(Value::as_f64)
            .is_none()
        || data.get("bytes").and_then(Value::as_u64).is_none()
    {
        return Err("smoke numeric schema mismatch".into());
    }
    println!("{}", String::from_utf8(encoded).map_err(|e| e.to_string())?);
    Ok(())
}

fn main() -> Result<(), String> {
    if env::args().nth(1).as_deref() == Some("--serialization-smoke") {
        return serialization_smoke();
    }
    let args = Args::parse()?;
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let mut log = DurableLog::open(&args)?;
    match run(&args, &mut log) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = log.emit("worker_failure", "error", json!({"error": error}));
            Err(error)
        }
    }
}
