//! Isolated M/U real-NIZK timing worker. The default protocol is untouched.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::{One, UniformRand};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::{
    protocols::{
        hrada_auth::{
            build_private_merkle_union_witness, AuthCircuit, AuthFixture,
            ExperimentalAuthWithPrivateMerkleUnion, ExperimentalAuthWithoutRequestHash,
            PrivateMerkleUnionWitness, REQUEST_FIELDS,
        },
        hrada_joint::{self, Header, JointVerifier},
        hrada_link::{self, LinkParameters},
        hrada_membership::{allocate_prime, CpProof, CpStatement, StateMembership, StateSet},
    },
    utils::integer_to_bigint_mod_q,
};
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    convert::TryFrom,
    env,
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    time::Instant,
};

const FIXTURE_SEED: u64 = 20261018;
const PRESENTATIONS: [(&str, u64, u64); 3] = [("P", 1, 101), ("Q", 2, 102), ("short_Q", 3, 103)];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Variant {
    M,
    U,
}

impl Variant {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "M" | "m" => Ok(Self::M),
            "U" | "u" => Ok(Self::U),
            _ => Err(format!("unknown variant: {}", value)),
        }
    }
    fn code(self) -> &'static str {
        match self {
            Self::M => "M",
            Self::U => "U",
        }
    }
    fn relation(self) -> &'static str {
        match self {
            Self::M => "ExperimentalAuthWithoutRequestHash",
            Self::U => "ExperimentalAuthWithPrivateMerkleUnion",
        }
    }
}

struct Args {
    output: PathBuf,
    primes: PathBuf,
    trial: u64,
    position: u64,
    variant: Variant,
}

impl Args {
    fn parse() -> Result<Self, String> {
        let mut output = None;
        let mut primes = None;
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
                "--primes" => primes = Some(PathBuf::from(value)),
                "--trial" => trial = Some(value.parse::<u64>().map_err(|e| e.to_string())?),
                "--position" => position = Some(value.parse::<u64>().map_err(|e| e.to_string())?),
                "--variant" => variant = Some(Variant::parse(&value)?),
                _ => return Err(format!("unknown argument: {}", arg)),
            }
        }
        let out = Self {
            output: output.ok_or("missing --output")?,
            primes: primes.ok_or("missing --primes")?,
            trial: trial.ok_or("missing --trial")?,
            position: position.ok_or("missing --position")?,
            variant: variant.ok_or("missing --variant")?,
        };
        if !(1..=4).contains(&out.trial) || !(1..=2).contains(&out.position) {
            return Err("trial must be 1..=4 and position must be 1..=2".into());
        }
        Ok(out)
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
            "schema": "hrada-union-timing-stage-v1",
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
    extern "C" {
        fn clock() -> i64;
    }
    let ticks = unsafe { clock() };
    if ticks < 0 {
        return Err("process_cpu_clock_failed".into());
    }
    Ok(ticks as f64 / 1_000_000.0)
}

fn timed_data(wall_ms: f64, cpu_seconds: f64) -> Map<String, Value> {
    let mut data = Map::new();
    data.insert("wall_ms".into(), json!(wall_ms));
    data.insert("process_cpu_seconds".into(), json!(cpu_seconds));
    data
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
        .map_err(|e| format!("compressed serialization: {:?}", e))?;
    let mut uncompressed = CountingWriter::default();
    value
        .serialize_uncompressed(&mut uncompressed)
        .map_err(|e| format!("uncompressed serialization: {:?}", e))?;
    Ok((compressed.bytes, uncompressed.bytes))
}

fn canonical_uncompressed_size<T: CanonicalSerialize>(value: &T) -> Result<u64, String> {
    let mut writer = CountingWriter::default();
    value
        .serialize_uncompressed(&mut writer)
        .map_err(|e| format!("uncompressed serialization: {:?}", e))?;
    Ok(writer.bytes)
}

fn write_blob<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), String> {
    let length = u32::try_from(bytes.len()).map_err(|_| "component length overflow")?;
    writer
        .write_all(&length.to_le_bytes())
        .map_err(|e| e.to_string())?;
    writer.write_all(bytes).map_err(|e| e.to_string())
}

fn write_canonical<T: CanonicalSerialize, W: Write>(
    writer: &mut W,
    value: &T,
) -> Result<(), String> {
    let length = u32::try_from(value.serialized_size()).map_err(|_| "canonical length overflow")?;
    writer
        .write_all(&length.to_le_bytes())
        .map_err(|e| e.to_string())?;
    value
        .serialize(writer)
        .map_err(|e| format!("canonical serialization: {:?}", e))
}

fn write_integer<W: Write>(writer: &mut W, value: &Integer) -> Result<(), String> {
    let sign = if value < &0 { 1u8 } else { 0u8 };
    let digits = value.clone().abs().to_digits::<u8>(Order::MsfBe);
    let length = digits
        .len()
        .checked_add(1)
        .ok_or("integer length overflow")?;
    writer
        .write_all(&(u32::try_from(length).map_err(|_| "integer length overflow")?).to_le_bytes())
        .map_err(|e| e.to_string())?;
    writer.write_all(&[sign]).map_err(|e| e.to_string())?;
    writer.write_all(&digits).map_err(|e| e.to_string())
}

fn encode_online_bundle(
    statement: &CpStatement,
    cp: &CpProof,
    auth: &legogro16::Proof<Bls12_381>,
    fields: &[Fr],
) -> Result<(u64, u64, u64, u64, u64), String> {
    let mut cp_writer = CountingWriter::default();
    for element in [
        &cp.c_e,
        &cp.proof_root.message1.c_w,
        &cp.proof_root.message1.c_r,
        &cp.proof_root.message2.alpha1,
        &cp.proof_root.message2.alpha2,
        &cp.proof_root.message2.alpha3,
        &cp.proof_root.message2.alpha4,
        &cp.proof_modeq.message1.alpha1,
    ]
    .iter()
    {
        write_blob(&mut cp_writer, &Rsa2048::elem_to_bytes(element))?;
    }
    let root = &cp.proof_root.message3;
    let modeq = &cp.proof_modeq.message2;
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
        write_integer(&mut cp_writer, integer)?;
    }
    write_canonical(&mut cp_writer, &cp.proof_modeq.message1.alpha2)?;
    write_canonical(&mut cp_writer, &modeq.s_r_q)?;
    write_canonical(&mut cp_writer, &cp.proof_hash_to_prime)?;

    let mut statement_writer = CountingWriter::default();
    write_blob(
        &mut statement_writer,
        &Rsa2048::elem_to_bytes(&statement.c_p),
    )?;
    write_canonical(&mut statement_writer, &statement.c_e_q)?;

    let mut auth_writer = CountingWriter::default();
    auth.serialize(&mut auth_writer)
        .map_err(|e| format!("Auth proof serialization: {:?}", e))?;

    let mut request_writer = CountingWriter::default();
    request_writer
        .write_all(
            &u32::try_from(fields.len())
                .map_err(|_| "request field count overflow")?
                .to_le_bytes(),
        )
        .map_err(|e| e.to_string())?;
    for field in fields {
        write_canonical(&mut request_writer, field)?;
    }
    let total = cp_writer
        .bytes
        .checked_add(statement_writer.bytes)
        .and_then(|v| v.checked_add(auth_writer.bytes))
        .and_then(|v| v.checked_add(request_writer.bytes))
        .ok_or("bundle size overflow")?;
    Ok((
        total,
        cp_writer.bytes,
        statement_writer.bytes,
        auth_writer.bytes,
        request_writer.bytes,
    ))
}

fn scalar_integer() -> Integer {
    let mut bytes = Vec::new();
    Fr::rand(&mut OsRng).serialize(&mut bytes).unwrap();
    Integer::from_digits(&bytes, Order::Lsf)
}

fn integer_to_hex(value: &Integer) -> String {
    value.to_string_radix(16)
}

#[derive(Serialize, Deserialize)]
struct PrimeFile {
    schema: String,
    primes_hex: Vec<String>,
}

fn generate_primes(path: &Path) -> Result<(), String> {
    let clock = StageClock::start()?;
    let primes = (0..3).map(|_| allocate_prime()).collect::<Vec<_>>();
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let file = PrimeFile {
        schema: "hrada-union-timing-primes-v1".into(),
        primes_hex: primes.iter().map(integer_to_hex).collect(),
    };
    let mut handle = File::create(path).map_err(|e| e.to_string())?;
    serde_json::to_writer_pretty(
        &mut handle,
        &json!({
            "schema": file.schema,
            "primes_hex": file.primes_hex,
            "generation_wall_ms": wall_ms,
            "generation_process_cpu_seconds": cpu_seconds,
            "prime_bits": primes.iter().map(|p| p.significant_bits() as u64).collect::<Vec<_>>(),
            "charged_once_per_attempt": true,
            "shared_by_all_eight_workers": true,
        }),
    )
    .map_err(|e| e.to_string())?;
    handle.write_all(b"\n").map_err(|e| e.to_string())?;
    handle.flush().map_err(|e| e.to_string())?;
    handle.sync_data().map_err(|e| e.to_string())
}

fn load_primes(path: &Path) -> Result<Vec<Integer>, String> {
    let value: Value = serde_json::from_reader(File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if value.get("schema").and_then(Value::as_str) != Some("hrada-union-timing-primes-v1") {
        return Err("prime file schema mismatch".into());
    }
    let strings = value
        .get("primes_hex")
        .and_then(Value::as_array)
        .ok_or("missing primes_hex")?;
    if strings.len() != 3 {
        return Err("expected exactly three state primes".into());
    }
    strings
        .iter()
        .map(|v| {
            let text = v.as_str().ok_or("prime must be a string")?;
            Integer::from_str_radix(text, 16).map_err(|e| e.to_string())
        })
        .collect()
}

fn update_header(fixture: &mut AuthFixture, header: &Header) {
    let digest = header.digest_fields();
    fixture.base.request.fields[0] = digest[0];
    fixture.base.request.fields[1] = digest[1];
    fixture.base.request.fields[2] = Fr::from(header.epoch);
}

fn signature_digest(fixture: &AuthFixture) -> String {
    let mut bytes = Vec::new();
    for grant in &fixture.all_grants {
        grant
            .signature
            .prover_response
            .serialize(&mut bytes)
            .unwrap();
        grant
            .signature
            .verifier_challenge
            .serialize(&mut bytes)
            .unwrap();
    }
    Blake2s::digest(&bytes)
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect()
}

fn setup_auth(
    variant: Variant,
    circuit: AuthCircuit,
    union: Option<PrivateMerkleUnionWitness>,
    cp: &StateMembership,
) -> Result<LinkParameters, String> {
    let commitment = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    match variant {
        Variant::M => hrada_link::setup(
            &mut OsRng,
            commitment,
            ExperimentalAuthWithoutRequestHash(circuit),
            REQUEST_FIELDS,
        ),
        Variant::U => hrada_link::setup(
            &mut OsRng,
            commitment,
            ExperimentalAuthWithPrivateMerkleUnion::with_witness(
                circuit,
                union.ok_or("missing setup union witness")?,
            ),
            REQUEST_FIELDS,
        ),
    }
    .map_err(|e| format!("Auth setup: {:?}", e))
}

fn prove_auth(
    variant: Variant,
    link: &LinkParameters,
    circuit: AuthCircuit,
    union: Option<PrivateMerkleUnionWitness>,
    randomness: &Integer,
) -> Result<legogro16::Proof<Bls12_381>, String> {
    match variant {
        Variant::M => hrada_link::prove(
            &mut OsRng,
            link,
            ExperimentalAuthWithoutRequestHash(circuit),
            randomness,
        ),
        Variant::U => hrada_link::prove(
            &mut OsRng,
            link,
            ExperimentalAuthWithPrivateMerkleUnion::with_witness(
                circuit,
                union.ok_or("missing request union witness")?,
            ),
            randomness,
        ),
    }
    .map_err(|e| format!("Auth prove: {:?}", e))
}

struct Bundle {
    statement: CpStatement,
    cp_proof: CpProof,
    auth_proof: legogro16::Proof<Bls12_381>,
    fields: Vec<Fr>,
}

fn authorize(
    joint: &mut JointVerifier,
    cp: &StateMembership,
    link: &LinkParameters,
    bundle: &Bundle,
) -> Result<(), String> {
    joint.authorize(
        cp,
        link,
        &bundle.statement,
        &bundle.cp_proof,
        &bundle.auth_proof,
        &bundle.fields,
        &bundle.fields,
        500,
        550,
        || 500,
    )
}

fn prepare_request(
    variant: Variant,
    fixture: &AuthFixture,
    path: &str,
    nonce: u64,
    parameter_digest: &[u8; 32],
) -> Result<
    (
        AuthCircuit,
        Option<PrivateMerkleUnionWitness>,
        Vec<Fr>,
        Vec<u8>,
        Integer,
    ),
    String,
> {
    let mut circuit = fixture.circuit_for(path);
    circuit.request.fields[10] = Fr::from(nonce);
    let union = if variant == Variant::U {
        Some(
            build_private_merkle_union_witness(&circuit)
                .map_err(|e| format!("union builder: {:?}", e))?,
        )
    } else {
        None
    };
    let fields = circuit.public_fields();
    let context = hrada_joint::context(parameter_digest, &fields)?;
    let randomness = scalar_integer();
    Ok((circuit, union, fields, context, randomness))
}

fn run(args: &Args, log: &mut DurableLog) -> Result<(), String> {
    let lifecycle = StageClock::start()?;
    let primes = load_primes(&args.primes)?;
    log.emit("worker_start", "ok", json!({
        "fixture_seed": FIXTURE_SEED,
        "rayon_num_threads": env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "unset".into()),
        "presentations": ["P", "Q", "short_Q"],
        "default_protocol_changed": false,
        "auth_boundary": "existing hrada_link::prove including constraint-satisfaction precheck",
        "union_builder_policy": "explicit one-time precompute inside each request-preparation stage; with_witness passes it to hrada_link::prove",
        "joint_verify_boundary": "one JointVerifier::authorize call including internal prepared-VK construction",
        "online_encoding": "executed local component encoding; no network or general wire-format claim",
        "shared_prime_input": args.primes,
    }))?;

    let clock = StageClock::start()?;
    let cp = StateMembership::setup_os()?;
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("setup_kind".into(), json!("fresh independent CP setup"));
    log.emit("cp_setup", "ok", Value::Object(data))?;

    let clock = StageClock::start()?;
    let cp_parameters = cp.canonical_parameters()?;
    let mut set = StateSet::rebuild(&[primes[0].clone()])?;
    let mut prepared = set.prepare_witness(&primes[0])?;
    let prime_field = integer_to_bigint_mod_q::<G1Projective>(&primes[0])
        .map_err(|e| format!("prime conversion: {:?}", e))?;
    let mut fixture = AuthFixture::new(FIXTURE_SEED);
    fixture.refresh_state(prime_field);
    let initial_grant_digest = signature_digest(&fixture);
    let initial_grant_count = fixture.grant_signatures;
    let initial_sr_count = fixture.sr_signatures;
    let initial_padding_count = fixture.padding_signatures.get();
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let initial_state_wall_ms = wall_ms;
    let initial_state_cpu_seconds = cpu_seconds;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert(
        "cp_parameter_bytes".into(),
        json!(cp_parameters.len() as u64),
    );
    data.insert(
        "prime_bits".into(),
        json!(primes[0].significant_bits() as u64),
    );
    data.insert("initial_sr_signatures".into(), json!(initial_sr_count));
    data.insert(
        "initial_grant_signatures".into(),
        json!(initial_grant_count),
    );
    log.emit("initial_fixture_state", "ok", Value::Object(data))?;

    let setup_prep_clock = StageClock::start()?;
    let setup_circuit = fixture.circuit_for("P");
    let setup_union = if args.variant == Variant::U {
        Some(
            build_private_merkle_union_witness(&setup_circuit)
                .map_err(|e| format!("setup union builder: {:?}", e))?,
        )
    } else {
        None
    };
    let (wall_ms, cpu_seconds) = setup_prep_clock.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("path".into(), json!("P"));
    data.insert(
        "union_witness_precomputed".into(),
        json!(args.variant == Variant::U),
    );
    data.insert("excluded_from_online_requests".into(), json!(true));
    log.emit("auth_setup_input_preparation", "ok", Value::Object(data))?;

    let clock = StageClock::start()?;
    let link = setup_auth(args.variant, setup_circuit, setup_union, &cp)?;
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert(
        "setup_kind".into(),
        json!("fresh independent Auth setup matched to selected relation"),
    );
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
        json!("streaming counting writer; key bytes not retained or written"),
    );
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

    let clock = StageClock::start()?;
    let parameter_digest = hrada_link::parameter_digest(&link, &cp_parameters)
        .map_err(|e| format!("parameter digest: {:?}", e))?;
    let header = Header::new(set.accumulator.clone(), 1, &parameter_digest);
    update_header(&mut fixture, &header);
    let mut joint = JointVerifier::new(
        Header::new(set.accumulator.clone(), 1, &parameter_digest),
        parameter_digest,
    );
    let (wall_ms, cpu_seconds) = clock.stop()?;
    let initial_header_wall_ms = wall_ms;
    let initial_header_cpu_seconds = cpu_seconds;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("epoch".into(), json!(1u64));
    data.insert(
        "parameter_digest_hex".into(),
        json!(parameter_digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()),
    );
    data.insert(
        "independent_setup_means_cross_variant_digest_differs".into(),
        json!(true),
    );
    log.emit("initial_header_preparation", "ok", Value::Object(data))?;

    let mut previous_bundle: Option<Bundle> = None;
    let mut trace_online_wall_ms = 0.0f64;
    let mut trace_online_cpu_seconds = 0.0f64;
    let mut transition_wall_ms = 0.0f64;
    let mut transition_cpu_seconds = 0.0f64;

    for (path, epoch, nonce) in PRESENTATIONS.iter().copied() {
        if epoch > 1 {
            let clock = StageClock::start()?;
            let old_prime = primes[(epoch - 2) as usize].clone();
            let new_prime = primes[(epoch - 1) as usize].clone();
            let old_set = set;
            let _old_prepared = prepared;
            if epoch == 2 {
                fixture.close_issuers();
                fixture.revoke_middle(
                    integer_to_bigint_mod_q::<G1Projective>(&new_prime)
                        .map_err(|e| format!("prime conversion: {:?}", e))?,
                );
            } else {
                fixture.all_grants[5].active = false;
                fixture.base.state_version += 1;
                fixture.base.request.fields[2] += Fr::one();
                fixture.base.transition = [5u8; 32];
                fixture.refresh_state(
                    integer_to_bigint_mod_q::<G1Projective>(&new_prime)
                        .map_err(|e| format!("prime conversion: {:?}", e))?,
                );
            }
            set = StateSet::rebuild(&[new_prime.clone()])?;
            prepared = set.prepare_witness(&new_prime)?;
            let new_header = Header::new(set.accumulator.clone(), epoch, &parameter_digest);
            joint.replace_header(new_header)?;
            update_header(&mut fixture, &joint.header);
            let (wall_ms, cpu_seconds) = clock.stop()?;
            transition_wall_ms += wall_ms;
            transition_cpu_seconds += cpu_seconds;
            let mut data = timed_data(wall_ms, cpu_seconds);
            data.insert("epoch".into(), json!(epoch));
            data.insert("old_prime_hex".into(), json!(integer_to_hex(&old_prime)));
            data.insert("new_prime_hex".into(), json!(integer_to_hex(&new_prime)));
            data.insert(
                "old_accumulator_replaced".into(),
                json!(old_set.accumulator != set.accumulator),
            );
            data.insert(
                "sr_signature_delta_from_initial".into(),
                json!(fixture.sr_signatures - initial_sr_count),
            );
            data.insert("issuers_closed".into(), json!(fixture.issuers_closed));
            data.insert(
                "grant_signature_count".into(),
                json!(fixture.grant_signatures),
            );
            data.insert(
                "grant_signature_digest".into(),
                json!(signature_digest(&fixture)),
            );
            data.insert(
                "current_header_and_cp_witness_refreshed".into(),
                json!(true),
            );
            log.emit("state_transition", "ok", Value::Object(data))?;

            let stale_clock = StageClock::start()?;
            let stale_result = authorize(
                &mut joint,
                &cp,
                &link,
                previous_bundle.as_ref().ok_or("missing previous bundle")?,
            );
            let (stale_wall_ms, stale_cpu_seconds) = stale_clock.stop()?;
            let mut data = timed_data(stale_wall_ms, stale_cpu_seconds);
            data.insert("epoch".into(), json!(epoch));
            data.insert("expected_error".into(), json!("stale_header"));
            data.insert("observed_error".into(), json!(stale_result.as_ref().err()));
            data.insert("real_previous_epoch_bundle".into(), json!(true));
            data.insert("excluded_from_online_metric".into(), json!(true));
            log.emit(
                "stale_header_regression",
                if stale_result == Err("stale_header".into()) {
                    "ok"
                } else {
                    "failed"
                },
                Value::Object(data),
            )?;
            if stale_result != Err("stale_header".into()) {
                return Err(format!("expected stale_header, got {:?}", stale_result));
            }
        }

        let padding_before = fixture.padding_signatures.get();
        let prep_clock = StageClock::start()?;
        let (circuit, union, fields, context, randomness) =
            prepare_request(args.variant, &fixture, path, nonce, &parameter_digest)?;
        let (prep_wall_ms, prep_cpu_seconds) = prep_clock.stop()?;
        let padding_after = fixture.padding_signatures.get();
        let mut data = timed_data(prep_wall_ms, prep_cpu_seconds);
        data.insert("epoch".into(), json!(epoch));
        data.insert("path".into(), json!(path));
        data.insert("nonce".into(), json!(nonce));
        data.insert(
            "padding_signatures_created".into(),
            json!(padding_after - padding_before),
        );
        data.insert(
            "union_witness_precomputed_once".into(),
            json!(args.variant == Variant::U),
        );
        data.insert(
            "includes_context_and_commitment_randomness".into(),
            json!(true),
        );
        log.emit("request_preparation", "ok", Value::Object(data))?;

        let cp_clock = StageClock::start()?;
        let prime = &primes[(epoch - 1) as usize];
        let (statement, cp_proof) =
            cp.prove_prepared(&set, prime, &prepared, &randomness, &context)?;
        let (cp_wall_ms, cp_cpu_seconds) = cp_clock.stop()?;
        let mut data = timed_data(cp_wall_ms, cp_cpu_seconds);
        data.insert("epoch".into(), json!(epoch));
        data.insert("path".into(), json!(path));
        log.emit("cp_prove", "ok", Value::Object(data))?;

        let auth_clock = StageClock::start()?;
        let auth_proof = prove_auth(args.variant, &link, circuit, union, &randomness)?;
        let (auth_wall_ms, auth_cpu_seconds) = auth_clock.stop()?;
        let mut data = timed_data(auth_wall_ms, auth_cpu_seconds);
        data.insert("epoch".into(), json!(epoch));
        data.insert("path".into(), json!(path));
        data.insert(
            "includes_hrada_link_constraint_precheck".into(),
            json!(true),
        );
        log.emit("auth_prove", "ok", Value::Object(data))?;

        let encoding_clock = StageClock::start()?;
        let (total_bytes, cp_bytes, statement_bytes, auth_bytes, request_bytes) =
            encode_online_bundle(&statement, &cp_proof, &auth_proof, &fields)?;
        let (encoding_wall_ms, encoding_cpu_seconds) = encoding_clock.stop()?;
        let mut data = timed_data(encoding_wall_ms, encoding_cpu_seconds);
        data.insert("epoch".into(), json!(epoch));
        data.insert("path".into(), json!(path));
        data.insert("local_component_bundle_bytes".into(), json!(total_bytes));
        data.insert("cp_proof_component_bytes".into(), json!(cp_bytes));
        data.insert(
            "cp_statement_component_bytes".into(),
            json!(statement_bytes),
        );
        data.insert(
            "auth_proof_canonical_compressed_bytes".into(),
            json!(auth_bytes),
        );
        data.insert(
            "public_request_component_bytes".into(),
            json!(request_bytes),
        );
        data.insert("network_wire_format_claimed".into(), json!(false));
        log.emit("online_component_encoding", "ok", Value::Object(data))?;

        let bundle = Bundle {
            statement,
            cp_proof,
            auth_proof,
            fields,
        };
        let joint_clock = StageClock::start()?;
        let result = authorize(&mut joint, &cp, &link, &bundle);
        let (joint_wall_ms, joint_cpu_seconds) = joint_clock.stop()?;
        let mut data = timed_data(joint_wall_ms, joint_cpu_seconds);
        data.insert("epoch".into(), json!(epoch));
        data.insert("path".into(), json!(path));
        data.insert("accepted".into(), json!(result.is_ok()));
        data.insert("calls".into(), json!(1u64));
        data.insert("includes_internal_vk_preparation".into(), json!(true));
        if let Err(error) = &result {
            data.insert("error".into(), json!(error));
        }
        log.emit(
            "joint_verify",
            if result.is_ok() { "ok" } else { "rejected" },
            Value::Object(data),
        )?;
        result.map_err(|e| format!("joint verification rejected: {}", e))?;

        let online_wall_ms =
            prep_wall_ms + cp_wall_ms + auth_wall_ms + encoding_wall_ms + joint_wall_ms;
        let online_cpu_seconds = prep_cpu_seconds
            + cp_cpu_seconds
            + auth_cpu_seconds
            + encoding_cpu_seconds
            + joint_cpu_seconds;
        trace_online_wall_ms += online_wall_ms;
        trace_online_cpu_seconds += online_cpu_seconds;
        log.emit("online_request_total", "ok", json!({
            "epoch": epoch,
            "path": path,
            "wall_ms": online_wall_ms,
            "process_cpu_seconds": online_cpu_seconds,
            "formula": "request_preparation + cp_prove + auth_prove + online_component_encoding + one joint_verify",
            "not_network_end_to_end": true,
        }))?;

        let duplicate_clock = StageClock::start()?;
        let duplicate = authorize(&mut joint, &cp, &link, &bundle);
        let (duplicate_wall_ms, duplicate_cpu_seconds) = duplicate_clock.stop()?;
        let mut data = timed_data(duplicate_wall_ms, duplicate_cpu_seconds);
        data.insert("epoch".into(), json!(epoch));
        data.insert("path".into(), json!(path));
        data.insert("expected_error".into(), json!("nonce_already_consumed"));
        data.insert("observed_error".into(), json!(duplicate.as_ref().err()));
        data.insert("excluded_from_online_metric".into(), json!(true));
        log.emit(
            "same_header_replay_regression",
            if duplicate == Err("nonce_already_consumed".into()) {
                "ok"
            } else {
                "failed"
            },
            Value::Object(data),
        )?;
        if duplicate != Err("nonce_already_consumed".into()) {
            return Err(format!(
                "expected nonce_already_consumed, got {:?}",
                duplicate
            ));
        }

        let diagnostic_clock = StageClock::start()?;
        let uncompressed = canonical_uncompressed_size(&bundle.auth_proof)?;
        let (diagnostic_wall_ms, diagnostic_cpu_seconds) = diagnostic_clock.stop()?;
        let mut data = timed_data(diagnostic_wall_ms, diagnostic_cpu_seconds);
        data.insert("epoch".into(), json!(epoch));
        data.insert("path".into(), json!(path));
        data.insert(
            "auth_proof_canonical_uncompressed_bytes".into(),
            json!(uncompressed),
        );
        data.insert("excluded_from_online_metric".into(), json!(true));
        log.emit("diagnostic_serialization", "ok", Value::Object(data))?;
        previous_bundle = Some(bundle);
    }

    let grant_digest_final = signature_digest(&fixture);
    let regression_ok = fixture.grant_signatures == initial_grant_count
        && grant_digest_final == initial_grant_digest
        && fixture.sr_signatures == initial_sr_count + 2;
    log.emit("signature_accounting", if regression_ok { "ok" } else { "failed" }, json!({
        "initial_grant_signature_count": initial_grant_count,
        "final_grant_signature_count": fixture.grant_signatures,
        "grant_signature_digest_unchanged": grant_digest_final == initial_grant_digest,
        "initial_sr_signature_count": initial_sr_count,
        "final_sr_signature_count": fixture.sr_signatures,
        "sr_signatures_for_two_transitions": fixture.sr_signatures - initial_sr_count,
        "padding_signatures_for_presentations": fixture.padding_signatures.get() - initial_padding_count,
    }))?;
    if !regression_ok {
        return Err("signature accounting regression".into());
    }

    log.emit("trace_total_excluding_setup", "ok", json!({
        "wall_ms": initial_state_wall_ms + initial_header_wall_ms + trace_online_wall_ms + transition_wall_ms,
        "process_cpu_seconds": initial_state_cpu_seconds + initial_header_cpu_seconds + trace_online_cpu_seconds + transition_cpu_seconds,
        "initial_fixture_state_wall_ms": initial_state_wall_ms,
        "initial_fixture_state_process_cpu_seconds": initial_state_cpu_seconds,
        "initial_header_preparation_wall_ms": initial_header_wall_ms,
        "initial_header_preparation_process_cpu_seconds": initial_header_cpu_seconds,
        "online_presentations_wall_ms": trace_online_wall_ms,
        "online_presentations_process_cpu_seconds": trace_online_cpu_seconds,
        "state_transitions_wall_ms": transition_wall_ms,
        "state_transitions_process_cpu_seconds": transition_cpu_seconds,
        "formula": "initial_fixture_state + initial_header_preparation + three online_request_total values + two state_transition values",
        "excluded": "CP/Auth setup, setup-input preparation, key serialization, regressions, diagnostics, durable logging, network",
    }))?;

    let (wall_ms, cpu_seconds) = lifecycle.stop()?;
    let mut data = timed_data(wall_ms, cpu_seconds);
    data.insert("presentations_completed".into(), json!(3u64));
    data.insert("all_joint_accepted".into(), json!(true));
    data.insert("stale_header_regressions".into(), json!(2u64));
    data.insert("same_header_replay_regressions".into(), json!(3u64));
    data.insert(
        "worker_high_water_rss_recorded_externally".into(),
        json!(true),
    );
    log.emit("worker_end", "ok", Value::Object(data))
}

fn serialization_smoke() -> Result<(), String> {
    let event = json!({
        "schema": "hrada-union-timing-stage-v1",
        "sequence_in_worker": 1u64,
        "trial": 1u64,
        "position": 1u64,
        "variant": "M",
        "stage": "schema_smoke",
        "status": "ok",
        "data": { "wall_ms": 1.25f64, "process_cpu_seconds": 0.5f64, "bytes": 42u64, "accepted": true }
    });
    let encoded = serde_json::to_vec(&event).map_err(|e| e.to_string())?;
    let decoded: Value = serde_json::from_slice(&encoded).map_err(|e| e.to_string())?;
    for path in ["sequence_in_worker", "trial", "position"] {
        if decoded.get(path).and_then(Value::as_u64).is_none() {
            return Err(format!("smoke expected u64 at {}", path));
        }
    }
    println!("{}", String::from_utf8(encoded).map_err(|e| e.to_string())?);
    Ok(())
}

fn main() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--serialization-smoke") {
        return serialization_smoke();
    }
    if args.get(1).map(String::as_str) == Some("--generate-primes") {
        let path = args.get(2).ok_or("usage: --generate-primes PATH")?;
        return generate_primes(Path::new(path));
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
