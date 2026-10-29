//! Correctness gate and isolated worker for the Auth slot/tree scaling study.
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::{
    commitments::{pedersen::PedersenCommitment, Commitment},
    protocols::{
        hrada_auth::{
            scaling::{full_active_circuit, prefix_circuit, relation_snapshot, ScalingAuthCircuit},
            AuthCircuit, AuthFixture,
        },
        hrada_link,
    },
};
use rand::{rngs::OsRng, rngs::StdRng, SeedableRng};
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{env, fs, io, io::Write, path::PathBuf, time::Instant};

const REQUEST_FIELDS: usize = 16;

struct Clock {
    wall: Instant,
    cpu: f64,
}

impl Clock {
    fn start() -> Result<Self, String> {
        Ok(Self {
            wall: Instant::now(),
            cpu: process_cpu_seconds()?,
        })
    }

    fn stop(self) -> Result<Value, String> {
        Ok(json!({
            "wall_ms": self.wall.elapsed().as_secs_f64() * 1000.0,
            "process_cpu_seconds": process_cpu_seconds()? - self.cpu,
        }))
    }
}

fn process_cpu_seconds() -> Result<f64, String> {
    extern "C" {
        fn clock() -> i64;
    }
    let ticks = unsafe { clock() };
    if ticks < 0 {
        return Err("process CPU clock failed".into());
    }
    Ok(ticks as f64 / 1_000_000.0)
}

#[derive(Default)]
struct Counter(u64);

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 += bytes.len() as u64;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn sizes<T: CanonicalSerialize>(value: &T) -> Result<Value, String> {
    let mut compressed = Counter::default();
    value
        .serialize(&mut compressed)
        .map_err(|e| format!("compressed serialization: {:?}", e))?;
    let mut uncompressed = Counter::default();
    value
        .serialize_uncompressed(&mut uncompressed)
        .map_err(|e| format!("uncompressed serialization: {:?}", e))?;
    Ok(json!({"compressed_bytes": compressed.0, "uncompressed_bytes": uncompressed.0}))
}

fn canonical_bytes<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut bytes)
        .map_err(|e| format!("canonical serialization: {:?}", e))?;
    Ok(bytes)
}

fn linux_memory_kib() -> Value {
    let status = match fs::read_to_string("/proc/self/status") {
        Ok(value) => value,
        Err(_) => return Value::Null,
    };
    let mut rss = None;
    let mut peak = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            rss = value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok());
        }
        if let Some(value) = line.strip_prefix("VmHWM:") {
            peak = value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok());
        }
    }
    json!({"vm_rss_kib": rss, "vm_hwm_kib": peak})
}

fn scalar_integer<R: rand::Rng>(rng: &mut R) -> Integer {
    let scalar = Fr::rand(rng);
    Integer::from_digits(&scalar.into_repr().to_bytes_le(), Order::Lsf)
}

fn prime_integer(circuit: &ScalingAuthCircuit) -> Integer {
    Integer::from_digits(&circuit.base.prime.into_repr().to_bytes_le(), Order::Lsf)
}

fn satisfied<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<bool, String> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|e| format!("synthesis: {:?}", e))?;
    cs.is_satisfied()
        .map_err(|e| format!("satisfaction: {:?}", e))
}

fn negative_pairs(canonical: &AuthCircuit) -> Result<Vec<Value>, String> {
    let mut cases: Vec<(&str, AuthCircuit)> = Vec::new();
    let mut c = canonical.clone();
    c.grants[1].signature.prover_response += ark_ed_on_bls12_381::Fr::from(1u64);
    cases.push(("grant_signature", c));
    let mut c = canonical.clone();
    c.grants[1].parent = [0; 32];
    cases.push(("parent", c));
    let mut c = canonical.clone();
    c.grants[1].fields[3] += Fr::from(1u64);
    cases.push(("issuer", c));
    let mut c = canonical.clone();
    c.grants[1].fields[7] += Fr::from(1u64);
    cases.push(("resource_policy", c));
    let mut c = canonical.clone();
    c.grants[0].fields[12] = Fr::from(1u64);
    cases.push(("delegation_depth", c));
    let mut c = canonical.clone();
    c.grants[1].active = false;
    cases.push(("active_bit", c));
    let mut c = canonical.clone();
    c.grants[1].fields[14] = Fr::from(7u64);
    cases.push(("leaf_index", c));
    let mut c = canonical.clone();
    c.paths[1][0][0] ^= 1;
    cases.push(("merkle_path", c));
    let mut c = canonical.clone();
    c.holder += ark_ed_on_bls12_381::Fr::from(1u64);
    cases.push(("terminal_holder", c));
    let mut c = canonical.clone();
    c.request.fields[14] += Fr::from(1u64);
    cases.push(("request_agent", c));

    let mut rows = Vec::new();
    for (name, bad) in cases {
        let default_satisfied = satisfied(bad.clone())?;
        let scaling_satisfied = satisfied(ScalingAuthCircuit::from_canonical(bad))?;
        if default_satisfied != scaling_satisfied || default_satisfied {
            return Err(format!(
                "negative {} mismatch/default unexpectedly satisfied: default={} scaling={}",
                name, default_satisfied, scaling_satisfied
            ));
        }
        rows.push(json!({
            "case": name,
            "default_satisfied": default_satisfied,
            "scaling_satisfied": scaling_satisfied,
        }));
    }
    Ok(rows)
}

fn generalized_prefix_checks() -> Result<Vec<Value>, String> {
    let mut rows = Vec::new();
    for (slots, active, depth) in [(3usize, 1usize, 3usize), (5, 3, 5)] {
        let seed = 20261100 + slots as u64;
        let full = relation_snapshot(full_active_circuit(seed, slots, depth))
            .map_err(|e| format!("full prefix shape: {:?}", e))?;
        let short = relation_snapshot(prefix_circuit(seed, slots, active, depth))
            .map_err(|e| format!("short prefix shape: {:?}", e))?;
        if !full.satisfied || !short.satisfied || full.matrices != short.matrices {
            return Err(format!(
                "prefix shape/satisfaction failed slots={} active={} depth={}",
                slots, active, depth
            ));
        }
        rows.push(json!({
            "slots": slots,
            "active_slots": active,
            "tree_depth": depth,
            "full_satisfied": full.satisfied,
            "short_satisfied": short.satisfied,
            "ordered_r1cs_matrices_equal": true,
            "constraints": full.matrices.num_constraints,
            "instances": full.matrices.num_instance_variables,
            "witnesses": full.matrices.num_witness_variables,
        }));
    }
    Ok(rows)
}

fn generalized_five_by_five_negatives() -> Result<Vec<Value>, String> {
    let base = full_active_circuit(20261355, 5, 5);
    let mut cases = Vec::new();
    let mut bad = base.clone();
    bad.base.grants[0].fields[12] = Fr::from(3u64);
    cases.push(("s5_d5_delegation_depth", bad));
    let mut bad = base.clone();
    bad.base.grants[2].active = false;
    cases.push(("s5_d5_active_bit", bad));
    let mut bad = base;
    bad.base.holder += ark_ed_on_bls12_381::Fr::from(1u64);
    cases.push(("s5_d5_terminal_holder", bad));
    let mut rows = Vec::new();
    for (name, circuit) in cases {
        let is_satisfied = satisfied(circuit)?;
        if is_satisfied {
            return Err(format!(
                "generalized negative unexpectedly satisfied: {}",
                name
            ));
        }
        rows.push(json!({"case": name, "satisfied": false}));
    }
    Ok(rows)
}

fn preflight(output: PathBuf) -> Result<(), String> {
    let canonical = AuthFixture::new(20261022).circuit_for("P");
    let scaling = ScalingAuthCircuit::from_canonical(canonical.clone());
    let default_snapshot = relation_snapshot(canonical.clone()).map_err(|e| format!("{:?}", e))?;
    let scaling_snapshot = relation_snapshot(scaling.clone()).map_err(|e| format!("{:?}", e))?;
    if default_snapshot.matrices != scaling_snapshot.matrices
        || default_snapshot.instance_assignment != scaling_snapshot.instance_assignment
        || default_snapshot.witness_assignment != scaling_snapshot.witness_assignment
        || canonical_bytes(&default_snapshot.instance_assignment)?
            != canonical_bytes(&scaling_snapshot.instance_assignment)?
        || canonical_bytes(&default_snapshot.witness_assignment)?
            != canonical_bytes(&scaling_snapshot.witness_assignment)?
        || !default_snapshot.satisfied
        || !scaling_snapshot.satisfied
    {
        return Err("ordered matrices or assignments differ".into());
    }

    let setup_seed = [91u8; 32];
    let mut left_rng = StdRng::from_seed(setup_seed);
    let left_cp = PedersenCommitment::<G1Projective>::setup(&mut left_rng);
    let left = hrada_link::setup(&mut left_rng, &left_cp, canonical.clone(), REQUEST_FIELDS)
        .map_err(|e| format!("left setup: {:?}", e))?;
    let mut right_rng = StdRng::from_seed(setup_seed);
    let right_cp = PedersenCommitment::<G1Projective>::setup(&mut right_rng);
    let right = hrada_link::setup(&mut right_rng, &right_cp, scaling.clone(), REQUEST_FIELDS)
        .map_err(|e| format!("right setup: {:?}", e))?;
    if left_cp.g != right_cp.g
        || left_cp.h != right_cp.h
        || canonical_bytes(&left.proving_key)? != canonical_bytes(&right.proving_key)?
    {
        return Err("same-seed setup keys differ".into());
    }

    let cp_bytes = b"HRADA-AUTH-SCALING-PREFLIGHT";
    let left_digest = hrada_link::parameter_digest(&left, cp_bytes)
        .map_err(|e| format!("left digest: {:?}", e))?;
    let right_digest = hrada_link::parameter_digest(&right, cp_bytes)
        .map_err(|e| format!("right digest: {:?}", e))?;
    if left_digest != right_digest {
        return Err("same-seed parameter digests differ".into());
    }
    let randomness = Integer::from(20261022u64);
    let commitment = left_cp
        .commit(&prime_integer(&scaling), &randomness)
        .map_err(|e| format!("commitment: {:?}", e))?;
    let proof_scaling_with_default =
        hrada_link::prove(&mut OsRng, &left, scaling.clone(), &randomness)
            .map_err(|e| format!("scaling/default-key proof: {:?}", e))?;
    let proof_default_with_scaling =
        hrada_link::prove(&mut OsRng, &right, canonical.clone(), &randomness)
            .map_err(|e| format!("default/scaling-key proof: {:?}", e))?;
    let fields = canonical.public_fields();
    let cross_a = hrada_link::verify(
        &left,
        &left_cp,
        cp_bytes,
        &left_digest,
        &proof_scaling_with_default,
        &fields,
        &commitment,
    )
    .map_err(|e| format!("cross A verify: {:?}", e))?;
    let cross_b = hrada_link::verify(
        &right,
        &right_cp,
        cp_bytes,
        &right_digest,
        &proof_default_with_scaling,
        &fields,
        &commitment,
    )
    .map_err(|e| format!("cross B verify: {:?}", e))?;
    if !cross_a || !cross_b {
        return Err("bidirectional cross-key verification failed".into());
    }
    let negatives = negative_pairs(&canonical)?;
    let prefix_checks = generalized_prefix_checks()?;
    let generalized_negatives = generalized_five_by_five_negatives()?;
    let report = json!({
        "schema": "hrada-auth-scaling-preflight-v1",
        "fixture_seed": 20261022u64,
        "ordered_r1cs_matrices_equal": true,
        "instance_assignments_equal": true,
        "witness_assignments_equal": true,
        "same_seed_proving_keys_equal": true,
        "same_seed_verifying_keys_equal": true,
        "cross_key_scaling_with_default": cross_a,
        "cross_key_default_with_scaling": cross_b,
        "constraints": default_snapshot.matrices.num_constraints,
        "instances": default_snapshot.matrices.num_instance_variables,
        "witnesses": default_snapshot.matrices.num_witness_variables,
        "negative_pairs": negatives,
        "generalized_prefix_checks": prefix_checks,
        "generalized_five_by_five_negatives": generalized_negatives,
    });
    fs::write(output, serde_json::to_vec_pretty(&report).unwrap()).map_err(|e| e.to_string())
}

fn cell(
    output: PathBuf,
    slots: usize,
    depth: usize,
    trial: usize,
    proofs: usize,
) -> Result<(), String> {
    let fixture_seed = 20261022u64 + (slots as u64) * 100 + depth as u64;
    let circuit = full_active_circuit(fixture_seed, slots, depth);
    let snapshot = relation_snapshot(circuit.clone()).map_err(|e| format!("{:?}", e))?;
    if !snapshot.satisfied {
        return Err("cell relation is unsatisfied".into());
    }
    let constraints = snapshot.matrices.num_constraints;
    let instances = snapshot.matrices.num_instance_variables;
    let witnesses = snapshot.matrices.num_witness_variables;
    let expected_radix2_domain = (constraints + instances).next_power_of_two();
    // Do not retain diagnostic matrices or assignments during setup/proving.
    drop(snapshot);
    let cp = PedersenCommitment::<G1Projective>::setup(&mut OsRng);
    let setup_clock = Clock::start()?;
    let link = hrada_link::setup(&mut OsRng, &cp, circuit.clone(), REQUEST_FIELDS)
        .map_err(|e| format!("Auth setup: {:?}", e))?;
    let setup_timing = setup_clock.stop()?;
    let memory_after_setup = linux_memory_kib();
    let pk_size = sizes(&link.proving_key)?;
    let vk_size = sizes(&link.proving_key.vk)?;
    let cp_bytes = b"HRADA-AUTH-SCALING-V1";
    let digest = hrada_link::parameter_digest(&link, cp_bytes)
        .map_err(|e| format!("parameter digest: {:?}", e))?;
    let mut proof_rows = Vec::new();
    for proof_index in 1..=proofs {
        let randomness = scalar_integer(&mut OsRng);
        let commitment = cp
            .commit(&prime_integer(&circuit), &randomness)
            .map_err(|e| format!("commitment: {:?}", e))?;
        let prove_clock = Clock::start()?;
        let proof = hrada_link::prove(&mut OsRng, &link, circuit.clone(), &randomness)
            .map_err(|e| format!("Auth proof: {:?}", e))?;
        let prove_timing = prove_clock.stop()?;
        let verify_clock = Clock::start()?;
        let valid = hrada_link::verify(
            &link,
            &cp,
            cp_bytes,
            &digest,
            &proof,
            &circuit.public_fields(),
            &commitment,
        )
        .map_err(|e| format!("Auth verify: {:?}", e))?;
        let verify_timing = verify_clock.stop()?;
        if !valid {
            return Err(format!("proof {} rejected", proof_index));
        }
        proof_rows.push(json!({
            "proof_index": proof_index,
            "prove": prove_timing,
            "verify": verify_timing,
            "proof_size": sizes(&proof)?,
            "valid": valid,
        }));
    }
    let result = json!({
        "schema": "hrada-auth-scaling-cell-v1",
        "slots": slots,
        "tree_depth": depth,
        "tree_capacity": 1usize << depth,
        "trial": trial,
        "fixture_seed": fixture_seed,
        "setup_randomness": "OsRng independent per process",
        "full_active_chain": true,
        "canonical_domain8_request_hash_retained": true,
        "default_auth_relation_changed": false,
        "measurement_boundary": "Auth/link only: hrada_link setup, proof with satisfaction precheck, and link verification; excludes CP membership, ACK, broker, and network",
        "rayon_num_threads": env::var("RAYON_NUM_THREADS").unwrap_or_default(),
        "constraints": constraints,
        "instances": instances,
        "witnesses": witnesses,
        "expected_radix2_domain": expected_radix2_domain,
        "h_query_len": link.proving_key.h_query.len(),
        "actual_qap_domain_from_h_query": link.proving_key.h_query.len() + 1,
        "setup": setup_timing,
        "memory_after_setup": memory_after_setup,
        "proving_key": pk_size,
        "verifying_key": vk_size,
        "proofs": proof_rows,
    });
    fs::write(output, serde_json::to_vec_pretty(&result).unwrap()).map_err(|e| e.to_string())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("preflight") if args.len() == 3 => preflight(PathBuf::from(&args[2])),
        Some("cell") if args.len() == 7 => cell(
            PathBuf::from(&args[2]),
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
            args[6].parse().unwrap(),
        ),
        _ => Err(format!(
            "usage: {} preflight OUTPUT | cell OUTPUT SLOTS DEPTH TRIAL PROOFS",
            args[0]
        )),
    };
    if let Err(error) = result {
        eprintln!("{}", error);
        std::process::exit(1);
    }
}
