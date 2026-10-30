//! Parameterized artifact proof driver. Verification reads public artifacts only.
use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use plan_a_joint_circuit::{
    fixture::{fixed, public_inputs},
    joint::JointCircuit,
};
use rand::{
    rngs::{OsRng, StdRng},
    seq::SliceRandom,
    Rng, SeedableRng,
};
use serde_json::json;
use std::{
    env,
    fs::File,
    io::{BufReader, BufWriter},
    process,
    time::Instant,
};

fn fail(message: &str) -> ! {
    println!("{}", json!({"ok":false,"error":message}));
    process::exit(2)
}
fn number<T: std::str::FromStr>(s: &str, name: &str) -> Result<T, String> {
    s.parse().map_err(|_| format!("bad {name}"))
}
fn metrics<const L: usize>(
    c: JointCircuit<L>,
) -> Result<(usize, usize, usize, usize, usize, usize, usize), String> {
    let cs = ConstraintSystem::new_ref();
    c.generate_constraints(cs.clone())
        .map_err(|e| e.to_string())?;
    cs.finalize();
    let m = cs.to_matrices().ok_or("missing matrices")?;
    let qap = (m.num_constraints + m.num_instance_variables).next_power_of_two();
    Ok((
        m.num_constraints,
        m.num_instance_variables,
        m.num_witness_variables,
        m.a_num_non_zero,
        m.b_num_non_zero,
        m.c_num_non_zero,
        qap,
    ))
}
fn setup<const L: usize>(
    pk_path: &str,
    vk_path: &str,
    ds: usize,
    dra: usize,
    drev: usize,
) -> Result<(), String> {
    let shape = metrics(fixed::<L>(L, 0, ds, dra, drev))?;
    let mut rng = OsRng;
    let start = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::setup(fixed::<L>(L, 0, ds, dra, drev), &mut rng)
        .map_err(|e| e.to_string())?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    pk.serialize_compressed(BufWriter::new(
        File::create(pk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    vk.serialize_compressed(BufWriter::new(
        File::create(vk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ok":true,"command":"setup","l_max":L,"state_depth":ds,"ra_depth":dra,"revocation_depth":drev,"grant_depth":3,"constraints":shape.0,"instances":shape.1,"witnesses":shape.2,"a_nnz":shape.3,"b_nnz":shape.4,"c_nnz":shape.5,"qap_domain":shape.6,"setup_ms":elapsed,"pk_bytes":std::fs::metadata(pk_path).unwrap().len(),"vk_bytes":std::fs::metadata(vk_path).unwrap().len()})
    );
    Ok(())
}
fn prove<const L: usize>(
    pk_path: &str,
    proof_path: &str,
    public_path: &str,
    active: usize,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
) -> Result<(), String> {
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(BufReader::new(
        File::open(pk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    let circuit: JointCircuit<L> = fixed::<L>(active, nonce, ds, dra, drev);
    let inputs = public_inputs(&circuit);
    let mut rng = OsRng;
    let start = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).map_err(|e| e.to_string())?;
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    proof
        .serialize_compressed(BufWriter::new(
            File::create(proof_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    inputs
        .serialize_compressed(BufWriter::new(
            File::create(public_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ok":true,"command":"prove","l_max":L,"active":active,"state_depth":ds,"ra_depth":dra,"revocation_depth":drev,"prove_ms":elapsed,"proof_bytes":std::fs::metadata(proof_path).unwrap().len(),"public_bytes":std::fs::metadata(public_path).unwrap().len()})
    );
    Ok(())
}
fn trial<const L: usize>(
    pk_path: &str,
    vk_path: &str,
    proof_path: &str,
    public_path: &str,
    active: usize,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
) -> Result<(), String> {
    let shape = metrics(fixed::<L>(active, nonce, ds, dra, drev))?;
    let mut rng = OsRng;
    let setup_start = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::setup(fixed::<L>(active, nonce, ds, dra, drev), &mut rng)
        .map_err(|e| e.to_string())?;
    let setup_ms = setup_start.elapsed().as_secs_f64() * 1000.0;
    let circuit = fixed::<L>(active, nonce, ds, dra, drev);
    let inputs = public_inputs(&circuit);
    let prove_start = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).map_err(|e| e.to_string())?;
    let prove_ms = prove_start.elapsed().as_secs_f64() * 1000.0;
    pk.serialize_compressed(BufWriter::new(
        File::create(pk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    vk.serialize_compressed(BufWriter::new(
        File::create(vk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    proof
        .serialize_compressed(BufWriter::new(
            File::create(proof_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    inputs
        .serialize_compressed(BufWriter::new(
            File::create(public_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ok":true,"command":"trial","l_max":L,"active":active,"state_depth":ds,"ra_depth":dra,"revocation_depth":drev,"grant_depth":3,"constraints":shape.0,"instances":shape.1,"witnesses":shape.2,"a_nnz":shape.3,"b_nnz":shape.4,"c_nnz":shape.5,"qap_domain":shape.6,"setup_ms":setup_ms,"prove_ms":prove_ms,"pk_bytes":std::fs::metadata(pk_path).unwrap().len(),"vk_bytes":std::fs::metadata(vk_path).unwrap().len(),"proof_bytes":std::fs::metadata(proof_path).unwrap().len(),"public_bytes":std::fs::metadata(public_path).unwrap().len()})
    );
    Ok(())
}
fn benchmark_trial<const L: usize>(
    pk_path: &str,
    vk_path: &str,
    proof_path: &str,
    public_path: &str,
    active: usize,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
) -> Result<(), String> {
    let shape = metrics(fixed::<L>(active, nonce, ds, dra, drev))?;
    let mut rng = OsRng;
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::setup(fixed::<L>(active, nonce, ds, dra, drev), &mut rng)
        .map_err(|e| e.to_string())?;
    let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
    let circuit = fixed::<L>(active, nonce, ds, dra, drev);
    let inputs = public_inputs(&circuit);
    let t = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).map_err(|e| e.to_string())?;
    let prove_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    if !Groth16::<Bls12_381>::verify(&vk, &inputs, &proof).map_err(|e| e.to_string())? {
        return Err("self-verification-failed".into());
    }
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let mut pk_bytes = vec![];
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| e.to_string())?;
    let mut vk_bytes = vec![];
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| e.to_string())?;
    let serialize_ms = t.elapsed().as_secs_f64() * 1000.0;
    let pk_load_ms = if env::var("PLAN_A_SKIP_PK_LOAD").as_deref() == Ok("1") {
        None
    } else {
        let t = Instant::now();
        let _loaded = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..])
            .map_err(|e| e.to_string())?;
        Some(t.elapsed().as_secs_f64() * 1000.0)
    };
    std::fs::write(pk_path, &pk_bytes).map_err(|e| e.to_string())?;
    std::fs::write(vk_path, &vk_bytes).map_err(|e| e.to_string())?;
    proof
        .serialize_compressed(BufWriter::new(
            File::create(proof_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    inputs
        .serialize_compressed(BufWriter::new(
            File::create(public_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ok":true,"command":"trial","l_max":L,"active":active,"state_depth":ds,"ra_depth":dra,"revocation_depth":drev,"grant_depth":3,"constraints":shape.0,"instances":shape.1,"witnesses":shape.2,"a_nnz":shape.3,"b_nnz":shape.4,"c_nnz":shape.5,"qap_domain":shape.6,"setup_ms":setup_ms,"prove_ms":prove_ms,"verify_ms":verify_ms,"serialize_ms":serialize_ms,"pk_load_ms":pk_load_ms,"pk_bytes":pk_bytes.len(),"vk_bytes":vk_bytes.len(),"proof_bytes":std::fs::metadata(proof_path).unwrap().len(),"public_bytes":std::fs::metadata(public_path).unwrap().len()})
    );
    Ok(())
}
fn service_prove<const L: usize>(
    pk_path: &str,
    proof_path: &str,
    public_path: &str,
    active: usize,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
    request_sha: &str,
) -> Result<(), String> {
    let raw = hex::decode(request_sha).map_err(|_| "bad request sha")?;
    if raw.len() != 32 {
        return Err("bad request sha".into());
    }
    let mut circuit = fixed::<L>(active, nonce, ds, dra, drev);
    circuit.request.canonical_request_lo =
        Fr::from(u128::from_be_bytes(raw[..16].try_into().unwrap()));
    circuit.request.canonical_request_hi =
        Fr::from(u128::from_be_bytes(raw[16..].try_into().unwrap()));
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(BufReader::new(
        File::open(pk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    let inputs = public_inputs(&circuit);
    let mut rng = OsRng;
    let t = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).map_err(|e| e.to_string())?;
    let prove_ms = t.elapsed().as_secs_f64() * 1000.0;
    proof
        .serialize_compressed(BufWriter::new(
            File::create(proof_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    inputs
        .serialize_compressed(BufWriter::new(
            File::create(public_path).map_err(|e| e.to_string())?,
        ))
        .map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ok":true,"command":"prove-service","prove_ms":prove_ms})
    );
    Ok(())
}
fn e5_batch<const L: usize>(
    pk_path: &str,
    count: usize,
    ds: usize,
    dra: usize,
    drev: usize,
) -> Result<(), String> {
    let t = Instant::now();
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(BufReader::new(
        File::open(pk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    let pk_load_ms = t.elapsed().as_secs_f64() * 1000.0;
    let expected = public_inputs(&fixed::<L>(1, 77, ds, dra, drev));
    let mut rng = OsRng;
    let mut prove_ms = Vec::with_capacity(count);
    let mut proof_bytes = 0usize;
    let mut active_counts = vec![0usize; L];
    for _ in 0..count {
        let active = rng.gen_range(1..=L);
        active_counts[active - 1] += 1;
        let circuit = fixed::<L>(active, 77, ds, dra, drev);
        if public_inputs(&circuit) != expected {
            return Err("E5-public-statement-mismatch".into());
        }
        let t = Instant::now();
        let proof =
            Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).map_err(|e| e.to_string())?;
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let mut bytes = vec![];
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|e| e.to_string())?;
        proof_bytes = bytes.len()
    }
    println!(
        "{}",
        json!({"ok":true,"command":"e5-batch","l_max":L,"count":count,"state_depth":ds,"ra_depth":dra,"revocation_depth":drev,"pk_load_ms":pk_load_ms,"active_counts":active_counts,"prove_ms":prove_ms,"proof_bytes":proof_bytes})
    );
    Ok(())
}
fn e5_fixed<const L: usize>(
    pk_path: &str,
    active: usize,
    count: usize,
    ds: usize,
    dra: usize,
    drev: usize,
) -> Result<(), String> {
    if active == 0 || active > L {
        return Err("bad active".into());
    }
    let t = Instant::now();
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(BufReader::new(
        File::open(pk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    let pk_load_ms = t.elapsed().as_secs_f64() * 1000.0;
    let expected = public_inputs(&fixed::<L>(1, 77, ds, dra, drev));
    let mut rng = OsRng;
    let mut prove_times = Vec::with_capacity(count);
    let mut verify_times = Vec::with_capacity(count);
    for _ in 0..count {
        let circuit = fixed::<L>(active, 77, ds, dra, drev);
        if public_inputs(&circuit) != expected {
            return Err("E5-public-statement-mismatch".into());
        }
        let t = Instant::now();
        let proof =
            Groth16::<Bls12_381>::prove(&pk, circuit, &mut rng).map_err(|e| e.to_string())?;
        prove_times.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now();
        if !Groth16::<Bls12_381>::verify(&pk.vk, &expected, &proof).map_err(|e| e.to_string())? {
            return Err("E5-self-verification-failed".into());
        }
        verify_times.push(t.elapsed().as_secs_f64() * 1000.0)
    }
    println!(
        "{}",
        json!({"ok":true,"command":"e5-fixed","l_max":L,"active":active,"count":count,"state_depth":ds,"ra_depth":dra,"revocation_depth":drev,"pk_load_ms":pk_load_ms,"prove_ms":prove_times,"verify_ms":verify_times,"all_verified":true})
    );
    Ok(())
}
fn e5_interleaved<const L: usize>(
    pk_path: &str,
    count: usize,
    ds: usize,
    dra: usize,
    drev: usize,
    seed: u64,
) -> Result<(), String> {
    if L < 3 {
        return Err("E5 interleaved requires L>=3".into());
    }
    let t = Instant::now();
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(BufReader::new(
        File::open(pk_path).map_err(|e| e.to_string())?,
    ))
    .map_err(|e| e.to_string())?;
    let pk_load_ms = t.elapsed().as_secs_f64() * 1000.0;
    let expected = public_inputs(&fixed::<L>(1, 77, ds, dra, drev));
    let mut order = (1..=3)
        .flat_map(|a| std::iter::repeat(a).take(count))
        .collect::<Vec<_>>();
    order.shuffle(&mut StdRng::seed_from_u64(seed));
    let mut proof_rng = OsRng;
    let mut prove_ms = Vec::with_capacity(order.len());
    let mut verify_ms = Vec::with_capacity(order.len());
    for active in &order {
        let circuit = fixed::<L>(*active, 77, ds, dra, drev);
        if public_inputs(&circuit) != expected {
            return Err("E5-public-statement-mismatch".into());
        }
        let t = Instant::now();
        let proof =
            Groth16::<Bls12_381>::prove(&pk, circuit, &mut proof_rng).map_err(|e| e.to_string())?;
        prove_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = Instant::now();
        if !Groth16::<Bls12_381>::verify(&pk.vk, &expected, &proof).map_err(|e| e.to_string())? {
            return Err("E5-self-verification-failed".into());
        }
        verify_ms.push(t.elapsed().as_secs_f64() * 1000.0)
    }
    println!(
        "{}",
        json!({"ok":true,"command":"e5-interleaved","l_max":L,"count_per_active":count,"shuffle_seed":seed,"order":order,"prove_ms":prove_ms,"verify_ms":verify_ms,"pk_load_ms":pk_load_ms,"all_verified":true})
    );
    Ok(())
}
fn main() {
    if let Err(e) = run() {
        fail(&e)
    }
}
fn run() -> Result<(), String> {
    let a = env::args().collect::<Vec<_>>();
    match a.get(1).map(String::as_str) {
        Some("setup") => {
            if a.len() != 8 {
                return Err("usage: setup PK VK L DS DRA DREV".into());
            }
            let l = number(&a[4], "L")?;
            let ds = number(&a[5], "DS")?;
            let dra = number(&a[6], "DRA")?;
            let dr = number(&a[7], "DREV")?;
            match l {
                1 => setup::<1>(&a[2], &a[3], ds, dra, dr),
                2 => setup::<2>(&a[2], &a[3], ds, dra, dr),
                3 => setup::<3>(&a[2], &a[3], ds, dra, dr),
                4 => setup::<4>(&a[2], &a[3], ds, dra, dr),
                5 => setup::<5>(&a[2], &a[3], ds, dra, dr),
                _ => Err("L must be 1..5".into()),
            }
        }
        Some("prove") => {
            if a.len() != 11 {
                return Err("usage: prove PK PROOF PUBLIC L ACTIVE NONCE DS DRA DREV".into());
            }
            let l = number(&a[5], "L")?;
            let active = number(&a[6], "ACTIVE")?;
            let nonce = number(&a[7], "NONCE")?;
            let ds = number(&a[8], "DS")?;
            let dra = number(&a[9], "DRA")?;
            let dr = number(&a[10], "DREV")?;
            match l {
                1 => prove::<1>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr),
                2 => prove::<2>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr),
                3 => prove::<3>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr),
                4 => prove::<4>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr),
                5 => prove::<5>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr),
                _ => Err("L must be 1..5".into()),
            }
        }
        Some("verify") => {
            if a.len() != 5 {
                return Err("usage: verify VK PROOF PUBLIC".into());
            }
            let vk = VerifyingKey::<Bls12_381>::deserialize_compressed(BufReader::new(
                File::open(&a[2]).map_err(|e| e.to_string())?,
            ))
            .map_err(|e| e.to_string())?;
            let proof = Proof::<Bls12_381>::deserialize_compressed(BufReader::new(
                File::open(&a[3]).map_err(|e| e.to_string())?,
            ))
            .map_err(|e| e.to_string())?;
            let inputs = Vec::<Fr>::deserialize_compressed(BufReader::new(
                File::open(&a[4]).map_err(|e| e.to_string())?,
            ))
            .map_err(|e| e.to_string())?;
            let start = Instant::now();
            let valid =
                Groth16::<Bls12_381>::verify(&vk, &inputs, &proof).map_err(|e| e.to_string())?;
            println!(
                "{}",
                json!({"ok":true,"command":"verify","verify_ms":start.elapsed().as_secs_f64()*1000.0,"valid":valid})
            );
            if valid {
                Ok(())
            } else {
                process::exit(1)
            }
        }
        Some("trial") => {
            if a.len() != 13 {
                return Err(
                    "usage: trial PK VK PROOF PUBLIC L ACTIVE NONCE DS DRA DREV TAG".into(),
                );
            }
            let l = number(&a[6], "L")?;
            let active = number(&a[7], "ACTIVE")?;
            let nonce = number(&a[8], "NONCE")?;
            let ds = number(&a[9], "DS")?;
            let dra = number(&a[10], "DRA")?;
            let dr = number(&a[11], "DREV")?;
            match l {
                1 => benchmark_trial::<1>(&a[2], &a[3], &a[4], &a[5], active, nonce, ds, dra, dr),
                2 => benchmark_trial::<2>(&a[2], &a[3], &a[4], &a[5], active, nonce, ds, dra, dr),
                3 => benchmark_trial::<3>(&a[2], &a[3], &a[4], &a[5], active, nonce, ds, dra, dr),
                4 => benchmark_trial::<4>(&a[2], &a[3], &a[4], &a[5], active, nonce, ds, dra, dr),
                5 => benchmark_trial::<5>(&a[2], &a[3], &a[4], &a[5], active, nonce, ds, dra, dr),
                _ => Err("L must be 1..5".into()),
            }
        }
        Some("prove-service") => {
            if a.len() != 12 {
                return Err(
                    "usage: prove-service PK PROOF PUBLIC L ACTIVE NONCE DS DRA DREV REQUEST_SHA"
                        .into(),
                );
            }
            let l = number(&a[5], "L")?;
            let active = number(&a[6], "ACTIVE")?;
            let nonce = number(&a[7], "NONCE")?;
            let ds = number(&a[8], "DS")?;
            let dra = number(&a[9], "DRA")?;
            let dr = number(&a[10], "DREV")?;
            match l {
                1 => service_prove::<1>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr, &a[11]),
                2 => service_prove::<2>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr, &a[11]),
                3 => service_prove::<3>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr, &a[11]),
                4 => service_prove::<4>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr, &a[11]),
                5 => service_prove::<5>(&a[2], &a[3], &a[4], active, nonce, ds, dra, dr, &a[11]),
                _ => Err("L must be 1..5".into()),
            }
        }
        Some("e5-batch") => {
            if a.len() != 8 {
                return Err("usage: e5-batch PK L COUNT DS DRA DREV".into());
            }
            let l = number(&a[3], "L")?;
            let count = number(&a[4], "COUNT")?;
            let ds = number(&a[5], "DS")?;
            let dra = number(&a[6], "DRA")?;
            let dr = number(&a[7], "DREV")?;
            match l {
                1 => e5_batch::<1>(&a[2], count, ds, dra, dr),
                2 => e5_batch::<2>(&a[2], count, ds, dra, dr),
                3 => e5_batch::<3>(&a[2], count, ds, dra, dr),
                4 => e5_batch::<4>(&a[2], count, ds, dra, dr),
                5 => e5_batch::<5>(&a[2], count, ds, dra, dr),
                _ => Err("L must be 1..5".into()),
            }
        }
        Some("e5-fixed") => {
            if a.len() != 9 {
                return Err("usage: e5-fixed PK L ACTIVE COUNT DS DRA DREV".into());
            }
            let l = number(&a[3], "L")?;
            let active = number(&a[4], "ACTIVE")?;
            let count = number(&a[5], "COUNT")?;
            let ds = number(&a[6], "DS")?;
            let dra = number(&a[7], "DRA")?;
            let dr = number(&a[8], "DREV")?;
            match l {
                1 => e5_fixed::<1>(&a[2], active, count, ds, dra, dr),
                2 => e5_fixed::<2>(&a[2], active, count, ds, dra, dr),
                3 => e5_fixed::<3>(&a[2], active, count, ds, dra, dr),
                4 => e5_fixed::<4>(&a[2], active, count, ds, dra, dr),
                5 => e5_fixed::<5>(&a[2], active, count, ds, dra, dr),
                _ => Err("L must be 1..5".into()),
            }
        }
        Some("e5-interleaved") => {
            if a.len() != 9 {
                return Err("usage: e5-interleaved PK L COUNT_PER_ACTIVE DS DRA DREV SEED".into());
            }
            let l = number(&a[3], "L")?;
            let count = number(&a[4], "COUNT")?;
            let ds = number(&a[5], "DS")?;
            let dra = number(&a[6], "DRA")?;
            let dr = number(&a[7], "DREV")?;
            let seed = number(&a[8], "SEED")?;
            match l {
                3 => e5_interleaved::<3>(&a[2], count, ds, dra, dr, seed),
                4 => e5_interleaved::<4>(&a[2], count, ds, dra, dr, seed),
                5 => e5_interleaved::<5>(&a[2], count, ds, dra, dr, seed),
                _ => Err("E5 L must be 3..5".into()),
            }
        }
        _ => Err("commands: setup, prove, prove-service, verify, trial, e5-batch, e5-fixed".into()),
    }
}
