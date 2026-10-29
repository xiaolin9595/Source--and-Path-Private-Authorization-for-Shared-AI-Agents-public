//! Standalone diagnosis. Production adapter and upstream prover are unchanged.
use ark_bls12_381::{Fr, G1Projective};
use ark_ff::UniformRand;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::{
    commitments::{pedersen::PedersenCommitment, Commitment},
    protocols::{
        hrada_auth::{AuthCircuit, AuthFixture},
        hrada_link,
    },
    utils::integer_to_bigint_mod_q,
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
fn cpu() -> f64 {
    extern "C" {
        fn clock() -> i64;
    }
    unsafe { clock() as f64 / 1e6 }
}
fn timer() -> (Instant, f64) {
    (Instant::now(), cpu())
}
fn elapsed(t: (Instant, f64)) -> Value {
    json!({"wall_ms":t.0.elapsed().as_secs_f64()*1000.,"cpu_seconds":cpu()-t.1})
}
fn enc<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = vec![];
    v.serialize(&mut b).unwrap();
    b
}
#[derive(Clone)]
struct TimedCircuit {
    c: AuthCircuit,
    rows: Arc<Mutex<Vec<Value>>>,
}
impl ConstraintSynthesizer<Fr> for TimedCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let t = timer();
        self.c.generate_constraints(cs.clone())?;
        self.rows.lock().unwrap().push(json!({"phase":"lego_synthesis","timing":elapsed(t),"constraints":cs.num_constraints(),"instances":cs.num_instance_variables(),"witnesses":cs.num_witness_variables()}));
        Ok(())
    }
}
fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("output dir"));
    fs::create_dir_all(&dir).unwrap();
    let seed = OsRng.next_u64() >> 1;
    let mut f = AuthFixture::new_with_expiry(seed, 86400);
    f.close_issuers();
    let c = f.circuit_for("Q");
    let cp = PedersenCommitment::<G1Projective>::setup(&mut OsRng);
    let mut cpbytes = enc(&cp.g);
    cpbytes.extend(enc(&cp.h));
    println!("PROFILE_SETUP_BEGIN");
    let t = timer();
    let params = hrada_link::setup(&mut OsRng, &cp, c.clone(), 16).unwrap();
    let setup = elapsed(t);
    println!("PROFILE_SETUP_END");
    let digest = hrada_link::parameter_digest(&params, &cpbytes).unwrap();
    fs::write(dir.join("verifying_key.bin"), enc(&params.proving_key.vk)).unwrap();
    fs::write(dir.join("cp_bases.bin"), &cpbytes).unwrap();
    let r = Integer::from_digits(&enc(&Fr::rand(&mut OsRng)), Order::Lsf);
    // Fixed commitment/witness/input is an A/A timing control. Every proof has fresh Groth16 randomness.
    let prime = Integer::from_digits(&enc(&c.prime), Order::Lsf);
    let commitment = cp.commit(&prime, &r).unwrap();
    fs::write(dir.join("commitment.bin"), enc(&commitment)).unwrap();
    fs::write(dir.join("request.bin"), enc(&c.request.fields.to_vec())).unwrap();
    let mut log = fs::File::create(dir.join("measurements.jsonl")).unwrap();
    let metadata = json!({"pk_queries":{"h":params.proving_key.h_query.len(),"l":params.proving_key.l_query.len(),"a":params.proving_key.a_query.len(),"b_g1":params.proving_key.b_g1_query.len(),"b_g2":params.proving_key.b_g2_query.len()},"seed":seed,"setup":setup,"rayon_num_threads":std::env::var("RAYON_NUM_THREADS").ok(),"available_parallelism":std::thread::available_parallelism().unwrap().get(),"debug_assertions":cfg!(debug_assertions),"public_request_fields":16,"same_input_same_witness_same_resident_key":true,"fresh_proof_randomness":true,"fixed_commitment_for_diagnostic_only":true,"upstream_feature":"legogro16/print-trace","preflight_cs_retained_through_prover":true});
    fs::write(
        dir.join("metadata.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();
    for i in 0..8 {
        let baseline = i == 0 || i == 7;
        println!(
            "PROFILE_REPEAT_BEGIN {} {}",
            i,
            if baseline { "original" } else { "profiled" }
        );
        std::io::stdout().flush().unwrap();
        let total = timer();
        let mut phases = vec![];
        let proof = if baseline {
            hrada_link::prove(&mut OsRng, &params, c.clone(), &r).unwrap()
        } else {
            let t = timer();
            let cs = ConstraintSystem::<Fr>::new_ref();
            c.clone().generate_constraints(cs.clone()).unwrap();
            phases.push(json!({"phase":"preflight_synthesis","timing":elapsed(t),"constraints":cs.num_constraints(),"instances":cs.num_instance_variables(),"witnesses":cs.num_witness_variables()}));
            let t = timer();
            assert!(cs.is_satisfied().unwrap());
            assert_eq!(cs.num_instance_variables(), params.request_fields + 2);
            phases.push(json!({"phase":"preflight_satisfaction","timing":elapsed(t)}));
            let t = timer();
            let link_randomness = integer_to_bigint_mod_q::<G1Projective>(&r).unwrap();
            let rows = Arc::new(Mutex::new(vec![]));
            let wrapped = TimedCircuit {
                c: c.clone(),
                rows: rows.clone(),
            };
            let proof = legogro16::create_random_proof(
                wrapped,
                Fr::rand(&mut OsRng),
                link_randomness,
                &params.proving_key,
                &mut OsRng,
            )
            .unwrap();
            phases.push(json!({"phase":"lego_prove_total","timing":elapsed(t)}));
            phases.extend(rows.lock().unwrap().clone());
            let t = timer();
            drop(cs);
            phases.push(json!({"phase":"preflight_drop","timing":elapsed(t)}));
            proof
        };
        let proof_total = elapsed(total);
        println!("PROFILE_REPEAT_PROOF_END {}", i);
        let t = timer();
        let valid = hrada_link::verify(
            &params,
            &cp,
            &cpbytes,
            &digest,
            &proof,
            &c.request.fields,
            &commitment,
        )
        .unwrap();
        assert!(valid);
        let verify = elapsed(t);
        let bytes = enc(&proof);
        fs::write(dir.join(format!("proof-{}.bin", i)), &bytes).unwrap();
        let row = json!({"repeat":i,"mode":if baseline{"original"}else{"profiled"},"proof_total":proof_total,"phases":phases,"verify":verify,"valid":valid,"proof_bytes":bytes.len()});
        writeln!(log, "{}", row).unwrap();
        log.flush().unwrap();
        println!("PROFILE_REPEAT_END {}", i);
    }
}
