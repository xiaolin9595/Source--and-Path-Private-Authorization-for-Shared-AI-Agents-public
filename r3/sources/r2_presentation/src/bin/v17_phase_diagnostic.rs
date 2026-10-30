use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use plan_a_joint_circuit::{fixture::{fixed, public_inputs}, phase_groth16::prove_with_randomness};
use rand::{rngs::{OsRng, StdRng}, SeedableRng};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, env, fs, time::Instant};

fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

fn main() {
    let args = env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 3, "usage: v17_phase_diagnostic PK SCHEDULE_JSON");
    let pk_bytes = fs::read(&args[1]).unwrap();
    assert_eq!(digest(&pk_bytes), "c35b69180afd18e44b0c0f890661583435395c7715f69f31ce3a4418f940c72e");
    let t = Instant::now();
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..]).unwrap();
    let pk_load_ms = t.elapsed().as_secs_f64() * 1000.0;
    let schedule: Vec<Vec<usize>> = serde_json::from_slice(&fs::read(&args[2]).unwrap()).unwrap();
    assert_eq!(schedule.len(), 4);
    assert!(schedule.iter().all(|b| b.len() == 9));
    assert!(schedule.iter().all(|b| (1..=3).all(|a| b.iter().filter(|x| **x == a).count() == 3)));

    let reference_inputs = public_inputs(&fixed::<3>(1, 0, 20, 20, 32));
    let mut matrix_hash = None;
    let mut matrix_rows = Vec::new();
    for active in 1..=3 {
        let circuit = fixed::<3>(active, 0, 20, 20, 32);
        assert_eq!(public_inputs(&circuit), reference_inputs);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        cs.finalize();
        let matrices = cs.to_matrices().unwrap();
        let mut raw = Vec::new();
        for matrix in [&matrices.a, &matrices.b, &matrices.c] {
            for row in matrix {
                raw.extend_from_slice(&(row.len() as u64).to_le_bytes());
                for (field, index) in row {
                    field.serialize_compressed(&mut raw).unwrap();
                    raw.extend_from_slice(&(*index as u64).to_le_bytes());
                }
            }
        }
        let hash = digest(&raw);
        if let Some(reference) = &matrix_hash { assert_eq!(reference, &hash); } else { matrix_hash = Some(hash.clone()); }
        assert_eq!(hash, "a56657ed27fecc76cdfa570bc01ba118f221baca86cf4c7bc4bc4a3ad202245a");
        assert_eq!(matrices.num_constraints, 179708);
        let mut invalid = circuit;
        invalid.grants[0].grant.action_mask = 0;
        let invalid_cs = ConstraintSystem::<Fr>::new_ref();
        invalid.generate_constraints(invalid_cs.clone()).unwrap();
        assert!(!invalid_cs.is_satisfied().unwrap());
        matrix_rows.push(json!({"active":active,"constraints":matrices.num_constraints,"matrix_sha256":hash,"private_invalid_unsatisfied":true}));
    }
    let dimensions = json!({
        "h_query":pk.h_query.len(), "l_query":pk.l_query.len(), "a_query":pk.a_query.len(),
        "b_g1_query":pk.b_g1_query.len(), "b_g2_query":pk.b_g2_query.len()
    });
    assert_eq!((pk.h_query.len(), pk.l_query.len(), pk.a_query.len(), pk.b_g1_query.len(), pk.b_g2_query.len()), (262143,164114,164138,164138,164138));

    let mut equivalence = Vec::new();
    for active in 1..=3 {
        let mut rng = StdRng::seed_from_u64(202610270500 + active as u64);
        let r = Fr::rand(&mut rng);
        let s = Fr::rand(&mut rng);
        let native = Groth16::<Bls12_381>::create_proof_with_reduction(fixed::<3>(active,0,20,20,32), &pk, r, s).unwrap();
        let (copied, _) = prove_with_randomness(&pk, fixed::<3>(active,0,20,20,32), r, s).unwrap();
        assert_eq!(native, copied);
        assert!(Groth16::<Bls12_381>::verify(&pk.vk, &reference_inputs, &copied).unwrap());
        equivalence.push(json!({"active":active,"same_explicit_randomness_exact_proof":true,"verified":true}));
    }
    println!("{}", json!({"event":"preflight","pk_sha256":digest(&pk_bytes),"pk_load_ms":pk_load_ms,"matrix":matrix_rows,"query_dimensions":dimensions,"equivalence":equivalence,"public_statement_equal":true}));

    for active in 1..=3 {
        let r = Fr::rand(&mut OsRng); let s = Fr::rand(&mut OsRng);
        let started = Instant::now();
        let (proof, phases) = prove_with_randomness(&pk, fixed::<3>(active,0,20,20,32),r,s).unwrap();
        let prove_ms = started.elapsed().as_secs_f64()*1000.0;
        assert!(Groth16::<Bls12_381>::verify(&pk.vk,&reference_inputs,&proof).unwrap());
        println!("{}",json!({"event":"warmup","active":active,"prove_ms":prove_ms,"phases":phases,"verified":true}));
    }

    let mut hashes = HashSet::new();
    let mut measured = 0usize;
    for (block, entries) in schedule.iter().enumerate() {
        for (block_index, active) in entries.iter().enumerate() {
            let t = Instant::now();
            let circuit = fixed::<3>(*active,0,20,20,32);
            let fixture_ms = t.elapsed().as_secs_f64()*1000.0;
            assert_eq!(public_inputs(&circuit), reference_inputs);
            let prove_started = Instant::now();
            let r = Fr::rand(&mut OsRng); let s = Fr::rand(&mut OsRng);
            let (proof, phases) = prove_with_randomness(&pk,circuit,r,s).unwrap();
            let prove_ms = prove_started.elapsed().as_secs_f64()*1000.0;
            let verify_started = Instant::now();
            let verified = Groth16::<Bls12_381>::verify(&pk.vk,&reference_inputs,&proof).unwrap();
            let verify_ms = verify_started.elapsed().as_secs_f64()*1000.0;
            assert!(verified);
            let mut bad = reference_inputs.clone(); bad[0] += Fr::from(1u64);
            assert!(!Groth16::<Bls12_381>::verify(&pk.vk,&bad,&proof).unwrap());
            let serialize_started = Instant::now();
            let mut encoded=Vec::new(); proof.serialize_compressed(&mut encoded).unwrap();
            let serialization_ms=serialize_started.elapsed().as_secs_f64()*1000.0;
            let proof_sha256=digest(&encoded); assert!(hashes.insert(proof_sha256.clone()));
            let value=serde_json::to_value(&phases).unwrap();
            let phase_sum_ms=value.as_object().unwrap().values().map(|v|v.as_f64().unwrap()).sum::<f64>();
            measured += 1;
            println!("{}",json!({"event":"proof","block":block,"block_index":block_index,"global_index":measured-1,"active":active,"fixture_ms":fixture_ms,"prove_ms":prove_ms,"phase_sum_ms":phase_sum_ms,"residual_ms":prove_ms-phase_sum_ms,"phases":phases,"verify_ms":verify_ms,"serialization_ms":serialization_ms,"verified":true,"changed_public_rejected":true,"proof_sha256":proof_sha256,"proof_bytes":encoded.len()}));
        }
    }
    assert_eq!(measured,36); assert_eq!(hashes.len(),36);
    println!("{}",json!({"event":"finished","measured_proofs":measured,"unique_proof_hashes":hashes.len(),"all_verified":true,"all_changed_public_rejected":true}));
}
