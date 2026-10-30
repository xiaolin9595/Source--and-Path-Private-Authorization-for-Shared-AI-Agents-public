use ark_bls12_381::{Bls12_381,Fr,G1Projective,G2Projective};
use ark_ec::scalar_mul::ScalarMul;
use ark_groth16::{Groth16,ProvingKey};
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize};
use ark_relations::r1cs::{ConstraintSynthesizer,ConstraintSystem};
use ark_snark::SNARK;
use plan_a_joint_circuit::{fixture::{fixed,public_inputs},profiled_groth16::prove_profiled};
use rand::rngs::OsRng;
use sha2::{Sha256,Digest};
use serde_json::json;
use std::{time::Instant,env};
fn digest(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn main(){let a:Vec<_>=env::args().collect();let t=Instant::now();let bytes=std::fs::read(&a[1]).unwrap();let pk=ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..]).unwrap();let load=t.elapsed().as_secs_f64()*1000.;
 let mut matrices=Vec::new();let mut reference=None;for active in 1..=3{let c=fixed::<3>(active,0,20,20,32);let cs=ConstraintSystem::<Fr>::new_ref();c.generate_constraints(cs.clone()).unwrap();assert!(cs.is_satisfied().unwrap());cs.finalize();let m=cs.to_matrices().unwrap();let mut raw=Vec::new();for matrix in [&m.a,&m.b,&m.c]{for row in matrix{raw.extend_from_slice(&(row.len() as u64).to_le_bytes());for (f,k) in row{f.serialize_compressed(&mut raw).unwrap();raw.extend_from_slice(&(*k as u64).to_le_bytes());}}}let hash=digest(&raw);if let Some(ref r)=reference {assert_eq!(r,&hash)}else{reference=Some(hash.clone())}matrices.push(json!({"active":active,"constraints":m.num_constraints,"matrix_sha256":hash}));}
 let reference_inputs=public_inputs(&fixed::<3>(1,0,20,20,32));let mut rows=Vec::new();
 for (active,dense) in [(2,false),(1,true),(3,false),(2,true),(1,false),(3,true)]{let t=Instant::now();let circuit=fixed::<3>(active,0,20,20,32);let fixture_ms=t.elapsed().as_secs_f64()*1000.;let inputs=public_inputs(&circuit);assert_eq!(inputs,reference_inputs);let mut phases=Vec::new();let t=Instant::now();let proof=prove_profiled(&pk,circuit,&mut OsRng,dense,&mut phases).unwrap();let profiled_prove_ms=t.elapsed().as_secs_f64()*1000.;assert!(Groth16::<Bls12_381>::verify(&pk.vk,&inputs,&proof).unwrap());let mut bad=inputs.clone();bad[0]+=Fr::from(1u64);assert!(!Groth16::<Bls12_381>::verify(&pk.vk,&bad,&proof).unwrap());let t=Instant::now();let mut encoded=Vec::new();proof.serialize_compressed(&mut encoded).unwrap();let serialization_ms=t.elapsed().as_secs_f64()*1000.;rows.push(json!({"active":active,"candidate_dense_digit":dense,"fixture_ms":fixture_ms,"profiled_prove_including_diagnostic_scans_ms":profiled_prove_ms,"serialization_ms":serialization_ms,"phases":phases,"verified":true,"mutated_statement_rejected":true,"proof_sha256":digest(&encoded),"proof_bytes":encoded.len()}));}
 println!("{}",json!({"diagnostic_only":true,"pk_sha256":digest(&bytes),"pk_load_ms":load,"g1_negation_is_cheap":G1Projective::NEGATION_IS_CHEAP,"g2_negation_is_cheap":G2Projective::NEGATION_IS_CHEAP,"selected_msm":"wnaf","matrices":matrices,"rows":rows,"signing_boundary":"grant signing in fixture; no terminal request signing or HTTP"}));}
