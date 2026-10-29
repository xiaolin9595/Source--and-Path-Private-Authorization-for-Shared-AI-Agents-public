use ark_bls12_381::{Bls12_381,Fr};
use ark_groth16::{Groth16,ProvingKey};
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize};
use ark_relations::r1cs::{ConstraintSynthesizer,ConstraintSystem};
use ark_snark::SNARK;
use plan_a_joint_circuit::{fixture::{fixed,public_inputs},pilot_groth16::prove_pilot};
use rand::{rngs::{OsRng,StdRng},seq::SliceRandom,SeedableRng};
use sha2::{Sha256,Digest};
use serde_json::json;
use std::{time::Instant,env};
fn digest(b:&[u8])->String{format!("{:x}",Sha256::digest(b))}
fn main(){let a:Vec<_>=env::args().collect();let t=Instant::now();let bytes=std::fs::read(&a[1]).unwrap();let pk=ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..]).unwrap();let load=t.elapsed().as_secs_f64()*1000.;
 for active in 1..=3{let c=fixed::<3>(active,1,20,20,32);let inputs=public_inputs(&c);let proof=prove_pilot(&pk,c.clone(),&mut OsRng,true,&mut Vec::new()).unwrap();assert!(Groth16::<Bls12_381>::verify(&pk.vk,&inputs,&proof).unwrap());let mut invalid=c;invalid.grants[0].grant.action_mask=0;let cs=ConstraintSystem::<Fr>::new_ref();invalid.generate_constraints(cs.clone()).unwrap();assert!(!cs.is_satisfied().unwrap());}
 let mut schedule=Vec::new();for repeat in 0..20{for active in 1..=3{schedule.push((active,(repeat+active)%2==0));}}schedule.shuffle(&mut StdRng::seed_from_u64(2026102702));
 let reference=public_inputs(&fixed::<3>(1,0,20,20,32));let mut x=Vec::new();reference.serialize_compressed(&mut x).unwrap();println!("{}",json!({"event":"start","pk_sha256":digest(&bytes),"pk_load_ms":load,"public_sha256":digest(&x),"additional_nonce1_candidate_proofs_verified":3,"invalid_witness_synthesis_rejections":3,"schedule":schedule,"seed":2026102702u64}));
 let mut rows=Vec::new();for (pair,(active,candidate_first)) in schedule.into_iter().enumerate(){for candidate in [candidate_first,!candidate_first]{let t=Instant::now();let circuit=fixed::<3>(active,0,20,20,32);let fixture_ms=t.elapsed().as_secs_f64()*1000.;let inputs=public_inputs(&circuit);assert_eq!(inputs,reference);let t=Instant::now();let proof=if candidate{prove_pilot(&pk,circuit,&mut OsRng,true,&mut Vec::new()).unwrap()}else{Groth16::<Bls12_381>::prove(&pk,circuit,&mut OsRng).unwrap()};let prove_ms=t.elapsed().as_secs_f64()*1000.;assert!(Groth16::<Bls12_381>::verify(&pk.vk,&inputs,&proof).unwrap());let mut bad=inputs;bad[0]+=Fr::from(1u64);assert!(!Groth16::<Bls12_381>::verify(&pk.vk,&bad,&proof).unwrap());let mut encoded=Vec::new();proof.serialize_compressed(&mut encoded).unwrap();let row=json!({"event":"proof","pair":pair,"active":active,"candidate":candidate,"fixture_ms":fixture_ms,"prove_ms":prove_ms,"verified":true,"mutated_statement_rejected":true,"proof_sha256":digest(&encoded),"proof_bytes":encoded.len()});println!("{}",row);rows.push(row);}}
 println!("{}",json!({"event":"complete","rows":rows.len(),"all_verified":true,"shared_host":true,"formal":false}));}
