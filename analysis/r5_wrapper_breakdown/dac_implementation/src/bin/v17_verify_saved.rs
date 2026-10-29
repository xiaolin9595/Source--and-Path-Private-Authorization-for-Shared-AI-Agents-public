use ark_bls12_377::Fq;
use ark_bw6_761::BW6_761;
use ark_groth16::{Groth16,Proof,VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use serde_json::json;
fn main(){let root=std::env::args().nth(1).expect("artifact directory");let vk=std::fs::read(format!("{root}/vk.bin")).unwrap();let vk=VerifyingKey::<BW6_761>::deserialize_compressed(&vk[..]).unwrap();let mut rows=Vec::new();let mut first=None;
for active in [3,2,1]{let b=std::fs::read(format!("{root}/proof-active{active}.bin")).unwrap();let proof=Proof::<BW6_761>::deserialize_compressed(&b[..]).unwrap();let b=std::fs::read(format!("{root}/public-active{active}.bin")).unwrap();let inputs=Vec::<Fq>::deserialize_compressed(&b[..]).unwrap();if let Some(ref f)=first{assert_eq!(f,&inputs)}else{first=Some(inputs.clone())};assert!(Groth16::<BW6_761>::verify(&vk,&inputs,&proof).unwrap());let mut bad=inputs;bad[0]+=Fq::from(1u64);assert!(!Groth16::<BW6_761>::verify(&vk,&bad,&proof).unwrap());rows.push(json!({"active":active,"saved_proof_checked_deserialize":true,"saved_public_statement_identical":true,"original_verifier_accepted":true,"mutated_public_rejected":true}));}println!("{}",json!({"independent_saved_artifact_verification":true,"rows":rows}));}
