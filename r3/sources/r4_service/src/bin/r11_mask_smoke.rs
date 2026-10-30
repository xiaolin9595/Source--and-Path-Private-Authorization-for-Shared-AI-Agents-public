use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize};
use ark_snark::SNARK;
use ark_r1cs_std::synthesis_patch::Mode;
use plan_a_joint_circuit::{
    fixture::{fixed, public_inputs},
    offline_mask::TokenPool,
    offline_mask_groth16::{prove_from_pool, PublicAssemblyContext},
    phase_groth16::prove_with_randomness_mode,
};
use rand::{rngs::StdRng, SeedableRng};
use std::{env, fs, sync::Arc};
use sha2::{Digest,Sha256};

fn assignment<const L: usize>(c: plan_a_joint_circuit::joint::JointCircuit<L>, mode: Mode) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>,String) {
    let cs=ConstraintSystem::<Fr>::new_ref(); cs.set_optimization_goal(OptimizationGoal::Constraints);
    let guard=ark_r1cs_std::synthesis_patch::enter(mode); c.generate_constraints(cs.clone()).unwrap(); drop(guard);
    assert!(cs.is_satisfied().unwrap()); cs.finalize();
    let matrices=cs.to_matrices().unwrap(); let mut raw=Vec::new();
    for matrix in [&matrices.a,&matrices.b,&matrices.c] { for row in matrix { for (v,i) in row { v.serialize_compressed(&mut raw).unwrap(); raw.extend_from_slice(&(*i as u64).to_le_bytes()); } raw.extend_from_slice(&(row.len() as u64).to_le_bytes()); } }
    let matrix_hash=format!("{:x}",Sha256::digest(&raw));
    let h=LibsnarkReduction::witness_map::<Fr,GeneralEvaluationDomain<Fr>>(cs.clone()).unwrap();
    let borrowed=cs.borrow().unwrap();
    (borrowed.instance_assignment.clone(),borrowed.witness_assignment.clone(),h,matrix_hash)
}

fn main() {
    let path = env::args().nth(1).expect("usage: r11_mask_smoke PK");
    let bytes = fs::read(path).unwrap();
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&bytes[..]).unwrap();
    let public = PublicAssemblyContext::new(Arc::new(pk.clone())).unwrap();
    for nonce in [0,7] { for active in 1..=3 {
        let c=fixed::<3>(active,nonce,20,20,32);
        let native=assignment(c.clone(),Mode::Native); let fixed_a=assignment(c.clone(),Mode::FixedWitness);
        assert_eq!(native,fixed_a); assert_eq!(native.2.len(),pk.h_query.len()+1); assert!(native.2.last().unwrap().is_zero());
        let mut invalid=c; invalid.grants[0].grant.action_mask=0;
        for mode in [Mode::Native,Mode::FixedWitness] { let cs=ConstraintSystem::<Fr>::new_ref(); let g=ark_r1cs_std::synthesis_patch::enter(mode); invalid.clone().generate_constraints(cs.clone()).unwrap(); drop(g); assert!(!cs.is_satisfied().unwrap()); }
    }}
    let tokens=(0..6).map(|id|public.generate_set(id).unwrap()).collect();
    let pool = TokenPool::new(tokens).unwrap();
    assert_eq!(pool.remaining(), 6);
    for active in 1..=3 {
    let circuit = fixed::<3>(active, 0, 20, 20, 32);
    let mut rng = StdRng::seed_from_u64(202610270601+active as u64);
    let r = Fr::rand(&mut rng);
    let s = Fr::rand(&mut rng);
    let native = Groth16::<Bls12_381>::create_proof_with_reduction(circuit.clone(), &pk, r, s).unwrap();
    let (fixed_proof,_)=prove_with_randomness_mode(&pk,circuit.clone(),r,s,Mode::FixedWitness).unwrap();
    assert_eq!(native,fixed_proof);
    let (masked, _) = prove_from_pool(&pool, &public, circuit.clone(), r, s, Mode::Native).unwrap();
    let (combined, _) = prove_from_pool(&pool, &public, circuit.clone(), r, s, Mode::FixedWitness).unwrap();
    assert_eq!(native, masked); assert_eq!(native, combined);
    let inputs=public_inputs(&circuit); assert!(Groth16::<Bls12_381>::verify(&pk.vk,&inputs,&masked).unwrap());
    let mut changed=inputs; changed[0]+=Fr::from(1u64); assert!(!Groth16::<Bls12_381>::verify(&pk.vk,&changed,&masked).unwrap());
    println!("MASK_FULL_GATE active={} exact_S_M_C=true verify=true changed_public_rejected=true",active);
    }
    assert_eq!(pool.remaining(), 0);
    assert_eq!(pool.consumed(),6); assert_eq!(pool.resident(),6);
    assert!(pool.claim_next().is_err());
    println!("MASK_FULL_GATE_PASS assignments_matrices_fullH_nonce0_7=true invalid_private_both_modes=true exact_S_M_C_all_lengths=true consumed=true");
}
