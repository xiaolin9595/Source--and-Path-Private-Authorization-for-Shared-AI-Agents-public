use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use plan_a_joint_circuit::fixture::l3;

#[test]
fn canonical_request_sha_limbs_are_128_bit() {
    let mut circuit = l3(2, 9);
    circuit.request.canonical_request_lo = Fr::from(2u64).pow([128]);
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}
