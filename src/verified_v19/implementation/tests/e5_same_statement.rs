use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use plan_a_joint_circuit::fixture::{fixed, public_inputs};

#[test]
fn different_private_lengths_share_identical_public_statement() {
    let a = fixed::<5>(1, 77, 10, 20, 32);
    let b = fixed::<5>(3, 77, 10, 20, 32);
    let c = fixed::<5>(5, 77, 10, 20, 32);
    assert_eq!(public_inputs(&a), public_inputs(&b));
    assert_eq!(public_inputs(&a), public_inputs(&c));
    for circuit in [a, b, c] {
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap())
    }
}
