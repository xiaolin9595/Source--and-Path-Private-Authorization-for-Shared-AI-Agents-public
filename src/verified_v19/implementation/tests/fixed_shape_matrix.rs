use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem};
use plan_a_joint_circuit::fixture::fixed;

fn matrices(active: usize, nonce: u64) -> ConstraintMatrices<Fr> {
    let cs = ConstraintSystem::new_ref();
    fixed::<5>(active, nonce, 20, 20, 32)
        .generate_constraints(cs.clone())
        .unwrap();
    assert!(cs.is_satisfied().unwrap());
    cs.finalize();
    cs.to_matrices().unwrap()
}
#[test]
fn full_abc_matrices_do_not_depend_on_request_or_private_length() {
    let a = matrices(1, 11);
    let b = matrices(3, 22);
    let c = matrices(5, 33);
    for x in [&b, &c] {
        assert_eq!(a.num_instance_variables, x.num_instance_variables);
        assert_eq!(a.num_witness_variables, x.num_witness_variables);
        assert_eq!(a.num_constraints, x.num_constraints);
        assert_eq!(a.a_num_non_zero, x.a_num_non_zero);
        assert_eq!(a.b_num_non_zero, x.b_num_non_zero);
        assert_eq!(a.c_num_non_zero, x.c_num_non_zero);
        assert_eq!(a.a, x.a);
        assert_eq!(a.b, x.b);
        assert_eq!(a.c, x.c)
    }
}
