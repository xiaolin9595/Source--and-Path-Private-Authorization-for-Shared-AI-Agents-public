use ark_bls12_381::Fr;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem};
use plan_a_joint_circuit::fixture::fixed;
fn matrices() -> ConstraintMatrices<Fr> {
    let cs = ConstraintSystem::new_ref();
    fixed::<3>(2, 77, 20, 20, 32)
        .generate_constraints(cs.clone())
        .unwrap();
    cs.finalize();
    cs.to_matrices().unwrap()
}
#[test]
fn observer_does_not_change_relation() {
    std::env::remove_var("PLAN_A_CONSTRAINT_PROFILE");
    let off = matrices();
    std::env::set_var("PLAN_A_CONSTRAINT_PROFILE", "1");
    let on = matrices();
    std::env::remove_var("PLAN_A_CONSTRAINT_PROFILE");
    assert_eq!(
        (
            off.num_constraints,
            off.num_instance_variables,
            off.num_witness_variables,
            off.a_num_non_zero,
            off.b_num_non_zero,
            off.c_num_non_zero
        ),
        (
            on.num_constraints,
            on.num_instance_variables,
            on.num_witness_variables,
            on.a_num_non_zero,
            on.b_num_non_zero,
            on.c_num_non_zero
        )
    );
    assert_eq!(off.a, on.a);
    assert_eq!(off.b, on.b);
    assert_eq!(off.c, on.c)
}
