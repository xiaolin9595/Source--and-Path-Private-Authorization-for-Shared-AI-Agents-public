//! SR-facing names for the canonical Joint benchmark fixtures.
//! The construction is maintained once in `plan_a_joint_circuit::fixture`.
pub use plan_a_joint_circuit::fixture::{
    offline_child_to_new_terminal, source_b_revocation_capability, two_source_same_terminal,
};

pub fn revoke_source_b(
    a: plan_a_joint_circuit::joint::JointCircuit<3>,
    b: plan_a_joint_circuit::joint::JointCircuit<3>,
) -> [plan_a_joint_circuit::joint::JointCircuit<3>; 2] {
    plan_a_joint_circuit::fixture::revoke_two_source_b(a, b)
}
