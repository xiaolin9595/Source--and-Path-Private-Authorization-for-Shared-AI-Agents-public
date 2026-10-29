use crate::core::{state_leaf, JointCoreCircuit};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use plan_a_joint_circuit::{
    fixture::public_inputs,
    joint::JointCircuit,
    poseidon::{hash_var, Domain},
    Fr,
};

#[derive(Clone)]
pub struct StateMembershipCircuit {
    pub root_state: Fr,
    pub leaf: Fr,
    pub position: u32,
    pub siblings: Vec<Fr>,
    pub directions: Vec<bool>,
}

fn witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs.clone(), || Ok(value))
}

impl ConstraintSynthesizer<Fr> for StateMembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if self.siblings.len() != self.directions.len() || self.siblings.len() > 32 {
            return Err(SynthesisError::Unsatisfiable);
        }
        // Must be the first two witnesses for LegoGroth16's committed-witness
        // prefix and must match the allocation order in JointCoreCircuit.
        let leaf = witness(&cs, self.leaf)?;
        let position = witness(&cs, Fr::from(self.position))?;
        let root = FpVar::new_input(cs.clone(), || Ok(self.root_state))?;
        let position_bits = position.to_bits_le()?;
        for bit in &position_bits[self.siblings.len()..] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        let mut current = leaf;
        for (index, (sibling, direction)) in
            self.siblings.iter().zip(self.directions.iter()).enumerate()
        {
            let sibling = witness(&cs, *sibling)?;
            let direction = Boolean::new_witness(cs.clone(), || Ok(*direction))?;
            direction.enforce_equal(
                position_bits
                    .get(index)
                    .ok_or(SynthesisError::Unsatisfiable)?,
            )?;
            let left = FpVar::conditionally_select(&direction, &sibling, &current)?;
            let right = FpVar::conditionally_select(&direction, &current, &sibling)?;
            current = hash_var(Domain::TreeNode, &[left, right])?;
        }
        current.enforce_equal(&root)
    }
}

pub fn split_from_joint<const L: usize>(
    joint: &JointCircuit<L>,
) -> (JointCoreCircuit<L>, StateMembershipCircuit) {
    let core = JointCoreCircuit {
        snapshot: joint.snapshot.clone(),
        request: joint.request.clone(),
        entitlement: joint.entitlement.clone(),
        state: joint.state.clone(),
        registration_salt: joint.registration_salt,
        grants: joint.grants.clone(),
    };
    let membership = StateMembershipCircuit {
        root_state: joint.snapshot.root_state,
        leaf: state_leaf(&joint.state),
        position: joint.state.position,
        siblings: joint.state.path.siblings.clone(),
        directions: joint.state.path.directions.clone(),
    };
    (core, membership)
}

/// The core retains the exact 23-field native Joint public-input order.
pub fn core_public_inputs<const L: usize>(joint: &JointCircuit<L>) -> Vec<Fr> {
    public_inputs(joint)
}

pub fn membership_public_inputs<const L: usize>(joint: &JointCircuit<L>) -> Vec<Fr> {
    vec![joint.snapshot.root_state]
}
