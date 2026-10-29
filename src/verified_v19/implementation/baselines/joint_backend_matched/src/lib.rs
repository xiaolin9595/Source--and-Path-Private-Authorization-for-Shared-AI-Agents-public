#![forbid(unsafe_code)]
//! Matched current-Joint backend experiment.
//!
//! The inline backend is the production `JointCircuit`.  The split backend
//! proves the same logical relation as a Joint core and a Poseidon state-tree
//! membership circuit joined by a fresh hidden-state commitment.

pub mod augmented;
pub mod certified_map;
pub mod core;
pub mod lego;
pub mod split;

pub use augmented::{
    augmented_core_public_inputs, augmented_membership_public_inputs, inline_augmented_from_joint,
    split_augmented_from_joint, AugmentedInlineCircuit, AugmentedJointCoreCircuit,
    AugmentedStateMembershipCircuit,
};
pub use core::state_leaf;
pub use core::{CoreOutputs, CoreStateBindings, JointCoreCircuit};
pub use lego::{
    prove as prove_linked, setup as setup_linked, verify as verify_linked,
    verify_with_inputs as verify_linked_inputs, LinkedParameters, LinkedProof,
};
pub use lego::{
    prove_augmented, setup_augmented, verify_augmented, verify_augmented_with_inputs,
    AugmentedLinkedParameters, AugmentedLinkedProof,
};
pub use lego::{
    prove_augmented_core_with_blind, setup_augmented_core_with_generators, verify_augmented_core,
    AugmentedCoreLinkedParameters, AugmentedCoreLinkedProof,
};
pub use split::{
    core_public_inputs, membership_public_inputs, split_from_joint, StateMembershipCircuit,
};
