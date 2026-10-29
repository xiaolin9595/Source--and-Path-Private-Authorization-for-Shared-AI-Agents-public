//! Certified-state-map augmented Joint relation used by the matched E8 gate.
//!
//! The first three witnesses are always `(prime,state_leaf,position)`.  The
//! Poseidon split backend links all three.  The CP/RSA backend links the first
//! witness to its public Pedersen commitment; the signed mapping certificate
//! then binds that prime to the leaf, position and typed state generation.

use crate::{
    certified_map::{enforce_certificate, MappingCertificate},
    core::{state_leaf, CoreStateBindings, JointCoreCircuit},
    core_public_inputs,
};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use plan_a_joint_circuit::{
    joint::JointCircuit,
    poseidon::{hash_var, Domain},
    signature::PublicKey,
    Fr,
};

#[derive(Clone)]
pub struct AugmentedJointCoreCircuit<const L: usize> {
    pub core: JointCoreCircuit<L>,
    pub mapping: MappingCertificate,
    pub mapping_pk: PublicKey,
}

#[derive(Clone)]
pub struct AugmentedStateMembershipCircuit {
    pub prime: Fr,
    pub root_state: Fr,
    pub leaf: Fr,
    pub position: u32,
    pub siblings: Vec<Fr>,
    pub directions: Vec<bool>,
}

#[derive(Clone)]
pub struct AugmentedInlineCircuit<const L: usize> {
    pub core: JointCoreCircuit<L>,
    pub mapping: MappingCertificate,
    pub mapping_pk: PublicKey,
    pub siblings: Vec<Fr>,
    pub directions: Vec<bool>,
}

struct PrefixVars {
    prime: FpVar<Fr>,
    leaf: FpVar<Fr>,
    position: FpVar<Fr>,
    owner: FpVar<Fr>,
    version: FpVar<Fr>,
    epoch: FpVar<Fr>,
}

fn witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs.clone(), || Ok(value))
}

fn enforce_unsigned(value: &FpVar<Fr>, bits: usize) -> Result<(), SynthesisError> {
    let decomposition = value.to_bits_le()?;
    for bit in &decomposition[bits..] {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(())
}

fn allocate_prefix(
    cs: &ConstraintSystemRef<Fr>,
    certificate: &MappingCertificate,
) -> Result<PrefixVars, SynthesisError> {
    let record = &certificate.record;
    // This order is a protocol invariant: CP commits to witness 0, while the
    // Poseidon composition commits to witnesses 0..3.
    let prime = witness(cs, record.prime)?;
    let leaf = witness(cs, record.state_leaf)?;
    let position = witness(cs, Fr::from(record.position))?;
    let owner = witness(cs, record.owner_commitment)?;
    let version = witness(cs, Fr::from(record.state_version))?;
    let epoch = witness(cs, Fr::from(record.state_epoch))?;
    enforce_unsigned(&position, 32)?;
    enforce_unsigned(&version, 64)?;
    enforce_unsigned(&epoch, 64)?;
    Ok(PrefixVars {
        prime,
        leaf,
        position,
        owner,
        version,
        epoch,
    })
}

fn enforce_mapping(
    cs: ConstraintSystemRef<Fr>,
    prefix: &PrefixVars,
    certificate: &MappingCertificate,
    mapping_pk: &PublicKey,
) -> Result<(), SynthesisError> {
    let deployment = FpVar::new_input(cs.clone(), || Ok(certificate.record.deployment_id))?;
    let mapping_version = FpVar::new_input(cs.clone(), || {
        Ok(Fr::from(certificate.record.mapping_version))
    })?;
    let pk_x = FpVar::new_input(cs.clone(), || Ok(mapping_pk.0.x))?;
    let pk_y = FpVar::new_input(cs.clone(), || Ok(mapping_pk.0.y))?;
    enforce_certificate(
        cs,
        (&pk_x, &pk_y),
        [
            &deployment,
            &prefix.owner,
            &prefix.leaf,
            &prefix.position,
            &prefix.version,
            &prefix.epoch,
            &prefix.prime,
            &mapping_version,
        ],
        &certificate.signature,
    )
}

fn enforce_state_path(
    cs: &ConstraintSystemRef<Fr>,
    root: &FpVar<Fr>,
    leaf: &FpVar<Fr>,
    position: &FpVar<Fr>,
    siblings: &[Fr],
    directions: &[bool],
) -> Result<(), SynthesisError> {
    if siblings.len() != directions.len() || siblings.len() > 32 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let position_bits = position.to_bits_le()?;
    for bit in &position_bits[siblings.len()..] {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    let mut current = leaf.clone();
    for (index, (sibling, direction)) in siblings.iter().zip(directions).enumerate() {
        let sibling = witness(cs, *sibling)?;
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
    current.enforce_equal(root)
}

impl<const L: usize> ConstraintSynthesizer<Fr> for AugmentedJointCoreCircuit<L> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prefix = allocate_prefix(&cs, &self.mapping)?;
        self.core.synthesize_with_bindings(
            cs.clone(),
            CoreStateBindings {
                leaf: prefix.leaf.clone(),
                position: prefix.position.clone(),
                owner_commitment: Some(prefix.owner.clone()),
                state_version: Some(prefix.version.clone()),
                state_epoch: Some(prefix.epoch.clone()),
            },
        )?;
        enforce_mapping(cs, &prefix, &self.mapping, &self.mapping_pk)
    }
}

impl ConstraintSynthesizer<Fr> for AugmentedStateMembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prime = witness(&cs, self.prime)?;
        let leaf = witness(&cs, self.leaf)?;
        let position = witness(&cs, Fr::from(self.position))?;
        // The prime is linked to the core and intentionally unused by the
        // Poseidon path equations themselves.
        prime.enforce_equal(&prime)?;
        enforce_unsigned(&position, 32)?;
        let root = FpVar::new_input(cs.clone(), || Ok(self.root_state))?;
        enforce_state_path(
            &cs,
            &root,
            &leaf,
            &position,
            &self.siblings,
            &self.directions,
        )
    }
}

impl<const L: usize> ConstraintSynthesizer<Fr> for AugmentedInlineCircuit<L> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prefix = allocate_prefix(&cs, &self.mapping)?;
        let output = self.core.synthesize_with_bindings(
            cs.clone(),
            CoreStateBindings {
                leaf: prefix.leaf.clone(),
                position: prefix.position.clone(),
                owner_commitment: Some(prefix.owner.clone()),
                state_version: Some(prefix.version.clone()),
                state_epoch: Some(prefix.epoch.clone()),
            },
        )?;
        enforce_mapping(cs.clone(), &prefix, &self.mapping, &self.mapping_pk)?;
        enforce_state_path(
            &cs,
            &output.root_state,
            &prefix.leaf,
            &prefix.position,
            &self.siblings,
            &self.directions,
        )
    }
}

pub fn split_augmented_from_joint<const L: usize>(
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
) -> (
    AugmentedJointCoreCircuit<L>,
    AugmentedStateMembershipCircuit,
) {
    let core = JointCoreCircuit {
        snapshot: joint.snapshot.clone(),
        request: joint.request.clone(),
        entitlement: joint.entitlement.clone(),
        state: joint.state.clone(),
        registration_salt: joint.registration_salt,
        grants: joint.grants.clone(),
    };
    (
        AugmentedJointCoreCircuit {
            core,
            mapping: mapping.clone(),
            mapping_pk: mapping_pk.clone(),
        },
        AugmentedStateMembershipCircuit {
            prime: mapping.record.prime,
            root_state: joint.snapshot.root_state,
            leaf: state_leaf(&joint.state),
            position: joint.state.position,
            siblings: joint.state.path.siblings.clone(),
            directions: joint.state.path.directions.clone(),
        },
    )
}

pub fn inline_augmented_from_joint<const L: usize>(
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
) -> AugmentedInlineCircuit<L> {
    let (core, _) = split_augmented_from_joint(joint, mapping, mapping_pk);
    AugmentedInlineCircuit {
        core: core.core,
        mapping: core.mapping,
        mapping_pk: core.mapping_pk,
        siblings: joint.state.path.siblings.clone(),
        directions: joint.state.path.directions.clone(),
    }
}

pub fn augmented_core_public_inputs<const L: usize>(
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
) -> Vec<Fr> {
    let mut inputs = core_public_inputs(joint);
    inputs.extend([
        mapping.record.deployment_id,
        Fr::from(mapping.record.mapping_version),
        mapping_pk.0.x,
        mapping_pk.0.y,
    ]);
    inputs
}

pub fn augmented_membership_public_inputs<const L: usize>(joint: &JointCircuit<L>) -> Vec<Fr> {
    vec![joint.snapshot.root_state]
}
