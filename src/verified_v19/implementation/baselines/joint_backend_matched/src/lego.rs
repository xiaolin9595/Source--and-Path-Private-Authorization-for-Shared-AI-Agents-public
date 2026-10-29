//! Current-stack LegoGroth16 composition for the split Joint relation.

use crate::{
    augmented::{
        augmented_core_public_inputs, augmented_membership_public_inputs,
        split_augmented_from_joint, AugmentedJointCoreCircuit, AugmentedStateMembershipCircuit,
    },
    certified_map::MappingCertificate,
    core_public_inputs, membership_public_inputs, split_from_joint, JointCoreCircuit,
    StateMembershipCircuit,
};
use ark_bls12_381::{Bls12_381, Fr, G1Projective, G2Projective};
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_std::rand::Rng;
use legogroth16::{
    create_random_proof_incl_cp_link, generate_random_parameters_incl_cp_link,
    prepare_verifying_key, verify_proof_incl_cp_link, LinkPublicGenerators, ProofWithLink,
    ProvingKeyWithLink,
};
use plan_a_joint_circuit::joint::JointCircuit;
use plan_a_joint_circuit::signature::PublicKey;

const COMMITTED_WITNESSES: u32 = 2;
const CORE_ROOT_STATE_INDEX: usize = 2;
const AUGMENTED_COMMITTED_WITNESSES: u32 = 3;
const CP_AUGMENTED_COMMITTED_WITNESSES: u32 = 1;

#[derive(Clone)]
pub struct LinkedParameters {
    pub core: ProvingKeyWithLink<Bls12_381>,
    pub membership: ProvingKeyWithLink<Bls12_381>,
}

#[derive(Clone)]
pub struct LinkedProof {
    pub core: ProofWithLink<Bls12_381>,
    pub membership: ProofWithLink<Bls12_381>,
}

#[derive(Clone)]
pub struct AugmentedLinkedParameters {
    pub core: ProvingKeyWithLink<Bls12_381>,
    pub membership: ProvingKeyWithLink<Bls12_381>,
}

#[derive(Clone)]
pub struct AugmentedLinkedProof {
    pub core: ProofWithLink<Bls12_381>,
    pub membership: ProofWithLink<Bls12_381>,
}

/// Current-stack half of the CP/RSA composition. The caller supplies the CP
/// commitment bases after canonical, subgroup-checked conversion from the
/// legacy stack. Only the first witness (`prime`) is committed.
pub type AugmentedCoreLinkedParameters = ProvingKeyWithLink<Bls12_381>;
pub type AugmentedCoreLinkedProof = ProofWithLink<Bls12_381>;

fn link_generators_for<R: Rng>(
    committed_witnesses: u32,
    rng: &mut R,
) -> LinkPublicGenerators<Bls12_381> {
    LinkPublicGenerators {
        pedersen_gens: (0..committed_witnesses + 1)
            .map(|_| G1Projective::rand(rng).into_affine())
            .collect(),
        g1: G1Projective::rand(rng).into_affine(),
        g2: G2Projective::rand(rng).into_affine(),
    }
}

pub fn link_generators<R: Rng>(rng: &mut R) -> LinkPublicGenerators<Bls12_381> {
    // Two committed witnesses followed by the link hiding generator.
    link_generators_for(COMMITTED_WITNESSES, rng)
}

pub fn setup<const L: usize, R: Rng>(
    joint: &JointCircuit<L>,
    rng: &mut R,
) -> Result<LinkedParameters, String> {
    let (core, membership) = split_from_joint(joint);
    let generators = link_generators(rng);
    let core = generate_random_parameters_incl_cp_link::<Bls12_381, JointCoreCircuit<L>, _>(
        core,
        generators.clone(),
        COMMITTED_WITNESSES,
        rng,
    )
    .map_err(|error| format!("core setup: {error:?}"))?;
    let membership =
        generate_random_parameters_incl_cp_link::<Bls12_381, StateMembershipCircuit, _>(
            membership,
            generators,
            COMMITTED_WITNESSES,
            rng,
        )
        .map_err(|error| format!("membership setup: {error:?}"))?;
    Ok(LinkedParameters { core, membership })
}

pub fn prove<const L: usize, R: Rng>(
    parameters: &LinkedParameters,
    joint: &JointCircuit<L>,
    rng: &mut R,
) -> Result<LinkedProof, String> {
    let (core, membership) = split_from_joint(joint);
    let shared_link_blind = Fr::rand(rng);
    let core_blind = Fr::rand(rng);
    let membership_blind = Fr::rand(rng);
    let core = create_random_proof_incl_cp_link(
        core,
        core_blind,
        shared_link_blind,
        &parameters.core,
        rng,
    )
    .map_err(|error| format!("core prove: {error:?}"))?;
    let membership = create_random_proof_incl_cp_link(
        membership,
        membership_blind,
        shared_link_blind,
        &parameters.membership,
        rng,
    )
    .map_err(|error| format!("membership prove: {error:?}"))?;
    if core.link_d != membership.link_d {
        return Err("prover generated unequal state-link commitments".into());
    }
    Ok(LinkedProof { core, membership })
}

pub fn verify<const L: usize>(
    parameters: &LinkedParameters,
    joint: &JointCircuit<L>,
    proof: &LinkedProof,
) -> Result<(), String> {
    verify_with_inputs(
        parameters,
        &core_public_inputs(joint),
        &membership_public_inputs(joint),
        proof,
    )
}

pub fn verify_with_inputs(
    parameters: &LinkedParameters,
    core_inputs: &[Fr],
    membership_inputs: &[Fr],
    proof: &LinkedProof,
) -> Result<(), String> {
    if core_inputs.len() != 23 || membership_inputs.len() != 1 {
        return Err("malformed public-input vector".into());
    }
    if core_inputs[CORE_ROOT_STATE_INDEX] != membership_inputs[0] {
        return Err("core and membership state roots differ".into());
    }
    if proof.core.link_d != proof.membership.link_d {
        return Err("state-link commitment mismatch".into());
    }
    let core_vk = prepare_verifying_key(&parameters.core.vk.groth16_vk);
    let membership_vk = prepare_verifying_key(&parameters.membership.vk.groth16_vk);
    verify_proof_incl_cp_link(&core_vk, &parameters.core.vk, &proof.core, core_inputs)
        .map_err(|error| format!("core verify: {error:?}"))?;
    verify_proof_incl_cp_link(
        &membership_vk,
        &parameters.membership.vk,
        &proof.membership,
        membership_inputs,
    )
    .map_err(|error| format!("membership verify: {error:?}"))?;
    Ok(())
}

pub fn setup_augmented<const L: usize, R: Rng>(
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    rng: &mut R,
) -> Result<AugmentedLinkedParameters, String> {
    let (core, membership) = split_augmented_from_joint(joint, mapping, mapping_pk);
    let generators = link_generators_for(AUGMENTED_COMMITTED_WITNESSES, rng);
    let core =
        generate_random_parameters_incl_cp_link::<Bls12_381, AugmentedJointCoreCircuit<L>, _>(
            core,
            generators.clone(),
            AUGMENTED_COMMITTED_WITNESSES,
            rng,
        )
        .map_err(|error| format!("augmented core setup: {error:?}"))?;
    let membership = generate_random_parameters_incl_cp_link::<
        Bls12_381,
        AugmentedStateMembershipCircuit,
        _,
    >(membership, generators, AUGMENTED_COMMITTED_WITNESSES, rng)
    .map_err(|error| format!("augmented membership setup: {error:?}"))?;
    Ok(AugmentedLinkedParameters { core, membership })
}

pub fn prove_augmented<const L: usize, R: Rng>(
    parameters: &AugmentedLinkedParameters,
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    rng: &mut R,
) -> Result<AugmentedLinkedProof, String> {
    let (core, membership) = split_augmented_from_joint(joint, mapping, mapping_pk);
    let shared_link_blind = Fr::rand(rng);
    let core = create_random_proof_incl_cp_link(
        core,
        Fr::rand(rng),
        shared_link_blind,
        &parameters.core,
        rng,
    )
    .map_err(|error| format!("augmented core prove: {error:?}"))?;
    let membership = create_random_proof_incl_cp_link(
        membership,
        Fr::rand(rng),
        shared_link_blind,
        &parameters.membership,
        rng,
    )
    .map_err(|error| format!("augmented membership prove: {error:?}"))?;
    if core.link_d != membership.link_d {
        return Err("augmented link commitment mismatch at prover".into());
    }
    Ok(AugmentedLinkedProof { core, membership })
}

pub fn verify_augmented<const L: usize>(
    parameters: &AugmentedLinkedParameters,
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    proof: &AugmentedLinkedProof,
) -> Result<(), String> {
    verify_augmented_with_inputs(
        parameters,
        &augmented_core_public_inputs(joint, mapping, mapping_pk),
        &augmented_membership_public_inputs(joint),
        proof,
    )
}

pub fn verify_augmented_with_inputs(
    parameters: &AugmentedLinkedParameters,
    core_inputs: &[Fr],
    membership_inputs: &[Fr],
    proof: &AugmentedLinkedProof,
) -> Result<(), String> {
    if core_inputs.len() != 27 || membership_inputs.len() != 1 {
        return Err("malformed augmented public-input vector".into());
    }
    if core_inputs[CORE_ROOT_STATE_INDEX] != membership_inputs[0] {
        return Err("augmented core and membership roots differ".into());
    }
    if proof.core.link_d != proof.membership.link_d {
        return Err("augmented state-map commitment mismatch".into());
    }
    let core_vk = prepare_verifying_key(&parameters.core.vk.groth16_vk);
    let membership_vk = prepare_verifying_key(&parameters.membership.vk.groth16_vk);
    verify_proof_incl_cp_link(&core_vk, &parameters.core.vk, &proof.core, core_inputs)
        .map_err(|error| format!("augmented core verify: {error:?}"))?;
    verify_proof_incl_cp_link(
        &membership_vk,
        &parameters.membership.vk,
        &proof.membership,
        membership_inputs,
    )
    .map_err(|error| format!("augmented membership verify: {error:?}"))?;
    Ok(())
}

pub fn setup_augmented_core_with_generators<const L: usize, R: Rng>(
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    generators: LinkPublicGenerators<Bls12_381>,
    rng: &mut R,
) -> Result<AugmentedCoreLinkedParameters, String> {
    if generators.pedersen_gens.len() != CP_AUGMENTED_COMMITTED_WITNESSES as usize + 1 {
        return Err("CP augmented commitment key must contain [prime, hider]".into());
    }
    let (core, _) = split_augmented_from_joint(joint, mapping, mapping_pk);
    generate_random_parameters_incl_cp_link::<Bls12_381, AugmentedJointCoreCircuit<L>, _>(
        core,
        generators,
        CP_AUGMENTED_COMMITTED_WITNESSES,
        rng,
    )
    .map_err(|error| format!("CP augmented core setup: {error:?}"))
}

pub fn prove_augmented_core_with_blind<const L: usize, R: Rng>(
    parameters: &AugmentedCoreLinkedParameters,
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    link_blind: Fr,
    rng: &mut R,
) -> Result<AugmentedCoreLinkedProof, String> {
    if parameters.vk.groth16_vk.commit_witness_count != CP_AUGMENTED_COMMITTED_WITNESSES {
        return Err("CP augmented core proving key commits the wrong witness count".into());
    }
    let (core, _) = split_augmented_from_joint(joint, mapping, mapping_pk);
    create_random_proof_incl_cp_link(core, Fr::rand(rng), link_blind, parameters, rng)
        .map_err(|error| format!("CP augmented core prove: {error:?}"))
}

pub fn verify_augmented_core(
    parameters: &AugmentedCoreLinkedParameters,
    core_inputs: &[Fr],
    proof: &AugmentedCoreLinkedProof,
) -> Result<(), String> {
    if core_inputs.len() != 27
        || parameters.vk.groth16_vk.commit_witness_count != CP_AUGMENTED_COMMITTED_WITNESSES
    {
        return Err("malformed CP augmented core verifier input".into());
    }
    let prepared = prepare_verifying_key(&parameters.vk.groth16_vk);
    verify_proof_incl_cp_link(&prepared, &parameters.vk, proof, core_inputs)
        .map_err(|error| format!("CP augmented core verify: {error:?}"))
}
