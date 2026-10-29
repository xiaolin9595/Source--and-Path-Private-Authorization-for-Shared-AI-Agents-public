//! Reusable constructor from native DAC artifacts to the fixed-policy circuit.
//!
//! The paired semantic driver builds every argument from its one parsed raw
//! object. This constructor checks that the supplied typed records are exactly
//! the signed credential attributes and that the credential verifies for the
//! statement terminal key before creating the circuit witness.

use crate::fixed_policy::{
    encode_record, public_inputs, FixedPolicyCircuit, FixedPolicyDeployment,
    FixedPolicySlotWitness, FixedPolicyStatement, FixedPolicyWitness, GrantRecord,
};
use ark_bls12_377::{Bls12_377, Fq, Fr, G1Affine};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_std::collections::BTreeSet;
use blake2::{Blake2s256, Digest};
use delegatable_credentials::{
    msbm::{
        issuance::Credential,
        keys::{PreparedRootIssuerPublicKey, RootIssuerPublicKey, UserPublicKey},
    },
    set_commitment::{SetCommitmentOpening, SetCommitmentSRS},
};
use thiserror::Error;
use vb_accumulator::witness::NonMembershipWitness;

#[derive(Debug, Error)]
pub enum MatchedBuilderError {
    #[error("record, credential, revocation witness, and deployment lengths differ")]
    LengthMismatch,
    #[error("slot {0} signed attributes differ from the canonical typed record")]
    SignedRecordMismatch(usize),
    #[error("slot {0} uses a trapdoor opening that is invalid for a holder proof")]
    TrapdoorOpening(usize),
    #[error("slot {0} exact-opening quotient construction failed")]
    ExactOpening(usize),
    #[error("native Dock credential verification failed")]
    CredentialVerification,
    #[error("fixed-policy synthesis failed")]
    Synthesis,
}

#[derive(Clone, Debug)]
pub struct MatchedSynthesisAudit {
    pub satisfied: bool,
    pub unsatisfied_constraint: Option<String>,
    pub public_inputs_equal_instance_assignment: bool,
    pub constraints: usize,
    pub canonical_matrix_blake2s: String,
}

fn hash_usize(hasher: &mut Blake2s256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hash_matrix(hasher: &mut Blake2s256, label: u8, matrix: &[Vec<(Fq, usize)>]) {
    hasher.update([label]);
    hash_usize(hasher, matrix.len());
    let mut coefficient_bytes = Vec::new();
    for (row_index, row) in matrix.iter().enumerate() {
        hash_usize(hasher, row_index);
        hash_usize(hasher, row.len());
        for (entry_index, (coefficient, column_index)) in row.iter().enumerate() {
            hash_usize(hasher, entry_index);
            hash_usize(hasher, *column_index);
            coefficient_bytes.clear();
            coefficient
                .serialize_compressed(&mut coefficient_bytes)
                .expect("canonical matrix coefficient serialization");
            hasher.update(&coefficient_bytes);
        }
    }
}

/// Synthesize one matched circuit before setup, check its witness and exact
/// public-input coordinates, and commit the complete finalized A/B/C matrices.
pub fn audit_matched_circuit(
    circuit: &FixedPolicyCircuit,
) -> Result<MatchedSynthesisAudit, MatchedBuilderError> {
    let cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .map_err(|_| MatchedBuilderError::Synthesis)?;
    let satisfied = cs
        .is_satisfied()
        .map_err(|_| MatchedBuilderError::Synthesis)?;
    let unsatisfied_constraint = cs
        .which_is_unsatisfied()
        .map_err(|_| MatchedBuilderError::Synthesis)?;
    let expected = public_inputs(&circuit.statement, circuit.deployment.relation_version);
    let actual = cs
        .borrow()
        .ok_or(MatchedBuilderError::Synthesis)?
        .instance_assignment[1..]
        .to_vec();
    cs.finalize();
    let matrices = cs.to_matrices().ok_or(MatchedBuilderError::Synthesis)?;
    drop(cs);
    let mut canonical = Blake2s256::new();
    canonical.update(b"plan-a-dac-fixed-wrapper-r1cs-matrices-v1");
    for value in [
        matrices.num_instance_variables,
        matrices.num_witness_variables,
        matrices.num_constraints,
        matrices.a_num_non_zero,
        matrices.b_num_non_zero,
        matrices.c_num_non_zero,
    ] {
        hash_usize(&mut canonical, value);
    }
    hash_matrix(&mut canonical, b'A', &matrices.a);
    hash_matrix(&mut canonical, b'B', &matrices.b);
    hash_matrix(&mut canonical, b'C', &matrices.c);
    Ok(MatchedSynthesisAudit {
        satisfied,
        unsatisfied_constraint,
        public_inputs_equal_instance_assignment: expected == actual,
        constraints: matrices.num_constraints,
        canonical_matrix_blake2s: canonical
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    })
}

pub struct MatchedCircuitInput {
    pub deployment: FixedPolicyDeployment,
    pub statement: FixedPolicyStatement,
    pub issuer_pk: RootIssuerPublicKey<Bls12_377>,
    pub credential: Credential<Bls12_377>,
    pub records: Vec<GrantRecord>,
    pub entitlement: crate::fixed_policy::DacEntitlementWitness,
    pub state: crate::fixed_policy::DacStateWitness,
    pub non_membership_witnesses: Vec<NonMembershipWitness<G1Affine>>,
}

fn exact_opening_quotients(
    credential: &Credential<Bls12_377>,
    slot: usize,
    set_srs: &SetCommitmentSRS<Bls12_377>,
) -> Result<Vec<G1Affine>, MatchedBuilderError> {
    let full_set = credential.attributes[slot]
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut prefix = BTreeSet::new();
    credential.attributes[slot]
        .iter()
        .map(|member| {
            prefix.insert(*member);
            credential.commitments[slot]
                .open_subset(
                    &credential.openings[slot],
                    prefix.clone(),
                    full_set.clone(),
                    set_srs,
                )
                .map(|witness| witness.0)
                .map_err(|_| MatchedBuilderError::ExactOpening(slot))
        })
        .collect()
}

fn opening_randomness(
    credential: &Credential<Bls12_377>,
    slot: usize,
) -> Result<Fr, MatchedBuilderError> {
    match &credential.openings[slot] {
        SetCommitmentOpening::SetWithoutTrapdoor(randomness) => Ok(*randomness),
        SetCommitmentOpening::SetWithTrapdoor(_, _) => {
            Err(MatchedBuilderError::TrapdoorOpening(slot))
        }
    }
}

pub fn build_matched_circuit(
    input: MatchedCircuitInput,
    set_srs: &SetCommitmentSRS<Bls12_377>,
) -> Result<FixedPolicyCircuit, MatchedBuilderError> {
    let slot_count = input.records.len();
    if slot_count != input.deployment.l_max
        || input.credential.attributes.len() != slot_count
        || input.credential.commitments.len() != slot_count
        || input.credential.openings.len() != slot_count
        || input.non_membership_witnesses.len() != slot_count
    {
        return Err(MatchedBuilderError::LengthMismatch);
    }
    for (slot, record) in input.records.iter().enumerate() {
        if encode_record(record, slot) != input.credential.attributes[slot] {
            return Err(MatchedBuilderError::SignedRecordMismatch(slot));
        }
    }
    input
        .credential
        .verify(
            None,
            &UserPublicKey(input.statement.terminal_key),
            PreparedRootIssuerPublicKey::from(input.issuer_pk.clone()),
            set_srs,
        )
        .map_err(|_| MatchedBuilderError::CredentialVerification)?;

    let mut slots = Vec::with_capacity(slot_count);
    for (slot, ((record, non_membership_witness), commitment)) in input
        .records
        .into_iter()
        .zip(input.non_membership_witnesses)
        .zip(input.credential.commitments.iter())
        .enumerate()
    {
        slots.push(FixedPolicySlotWitness {
            record,
            commitment: commitment.clone(),
            exact_opening_quotients: exact_opening_quotients(&input.credential, slot, set_srs)?,
            opening_randomness: opening_randomness(&input.credential, slot)?,
            non_membership_witness,
        });
    }
    Ok(FixedPolicyCircuit {
        deployment: input.deployment,
        statement: input.statement,
        witness: FixedPolicyWitness {
            issuer_pk: input.issuer_pk,
            entitlement: input.entitlement,
            state: input.state,
            slots,
            signature: input.credential.signature,
        },
    })
}
