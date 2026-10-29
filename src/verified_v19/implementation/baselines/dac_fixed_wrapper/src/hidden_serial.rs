//! Native composite proof linking a hidden signed DAC set member to the same
//! hidden element in a dynamic-accumulator non-membership proof.
//!
//! This closes the concrete linkage gap in the old disclosed-serial component.
//! It does not by itself hide the number of DAC commitment layers or enforce
//! the Plan-A business predicates; those remain wrapper-circuit obligations.

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::{collections::BTreeSet, io::Write, rand::RngCore, UniformRand};
use delegatable_credentials::{
    error::DelegationError,
    set_commitment::{SetCommitment, SetCommitmentOpening, SetCommitmentSRS, SubsetWitness},
};
use schnorr_pok::{
    discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol},
    error::SchnorrError,
};
use thiserror::Error;
use vb_accumulator::{
    error::VBAccumulatorError,
    proofs::{NonMembershipProof, NonMembershipProofProtocol},
    setup::{
        NonMembershipProvingKey, PreparedPublicKey, PreparedSetupParams, PublicKey, SetupParams,
    },
    witness::NonMembershipWitness,
};

#[derive(Debug, Error)]
pub enum HiddenSerialError {
    #[error("DAC set-membership relation failed: {0:?}")]
    Dac(DelegationError),
    #[error("accumulator relation failed: {0:?}")]
    Accumulator(VBAccumulatorError),
    #[error("Schnorr relation failed: {0:?}")]
    Schnorr(SchnorrError),
    #[error("transcript serialization failed: {0}")]
    Serialization(#[from] ark_serialize::SerializationError),
    #[error("transcript write failed: {0}")]
    Io(#[from] ark_std::io::Error),
    #[error("hidden set-member pairing equation failed")]
    InvalidSetMembershipPairing,
    #[error("hidden set-member Schnorr equation failed")]
    InvalidSetMembershipSchnorr,
}

impl From<DelegationError> for HiddenSerialError {
    fn from(error: DelegationError) -> Self {
        Self::Dac(error)
    }
}

impl From<VBAccumulatorError> for HiddenSerialError {
    fn from(error: VBAccumulatorError) -> Self {
        Self::Accumulator(error)
    }
}

impl From<SchnorrError> for HiddenSerialError {
    fn from(error: SchnorrError) -> Self {
        Self::Schnorr(error)
    }
}

/// First move of the hidden KZG set-member proof.
pub struct HiddenSetMemberProtocol<E: Pairing> {
    pub subset_witness: SubsetWitness<E>,
    pub member_commitment: E::G1Affine,
    pub schnorr: PokDiscreteLogProtocol<E::G1Affine>,
}

/// Proof that one undisclosed scalar belongs to a randomized KZG set
/// commitment.  `member_commitment = member * subset_witness`; both group
/// elements inherit the presentation randomizer and are fresh across shows.
#[derive(Clone, Debug)]
pub struct HiddenSetMemberProof<E: Pairing> {
    pub subset_witness: SubsetWitness<E>,
    pub member_commitment: E::G1Affine,
    pub schnorr: PokDiscreteLog<E::G1Affine>,
}

impl<E: Pairing> HiddenSetMemberProtocol<E> {
    pub fn init(
        set_commitment: &SetCommitment<E>,
        opening: &SetCommitmentOpening<E>,
        full_set: BTreeSet<E::ScalarField>,
        member: E::ScalarField,
        shared_member_blinding: E::ScalarField,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, HiddenSerialError> {
        let mut singleton = BTreeSet::new();
        singleton.insert(member);
        let subset_witness = set_commitment.open_subset(opening, singleton, full_set, srs)?;
        let member_commitment = subset_witness
            .0
            .mul_bigint(member.into_bigint())
            .into_affine();
        let schnorr =
            PokDiscreteLogProtocol::init(member, shared_member_blinding, &subset_witness.0);
        Ok(Self {
            subset_witness,
            member_commitment,
            schnorr,
        })
    }

    pub fn challenge_contribution<W: Write>(
        &self,
        set_commitment: &SetCommitment<E>,
        mut writer: W,
    ) -> Result<(), HiddenSerialError> {
        set_commitment.0.serialize_compressed(&mut writer)?;
        self.subset_witness.0.serialize_compressed(&mut writer)?;
        self.member_commitment.serialize_compressed(&mut writer)?;
        self.schnorr.challenge_contribution(
            &self.subset_witness.0,
            &self.member_commitment,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof(self, challenge: &E::ScalarField) -> HiddenSetMemberProof<E> {
        HiddenSetMemberProof {
            subset_witness: self.subset_witness,
            member_commitment: self.member_commitment,
            schnorr: self.schnorr.gen_proof(challenge),
        }
    }
}

impl<E: Pairing> HiddenSetMemberProof<E> {
    pub fn challenge_contribution<W: Write>(
        &self,
        set_commitment: &SetCommitment<E>,
        mut writer: W,
    ) -> Result<(), HiddenSerialError> {
        set_commitment.0.serialize_compressed(&mut writer)?;
        self.subset_witness.0.serialize_compressed(&mut writer)?;
        self.member_commitment.serialize_compressed(&mut writer)?;
        self.schnorr.challenge_contribution(
            &self.subset_witness.0,
            &self.member_commitment,
            writer,
        )?;
        Ok(())
    }

    pub fn verify(
        &self,
        set_commitment: &SetCommitment<E>,
        challenge: &E::ScalarField,
        srs: &SetCommitmentSRS<E>,
    ) -> Result<(), HiddenSerialError> {
        // If C = r * f(s) * P1 and member is a root of f, W is
        // r * f(s)/(s-member) * P1.  With T=member*W, the verifier checks
        // e(W,sP2) = e(C+T,P2) without learning member.
        let commitment_plus_member =
            (set_commitment.0.into_group() + self.member_commitment).into_affine();
        if !E::multi_pairing(
            [
                self.subset_witness.0,
                (-commitment_plus_member.into_group()).into_affine(),
            ],
            [
                E::G2Prepared::from(*srs.get_s_P2()),
                E::G2Prepared::from(*srs.get_P2()),
            ],
        )
        .is_zero()
        {
            return Err(HiddenSerialError::InvalidSetMembershipPairing);
        }
        if !self
            .schnorr
            .verify(&self.member_commitment, &self.subset_witness.0, challenge)
        {
            return Err(HiddenSerialError::InvalidSetMembershipSchnorr);
        }
        Ok(())
    }
}

/// Composite first move.  The same blinding is supplied to the DAC member PoK
/// and the accumulator PoK, which makes their element response identical.
pub struct HiddenSerialProtocol<E: Pairing> {
    pub set_member: HiddenSetMemberProtocol<E>,
    pub non_membership: NonMembershipProofProtocol<E>,
}

#[derive(Clone, Debug)]
pub struct HiddenSerialProof<E: Pairing> {
    pub set_member: HiddenSetMemberProof<E>,
    pub non_membership: NonMembershipProof<E>,
}

impl<E: Pairing> HiddenSerialProtocol<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn init<R: RngCore>(
        rng: &mut R,
        set_commitment: &SetCommitment<E>,
        opening: &SetCommitmentOpening<E>,
        full_set: BTreeSet<E::ScalarField>,
        serial: E::ScalarField,
        non_membership_witness: &NonMembershipWitness<E::G1Affine>,
        accumulator_pk: &PublicKey<E>,
        accumulator_params: &SetupParams<E>,
        accumulator_proving_key: &NonMembershipProvingKey<E::G1Affine>,
        set_commitment_srs: &SetCommitmentSRS<E>,
    ) -> Result<Self, HiddenSerialError> {
        let shared_blinding = E::ScalarField::rand(rng);
        let set_member = HiddenSetMemberProtocol::init(
            set_commitment,
            opening,
            full_set,
            serial,
            shared_blinding,
            set_commitment_srs,
        )?;
        let non_membership = NonMembershipProofProtocol::init(
            rng,
            serial,
            Some(shared_blinding),
            non_membership_witness,
            accumulator_pk,
            accumulator_params,
            accumulator_proving_key,
        );
        Ok(Self {
            set_member,
            non_membership,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn challenge_contribution<W: Write>(
        &self,
        domain_and_public_context: &[u8],
        set_commitment: &SetCommitment<E>,
        accumulator_value: &E::G1Affine,
        accumulator_pk: &PublicKey<E>,
        accumulator_params: &SetupParams<E>,
        accumulator_proving_key: &NonMembershipProvingKey<E::G1Affine>,
        mut writer: W,
    ) -> Result<(), HiddenSerialError> {
        writer.write_all(&(domain_and_public_context.len() as u64).to_le_bytes())?;
        writer.write_all(domain_and_public_context)?;
        self.set_member
            .challenge_contribution(set_commitment, &mut writer)?;
        self.non_membership.challenge_contribution(
            accumulator_value,
            accumulator_pk,
            accumulator_params,
            accumulator_proving_key,
            writer,
        )?;
        Ok(())
    }

    pub fn gen_proof(
        self,
        challenge: &E::ScalarField,
    ) -> Result<HiddenSerialProof<E>, HiddenSerialError> {
        Ok(HiddenSerialProof {
            set_member: self.set_member.gen_proof(challenge),
            // Omit the accumulator's element response.  The verifier supplies
            // the linked response from `set_member.schnorr`.
            non_membership: self.non_membership.gen_partial_proof(challenge)?,
        })
    }
}

impl<E: Pairing> HiddenSerialProof<E> {
    #[allow(clippy::too_many_arguments)]
    pub fn challenge_contribution<W: Write>(
        &self,
        domain_and_public_context: &[u8],
        set_commitment: &SetCommitment<E>,
        accumulator_value: &E::G1Affine,
        accumulator_pk: &PublicKey<E>,
        accumulator_params: &SetupParams<E>,
        accumulator_proving_key: &NonMembershipProvingKey<E::G1Affine>,
        mut writer: W,
    ) -> Result<(), HiddenSerialError> {
        writer.write_all(&(domain_and_public_context.len() as u64).to_le_bytes())?;
        writer.write_all(domain_and_public_context)?;
        self.set_member
            .challenge_contribution(set_commitment, &mut writer)?;
        self.non_membership.challenge_contribution(
            accumulator_value,
            accumulator_pk,
            accumulator_params,
            accumulator_proving_key,
            writer,
        )?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn verify(
        &self,
        set_commitment: &SetCommitment<E>,
        accumulator_value: &E::G1Affine,
        challenge: &E::ScalarField,
        accumulator_pk: PreparedPublicKey<E>,
        accumulator_params: PreparedSetupParams<E>,
        accumulator_proving_key: &NonMembershipProvingKey<E::G1Affine>,
        set_commitment_srs: &SetCommitmentSRS<E>,
    ) -> Result<(), HiddenSerialError> {
        self.set_member
            .verify(set_commitment, challenge, set_commitment_srs)?;
        self.non_membership.verify_partial(
            &self.set_member.schnorr.response,
            accumulator_value,
            challenge,
            accumulator_pk,
            accumulator_params,
            accumulator_proving_key,
        )?;
        Ok(())
    }
}
