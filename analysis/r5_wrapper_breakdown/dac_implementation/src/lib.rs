//! First executable gate for the fixed-shape Mir-DAC wrapper.
//!
//! This circuit proves validity of one real Dock SPSEQ-UC root credential
//! commitment.  It is intentionally a stage gate: delegation, fixed `L_max`,
//! policy attenuation, per-grant revocation, and the complete Joint public
//! statement are added by later relations.  Callers must not treat this crate
//! alone as a same-contract B2 result.

pub mod fixed_policy;
pub mod hidden_serial;
pub mod matched_builder;
pub mod semantic_schema;
pub mod service_adapter;
pub mod service_wire;

use ark_bls12_377::{
    constraints::{G1Var, G2Var, PairingVar},
    Bls12_377, Fq, G1Affine, G2Affine,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveConfig};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBitsGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
    pairing::PairingVar as PairingVarTrait,
    prelude::{Boolean, EqGadget},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;
use delegatable_credentials::{
    msbm::{
        keys::{RootIssuerPublicKey, UserPublicKey},
        sps_eq_uc_sig::Signature,
    },
    set_commitment::SetCommitment,
};

pub type DacEngine = Bls12_377;

/// Deployment constants fixed into the wrapper proving and verifying keys.
///
/// Fixing these values is deliberate: the wrapper CRS is scoped to one DAC
/// issuer key and one set-commitment SRS.  A production adapter may instead
/// allocate them as public inputs, paying the corresponding verifier cost.
#[derive(Clone)]
pub struct DeploymentConstants {
    pub p1: G1Affine,
    pub s_p1: G1Affine,
    pub p2: G2Affine,
    pub issuer_pk: RootIssuerPublicKey<DacEngine>,
}

/// Private witness for one singleton-set root credential.
#[derive(Clone)]
pub struct RootCredentialWitness {
    pub commitment: SetCommitment<DacEngine>,
    pub opening_randomness: <DacEngine as Pairing>::ScalarField,
    pub signature: Signature<DacEngine>,
    pub holder_pk: UserPublicKey<DacEngine>,
}

/// Minimal wrapper relation.
///
/// Public input: one canonical `u64` business attribute represented in `Fq`.
/// Private witness: the randomized-set commitment opening, holder key and
/// SPSEQ-UC signature.  The relation enforces the KZG singleton opening and all
/// three pairing-product equations used by Dock's native verifier.
#[derive(Clone)]
pub struct RootCredentialCircuit {
    pub deployment: DeploymentConstants,
    pub public_attribute: u64,
    pub witness: RootCredentialWitness,
}

fn scalar_bits_le(value: <DacEngine as Pairing>::ScalarField) -> Vec<bool> {
    value.into_bigint().to_bits_le()
}

pub(crate) fn enforce_pairing_product_is_one(
    g1: &[G1Var],
    g2: &[G2Var],
) -> Result<(), SynthesisError> {
    let prepared_g1 = g1
        .iter()
        .map(PairingVar::prepare_g1)
        .collect::<Result<Vec<_>, _>>()?;
    let prepared_g2 = g2
        .iter()
        .map(PairingVar::prepare_g2)
        .collect::<Result<Vec<_>, _>>()?;
    let product = PairingVar::product_of_pairings(&prepared_g1, &prepared_g2)?;
    product.enforce_equal(&<PairingVar as PairingVarTrait<DacEngine>>::GTVar::one())
}

/// Allocate a BLS12-377 G2 witness by explicitly clearing its full cofactor.
///
/// ark-r1cs-std 0.4's generic short-Weierstrass witness allocator selects its
/// scalar-order branch for this G2 cofactor, but that branch does not constrain
/// the computed order check. We allocate an on-curve cofactor preimage and
/// expose only `[h]preimage`; the exposed value is therefore in the r-order
/// image because `#E = h*r` and gcd(h,r)=1.
pub(crate) fn new_g2_subgroup_witness(
    cs: ConstraintSystemRef<Fq>,
    value: G2Affine,
) -> Result<G2Var, SynthesisError> {
    let claimed = G2Var::new_variable_omit_prime_order_check(
        cs.clone(),
        || Ok(value.into_group()),
        AllocationMode::Witness,
    )?;
    let preimage = value.mul_by_cofactor_inv();
    let raw = G2Var::new_variable_omit_prime_order_check(
        cs,
        || Ok(preimage.into_group()),
        AllocationMode::Witness,
    )?;
    let cofactor_bits = <ark_bls12_377::g2::Config as CurveConfig>::COFACTOR
        .iter()
        .flat_map(|limb| (0..64).map(move |i| Boolean::constant(((limb >> i) & 1) == 1)))
        .collect::<Vec<_>>();
    let subgroup_value = raw.scalar_mul_le(cofactor_bits.iter())?;
    claimed.enforce_equal(&subgroup_value)?;
    Ok(claimed)
}

/// Allocate a BLS12-377 G1 witness as an explicit full-cofactor image. This
/// mirrors the G2 construction so every adversary-selected pairing point has
/// an auditable subgroup constraint independent of allocator internals.
pub(crate) fn new_g1_subgroup_witness(
    cs: ConstraintSystemRef<Fq>,
    value: G1Affine,
) -> Result<G1Var, SynthesisError> {
    let claimed = G1Var::new_variable_omit_prime_order_check(
        cs.clone(),
        || Ok(value.into_group()),
        AllocationMode::Witness,
    )?;
    let preimage = value.mul_by_cofactor_inv();
    let raw = G1Var::new_variable_omit_prime_order_check(
        cs,
        || Ok(preimage.into_group()),
        AllocationMode::Witness,
    )?;
    let cofactor_bits = <ark_bls12_377::g1::Config as CurveConfig>::COFACTOR
        .iter()
        .flat_map(|limb| (0..64).map(move |i| Boolean::constant(((limb >> i) & 1) == 1)))
        .collect::<Vec<_>>();
    claimed.enforce_equal(&raw.scalar_mul_le(cofactor_bits.iter())?)?;
    Ok(claimed)
}

pub(crate) fn enforce_non_identity<G: CurveVar<C, Fq>, C: ark_ec::CurveGroup>(
    point: &G,
) -> Result<(), SynthesisError> {
    point.is_zero()?.enforce_equal(&Boolean::FALSE)
}

impl ConstraintSynthesizer<Fq> for RootCredentialCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        if self.deployment.issuer_pk.X.0.is_empty() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // The input is range-bound to u64 so its bits define the same scalar in
        // the DAC field.  This avoids an unchecked Fq -> Fr reduction.
        let attribute = FpVar::<Fq>::new_input(cs.clone(), || Ok(Fq::from(self.public_attribute)))?;
        let attribute_bits = attribute.to_bits_le()?;
        for bit in attribute_bits.iter().skip(64) {
            bit.enforce_equal(&Boolean::FALSE)?;
        }

        let p1 = G1Var::new_constant(cs.clone(), self.deployment.p1)?;
        let s_p1 = G1Var::new_constant(cs.clone(), self.deployment.s_p1)?;
        let p2 = G2Var::new_constant(cs.clone(), self.deployment.p2)?;
        let issuer_x0_hat = G2Var::new_constant(cs.clone(), self.deployment.issuer_pk.X_0_hat)?;
        let issuer_x1 = G2Var::new_constant(cs.clone(), self.deployment.issuer_pk.X.0[0])?;

        let commitment = new_g1_subgroup_witness(cs.clone(), self.witness.commitment.0)?;
        let holder_pk = new_g1_subgroup_witness(cs.clone(), self.witness.holder_pk.0)?;
        let z = new_g1_subgroup_witness(cs.clone(), self.witness.signature.comm_sig.Z)?;
        let y = new_g1_subgroup_witness(cs.clone(), self.witness.signature.comm_sig.Y)?;
        let y_tilde = new_g2_subgroup_witness(cs.clone(), self.witness.signature.comm_sig.Y_tilde)?;
        let tag = new_g1_subgroup_witness(cs.clone(), self.witness.signature.T)?;

        // Exclude the all-identity pairing forgery and degenerate holder keys.
        // Both G1 and G2 witnesses use explicit cofactor-image constraints.
        enforce_non_identity(&commitment)?;
        enforce_non_identity(&holder_pk)?;
        enforce_non_identity(&z)?;
        enforce_non_identity(&y)?;
        enforce_non_identity(&y_tilde)?;
        enforce_non_identity(&tag)?;

        // KZG singleton commitment: C = r * (s - attribute) * P1.
        let attribute_p1 = p1.scalar_mul_le(attribute_bits[..64].iter())?;
        let singleton_base = &s_p1 - &attribute_p1;
        let opening_bits_native = scalar_bits_le(self.witness.opening_randomness);
        let opening_bits = opening_bits_native
            .into_iter()
            .map(|bit| Boolean::new_witness(cs.clone(), || Ok(bit)))
            .collect::<Result<Vec<_>, _>>()?;
        let expected_commitment = singleton_base.scalar_mul_le(opening_bits.iter())?;
        expected_commitment.enforce_equal(&commitment)?;

        // Mercurial signature equation 1:
        // e(C, X_1) * e(-Z, Y_tilde) = 1.
        enforce_pairing_product_is_one(
            &[commitment.clone(), z.negate()?],
            &[issuer_x1.clone(), y_tilde.clone()],
        )?;

        // Mercurial signature equation 2:
        // e(Y, P2) * e(-P1, Y_tilde) = 1.
        enforce_pairing_product_is_one(&[y.clone(), p1.negate()?], &[p2.clone(), y_tilde])?;

        // SPSEQ-UC holder binding:
        // e(Y, X_1) * e(holder_pk, X_0_hat) * e(-T, P2) = 1.
        enforce_pairing_product_is_one(
            &[y, holder_pk, tag.negate()?],
            &[issuer_x1, issuer_x0_hat, p2],
        )?;

        Ok(())
    }
}

/// Public input encoding used by Groth16 verification.
pub fn public_inputs(attribute: u64) -> Vec<Fq> {
    vec![Fq::from(attribute)]
}
