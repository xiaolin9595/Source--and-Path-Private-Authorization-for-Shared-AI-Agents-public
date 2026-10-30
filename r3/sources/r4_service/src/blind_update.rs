//! Groth16 relation for owner-authorized state updates whose openings stay client-side.
use crate::{
    poseidon::{hash, hash_var, Domain},
    Fr,
};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

/// Public statement. The SR constructs admission-bound fields from its database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindUpdateStatement {
    pub config_digest: Fr,
    pub deployment: Fr,
    pub circuit_id: Fr,
    pub owner: Fr,
    pub position: u32,
    pub expiry_cap: u64,
    pub admission_version: u64,
    pub old_leaf: Fr,
    pub new_leaf: Fr,
    pub old_version: u64,
    pub new_version: u64,
    pub old_epoch: u64,
    pub new_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateOpening {
    pub grant_root: Fr,
    pub expiry: u64,
    pub active: bool,
    pub salt: Fr,
}

#[derive(Clone)]
pub struct BlindUpdateCircuit {
    pub statement: BlindUpdateStatement,
    pub old: StateOpening,
    pub new: StateOpening,
}

pub fn state_leaf(
    owner: Fr,
    version: u64,
    epoch: u64,
    position: u32,
    opening: &StateOpening,
) -> Fr {
    hash(
        Domain::StateLeaf,
        &[
            owner,
            opening.grant_root,
            Fr::from(version),
            Fr::from(epoch),
            Fr::from(opening.expiry),
            Fr::from(opening.active as u64),
            opening.salt,
            Fr::from(position),
        ],
    )
}

pub fn public_inputs(s: &BlindUpdateStatement) -> Vec<Fr> {
    vec![
        s.config_digest,
        s.deployment,
        s.circuit_id,
        s.owner,
        Fr::from(s.position),
        Fr::from(s.expiry_cap),
        Fr::from(s.admission_version),
        s.old_leaf,
        s.new_leaf,
        Fr::from(s.old_version),
        Fr::from(s.new_version),
        Fr::from(s.old_epoch),
        Fr::from(s.new_epoch),
        identity_binding(s),
    ]
}

pub fn identity_binding(s: &BlindUpdateStatement) -> Fr {
    hash(
        Domain::BlindUpdateIdentity,
        &[s.config_digest, s.deployment, s.circuit_id],
    )
}

fn input(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_input(cs.clone(), || Ok(value))
}

fn witness(cs: &ConstraintSystemRef<Fr>, value: Fr) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs.clone(), || Ok(value))
}

fn u64_bits(value: &FpVar<Fr>) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let bits = value.to_bits_le()?;
    for bit in &bits[64..] {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(bits[..64].to_vec())
}

fn less_than(a: &[Boolean<Fr>], b: &[Boolean<Fr>]) -> Result<Boolean<Fr>, SynthesisError> {
    let mut less = Boolean::FALSE;
    let mut equal = Boolean::TRUE;
    for i in (0..a.len()).rev() {
        less = less.or(&equal.and(&a[i].not().and(&b[i])?)?)?;
        equal = equal.and(&a[i].xor(&b[i])?.not())?;
    }
    Ok(less)
}

fn less_or_equal(a: &[Boolean<Fr>], b: &[Boolean<Fr>]) -> Result<Boolean<Fr>, SynthesisError> {
    let lt = less_than(a, b)?;
    let mut eq = Boolean::TRUE;
    for (x, y) in a.iter().zip(b) {
        eq = eq.and(&x.is_eq(y)?)?;
    }
    lt.or(&eq)
}

impl ConstraintSynthesizer<Fr> for BlindUpdateCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let config = input(&cs, self.statement.config_digest)?;
        let deployment = input(&cs, self.statement.deployment)?;
        let circuit_id = input(&cs, self.statement.circuit_id)?;
        let owner = input(&cs, self.statement.owner)?;
        let position = input(&cs, Fr::from(self.statement.position))?;
        let position_bits = position.to_bits_le()?;
        for bit in &position_bits[32..] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        let cap = input(&cs, Fr::from(self.statement.expiry_cap))?;
        let cap_bits = u64_bits(&cap)?;
        let admission_version = input(&cs, Fr::from(self.statement.admission_version))?;
        u64_bits(&admission_version)?;
        let old_leaf = input(&cs, self.statement.old_leaf)?;
        let new_leaf = input(&cs, self.statement.new_leaf)?;
        let old_version = input(&cs, Fr::from(self.statement.old_version))?;
        let new_version = input(&cs, Fr::from(self.statement.new_version))?;
        let old_version_bits = u64_bits(&old_version)?;
        let new_version_bits = u64_bits(&new_version)?;
        let old_epoch = input(&cs, Fr::from(self.statement.old_epoch))?;
        let new_epoch = input(&cs, Fr::from(self.statement.new_epoch))?;
        let old_epoch_bits = u64_bits(&old_epoch)?;
        let new_epoch_bits = u64_bits(&new_epoch)?;
        // Allocate this last to match `public_inputs`. Hashing into a public
        // binding makes all identities non-dead while keeping the matrix
        // independent of their values.
        let identity = input(&cs, identity_binding(&self.statement))?;
        identity.enforce_equal(&hash_var(
            Domain::BlindUpdateIdentity,
            &[config, deployment, circuit_id],
        )?)?;

        // Equality in the field plus both operands' u64 range checks gives integer
        // addition without wraparound. In particular, u64::MAX has no successor.
        (&old_version + Fr::from(1u64)).enforce_equal(&new_version)?;
        less_than(&old_version_bits, &new_version_bits)?.enforce_equal(&Boolean::TRUE)?;
        less_than(&old_epoch_bits, &new_epoch_bits)?.enforce_equal(&Boolean::TRUE)?;

        let old_root = witness(&cs, self.old.grant_root)?;
        let old_expiry = witness(&cs, Fr::from(self.old.expiry))?;
        let old_expiry_bits = u64_bits(&old_expiry)?;
        let old_active = Boolean::new_witness(cs.clone(), || Ok(self.old.active))?;
        let old_salt = witness(&cs, self.old.salt)?;
        let new_root = witness(&cs, self.new.grant_root)?;
        let new_expiry = witness(&cs, Fr::from(self.new.expiry))?;
        let new_expiry_bits = u64_bits(&new_expiry)?;
        let new_active = Boolean::new_witness(cs.clone(), || Ok(self.new.active))?;
        let new_salt = witness(&cs, self.new.salt)?;

        less_or_equal(&new_expiry_bits, &cap_bits)?.enforce_equal(&Boolean::TRUE)?;
        // Preserve baseline semantics: an owner may deactivate but cannot reactivate.
        new_active
            .and(&old_active.not())?
            .enforce_equal(&Boolean::FALSE)?;

        let old_active_fp = Boolean::le_bits_to_fp_var(&[old_active])?;
        let new_active_fp = Boolean::le_bits_to_fp_var(&[new_active])?;
        old_leaf.enforce_equal(&hash_var(
            Domain::StateLeaf,
            &[
                owner.clone(),
                old_root,
                old_version,
                old_epoch,
                old_expiry,
                old_active_fp,
                old_salt,
                position.clone(),
            ],
        )?)?;
        new_leaf.enforce_equal(&hash_var(
            Domain::StateLeaf,
            &[
                owner,
                new_root,
                new_version,
                new_epoch,
                new_expiry,
                new_active_fp,
                new_salt,
                position,
            ],
        )?)?;
        // Old expiry is range checked above. Its cap validity is an enrollment/
        // induction premise; only the new expiry is required to satisfy current cap.
        let _ = old_expiry_bits;
        Ok(())
    }
}

/// Complete owner authorization transcript, including the exact proof encoding digest.
pub fn authorization_digest(s: &BlindUpdateStatement, proof_sha256_limbs: [Fr; 2]) -> Fr {
    hash(
        Domain::BlindUpdateAuth,
        &[
            s.config_digest,
            s.deployment,
            s.circuit_id,
            s.owner,
            Fr::from(s.position),
            Fr::from(s.expiry_cap),
            Fr::from(s.admission_version),
            s.old_leaf,
            s.new_leaf,
            Fr::from(s.old_version),
            Fr::from(s.new_version),
            Fr::from(s.old_epoch),
            Fr::from(s.new_epoch),
            proof_sha256_limbs[0],
            proof_sha256_limbs[1],
        ],
    )
}
