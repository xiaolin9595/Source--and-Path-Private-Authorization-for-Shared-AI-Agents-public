#![forbid(unsafe_code)]
//! Cross-stack CP/RSA adapter for the E8 certified-state-map relation.
//!
//! The legacy CP proof and the current Joint-core proof share the exact
//! Pedersen bases and opening. The two arkworks generations use different
//! point codecs, so the bridge converts explicit canonical field coordinates,
//! checks lossless round trips, and performs current-stack curve and subgroup
//! validation. The mapping certificate remains inside the current Joint core
//! and binds the committed 252-bit prime to the typed state generation.

use ark_bls12_381_current::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_bls12_381_old::{Fq as OldFq, Fr as OldFr, G1Projective as OldG1Projective};
use ark_ec_current::{AffineRepr, CurveGroup};
use ark_ec_old::ProjectiveCurve as OldProjectiveCurve;
use ark_ff_current::{
    BigInteger as CurrentBigInteger, PrimeField as CurrentPrimeField, UniformRand,
};
use ark_ff_old::{BigInteger as OldBigInteger, FpParameters, PrimeField as OldPrimeField};
use ark_serialize_current::CanonicalSerialize;
use cpsnarks_set::protocols::hrada_membership::{
    validate_prime, CpProof, CpStatement, StateMembership, StateSet,
};
use joint_backend_matched::{
    augmented_core_public_inputs,
    certified_map::{verify_certificate, AccumulatorTransition, MappingCertificate},
    prove_augmented_core_with_blind, setup_augmented_core_with_generators, verify_augmented_core,
    AugmentedCoreLinkedParameters, AugmentedCoreLinkedProof,
};
use legogroth16_current::LinkPublicGenerators;
use plan_a_joint_circuit::{
    joint::JointCircuit, poseidon::canonical_le_bytes, signature::PublicKey,
};
use rand_current::Rng;
use rug::{integer::Order, Integer};
use sha2::{Digest, Sha256};

const CONTEXT_TAG: &[u8] = b"plan-a/e8/augmented-cp-joint/v1";

fn same_scalar_modulus() -> bool {
    let old = <OldFr as OldPrimeField>::Params::MODULUS.to_bytes_le();
    let current = Fr::MODULUS.to_bytes_le();
    old == current
}

fn same_base_modulus() -> bool {
    let old = <OldFq as OldPrimeField>::Params::MODULUS.to_bytes_le();
    let current = Fq::MODULUS.to_bytes_le();
    old == current
}

fn fixed_fq_bytes(bytes: Vec<u8>) -> Result<[u8; 48], String> {
    if bytes.len() > 48 {
        return Err("BLS12-381 base-field coordinate exceeds 48 bytes".into());
    }
    let mut output = [0u8; 48];
    output[..bytes.len()].copy_from_slice(&bytes);
    Ok(output)
}

fn old_bridge_point_bytes(value: &OldG1Projective) -> Result<Vec<u8>, String> {
    let affine = value.into_affine();
    let mut output = vec![u8::from(affine.infinity)];
    output.extend(fixed_fq_bytes(affine.x.into_repr().to_bytes_le())?);
    output.extend(fixed_fq_bytes(affine.y.into_repr().to_bytes_le())?);
    Ok(output)
}

fn current_bridge_point_bytes(value: &G1Affine) -> Result<Vec<u8>, String> {
    let mut output = vec![u8::from(value.is_zero())];
    output.extend(fixed_fq_bytes(value.x.into_bigint().to_bytes_le())?);
    output.extend(fixed_fq_bytes(value.y.into_bigint().to_bytes_le())?);
    Ok(output)
}

/// Convert through explicit affine coordinates because the retained arkworks
/// codec predates the IETF-oriented arkworks 0.4 BLS12-381 encoding. Both
/// coordinates are checked for lossless field round trips, then the current
/// point is checked on-curve and in the prime-order subgroup.
fn current_point(value: &OldG1Projective) -> Result<G1Affine, String> {
    if !same_base_modulus() {
        return Err("legacy and current BLS12-381 base-field moduli differ".into());
    }
    let old = value.into_affine();
    if old.infinity {
        let current = G1Affine::zero();
        if old_bridge_point_bytes(value)? != current_bridge_point_bytes(&current)? {
            return Err("identity point coordinate bridge mismatch".into());
        }
        return Ok(current);
    }
    let old_x = fixed_fq_bytes(old.x.into_repr().to_bytes_le())?;
    let old_y = fixed_fq_bytes(old.y.into_repr().to_bytes_le())?;
    let x = Fq::from_le_bytes_mod_order(&old_x);
    let y = Fq::from_le_bytes_mod_order(&old_y);
    if fixed_fq_bytes(x.into_bigint().to_bytes_le())? != old_x
        || fixed_fq_bytes(y.into_bigint().to_bytes_le())? != old_y
    {
        return Err("noncanonical base-field coordinate in cross-version bridge".into());
    }
    let current = G1Affine::new_unchecked(x, y);
    if !current.is_on_curve() || !current.is_in_correct_subgroup_assuming_on_curve() {
        return Err("cross-version point is off-curve or outside the prime-order subgroup".into());
    }
    if old_bridge_point_bytes(value)? != current_bridge_point_bytes(&current)? {
        return Err("cross-version coordinate bridge round trip differs".into());
    }
    Ok(current)
}

fn current_bytes<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

pub fn prime_integer(prime: Fr) -> Integer {
    Integer::from_digits(&canonical_le_bytes(prime), Order::Lsf)
}

pub fn scalar_integer(value: Fr) -> Integer {
    Integer::from_digits(&canonical_le_bytes(value), Order::Lsf)
}

pub fn binding_context(
    parameters: &CpLinkedParameters,
    core_inputs: &[Fr],
) -> Result<Vec<u8>, String> {
    let mut transcript = Sha256::new();
    transcript.update(CONTEXT_TAG);
    transcript.update((parameters.cp_parameter_bytes.len() as u64).to_le_bytes());
    transcript.update(&parameters.cp_parameter_bytes);
    let vk = current_bytes(&parameters.core.vk)?;
    transcript.update((vk.len() as u64).to_le_bytes());
    transcript.update(vk);
    transcript.update((core_inputs.len() as u64).to_le_bytes());
    for input in core_inputs {
        transcript.update(canonical_le_bytes(*input));
    }
    Ok(transcript.finalize().to_vec())
}

pub struct CpLinkedParameters {
    pub cp: StateMembership,
    pub core: AugmentedCoreLinkedParameters,
    pub cp_parameter_bytes: Vec<u8>,
    pub commitment_g: G1Affine,
    pub commitment_h: G1Affine,
}

pub struct CpLinkedProof {
    pub statement: CpStatement,
    pub membership: CpProof,
    pub core: AugmentedCoreLinkedProof,
}

/// Validate the complete cross-version commitment bridge. Explicit coordinate
/// conversion is curve and subgroup checked; equality in the version-neutral
/// coordinate encoding prevents a silent point change, and the ordered bases
/// pin `g*prime + h*opening`.
pub fn validate_bridge(parameters: &CpLinkedParameters) -> Result<(), String> {
    if !same_scalar_modulus() {
        return Err("legacy and current BLS12-381 scalar moduli differ".into());
    }
    if !same_base_modulus() {
        return Err("legacy and current BLS12-381 base-field moduli differ".into());
    }
    if parameters.commitment_g.is_zero()
        || parameters.commitment_h.is_zero()
        || parameters.commitment_g == parameters.commitment_h
        || parameters.commitment_g == -parameters.commitment_h
    {
        return Err("CP Pedersen bases must be nonidentity and nontrivially distinct".into());
    }
    if parameters.core.vk.link_pp.g1.is_zero() || parameters.core.vk.link_pp.g2.is_zero() {
        return Err("Lego link public generators must be nonidentity".into());
    }
    let legacy = &parameters
        .cp
        .protocol
        .crs
        .crs_modeq
        .pedersen_commitment_parameters;
    if old_bridge_point_bytes(&legacy.g)? != current_bridge_point_bytes(&parameters.commitment_g)?
        || old_bridge_point_bytes(&legacy.h)?
            != current_bridge_point_bytes(&parameters.commitment_h)?
    {
        return Err("canonical CP/current commitment-base bytes differ".into());
    }
    if parameters.core.vk.link_bases != vec![parameters.commitment_g, parameters.commitment_h] {
        return Err("Joint core does not use ordered CP bases [g,h]".into());
    }
    Ok(())
}

pub fn setup<const L: usize, R: Rng>(
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    rng: &mut R,
) -> Result<CpLinkedParameters, String> {
    if !verify_certificate(mapping_pk, mapping) {
        return Err("mapping certificate failed native verification before setup".into());
    }
    let cp = StateMembership::setup_os()?;
    let commitment = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let commitment_g = current_point(&commitment.g)?;
    let commitment_h = current_point(&commitment.h)?;
    let generators = LinkPublicGenerators::<Bls12_381> {
        pedersen_gens: vec![commitment_g, commitment_h],
        g1: G1Projective::rand(rng).into_affine(),
        g2: G2Projective::rand(rng).into_affine(),
    };
    let core = setup_augmented_core_with_generators(joint, mapping, mapping_pk, generators, rng)?;
    if core.vk.link_bases != vec![commitment_g, commitment_h] {
        return Err("current core did not retain the converted CP commitment key".into());
    }
    let cp_parameter_bytes = cp.canonical_parameters()?;
    let parameters = CpLinkedParameters {
        cp,
        core,
        cp_parameter_bytes,
        commitment_g,
        commitment_h,
    };
    validate_bridge(&parameters)?;
    Ok(parameters)
}

pub fn prove<const L: usize, R: Rng>(
    parameters: &CpLinkedParameters,
    set: &StateSet,
    joint: &JointCircuit<L>,
    mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    rng: &mut R,
) -> Result<CpLinkedProof, String> {
    if !verify_certificate(mapping_pk, mapping) {
        return Err("mapping certificate failed native verification".into());
    }
    let prime = prime_integer(mapping.record.prime);
    validate_prime(&prime)?;
    let blind = Fr::rand(rng);
    let blind_integer = scalar_integer(blind);
    let inputs = augmented_core_public_inputs(joint, mapping, mapping_pk);
    let context = binding_context(parameters, &inputs)?;
    let (statement, membership) = parameters.cp.prove(set, &prime, &blind_integer, &context)?;
    let core =
        prove_augmented_core_with_blind(&parameters.core, joint, mapping, mapping_pk, blind, rng)?;
    let cp_commitment = current_point(&statement.c_e_q)?;
    let expected_commitment = (parameters
        .commitment_g
        .mul_bigint(mapping.record.prime.into_bigint())
        + parameters.commitment_h.mul_bigint(blind.into_bigint()))
    .into_affine();
    if cp_commitment != expected_commitment || expected_commitment != core.link_d {
        return Err("prover produced unequal CP and Joint-core commitments".into());
    }
    Ok(CpLinkedProof {
        statement,
        membership,
        core,
    })
}

pub fn verify<const L: usize>(
    parameters: &CpLinkedParameters,
    expected_set: &StateSet,
    joint: &JointCircuit<L>,
    current_mapping: &MappingCertificate,
    mapping_pk: &PublicKey,
    proof: &CpLinkedProof,
) -> Result<(), String> {
    if proof.statement.c_p != expected_set.accumulator {
        return Err("CP statement uses a retired accumulator".into());
    }
    if !verify_certificate(mapping_pk, current_mapping) {
        return Err("current mapping certificate failed native verification".into());
    }
    let inputs = augmented_core_public_inputs(joint, current_mapping, mapping_pk);
    verify_with_inputs(parameters, expected_set, &inputs, proof)
}

pub fn verify_with_inputs(
    parameters: &CpLinkedParameters,
    expected_set: &StateSet,
    core_inputs: &[Fr],
    proof: &CpLinkedProof,
) -> Result<(), String> {
    validate_bridge(parameters)?;
    if core_inputs.len() != 27 {
        return Err("malformed CP augmented public inputs".into());
    }
    if proof.statement.c_p != expected_set.accumulator {
        return Err("CP statement uses a retired accumulator".into());
    }
    let context = binding_context(parameters, core_inputs)?;
    parameters
        .cp
        .verify(&proof.statement, &proof.membership, &context)?;
    verify_augmented_core(&parameters.core, core_inputs, &proof.core)?;
    let cp_commitment = current_point(&proof.statement.c_e_q)?;
    if cp_commitment != proof.core.link_d {
        return Err("CP and Joint-core commitments differ".into());
    }
    Ok(())
}

/// Actual CP set transition used by the certified-map replacement gate. It
/// rebuilds the retained public-exponent accumulator, then confirms old
/// absence and successor membership before returning success.
pub struct CpStateLifecycle {
    primes: Vec<Integer>,
    set: StateSet,
}

impl CpStateLifecycle {
    pub fn new(primes: Vec<Integer>) -> Result<Self, String> {
        let set = StateSet::rebuild(&primes)?;
        Ok(Self { primes, set })
    }

    pub fn set(&self) -> &StateSet {
        &self.set
    }

    pub fn contains(&self, prime: Fr) -> bool {
        self.set.prepare_witness(&prime_integer(prime)).is_ok()
    }

    pub fn member_count(&self) -> usize {
        self.primes.len()
    }
}

impl AccumulatorTransition for CpStateLifecycle {
    fn replace_and_confirm(&mut self, old_prime: Fr, next_prime: Fr) -> bool {
        let old = prime_integer(old_prime);
        let next = prime_integer(next_prime);
        if validate_prime(&old).is_err() || validate_prime(&next).is_err() || old == next {
            return false;
        }
        let Some(position) = self.primes.iter().position(|candidate| candidate == &old) else {
            return false;
        };
        if self.primes.contains(&next) {
            return false;
        }
        let mut candidate = self.primes.clone();
        candidate[position] = next.clone();
        let Ok(next_set) = StateSet::rebuild(&candidate) else {
            return false;
        };
        if next_set.prepare_witness(&old).is_ok() || next_set.prepare_witness(&next).is_err() {
            return false;
        }
        self.primes = candidate;
        self.set = next_set;
        true
    }
}
