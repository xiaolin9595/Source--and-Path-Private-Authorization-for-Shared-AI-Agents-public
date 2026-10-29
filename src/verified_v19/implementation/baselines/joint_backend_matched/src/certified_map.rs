//! Certified state-to-prime mapping for the augmented E8 relation.
//!
//! This module does not make the mapping free: the trusted state publisher
//! signs each record and maintains uniqueness and generation transitions.  A
//! CP adapter must additionally validate that `prime` is the exact 252-bit
//! integer used by the RSA membership proof and confirm each accumulator
//! transition before the mapping lifecycle commits.

use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use plan_a_joint_circuit::{
    poseidon::{canonical_le_bytes, hash, hash_var, Domain},
    signature::{
        public_key, sign, verify, verify_allocated_if, PublicKey, SecretKey, Signature,
        SignatureError,
    },
    Fr,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Reserved subtype inside the fixed StateUpdate Poseidon domain.  The outer
/// two-field frame makes it disjoint from the implemented nine-field owner
/// state-update message.
const CERTIFIED_MAP_TAG: u64 = 0x4538_4d41_5001;
const PRIME_DERIVATION_TAG: &[u8] = b"plan-a/e8/certified-map-prime/v1";
const MILLER_RABIN_TAG: &[u8] = b"plan-a/e8/miller-rabin-base/v1";
pub const MILLER_RABIN_ROUNDS: u32 = 64;
const MAX_PRIME_CANDIDATES: u32 = 1 << 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingRecord {
    pub deployment_id: Fr,
    pub owner_commitment: Fr,
    pub state_leaf: Fr,
    pub position: u32,
    pub state_version: u64,
    pub state_epoch: u64,
    /// Canonical field image of the exact 252-bit accumulator prime.
    pub prime: Fr,
    pub mapping_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MappingCertificate {
    pub record: MappingRecord,
    pub signature: Signature,
}

fn record_fields(record: &MappingRecord) -> [Fr; 8] {
    [
        record.deployment_id,
        record.owner_commitment,
        record.state_leaf,
        Fr::from(record.position),
        Fr::from(record.state_version),
        Fr::from(record.state_epoch),
        record.prime,
        Fr::from(record.mapping_version),
    ]
}

pub fn mapping_digest(record: &MappingRecord) -> Fr {
    let inner = hash(Domain::StateUpdate, &record_fields(record));
    hash(Domain::StateUpdate, &[Fr::from(CERTIFIED_MAP_TAG), inner])
}

pub fn mapping_digest_var(fields: &[FpVar<Fr>; 8]) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = hash_var(Domain::StateUpdate, fields)?;
    hash_var(
        Domain::StateUpdate,
        &[FpVar::constant(Fr::from(CERTIFIED_MAP_TAG)), inner],
    )
}

pub fn canonical_prime_252(prime: Fr) -> bool {
    let bits = prime.into_bigint().to_bits_le();
    bits.get(251).copied().unwrap_or(false)
        && bits.first().copied().unwrap_or(false)
        && bits.iter().skip(252).all(|bit| !bit)
}

fn prime_integer(prime: Fr) -> BigUint {
    BigUint::from_bytes_le(&canonical_le_bytes(prime))
}

/// Deterministic 64-round strong Miller--Rabin validation after small-prime
/// trial division.  The bases are domain-separated SHA-256 outputs reduced
/// uniformly into [2,n-2].  For each fixed odd composite, 64 independent
/// uniform bases give false acceptance at most 4^-64 = 2^-128. Treating these
/// derived bases that way requires a SHA-256 random-oracle model; adaptive
/// candidate selection and repeated issuance incur the corresponding union
/// loss. This is a native issuer/verifier check, not a circuit primality proof.
pub fn is_probable_prime_252(prime: Fr) -> bool {
    if !canonical_prime_252(prime) {
        return false;
    }
    let n = prime_integer(prime);
    const SMALL_PRIMES: [u32; 24] = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    ];
    for divisor in SMALL_PRIMES {
        let d = BigUint::from(divisor);
        if n == d {
            return true;
        }
        if (&n % &d).is_zero() {
            return false;
        }
    }

    let one = BigUint::one();
    let two = BigUint::from(2u32);
    let n_minus_one = &n - &one;
    let base_span = &n - BigUint::from(3u32);
    let mut d = n_minus_one.clone();
    let mut s = 0u32;
    while !d.bit(0) {
        d >>= 1usize;
        s += 1;
    }
    let n_bytes = n.to_bytes_le();
    let sample_space = BigUint::one() << 256usize;
    let rejection_limit = &sample_space - (&sample_space % &base_span);
    for round in 0..MILLER_RABIN_ROUNDS {
        let mut attempt = 0u32;
        let a = loop {
            let mut transcript = Sha256::new();
            transcript.update(MILLER_RABIN_TAG);
            transcript.update(&n_bytes);
            transcript.update(round.to_le_bytes());
            transcript.update(attempt.to_le_bytes());
            let sample = BigUint::from_bytes_le(&transcript.finalize());
            if sample < rejection_limit {
                break sample % &base_span + &two;
            }
            attempt = attempt.checked_add(1).expect("SHA-256 rejection counter");
        };
        let mut x = a.modpow(&d, &n);
        if x == one || x == n_minus_one {
            continue;
        }
        let mut witness = true;
        for _ in 1..s {
            x = (&x * &x) % &n;
            if x == n_minus_one {
                witness = false;
                break;
            }
        }
        if witness {
            return false;
        }
    }
    true
}

fn generation_bytes(record: &MappingRecord) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 4 + 8 + 8 + 8);
    bytes.extend_from_slice(&canonical_le_bytes(record.deployment_id));
    bytes.extend_from_slice(&canonical_le_bytes(record.owner_commitment));
    bytes.extend_from_slice(&record.position.to_le_bytes());
    bytes.extend_from_slice(&record.state_version.to_le_bytes());
    bytes.extend_from_slice(&record.state_epoch.to_le_bytes());
    bytes.extend_from_slice(&record.mapping_version.to_le_bytes());
    bytes
}

/// Generate the generation-bound accumulator prime from issuer entropy.  The
/// returned field element is the exact integer because every candidate is at
/// most 252 bits, below the BLS12-381 scalar modulus.
pub fn generate_prime_252(
    record_without_prime: &MappingRecord,
    issuer_entropy: [u8; 32],
) -> Result<Fr, MappingError> {
    let generation = generation_bytes(record_without_prime);
    for counter in 0..MAX_PRIME_CANDIDATES {
        let mut transcript = Sha256::new();
        transcript.update(PRIME_DERIVATION_TAG);
        transcript.update(&generation);
        transcript.update(issuer_entropy);
        transcript.update(counter.to_le_bytes());
        let mut bytes: [u8; 32] = transcript.finalize().into();
        bytes[31] &= 0x0f;
        bytes[31] |= 0x08;
        bytes[0] |= 1;
        let candidate = Fr::from_le_bytes_mod_order(&bytes);
        if is_probable_prime_252(candidate) {
            return Ok(candidate);
        }
    }
    Err(MappingError::PrimeGenerationExhausted)
}

pub fn verify_certificate(pk: &PublicKey, certificate: &MappingCertificate) -> bool {
    certificate.record.mapping_version > 0
        && is_probable_prime_252(certificate.record.prime)
        && verify(
            pk,
            mapping_digest(&certificate.record),
            &certificate.signature,
        )
}

/// Verify one certificate against variables already used by the Joint core.
/// The caller decides which of these variables are public; all three augmented
/// variants must use the same choice and order.
pub fn enforce_certificate(
    cs: ConstraintSystemRef<Fr>,
    mapping_pk: (&FpVar<Fr>, &FpVar<Fr>),
    fields: [&FpVar<Fr>; 8],
    signature: &Signature,
) -> Result<(), SynthesisError> {
    let prime_bits = fields[6].to_bits_le()?;
    prime_bits[0].enforce_equal(&Boolean::TRUE)?;
    prime_bits[251].enforce_equal(&Boolean::TRUE)?;
    for bit in &prime_bits[252..] {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    let mapping_version_bits = fields[7].to_bits_le()?;
    for bit in &mapping_version_bits[64..] {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Boolean::kary_or(&mapping_version_bits[..64])?.enforce_equal(&Boolean::TRUE)?;

    let owned = fields.map(|field| (*field).clone());
    let digest = mapping_digest_var(&owned)?;
    let r_x = FpVar::new_witness(cs.clone(), || Ok(signature.r.x))?;
    let r_y = FpVar::new_witness(cs.clone(), || Ok(signature.r.y))?;
    verify_allocated_if(
        cs,
        &Boolean::TRUE,
        &EdwardsVar::new(mapping_pk.0.clone(), mapping_pk.1.clone()),
        digest,
        &EdwardsVar::new(r_x, r_y),
        signature.s,
    )
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MappingError {
    #[error("mapping version must be nonzero")]
    MappingVersion,
    #[error("prime is not a canonical probable-prime 252-bit field integer")]
    PrimeEncoding,
    #[error("prime generation exhausted the bounded candidate search")]
    PrimeGenerationExhausted,
    #[error("generation already exists")]
    DuplicateGeneration,
    #[error("prime was already assigned during this service lifetime")]
    DuplicatePrime,
    #[error("old generation is absent or already retired")]
    MissingOldGeneration,
    #[error("replacement changes identity or does not advance version and epoch")]
    InvalidReplacement,
    #[error("mapping signature failed")]
    Signature,
    #[error("accumulator replacement did not confirm old removal and successor admission")]
    AccumulatorTransition,
}

type GenerationKey = ([u8; 32], [u8; 32], u32, u64, u64);

fn generation_key(record: &MappingRecord) -> GenerationKey {
    (
        canonical_le_bytes(record.deployment_id),
        canonical_le_bytes(record.owner_commitment),
        record.position,
        record.state_version,
        record.state_epoch,
    )
}

/// Native SR boundary for the CP/RSA backend.  Success means the adapter has
/// checked that `old_prime` was in the pre-state and is absent from the
/// post-state, while `next_prime` is in the same committed post-state.
pub trait AccumulatorTransition {
    fn replace_and_confirm(&mut self, old_prime: Fr, next_prime: Fr) -> bool;
}

#[derive(Clone)]
pub struct CertifiedStateMap {
    signer: SecretKey,
    pub public_key: PublicKey,
    live: BTreeMap<GenerationKey, MappingCertificate>,
    retired: BTreeSet<GenerationKey>,
    /// Never reuse a prime, including after retirement. Otherwise a retired
    /// certificate could become usable when the same prime re-enters the RSA
    /// accumulator for a different record.
    used_primes: BTreeSet<[u8; 32]>,
}

impl CertifiedStateMap {
    pub fn new(signer: SecretKey) -> Result<Self, SignatureError> {
        let public_key = public_key(&signer)?;
        Ok(Self {
            signer,
            public_key,
            live: BTreeMap::new(),
            retired: BTreeSet::new(),
            used_primes: BTreeSet::new(),
        })
    }

    /// Native issuer path: derive and validate a generation-bound prime before
    /// signing. The entropy is an issuer input and is not stored in the public
    /// certificate; verifiers repeat the deterministic primality test on the
    /// resulting integer.
    pub fn generate_and_issue(
        &mut self,
        mut record_without_prime: MappingRecord,
        issuer_entropy: [u8; 32],
        auxiliary_randomness: [u8; 32],
    ) -> Result<MappingCertificate, MappingError> {
        record_without_prime.prime = generate_prime_252(&record_without_prime, issuer_entropy)?;
        self.issue(record_without_prime, auxiliary_randomness)
    }

    /// Validate integer primality, sign the canonical record, and reserve its
    /// prime for the whole service lifetime. Accumulator admission is a
    /// separate transition performed by the backend adapter.
    pub fn issue(
        &mut self,
        record: MappingRecord,
        auxiliary_randomness: [u8; 32],
    ) -> Result<MappingCertificate, MappingError> {
        if record.mapping_version == 0 {
            return Err(MappingError::MappingVersion);
        }
        if !is_probable_prime_252(record.prime) {
            return Err(MappingError::PrimeEncoding);
        }
        let key = generation_key(&record);
        if self.live.contains_key(&key) || self.retired.contains(&key) {
            return Err(MappingError::DuplicateGeneration);
        }
        let prime_key = canonical_le_bytes(record.prime);
        if self.used_primes.contains(&prime_key) {
            return Err(MappingError::DuplicatePrime);
        }
        let signature = sign(&self.signer, mapping_digest(&record), auxiliary_randomness)
            .map_err(|_| MappingError::Signature)?;
        let certificate = MappingCertificate { record, signature };
        self.used_primes.insert(prime_key);
        self.live.insert(key, certificate.clone());
        Ok(certificate)
    }

    pub fn replace_with_accumulator<A: AccumulatorTransition>(
        &mut self,
        old: &MappingRecord,
        next: MappingRecord,
        auxiliary_randomness: [u8; 32],
        accumulator: &mut A,
    ) -> Result<MappingCertificate, MappingError> {
        let old_key = generation_key(old);
        let Some(current) = self.live.get(&old_key) else {
            return Err(MappingError::MissingOldGeneration);
        };
        if current.record != *old {
            return Err(MappingError::MissingOldGeneration);
        }
        if next.deployment_id != old.deployment_id
            || next.owner_commitment != old.owner_commitment
            || next.position != old.position
            || next.mapping_version != old.mapping_version
            || next.state_version <= old.state_version
            || next.state_epoch <= old.state_epoch
        {
            return Err(MappingError::InvalidReplacement);
        }
        if next.mapping_version == 0 {
            return Err(MappingError::MappingVersion);
        }
        if !is_probable_prime_252(next.prime) {
            return Err(MappingError::PrimeEncoding);
        }
        let next_key = generation_key(&next);
        if self.live.contains_key(&next_key) || self.retired.contains(&next_key) {
            return Err(MappingError::DuplicateGeneration);
        }
        let next_prime_key = canonical_le_bytes(next.prime);
        if self.used_primes.contains(&next_prime_key) {
            return Err(MappingError::DuplicatePrime);
        }
        let signature = sign(&self.signer, mapping_digest(&next), auxiliary_randomness)
            .map_err(|_| MappingError::Signature)?;
        let certificate = MappingCertificate {
            record: next,
            signature,
        };
        if !accumulator.replace_and_confirm(old.prime, certificate.record.prime) {
            return Err(MappingError::AccumulatorTransition);
        }
        self.live.remove(&old_key).expect("checked live generation");
        self.retired.insert(old_key);
        self.used_primes.insert(next_prime_key);
        self.live.insert(next_key, certificate.clone());
        Ok(certificate)
    }

    pub fn is_live(&self, certificate: &MappingCertificate) -> bool {
        self.live
            .get(&generation_key(&certificate.record))
            .is_some_and(|stored| {
                stored.record == certificate.record
                    && verify_certificate(&self.public_key, certificate)
            })
    }
}
