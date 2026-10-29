//! Minimal reusable Delta=0 service boundary for the DAC wrapper.
//!
//! The circuit commits the complete typed header and request into public
//! digests.  This adapter verifies the Groth16 proof at read, verifies a
//! terminal Schnorr signature over those digests and the exact proof bytes,
//! then rechecks the current header, clock, request encoding, signature and
//! nonce under one mutable commit operation.  It is an in-memory reference
//! boundary, not the main service implementation or an HTTP benchmark.

use crate::fixed_policy::{
    compute_header_digest, compute_request_digest, public_inputs, FixedPolicyStatement,
};
use ark_bls12_377::{Fr, G1Affine};
use ark_bw6_761::BW6_761;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::{collections::BTreeSet, rand::RngCore, UniformRand};
use blake2::{Blake2b512, Blake2s256, Digest};

const HEADER_SIGNATURE_DOMAIN: &[u8] = b"plan-a-dac-header-signature-v1\0";
const TERMINAL_SIGNATURE_DOMAIN: &[u8] = b"plan-a-dac-terminal-signature-v1\0";

#[derive(Clone, Debug)]
pub struct SchnorrSignature {
    pub r: G1Affine,
    pub s: Fr,
}

#[derive(Clone, Debug)]
pub struct VerificationTicket {
    header_digest: ark_bls12_377::Fq,
    request_digest: ark_bls12_377::Fq,
    relation_version: u64,
    nonce_key: [u8; 32],
    proof_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    BadHeaderEncoding,
    BadHeaderSignature,
    ReplayedHeader,
    NonMonotoneHeader,
    StaleHeader,
    BadRequestEncoding,
    BadProofEncoding,
    BadProof,
    BadTerminalSignature,
    OutsideRequestInterval,
    ReplayedNonce,
    TicketMismatch,
}

fn append_canonical<T: CanonicalSerialize>(bytes: &mut Vec<u8>, value: &T) {
    value.serialize_compressed(bytes).expect("vec writer")
}

fn schnorr_challenge(domain: &[u8], message: &[u8], r: &G1Affine, public_key: &G1Affine) -> Fr {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(domain);
    transcript.extend_from_slice(&(message.len() as u64).to_le_bytes());
    transcript.extend_from_slice(message);
    append_canonical(&mut transcript, r);
    append_canonical(&mut transcript, public_key);
    Fr::from_le_bytes_mod_order(&Blake2b512::digest(transcript))
}

pub fn schnorr_sign<R: RngCore>(
    rng: &mut R,
    generator: &G1Affine,
    secret_key: &Fr,
    domain: &[u8],
    message: &[u8],
) -> SchnorrSignature {
    loop {
        let nonce = Fr::rand(rng);
        if nonce.is_zero() {
            continue;
        }
        let r = generator.mul_bigint(nonce.into_bigint()).into_affine();
        let public_key = generator.mul_bigint(secret_key.into_bigint()).into_affine();
        let challenge = schnorr_challenge(domain, message, &r, &public_key);
        let s = nonce + challenge * secret_key;
        if !s.is_zero() {
            return SchnorrSignature { r, s };
        }
    }
}

pub fn schnorr_verify(
    generator: &G1Affine,
    public_key: &G1Affine,
    domain: &[u8],
    message: &[u8],
    signature: &SchnorrSignature,
) -> bool {
    if !generator.is_on_curve()
        || !public_key.is_on_curve()
        || !signature.r.is_on_curve()
        || generator.is_zero()
        || public_key.is_zero()
        || signature.r.is_zero()
        || !generator.is_in_correct_subgroup_assuming_on_curve()
        || !public_key.is_in_correct_subgroup_assuming_on_curve()
        || !signature.r.is_in_correct_subgroup_assuming_on_curve()
    {
        return false;
    }
    let challenge = schnorr_challenge(domain, message, &signature.r, public_key);
    generator.mul_bigint(signature.s.into_bigint())
        == signature.r.into_group() + public_key.mul_bigint(challenge.into_bigint())
}

pub fn header_signature_message(statement: &FixedPolicyStatement) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_canonical(&mut bytes, &statement.deployment_id);
    append_canonical(&mut bytes, &statement.header_digest);
    bytes.extend_from_slice(&statement.tuple_version.to_le_bytes());
    bytes
}

pub fn terminal_signature_message(
    statement: &FixedPolicyStatement,
    relation_version: u64,
    proof_bytes: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_canonical(&mut bytes, &statement.deployment_id);
    append_canonical(&mut bytes, &statement.header_digest);
    append_canonical(&mut bytes, &statement.request_digest);
    append_canonical(&mut bytes, &statement.circuit_id);
    append_canonical(&mut bytes, &statement.nonce);
    append_canonical(&mut bytes, &statement.terminal_key);
    bytes.extend_from_slice(&relation_version.to_le_bytes());
    bytes.extend_from_slice(&(proof_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(proof_bytes);
    bytes
}

fn fq_key(value: &ark_bls12_377::Fq) -> Vec<u8> {
    let mut bytes = Vec::new();
    append_canonical(&mut bytes, value);
    bytes
}

fn nonce_key(value: &ark_bls12_377::Fq) -> [u8; 32] {
    Blake2s256::digest(fq_key(value)).into()
}

fn proof_digest(proof_bytes: &[u8]) -> [u8; 32] {
    Blake2s256::digest(proof_bytes).into()
}

pub struct DeltaZeroAdapter {
    generator: G1Affine,
    registry_public_key: G1Affine,
    deployment_id: ark_bls12_377::Fq,
    current_header: Option<ark_bls12_377::Fq>,
    current_tuple_version: Option<u64>,
    seen_headers: BTreeSet<Vec<u8>>,
    used_nonces: BTreeSet<[u8; 32]>,
}

impl DeltaZeroAdapter {
    pub fn new(
        generator: G1Affine,
        registry_public_key: G1Affine,
        deployment_id: ark_bls12_377::Fq,
    ) -> Self {
        Self {
            generator,
            registry_public_key,
            deployment_id,
            current_header: None,
            current_tuple_version: None,
            seen_headers: BTreeSet::new(),
            used_nonces: BTreeSet::new(),
        }
    }

    pub fn install_header(
        &mut self,
        statement: &FixedPolicyStatement,
        signature: &SchnorrSignature,
    ) -> Result<(), AdapterError> {
        if statement.deployment_id != self.deployment_id
            || compute_header_digest(statement) != statement.header_digest
        {
            return Err(AdapterError::BadHeaderEncoding);
        }
        if !schnorr_verify(
            &self.generator,
            &self.registry_public_key,
            HEADER_SIGNATURE_DOMAIN,
            &header_signature_message(statement),
            signature,
        ) {
            return Err(AdapterError::BadHeaderSignature);
        }
        let key = fq_key(&statement.header_digest);
        if self.seen_headers.contains(&key) {
            return Err(AdapterError::ReplayedHeader);
        }
        if self
            .current_tuple_version
            .is_some_and(|current| statement.tuple_version <= current)
        {
            return Err(AdapterError::NonMonotoneHeader);
        }
        self.seen_headers.insert(key);
        self.current_header = Some(statement.header_digest);
        self.current_tuple_version = Some(statement.tuple_version);
        Ok(())
    }

    pub fn verify_at_read(
        &self,
        verifying_key: &VerifyingKey<BW6_761>,
        statement: &FixedPolicyStatement,
        relation_version: u64,
        proof: &Proof<BW6_761>,
        proof_bytes: &[u8],
        terminal_signature: &SchnorrSignature,
    ) -> Result<VerificationTicket, AdapterError> {
        if statement.deployment_id != self.deployment_id {
            return Err(AdapterError::BadHeaderEncoding);
        }
        if self.current_header != Some(statement.header_digest) {
            return Err(AdapterError::StaleHeader);
        }
        if compute_header_digest(statement) != statement.header_digest {
            return Err(AdapterError::BadHeaderEncoding);
        }
        if compute_request_digest(statement) != statement.request_digest {
            return Err(AdapterError::BadRequestEncoding);
        }
        let mut canonical_proof = Vec::new();
        proof
            .serialize_compressed(&mut canonical_proof)
            .map_err(|_| AdapterError::BadProofEncoding)?;
        if canonical_proof != proof_bytes {
            return Err(AdapterError::BadProofEncoding);
        }
        if statement.now < statement.request_lo || statement.now > statement.request_hi {
            return Err(AdapterError::OutsideRequestInterval);
        }
        if !Groth16::<BW6_761>::verify(
            verifying_key,
            &public_inputs(statement, relation_version),
            proof,
        )
        .map_err(|_| AdapterError::BadProof)?
        {
            return Err(AdapterError::BadProof);
        }
        if !schnorr_verify(
            &self.generator,
            &statement.terminal_key,
            TERMINAL_SIGNATURE_DOMAIN,
            &terminal_signature_message(statement, relation_version, proof_bytes),
            terminal_signature,
        ) {
            return Err(AdapterError::BadTerminalSignature);
        }
        Ok(VerificationTicket {
            header_digest: statement.header_digest,
            request_digest: statement.request_digest,
            relation_version,
            nonce_key: nonce_key(&statement.nonce),
            proof_digest: proof_digest(proof_bytes),
        })
    }

    /// One mutable operation models the service transaction: all rechecks run
    /// before the nonce is inserted, and insertion is the resource commit.
    pub fn commit(
        &mut self,
        ticket: &VerificationTicket,
        statement: &FixedPolicyStatement,
        relation_version: u64,
        proof_bytes: &[u8],
        terminal_signature: &SchnorrSignature,
        trusted_now: u64,
    ) -> Result<(), AdapterError> {
        if statement.deployment_id != self.deployment_id {
            return Err(AdapterError::BadHeaderEncoding);
        }
        if self.current_header != Some(statement.header_digest) {
            return Err(AdapterError::StaleHeader);
        }
        if compute_header_digest(statement) != statement.header_digest {
            return Err(AdapterError::BadHeaderEncoding);
        }
        if compute_request_digest(statement) != statement.request_digest {
            return Err(AdapterError::BadRequestEncoding);
        }
        if trusted_now < statement.request_lo || trusted_now > statement.request_hi {
            return Err(AdapterError::OutsideRequestInterval);
        }
        let nonce = nonce_key(&statement.nonce);
        if ticket.header_digest != statement.header_digest
            || ticket.request_digest != statement.request_digest
            || ticket.relation_version != relation_version
            || ticket.nonce_key != nonce
            || ticket.proof_digest != proof_digest(proof_bytes)
        {
            return Err(AdapterError::TicketMismatch);
        }
        if self.used_nonces.contains(&nonce) {
            return Err(AdapterError::ReplayedNonce);
        }
        if !schnorr_verify(
            &self.generator,
            &statement.terminal_key,
            TERMINAL_SIGNATURE_DOMAIN,
            &terminal_signature_message(statement, relation_version, proof_bytes),
            terminal_signature,
        ) {
            return Err(AdapterError::BadTerminalSignature);
        }
        self.used_nonces.insert(nonce);
        Ok(())
    }
}

pub fn sign_header<R: RngCore>(
    rng: &mut R,
    generator: &G1Affine,
    registry_secret_key: &Fr,
    statement: &FixedPolicyStatement,
) -> SchnorrSignature {
    schnorr_sign(
        rng,
        generator,
        registry_secret_key,
        HEADER_SIGNATURE_DOMAIN,
        &header_signature_message(statement),
    )
}

pub fn sign_terminal<R: RngCore>(
    rng: &mut R,
    generator: &G1Affine,
    terminal_secret_key: &Fr,
    statement: &FixedPolicyStatement,
    relation_version: u64,
    proof_bytes: &[u8],
) -> SchnorrSignature {
    schnorr_sign(
        rng,
        generator,
        terminal_secret_key,
        TERMINAL_SIGNATURE_DOMAIN,
        &terminal_signature_message(statement, relation_version, proof_bytes),
    )
}
