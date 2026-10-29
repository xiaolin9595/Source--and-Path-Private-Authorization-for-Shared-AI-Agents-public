//! Residual-commitment adapter between CP-RSA membership and LegoGroth16 ABAC.
//!
//! The CP-RSA statement contains `C_p = B_p * p + H * r`.  LegoGroth16 links
//! all instance variables in one commitment:
//!
//! `link_d = B_0 + B_p*p + sum(B_q[i] * q[i]) + H*r`.
//!
//! A verifier that already knows the request instance `q` can therefore
//! recover the *same* hidden-member commitment without learning `p`:
//!
//! `C_p = link_d - B_0 - sum(B_q[i] * q[i])`.
//!
//! This module implements that adapter for a minimal ABAC relation.  The
//! hidden policy binds resource, action, epoch and agent id to a 128-bit
//! message.  The circuit recomputes the same Blake2s hash-to-prime relation as
//! `hash_to_prime::snark_hash`, while a public nonce is linked to the proof to
//! prevent cross-request replay.

use crate::{
    commitments::pedersen::PedersenCommitment,
    protocols::hash_to_prime::snark_hash::HashToPrimeHashParameters,
    utils::integer_to_bigint_mod_q,
};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_crypto_primitives::prf::blake2s::constraints::evaluate_blake2s;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBitsGadget,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    Assignment, R1CSVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalSerialize, SerializationError};
use blake2::{Blake2s, Digest};
use rand::Rng;
use rug::Integer;

const RESOURCE_BITS: usize = 16;
const ACTION_BITS: usize = 16;
const EPOCH_BITS: usize = 32;
const AGENT_BITS: usize = 32;
const SERIAL_BITS: usize = 32;
const NONCE_BITS: usize = 64;
const MESSAGE_BITS: usize = RESOURCE_BITS + ACTION_BITS + EPOCH_BITS + AGENT_BITS + SERIAL_BITS;

/// Public request attributes bound to the proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbacRequest {
    pub resource: u16,
    pub action: u16,
    pub epoch: u32,
    pub agent_id: u32,
    pub nonce: u64,
}

impl AbacRequest {
    fn field_elements(&self) -> [Fr; 5] {
        [
            Fr::from(self.resource as u64),
            Fr::from(self.action as u64),
            Fr::from(self.epoch as u64),
            Fr::from(self.agent_id as u64),
            Fr::from(self.nonce),
        ]
    }
}

/// Hidden authorization policy committed through the hash-to-prime member.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbacPolicy {
    pub resource: u16,
    pub action: u16,
    pub epoch: u32,
    pub agent_id: u32,
    pub serial: u32,
}

impl AbacPolicy {
    /// Canonical little-endian bit packing used by both the circuit and issuer.
    pub fn packed_message(&self) -> Integer {
        let mut message = Integer::from(self.resource);
        message += Integer::from(self.action) << RESOURCE_BITS as u32;
        message += Integer::from(self.epoch) << (RESOURCE_BITS + ACTION_BITS) as u32;
        message +=
            Integer::from(self.agent_id) << (RESOURCE_BITS + ACTION_BITS + EPOCH_BITS) as u32;
        message += Integer::from(self.serial)
            << (RESOURCE_BITS + ACTION_BITS + EPOCH_BITS + AGENT_BITS) as u32;
        message
    }
}

/// Hash-to-prime configuration shared with the CP-RSA membership protocol.
pub struct M3HashParameters;

impl HashToPrimeHashParameters for M3HashParameters {
    const MESSAGE_SIZE: u16 = MESSAGE_BITS as u16;
}

#[derive(Clone)]
pub struct AbacLinkParameters {
    pub proving_key: legogro16::ProvingKey<Bls12_381>,
}

/// Private and public values needed to create the linked ABAC proof.
pub struct AbacProverInput<'a> {
    pub security_level: u16,
    pub required_prime_bits: u16,
    pub prime: &'a Integer,
    pub commitment_randomness: &'a Integer,
    pub hash_to_prime_index: u64,
    pub request: AbacRequest,
    pub policy: AbacPolicy,
}

struct AbacCircuit {
    security_level: u16,
    required_prime_bits: u16,
    prime: Option<Fr>,
    request: Option<AbacRequest>,
    policy: Option<AbacPolicy>,
    hash_to_prime_index: Option<u64>,
}

impl ConstraintSynthesizer<Fr> for AbacCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Instance order is security critical and mirrors `setup` and
        // `residual_commitment`: [1, p, resource, action, epoch, agent, nonce].
        let prime = FpVar::new_variable(
            ark_relations::ns!(cs, "prime"),
            || self.prime.get(),
            AllocationMode::Input,
        )?;
        let request = self.request;
        let request_resource = input_u64(cs.clone(), "request resource", || {
            Ok(request.get()?.resource as u64)
        })?;
        let request_action = input_u64(cs.clone(), "request action", || {
            Ok(request.get()?.action as u64)
        })?;
        let request_epoch = input_u64(cs.clone(), "request epoch", || {
            Ok(request.get()?.epoch as u64)
        })?;
        let request_agent = input_u64(cs.clone(), "request agent", || {
            Ok(request.get()?.agent_id as u64)
        })?;
        let request_nonce = input_u64(cs.clone(), "request nonce", || Ok(request.get()?.nonce))?;

        let policy = self.policy;
        let policy_resource = witness_u64(cs.clone(), "policy resource", || {
            Ok(policy.get()?.resource as u64)
        })?;
        let policy_action = witness_u64(cs.clone(), "policy action", || {
            Ok(policy.get()?.action as u64)
        })?;
        let policy_epoch =
            witness_u64(
                cs.clone(),
                "policy epoch",
                || Ok(policy.get()?.epoch as u64),
            )?;
        let policy_agent = witness_u64(cs.clone(), "policy agent", || {
            Ok(policy.get()?.agent_id as u64)
        })?;
        let policy_serial = witness_u64(cs.clone(), "policy serial", || {
            Ok(policy.get()?.serial as u64)
        })?;

        enforce_width(&policy_resource, RESOURCE_BITS)?;
        enforce_width(&policy_action, ACTION_BITS)?;
        enforce_width(&policy_epoch, EPOCH_BITS)?;
        enforce_width(&policy_agent, AGENT_BITS)?;
        enforce_width(&policy_serial, SERIAL_BITS)?;
        enforce_width(&request_nonce, NONCE_BITS)?;

        // Minimal ABAC predicates: exact resource/action scope, authorized
        // epoch and the intended agent pseudonym.
        request_resource.enforce_equal(&policy_resource)?;
        request_action.enforce_equal(&policy_action)?;
        request_epoch.enforce_equal(&policy_epoch)?;
        request_agent.enforce_equal(&policy_agent)?;

        let packed_message = policy_resource
            + policy_action * constant_pow2(RESOURCE_BITS)
            + policy_epoch * constant_pow2(RESOURCE_BITS + ACTION_BITS)
            + policy_agent * constant_pow2(RESOURCE_BITS + ACTION_BITS + EPOCH_BITS)
            + policy_serial * constant_pow2(RESOURCE_BITS + ACTION_BITS + EPOCH_BITS + AGENT_BITS);

        enforce_hash_to_prime(
            &packed_message,
            &prime,
            self.hash_to_prime_index,
            self.security_level,
            self.required_prime_bits,
        )?;

        Ok(())
    }
}

fn input_u64<F>(
    cs: ConstraintSystemRef<Fr>,
    _label: &'static str,
    value: F,
) -> Result<FpVar<Fr>, SynthesisError>
where
    F: FnOnce() -> Result<u64, SynthesisError>,
{
    FpVar::new_variable(
        ark_relations::ns!(cs, "public u64"),
        || Ok(Fr::from(value()?)),
        AllocationMode::Input,
    )
}

fn witness_u64<F>(
    cs: ConstraintSystemRef<Fr>,
    _label: &'static str,
    value: F,
) -> Result<FpVar<Fr>, SynthesisError>
where
    F: FnOnce() -> Result<u64, SynthesisError>,
{
    FpVar::new_variable(
        ark_relations::ns!(cs, "private u64"),
        || Ok(Fr::from(value()?)),
        AllocationMode::Witness,
    )
}

fn constant_pow2(exponent: usize) -> Fr {
    Fr::from(2u64).pow([exponent as u64])
}

fn enforce_width(value: &FpVar<Fr>, width: usize) -> Result<(), SynthesisError> {
    let bits = value.to_bits_le()?;
    for bit in bits.iter().skip(width) {
        bit.enforce_equal(&Boolean::constant(false))?;
    }
    Ok(())
}

fn enforce_hash_to_prime(
    message: &FpVar<Fr>,
    prime: &FpVar<Fr>,
    index: Option<u64>,
    security_level: u16,
    required_prime_bits: u16,
) -> Result<(), SynthesisError> {
    let index_bit_length = M3HashParameters::index_bit_length(security_level);
    if index_bit_length > 64 {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut index_bits = Vec::with_capacity(index_bit_length as usize);
    for bit_index in 0..index_bit_length {
        index_bits.push(Boolean::new_variable(
            ark_relations::ns!(prime.cs(), "hash-to-prime index bit"),
            || {
                let index = index.get()?;
                Ok((index & (1u64 << bit_index)) != 0)
            },
            AllocationMode::Witness,
        )?);
    }

    let message_bits = message.to_bits_be()?;
    let bits_to_hash: Vec<Boolean<Fr>> = [
        index_bits.as_slice(),
        &message_bits[Fr::size_in_bits() - MESSAGE_BITS..],
    ]
    .concat();
    let bits_to_hash = if bits_to_hash.len() % 8 == 0 {
        bits_to_hash
    } else {
        let padding_length = 8 - bits_to_hash.len() % 8;
        [
            vec![Boolean::constant(false); padding_length].as_slice(),
            bits_to_hash.as_slice(),
        ]
        .concat()
    };

    let hash_bits = evaluate_blake2s(&bits_to_hash)?
        .into_iter()
        .flat_map(|word| word.to_bits_le())
        .take(required_prime_bits as usize - 1)
        .collect::<Vec<_>>();
    let expected_prime_bits = [&[Boolean::constant(true)][..], hash_bits.as_slice()].concat();

    let prime_bits = prime.to_bits_be()?;
    let leading_zero_count = Fr::size_in_bits() - required_prime_bits as usize;
    for bit in prime_bits.iter().take(leading_zero_count) {
        bit.enforce_equal(&Boolean::constant(false))?;
    }
    for (expected, actual) in expected_prime_bits
        .iter()
        .zip(prime_bits.iter().skip(leading_zero_count))
    {
        expected.enforce_equal(actual)?;
    }

    Ok(())
}

/// Creates a LegoGroth16 CRS whose member and hiding bases are exactly those
/// used by the CP-RSA Pedersen commitment.
pub fn setup<R: Rng>(
    rng: &mut R,
    cp_pedersen: &PedersenCommitment<G1Projective>,
    security_level: u16,
    required_prime_bits: u16,
) -> Result<AbacLinkParameters, SynthesisError> {
    let circuit = AbacCircuit {
        security_level,
        required_prime_bits,
        prime: None,
        request: None,
        policy: None,
        hash_to_prime_index: None,
    };

    // [B0, Bp, Bresource, Baction, Bepoch, Bagent, Bnonce, H]
    let bases = vec![
        G1Projective::rand(rng),
        cp_pedersen.g,
        G1Projective::rand(rng),
        G1Projective::rand(rng),
        G1Projective::rand(rng),
        G1Projective::rand(rng),
        G1Projective::rand(rng),
        cp_pedersen.h,
    ];
    let proving_key = legogro16::generate_random_parameters(
        circuit,
        &bases
            .into_iter()
            .map(|point| point.into_affine())
            .collect::<Vec<_>>(),
        rng,
    )?;
    Ok(AbacLinkParameters { proving_key })
}

/// Proves the ABAC predicates and links the proof to the same hidden prime and
/// Pedersen randomness used by CP-RSA.
pub fn prove<R: Rng>(
    rng: &mut R,
    parameters: &AbacLinkParameters,
    input: AbacProverInput<'_>,
) -> Result<legogro16::Proof<Bls12_381>, SynthesisError> {
    let circuit = AbacCircuit {
        security_level: input.security_level,
        required_prime_bits: input.required_prime_bits,
        prime: Some(
            integer_to_bigint_mod_q::<G1Projective>(input.prime)
                .map_err(|_| SynthesisError::Unsatisfiable)?,
        ),
        request: Some(input.request),
        policy: Some(input.policy),
        hash_to_prime_index: Some(input.hash_to_prime_index),
    };
    let v = Fr::rand(rng);
    let link_v = integer_to_bigint_mod_q::<G1Projective>(input.commitment_randomness)
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    legogro16::create_random_proof(circuit, v, link_v, &parameters.proving_key, rng)
}

/// Removes the public request contribution from `link_d`, leaving a standard
/// two-base Pedersen commitment to the hidden accumulator member.
pub fn residual_commitment(
    parameters: &AbacLinkParameters,
    proof: &legogro16::Proof<Bls12_381>,
    request: AbacRequest,
) -> Result<G1Projective, SynthesisError> {
    let bases = &parameters.proving_key.vk.link_bases;
    if bases.len() != 8 {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    let mut residual = proof.link_d.into_projective();
    residual -= &bases[0].into_projective();
    for (value, base) in request
        .field_elements()
        .iter()
        .zip(bases.iter().skip(2).take(5))
    {
        residual -= &base.mul(value.into_repr());
    }
    Ok(residual)
}

/// Domain-separated digest that pins the complete Lego verification key and
/// the CP-RSA Pedersen bases. Applications publish this value as `paramsHash`
/// and reject proofs made under any other setup.
pub fn parameter_digest(
    parameters: &AbacLinkParameters,
    cp_pedersen: &PedersenCommitment<G1Projective>,
) -> Result<[u8; 32], SerializationError> {
    let mut encoded = b"HRADA-M3-PARAMETERS-V1".to_vec();
    cp_pedersen.g.into_affine().serialize(&mut encoded)?;
    cp_pedersen.h.into_affine().serialize(&mut encoded)?;
    parameters.proving_key.vk.serialize(&mut encoded)?;
    let digest = Blake2s::digest(&encoded);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(output)
}

/// Verifies both the LegoGroth16 relation and equality of its residual with
/// the CP-RSA statement commitment.
pub fn verify(
    parameters: &AbacLinkParameters,
    proof: &legogro16::Proof<Bls12_381>,
    request: AbacRequest,
    cp_member_commitment: &G1Projective,
    cp_pedersen: &PedersenCommitment<G1Projective>,
    expected_parameter_digest: &[u8; 32],
) -> Result<bool, SynthesisError> {
    let bases = &parameters.proving_key.vk.link_bases;
    if bases.len() != 8
        || bases[1].into_projective() != cp_pedersen.g
        || bases[7].into_projective() != cp_pedersen.h
    {
        return Ok(false);
    }
    let actual_digest = parameter_digest(parameters, cp_pedersen)
        .map_err(|_| SynthesisError::MalformedVerifyingKey)?;
    if actual_digest != *expected_parameter_digest {
        return Ok(false);
    }
    let prepared = legogro16::prepare_verifying_key(&parameters.proving_key.vk);
    if !legogro16::verify_proof(&prepared, proof)? {
        return Ok(false);
    }
    Ok(residual_commitment(parameters, proof, request)? == *cp_member_commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        commitments::Commitment,
        parameters::Parameters,
        protocols::{
            hash_to_prime::snark_hash::Protocol as HashProtocol,
            membership::{
                transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
                Protocol as MembershipProtocol, Statement as MembershipStatement,
                Witness as MembershipWitness,
            },
        },
    };
    use accumulator::{
        group::{Group, Rsa2048},
        Accumulator, AccumulatorWithoutHashToPrime,
    };
    use ark_ec::ProjectiveCurve;
    use merlin::Transcript;
    use rand::{thread_rng, CryptoRng};
    use rug::{rand::RandState, Integer};
    use std::cell::RefCell;

    type Hp = HashProtocol<Bls12_381, M3HashParameters>;
    type Membership = MembershipProtocol<Rsa2048, G1Projective, Hp>;
    type MembershipProof = crate::protocols::membership::Proof<Rsa2048, G1Projective, Hp>;
    type MembershipCrs = crate::protocols::membership::CRS<Rsa2048, G1Projective, Hp>;

    fn membership_proof(
        protocol: &Membership,
        rng1: &mut RandState,
        rng2: &mut (impl Rng + CryptoRng),
        statement: &MembershipStatement<Rsa2048, G1Projective>,
        message: Integer,
        randomness: Integer,
        witness: <Rsa2048 as Group>::Elem,
    ) -> MembershipProof {
        let transcript = RefCell::new(Transcript::new(b"hrada-m3-membership-v1"));
        let mut channel = TranscriptVerifierChannel::new(&protocol.crs, &transcript);
        protocol
            .prove(
                &mut channel,
                rng1,
                rng2,
                statement,
                &MembershipWitness {
                    e: message,
                    r_q: randomness,
                    w: witness,
                },
            )
            .unwrap();
        channel.proof().unwrap()
    }

    fn verify_membership(
        crs: &MembershipCrs,
        proof: &MembershipProof,
        statement: &MembershipStatement<Rsa2048, G1Projective>,
    ) -> bool {
        let transcript = RefCell::new(Transcript::new(b"hrada-m3-membership-v1"));
        let mut channel = TranscriptProverChannel::new(crs, &transcript, proof);
        Membership::from_crs(crs)
            .verify(&mut channel, statement)
            .is_ok()
    }

    #[test]
    fn joint_proof_accepts_and_rejects_splices() {
        let system_parameters = Parameters::from_security_level(128).unwrap();
        let mut rng1 = RandState::new();
        rng1.seed(&Integer::from(20_260_805));
        let mut rng2 = thread_rng();

        let membership = Membership::setup(&system_parameters, &mut rng1, &mut rng2).unwrap();
        let cp_pedersen = &membership.crs.crs_modeq.pedersen_commitment_parameters;
        let abac_parameters = setup(
            &mut rng2,
            cp_pedersen,
            system_parameters.security_level,
            system_parameters.hash_to_prime_bits,
        )
        .unwrap();
        let expected_parameter_digest = parameter_digest(&abac_parameters, cp_pedersen).unwrap();

        let policy_1 = AbacPolicy {
            resource: 7,
            action: 3,
            epoch: 42,
            agent_id: 9001,
            serial: 11,
        };
        let policy_2 = AbacPolicy {
            serial: 12,
            ..policy_1
        };
        let request = AbacRequest {
            resource: policy_1.resource,
            action: policy_1.action,
            epoch: policy_1.epoch,
            agent_id: policy_1.agent_id,
            nonce: 0x1020_3040_5060_7080,
        };

        let message_1 = policy_1.packed_message();
        let message_2 = policy_2.packed_message();
        let (prime_1, index_1) = membership.hash_to_prime(&message_1).unwrap();
        let (prime_2, _) = membership.hash_to_prime(&message_2).unwrap();
        assert_ne!(prime_1, prime_2);

        // Build two independently valid membership witnesses for the same
        // final accumulator so the p-splice negative is meaningful.
        let base = Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty()
            .add(&[Integer::from(65_537), Integer::from(65_539)]);
        let with_2 = base.clone().add(&[prime_2.clone()]);
        let member_1 = with_2.add_with_proof(&[prime_1.clone()]);
        let with_1 = base.add(&[prime_1.clone()]);
        let member_2 = with_1.add_with_proof(&[prime_2.clone()]);
        let accumulator_value = member_1.0.value;
        assert_eq!(accumulator_value, member_2.0.value);

        let randomness_1 = Integer::from(17);
        let randomness_2 = Integer::from(19);
        let commitment_1 = cp_pedersen.commit(&prime_1, &randomness_1).unwrap();
        let commitment_2 = cp_pedersen.commit(&prime_2, &randomness_2).unwrap();
        let statement_1 = MembershipStatement {
            c_p: accumulator_value.clone(),
            c_e_q: commitment_1,
        };
        let statement_2 = MembershipStatement {
            c_p: accumulator_value,
            c_e_q: commitment_2,
        };
        let cp_proof_1 = membership_proof(
            &membership,
            &mut rng1,
            &mut rng2,
            &statement_1,
            message_1,
            randomness_1.clone(),
            member_1.1.witness.0.value.clone(),
        );
        let cp_proof_2 = membership_proof(
            &membership,
            &mut rng1,
            &mut rng2,
            &statement_2,
            message_2,
            randomness_2,
            member_2.1.witness.0.value,
        );
        assert!(verify_membership(
            &membership.crs,
            &cp_proof_1,
            &statement_1
        ));
        assert!(verify_membership(
            &membership.crs,
            &cp_proof_2,
            &statement_2
        ));

        // The same member with different commitment randomness is also a
        // separately valid CP statement.  It must not be spliceable into a
        // Lego proof linked with randomness_1.
        let randomness_3 = Integer::from(23);
        let commitment_3 = cp_pedersen.commit(&prime_1, &randomness_3).unwrap();
        let statement_3 = MembershipStatement {
            c_p: statement_1.c_p.clone(),
            c_e_q: commitment_3,
        };
        let cp_proof_3 = membership_proof(
            &membership,
            &mut rng1,
            &mut rng2,
            &statement_3,
            policy_1.packed_message(),
            randomness_3,
            member_1.1.witness.0.value.clone(),
        );
        assert!(verify_membership(
            &membership.crs,
            &cp_proof_3,
            &statement_3
        ));

        let abac_proof_1 = prove(
            &mut rng2,
            &abac_parameters,
            AbacProverInput {
                security_level: system_parameters.security_level,
                required_prime_bits: system_parameters.hash_to_prime_bits,
                prime: &prime_1,
                commitment_randomness: &randomness_1,
                hash_to_prime_index: index_1,
                request,
                policy: policy_1,
            },
        )
        .unwrap();

        // Positive: CP-RSA membership and ABAC are both valid and bound to p1.
        assert!(verify(
            &abac_parameters,
            &abac_proof_1,
            request,
            &statement_1.c_e_q,
            cp_pedersen,
            &expected_parameter_digest,
        )
        .unwrap());
        println!("M3_CASE joint-positive PASS");

        // p-splice: a separately valid CP proof for p2 cannot be combined
        // with the valid ABAC proof for p1.
        assert!(!verify(
            &abac_parameters,
            &abac_proof_1,
            request,
            &statement_2.c_e_q,
            cp_pedersen,
            &expected_parameter_digest,
        )
        .unwrap());
        println!("M3_CASE prime-splice-rejected PASS");

        // Randomness splice: even when p is unchanged, a CP statement with a
        // different Pedersen opening cannot be paired with this ABAC proof.
        assert!(!verify(
            &abac_parameters,
            &abac_proof_1,
            request,
            &statement_3.c_e_q,
            cp_pedersen,
            &expected_parameter_digest,
        )
        .unwrap());
        println!("M3_CASE randomness-splice-rejected PASS");

        // Request splice: every public request field contributes to the
        // residual commitment and is mutated independently.
        let request_mutations = [
            (
                "resource",
                AbacRequest {
                    resource: request.resource + 1,
                    ..request
                },
            ),
            (
                "action",
                AbacRequest {
                    action: request.action + 1,
                    ..request
                },
            ),
            (
                "epoch",
                AbacRequest {
                    epoch: request.epoch + 1,
                    ..request
                },
            ),
            (
                "agent",
                AbacRequest {
                    agent_id: request.agent_id + 1,
                    ..request
                },
            ),
            (
                "nonce",
                AbacRequest {
                    nonce: request.nonce + 1,
                    ..request
                },
            ),
        ];
        for (field, wrong_request) in request_mutations {
            assert!(!verify(
                &abac_parameters,
                &abac_proof_1,
                wrong_request,
                &statement_1.c_e_q,
                cp_pedersen,
                &expected_parameter_digest,
            )
            .unwrap());
            println!("M3_CASE request-{}-splice-rejected PASS", field);
        }
        println!("M3_CASE request-splice-rejected PASS");

        // Parameter splice: a fresh Lego CRS using the same CP bases still has
        // independent request bases and verification key, and must reject.
        let wrong_parameters = setup(
            &mut rng2,
            cp_pedersen,
            system_parameters.security_level,
            system_parameters.hash_to_prime_bits,
        )
        .unwrap();
        assert!(!verify(
            &wrong_parameters,
            &abac_proof_1,
            request,
            &statement_1.c_e_q,
            cp_pedersen,
            &expected_parameter_digest,
        )
        .unwrap());
        println!("M3_CASE parameter-splice-rejected PASS");

        let mut wrong_parameter_digest = expected_parameter_digest;
        wrong_parameter_digest[0] ^= 1;
        assert!(!verify(
            &abac_parameters,
            &abac_proof_1,
            request,
            &statement_1.c_e_q,
            cp_pedersen,
            &wrong_parameter_digest,
        )
        .unwrap());
        println!("M3_CASE parameter-digest-splice-rejected PASS");

        let independent_membership =
            Membership::setup(&system_parameters, &mut rng1, &mut rng2).unwrap();
        let wrong_cp_pedersen = &independent_membership
            .crs
            .crs_modeq
            .pedersen_commitment_parameters;
        assert!(!verify(
            &abac_parameters,
            &abac_proof_1,
            request,
            &statement_1.c_e_q,
            wrong_cp_pedersen,
            &expected_parameter_digest,
        )
        .unwrap());
        println!("M3_CASE cp-bases-splice-rejected PASS");
    }
}
