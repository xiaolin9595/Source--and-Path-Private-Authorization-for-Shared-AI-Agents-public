//! Shared-opening adapter for the new HRADA authorization relation.
//! Instance order is [1, state_prime, request[0], ..., request[n-1]].
//! The public request is removed from Lego's linked commitment; the residual
//! must equal the CP-RSA statement commitment under exactly the same bases.
use crate::commitments::pedersen::PedersenCommitment;
use crate::utils::integer_to_bigint_mod_q;
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use rand::{CryptoRng, Rng};
use rug::{integer::Order, Integer};

/// Sample the shared commitment opening uniformly over the entire scalar field.
/// The canonical integer is reused by the member and authorization proofs.
pub fn sample_commitment_randomness<R: Rng + CryptoRng>(rng: &mut R) -> Integer {
    scalar_to_integer(&Fr::rand(rng))
}

fn scalar_to_integer(value: &Fr) -> Integer {
    Integer::from_digits(&value.into_repr().to_bytes_le(), Order::Lsf)
}

pub struct LinkParameters {
    pub proving_key: legogro16::ProvingKey<Bls12_381>,
    pub request_fields: usize,
}

pub fn setup<C, R>(
    rng: &mut R,
    cp: &PedersenCommitment<G1Projective>,
    circuit: C,
    request_fields: usize,
) -> Result<LinkParameters, SynthesisError>
where
    C: ConstraintSynthesizer<Fr>,
    R: Rng + CryptoRng,
{
    let mut bases = vec![G1Projective::rand(rng), cp.g];
    for _ in 0..request_fields {
        bases.push(G1Projective::rand(rng));
    }
    bases.push(cp.h);
    let affine = bases.iter().map(|p| p.into_affine()).collect::<Vec<_>>();
    let proving_key = legogro16::generate_random_parameters(circuit, &affine, rng)?;
    if proving_key.vk.link_bases.len() != request_fields + 3 {
        return Err(SynthesisError::MalformedVerifyingKey);
    }
    Ok(LinkParameters {
        proving_key,
        request_fields,
    })
}

pub fn prove<C, R>(
    rng: &mut R,
    parameters: &LinkParameters,
    circuit: C,
    commitment_randomness: &Integer,
) -> Result<legogro16::Proof<Bls12_381>, SynthesisError>
where
    C: ConstraintSynthesizer<Fr> + Clone,
    R: Rng + CryptoRng,
{
    // A diagnostic constraint failure is not reported as a pairing rejection.
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.clone().generate_constraints(cs.clone())?;
    if !cs.is_satisfied()? {
        return Err(SynthesisError::Unsatisfiable);
    }
    if cs.num_instance_variables() != parameters.request_fields + 2 {
        return Err(SynthesisError::MalformedVerifyingKey);
    }
    let link_randomness = integer_to_bigint_mod_q::<G1Projective>(commitment_randomness)
        .map_err(|_| SynthesisError::Unsatisfiable)?;
    legogro16::create_random_proof(
        circuit,
        Fr::rand(rng),
        link_randomness,
        &parameters.proving_key,
        rng,
    )
}

pub fn parameter_digest(
    parameters: &LinkParameters,
    cp_parameter_bytes: &[u8],
) -> Result<[u8; 32], SynthesisError> {
    let mut bytes = b"HRADA-JOINT-BLS12381-EXPERIMENT-V1".to_vec();
    bytes.extend_from_slice(&(parameters.request_fields as u64).to_le_bytes());
    bytes.extend_from_slice(&(cp_parameter_bytes.len() as u64).to_le_bytes());
    bytes.extend_from_slice(cp_parameter_bytes);
    parameters
        .proving_key
        .vk
        .serialize(&mut bytes)
        .map_err(|_| SynthesisError::MalformedVerifyingKey)?;
    let hash = Blake2s::digest(&bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    Ok(out)
}

pub fn verify(
    parameters: &LinkParameters,
    cp: &PedersenCommitment<G1Projective>,
    cp_parameter_bytes: &[u8],
    expected_parameters_digest: &[u8; 32],
    proof: &legogro16::Proof<Bls12_381>,
    public_request: &[Fr],
    cp_commitment: &G1Projective,
) -> Result<bool, SynthesisError> {
    let bases = &parameters.proving_key.vk.link_bases;
    if public_request.len() != parameters.request_fields || bases.len() != public_request.len() + 3
    {
        return Ok(false);
    }
    if bases[1].into_projective() != cp.g || bases.last().unwrap().into_projective() != cp.h {
        return Ok(false);
    }
    if parameter_digest(parameters, cp_parameter_bytes)? != *expected_parameters_digest {
        return Ok(false);
    }
    let prepared = legogro16::prepare_verifying_key(&parameters.proving_key.vk);
    if !legogro16::verify_proof(&prepared, proof)? {
        return Ok(false);
    }
    let mut residual = proof.link_d.into_projective() - &bases[0].into_projective();
    for (value, base) in public_request.iter().zip(bases.iter().skip(2)) {
        residual -= &base.mul(value.into_repr());
    }
    Ok(residual == *cp_commitment)
}

#[cfg(test)]
mod commitment_randomness_tests {
    use super::*;
    use ark_ff::{FpParameters, Zero};

    #[test]
    fn canonical_opening_boundaries_round_trip_without_truncation() {
        let modulus = Integer::from_digits(
            &<Fr as PrimeField>::Params::MODULUS.to_bytes_le(),
            Order::Lsf,
        );
        let mut above_old_range = Integer::from(1);
        above_old_range <<= 240;
        above_old_range += 17;
        let cases = [
            Integer::from(0),
            Integer::from(1),
            above_old_range,
            modulus - 1,
        ];
        for expected in cases.iter() {
            let scalar = integer_to_bigint_mod_q::<G1Projective>(expected).unwrap();
            assert_eq!(scalar_to_integer(&scalar), *expected);
            let mut serialized = Vec::new();
            scalar.serialize(&mut serialized).unwrap();
            // Matches the previous latency worker's canonical encoding.
            assert_eq!(Integer::from_digits(&serialized, Order::Lsf), *expected);
            let round_trip =
                integer_to_bigint_mod_q::<G1Projective>(&scalar_to_integer(&scalar)).unwrap();
            assert_eq!(round_trip, scalar);
        }
        assert_eq!(scalar_to_integer(&Fr::zero()), Integer::from(0));
    }
}
