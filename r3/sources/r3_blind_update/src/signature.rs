//! Explicit Schnorr-Poseidon over the prime-order Jubjub subgroup.
use crate::poseidon::{hash, hash_var, Domain};
use ark_bls12_381::Fr as Base;
use ark_ec::{twisted_edwards::TECurveConfig, AffineRepr, CurveGroup, Group};
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsAffine, EdwardsProjective, Fr as Scalar,
};
use ark_ff::{BigInteger, One, PrimeField, Zero};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, groups::CurveVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::Cursor;
use thiserror::Error;

const CHALLENGE_BITS: usize = Scalar::MODULUS_BIT_SIZE as usize - 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub EdwardsAffine);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey(pub Scalar);
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub r: EdwardsAffine,
    pub s: Scalar,
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("zero secret, nonce, response, or identity point")]
    Identity,
    #[error("point is not in the prime-order subgroup")]
    WrongSubgroup,
    #[error("non-canonical or trailing encoding")]
    Encoding,
    #[error("deterministic nonce counter exhausted")]
    NonceExhausted,
}

/// Deterministically sample over the full scalar field.  A Poseidon output is
/// accepted only when its integer encoding is a canonical, nonzero scalar;
/// no modular reduction or high-bit truncation is used.
fn signing_nonce(sk: &SecretKey, message: Base, aux: [u8; 32], counter: u64) -> Option<Scalar> {
    let lo = Base::from(u128::from_le_bytes(
        aux[..16].try_into().expect("fixed slice"),
    ));
    let hi = Base::from(u128::from_le_bytes(
        aux[16..].try_into().expect("fixed slice"),
    ));
    let candidate = hash(
        Domain::SignatureNonce,
        &[
            Base::from_le_bytes_mod_order(&sk.0.into_bigint().to_bytes_le()),
            message,
            lo,
            hi,
            Base::from(counter),
        ],
    );
    Scalar::from_bigint(candidate.into_bigint()).filter(|x| !x.is_zero())
}

fn scalar_from_low_bits(x: Base) -> Scalar {
    let mut bits = x.into_bigint().to_bits_le();
    bits.truncate(CHALLENGE_BITS);
    let mut bytes = vec![0u8; (CHALLENGE_BITS + 7) / 8];
    for (i, bit) in bits.into_iter().enumerate() {
        if bit {
            bytes[i / 8] |= 1 << (i % 8);
        }
    }
    Scalar::from_le_bytes_mod_order(&bytes)
}
fn challenge(r: EdwardsAffine, a: EdwardsAffine, message: Base) -> Scalar {
    scalar_from_low_bits(hash(
        Domain::SignatureChallenge,
        &[r.x, r.y, a.x, a.y, message],
    ))
}
pub fn public_key(sk: &SecretKey) -> Result<PublicKey, SignatureError> {
    if sk.0.is_zero() {
        return Err(SignatureError::Identity);
    }
    Ok(PublicKey(
        EdwardsProjective::generator()
            .mul_bigint(sk.0.into_bigint())
            .into_affine(),
    ))
}
/// Deterministic nonce with mandatory caller-provided 256-bit auxiliary randomness.
pub fn sign(sk: &SecretKey, message: Base, aux: [u8; 32]) -> Result<Signature, SignatureError> {
    let pk = public_key(sk)?;
    for counter in 0..=u64::MAX {
        let Some(nonce) = signing_nonce(sk, message, aux, counter) else {
            continue;
        };
        let r = EdwardsProjective::generator()
            .mul_bigint(nonce.into_bigint())
            .into_affine();
        let s = nonce + challenge(r, pk.0, message) * sk.0;
        if !s.is_zero() {
            return Ok(Signature { r, s });
        }
    }
    Err(SignatureError::NonceExhausted)
}
fn valid_point(p: EdwardsAffine) -> bool {
    !p.is_zero() && p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}
pub fn verify(pk: &PublicKey, message: Base, sig: &Signature) -> bool {
    if !valid_point(pk.0) || !valid_point(sig.r) || sig.s.is_zero() {
        return false;
    }
    let lhs = EdwardsProjective::generator().mul_bigint(sig.s.into_bigint());
    let rhs = sig.r.into_group()
        + pk.0
            .mul_bigint(challenge(sig.r, pk.0, message).into_bigint());
    lhs == rhs
}

pub fn decode_public_key(bytes: &[u8]) -> Result<PublicKey, SignatureError> {
    let mut c = Cursor::new(bytes);
    let p = EdwardsAffine::deserialize_compressed(&mut c).map_err(|_| SignatureError::Encoding)?;
    if c.position() != bytes.len() as u64 {
        return Err(SignatureError::Encoding);
    }
    if !valid_point(p) {
        return Err(if p.is_zero() {
            SignatureError::Identity
        } else {
            SignatureError::WrongSubgroup
        });
    }
    Ok(PublicKey(p))
}
pub fn encode_signature(sig: &Signature) -> Vec<u8> {
    let mut out = Vec::new();
    sig.r.serialize_compressed(&mut out).expect("vec write");
    sig.s.serialize_compressed(&mut out).expect("vec write");
    out
}
pub fn decode_signature(bytes: &[u8]) -> Result<Signature, SignatureError> {
    let mut c = Cursor::new(bytes);
    let r = EdwardsAffine::deserialize_compressed(&mut c).map_err(|_| SignatureError::Encoding)?;
    let s = Scalar::deserialize_compressed(&mut c).map_err(|_| SignatureError::Encoding)?;
    if c.position() != bytes.len() as u64 {
        return Err(SignatureError::Encoding);
    }
    if !valid_point(r) || s.is_zero() {
        return Err(SignatureError::Identity);
    }
    Ok(Signature { r, s })
}

fn scalar_bits(
    cs: ConstraintSystemRef<Base>,
    value: Scalar,
) -> Result<Vec<Boolean<Base>>, SynthesisError> {
    let native = value.into_bigint().to_bits_le();
    let bits = (0..Scalar::MODULUS_BIT_SIZE as usize)
        .map(|i| Boolean::new_witness(cs.clone(), || Ok(native.get(i).copied().unwrap_or(false))))
        .collect::<Result<Vec<_>, _>>()?;
    let modulus = Scalar::MODULUS.to_bits_le();
    let mut less = Boolean::FALSE;
    let mut equal = Boolean::TRUE;
    for i in (0..bits.len()).rev() {
        if modulus.get(i).copied().unwrap_or(false) {
            less = less.or(&equal.and(&bits[i].not())?)?;
        }
        equal = equal
            .and(&bits[i].is_eq(&Boolean::constant(modulus.get(i).copied().unwrap_or(false)))?)?;
    }
    less.enforce_equal(&Boolean::TRUE)?;
    Ok(bits)
}
fn enforce_nonidentity_and_subgroup(p: &EdwardsVar) -> Result<(), SynthesisError> {
    p.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    let modulus = Scalar::MODULUS.to_bits_le();
    let bits = modulus
        .iter()
        .map(|b| Boolean::constant(*b))
        .collect::<Vec<_>>();
    p.scalar_mul_le(bits.iter())?
        .is_zero()?
        .enforce_equal(&Boolean::TRUE)
}
pub fn enforce_valid_allocated_if(
    enabled: &Boolean<Base>,
    point: &EdwardsVar,
) -> Result<(), SynthesisError> {
    let a = ark_ed_on_bls12_381::EdwardsConfig::COEFF_A;
    let d = ark_ed_on_bls12_381::EdwardsConfig::COEFF_D;
    let x2 = point.x.square()?;
    let y2 = point.y.square()?;
    let equation = &x2 * a + &y2 - Base::one() - (x2 * y2) * d;
    enabled
        .and(&equation.is_zero()?.not())?
        .enforce_equal(&Boolean::FALSE)?;
    point.is_zero()?.not().enforce_equal(enabled)?;
    let modulus = Scalar::MODULUS
        .to_bits_le()
        .into_iter()
        .map(Boolean::constant)
        .collect::<Vec<_>>();
    enabled
        .and(&point.scalar_mul_le(modulus.iter())?.is_zero()?.not())?
        .enforce_equal(&Boolean::FALSE)
}

pub fn verify_var(
    cs: ConstraintSystemRef<Base>,
    pk: EdwardsAffine,
    message: FpVar<Base>,
    sig: Signature,
) -> Result<(), SynthesisError> {
    let pkv = EdwardsVar::new_witness(cs.clone(), || Ok(pk.into_group()))?;
    let rv = EdwardsVar::new_witness(cs.clone(), || Ok(sig.r.into_group()))?;
    enforce_nonidentity_and_subgroup(&pkv)?;
    enforce_nonidentity_and_subgroup(&rv)?;
    let digest = hash_var(
        Domain::SignatureChallenge,
        &[
            rv.x.clone(),
            rv.y.clone(),
            pkv.x.clone(),
            pkv.y.clone(),
            message,
        ],
    )?;
    let digest_bits = digest.to_bits_le()?;
    let c_bits = &digest_bits[..CHALLENGE_BITS];
    let s_bits = scalar_bits(cs, sig.s)?;
    Boolean::kary_or(&s_bits)?.enforce_equal(&Boolean::TRUE)?;
    let generator = EdwardsVar::constant(EdwardsProjective::generator());
    let lhs = generator.scalar_mul_le(s_bits.iter())?;
    let rhs = rv + pkv.scalar_mul_le(c_bits.iter())?;
    lhs.enforce_equal(&rhs)
}

pub fn verify_var_if(
    cs: ConstraintSystemRef<Base>,
    enabled: &Boolean<Base>,
    pk: EdwardsAffine,
    message: FpVar<Base>,
    sig: Signature,
) -> Result<(), SynthesisError> {
    let pkv = EdwardsVar::new_witness(cs.clone(), || Ok(pk.into_group()))?;
    let rv = EdwardsVar::new_witness(cs.clone(), || Ok(sig.r.into_group()))?;
    let pk_bad = pkv.is_zero()?.not();
    pk_bad.enforce_equal(enabled)?;
    let r_nonzero = rv.is_zero()?.not();
    r_nonzero.enforce_equal(enabled)?;
    let modulus = Scalar::MODULUS
        .to_bits_le()
        .into_iter()
        .map(Boolean::constant)
        .collect::<Vec<_>>();
    let pk_subgroup = pkv.scalar_mul_le(modulus.iter())?.is_zero()?;
    let r_subgroup = rv.scalar_mul_le(modulus.iter())?.is_zero()?;
    enabled
        .and(&pk_subgroup.not())?
        .enforce_equal(&Boolean::FALSE)?;
    enabled
        .and(&r_subgroup.not())?
        .enforce_equal(&Boolean::FALSE)?;
    let digest = hash_var(
        Domain::SignatureChallenge,
        &[
            rv.x.clone(),
            rv.y.clone(),
            pkv.x.clone(),
            pkv.y.clone(),
            message,
        ],
    )?;
    let db = digest.to_bits_le()?;
    let sb = scalar_bits(cs, sig.s)?;
    let s_nonzero = Boolean::kary_or(&sb)?;
    s_nonzero.enforce_equal(enabled)?;
    let generator = EdwardsVar::constant(EdwardsProjective::generator());
    let lhs = generator.scalar_mul_le(sb.iter())?;
    let rhs = rv + pkv.scalar_mul_le(db[..CHALLENGE_BITS].iter())?;
    enabled
        .and(&lhs.is_eq(&rhs)?.not())?
        .enforce_equal(&Boolean::FALSE)
}

/// Verify using point coordinates already allocated by the caller. This is the
/// entry point used by the joint circuit so the signed issuer is exactly the
/// issuer committed by the grant hash.
pub fn verify_allocated_if(
    cs: ConstraintSystemRef<Base>,
    enabled: &Boolean<Base>,
    pkv: &EdwardsVar,
    message: FpVar<Base>,
    rv: &EdwardsVar,
    response: Scalar,
) -> Result<(), SynthesisError> {
    for point in [pkv, rv] {
        enforce_valid_allocated_if(enabled, point)?;
    }
    let digest = hash_var(
        Domain::SignatureChallenge,
        &[
            rv.x.clone(),
            rv.y.clone(),
            pkv.x.clone(),
            pkv.y.clone(),
            message,
        ],
    )?;
    let db = digest.to_bits_le()?;
    let sb = scalar_bits(cs, response)?;
    Boolean::kary_or(&sb)?.enforce_equal(enabled)?;
    let lhs = EdwardsVar::constant(EdwardsProjective::generator()).scalar_mul_le(sb.iter())?;
    let rhs = rv.clone() + pkv.scalar_mul_le(db[..CHALLENGE_BITS].iter())?;
    enabled
        .and(&lhs.is_eq(&rhs)?.not())?
        .enforce_equal(&Boolean::FALSE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    #[test]
    fn native_and_circuit_accept_and_reject() {
        let sk = SecretKey(Scalar::from(7u64));
        let pk = public_key(&sk).unwrap();
        let msg = Base::from(99u64);
        let sig = sign(&sk, msg, [42u8; 32]).unwrap();
        assert!(verify(&pk, msg, &sig));
        assert!(!verify(&pk, Base::from(100u64), &sig));
        let cs = ConstraintSystem::new_ref();
        let mv = FpVar::new_witness(cs.clone(), || Ok(msg)).unwrap();
        verify_var(cs.clone(), pk.0, mv, sig).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
    #[test]
    fn identity_and_trailing_encodings_rejected() {
        assert!(decode_public_key(&[0u8; 32]).is_err());
        let sk = SecretKey(Scalar::from(9u64));
        let sig = sign(&sk, Base::from(1u64), [1u8; 32]).unwrap();
        let mut enc = encode_signature(&sig);
        enc.push(0);
        assert!(decode_signature(&enc).is_err());
    }
    #[test]
    fn nonce_rejection_sampling_uses_full_scalar_range() {
        let sk = SecretKey(Scalar::from(17u64));
        let msg = Base::from(123u64);
        let a = sign(&sk, msg, [9u8; 32]).unwrap();
        let b = sign(&sk, msg, [9u8; 32]).unwrap();
        assert_eq!(a, b);
        let mut saw_high = false;
        for byte in 0u8..=255 {
            for counter in 0..64 {
                if let Some(n) = signing_nonce(&sk, msg, [byte; 32], counter) {
                    assert!(!n.is_zero());
                    let bits = n.into_bigint().to_bits_le();
                    saw_high |= bits.get(CHALLENGE_BITS).copied().unwrap_or(false);
                    break;
                }
            }
            if saw_high {
                break;
            }
        }
        assert!(
            saw_high,
            "nonce sampler must not truncate to challenge width"
        );
    }
}
