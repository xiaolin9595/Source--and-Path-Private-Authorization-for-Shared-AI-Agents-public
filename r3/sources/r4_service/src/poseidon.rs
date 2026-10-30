//! Versioned original Poseidon over BLS12-381 Fr.
use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    },
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ff::{BigInteger, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::SynthesisError;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s256, Digest};
use std::sync::OnceLock;

pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 57;
pub const ALPHA: u64 = 5;
pub const RATE: usize = 2;
pub const CAPACITY: usize = 1;

/// Tags are protocol constants, not caller-selected labels.
#[repr(u64)]
#[derive(Clone, Copy, Debug)]
pub enum Domain {
    Grant = 0x5041_0001,
    RaLeaf = 0x5041_0002,
    StateLeaf = 0x5041_0003,
    TreeNode = 0x5041_0004,
    RevLeaf = 0x5041_0005,
    RevNode = 0x5041_0006,
    Request = 0x5041_0007,
    SignatureChallenge = 0x5041_0008,
    SignatureNonce = 0x5041_0009,
    Owner = 0x5041_000a,
    Snapshot = 0x5041_000b,
    Terminal = 0x5041_000c,
    RevocationSerial = 0x5041_000d,
    GrantLeaf = 0x5041_000e,
    StateUpdate = 0x5041_000f,
    BlindUpdateAuth = 0x5041_0010,
    BlindUpdateIdentity = 0x5041_0011,
}

pub fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            RATE,
            FULL_ROUNDS as u64,
            PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(FULL_ROUNDS, PARTIAL_ROUNDS, ALPHA, mds, ark, RATE, CAPACITY)
    })
}

pub fn descriptor() -> &'static str {
    "plan-a-poseidon-v2|ark-crypto-primitives=0.4|BLS12-381-Fr|t=3|rate=2|capacity=1|alpha=5|RF=8|RP=57|grain-lfsr|skip-matrices=0|absorb=[version,tag,len,inputs]|squeeze=1Fr"
}

pub fn parameter_fingerprint() -> String {
    let mut bytes = Vec::new();
    for row in &config().ark {
        for x in row {
            x.serialize_compressed(&mut bytes).expect("vec");
        }
    }
    for row in &config().mds {
        for x in row {
            x.serialize_compressed(&mut bytes).expect("vec");
        }
    }
    format!("{:x}", Blake2s256::digest(bytes))
}

/// Versioned fixed-length sponge absorbing `[version, domain, length, inputs]`.
pub fn hash(domain: Domain, inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    let header = vec![
        Fr::from(2u64),
        Fr::from(domain as u64),
        Fr::from(inputs.len() as u64),
    ];
    sponge.absorb(&header.as_slice());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn hash_var(domain: Domain, inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let cs = inputs
        .first()
        .map(|x| x.cs())
        .unwrap_or(ark_relations::r1cs::ConstraintSystemRef::None);
    let mut sponge = PoseidonSpongeVar::new(cs, config());
    sponge.absorb(&vec![
        FpVar::constant(Fr::from(2u64)),
        FpVar::constant(Fr::from(domain as u64)),
        FpVar::constant(Fr::from(inputs.len() as u64)),
    ])?;
    sponge.absorb(&inputs.to_vec())?;
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}

pub fn canonical_le_bytes(x: Fr) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = x.into_bigint().to_bytes_le();
    out[..bytes.len()].copy_from_slice(&bytes);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use ark_relations::r1cs::ConstraintSystem;
    #[test]
    fn native_and_gadget_match_all_lengths() {
        for n in 0..=17 {
            let xs: Vec<_> = (0..n).map(|i| Fr::from((i + 1) as u64)).collect();
            let cs = ConstraintSystem::new_ref();
            let vars = xs
                .iter()
                .map(|x| FpVar::new_witness(cs.clone(), || Ok(*x)).unwrap())
                .collect::<Vec<_>>();
            let got = hash_var(Domain::Request, &vars).unwrap();
            got.enforce_equal(&FpVar::constant(hash(Domain::Request, &xs)))
                .unwrap();
            assert!(cs.is_satisfied().unwrap());
        }
    }
    #[test]
    fn domain_and_length_are_bound() {
        assert_ne!(
            hash(Domain::Grant, &[Fr::from(1u64)]),
            hash(Domain::Request, &[Fr::from(1u64)])
        );
        assert_ne!(
            hash(Domain::Grant, &[Fr::from(1u64)]),
            hash(Domain::Grant, &[Fr::from(1u64), Fr::zero()])
        );
    }
}
