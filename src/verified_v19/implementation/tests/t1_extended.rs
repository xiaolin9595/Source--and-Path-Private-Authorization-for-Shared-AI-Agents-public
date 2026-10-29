use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as Scalar};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar};
use ark_relations::r1cs::ConstraintSystem;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use plan_a_joint_circuit::{
    poseidon::{hash, hash_var, Domain},
    signature::{
        decode_public_key, decode_signature, encode_signature, public_key, sign, verify,
        verify_var, PublicKey, SecretKey, Signature,
    },
};

const DOMAINS: [Domain; 13] = [
    Domain::Grant,
    Domain::RaLeaf,
    Domain::StateLeaf,
    Domain::TreeNode,
    Domain::RevLeaf,
    Domain::RevNode,
    Domain::Request,
    Domain::SignatureChallenge,
    Domain::SignatureNonce,
    Domain::Owner,
    Domain::Snapshot,
    Domain::Terminal,
    Domain::RevocationSerial,
];

#[test]
fn poseidon_ten_thousand_random_native_gadget_pairs() {
    let mut checked = 0usize;
    for seed in [1u64, 73, 20261023, u32::MAX as u64] {
        let mut rng = StdRng::seed_from_u64(seed);
        for batch in 0..25 {
            let cs = ConstraintSystem::<Fr>::new_ref();
            for offset in 0..100 {
                let index = checked + offset;
                let len = (index + batch) % 24;
                let domain = DOMAINS[(index + seed as usize) % DOMAINS.len()];
                let values = (0..len).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
                let vars = values
                    .iter()
                    .map(|value| FpVar::new_witness(cs.clone(), || Ok(*value)).unwrap())
                    .collect::<Vec<_>>();
                let actual = hash_var(domain, &vars).unwrap();
                actual
                    .enforce_equal(&FpVar::Constant(hash(domain, &values)))
                    .unwrap();
            }
            assert!(cs.is_satisfied().unwrap(), "seed={seed} batch={batch}");
            checked += 100;
        }
    }
    assert_eq!(checked, 10_000);
}

#[test]
fn signature_adversarial_native_and_gadget_consistency() {
    assert!(public_key(&SecretKey(Scalar::zero())).is_err());

    let identity = EdwardsAffine::zero();
    let order_two = EdwardsAffine::new_unchecked(Fr::zero(), -Fr::from(1u64));
    let valid_sk = SecretKey(Scalar::from(17u64));
    let valid_pk = public_key(&valid_sk).unwrap();
    let message = Fr::from(31337u64);
    let valid_sig = sign(&valid_sk, message, [9u8; 32]).unwrap();
    assert!(!verify(&PublicKey(identity), message, &valid_sig));
    assert!(!verify(&PublicKey(order_two), message, &valid_sig));
    assert!(!verify(
        &valid_pk,
        message,
        &Signature {
            r: identity,
            s: valid_sig.s
        }
    ));
    assert!(!verify(
        &valid_pk,
        message,
        &Signature {
            r: order_two,
            s: valid_sig.s
        }
    ));

    let mut identity_bytes = Vec::new();
    identity.serialize_compressed(&mut identity_bytes).unwrap();
    assert!(decode_public_key(&identity_bytes).is_err());
    let mut order_two_bytes = Vec::new();
    order_two
        .serialize_compressed(&mut order_two_bytes)
        .unwrap();
    assert!(decode_public_key(&order_two_bytes).is_err());

    let mut noncanonical = Vec::new();
    valid_sig.r.serialize_compressed(&mut noncanonical).unwrap();
    let mut modulus = Scalar::MODULUS.to_bytes_le();
    modulus.resize(32, 0);
    noncanonical.extend_from_slice(&modulus);
    assert!(decode_signature(&noncanonical).is_err());
    let mut trailing = encode_signature(&valid_sig);
    trailing.push(0);
    assert!(decode_signature(&trailing).is_err());

    let mut rng = StdRng::seed_from_u64(0x5349_474e_4154_5552);
    for i in 0..128u64 {
        let sk = SecretKey(Scalar::rand(&mut rng));
        if sk.0.is_zero() {
            continue;
        }
        let pk = public_key(&sk).unwrap();
        let msg = Fr::rand(&mut rng);
        let sig = sign(&sk, msg, [i as u8; 32]).unwrap();
        assert!(verify(&pk, msg, &sig));
        let wrong = msg + Fr::from(1u64);
        assert!(!verify(&pk, wrong, &sig));

        let good_cs = ConstraintSystem::<Fr>::new_ref();
        let good_msg = FpVar::new_witness(good_cs.clone(), || Ok(msg)).unwrap();
        verify_var(good_cs.clone(), pk.0, good_msg, sig.clone()).unwrap();
        assert!(good_cs.is_satisfied().unwrap());

        let bad_cs = ConstraintSystem::<Fr>::new_ref();
        let bad_msg = FpVar::new_witness(bad_cs.clone(), || Ok(wrong)).unwrap();
        verify_var(bad_cs.clone(), pk.0, bad_msg, sig).unwrap();
        assert!(!bad_cs.is_satisfied().unwrap());
    }
}
