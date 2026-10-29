use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::AllocVar};
use ark_relations::r1cs::ConstraintSystem;
use joint_backend_matched::certified_map::{
    canonical_prime_252, enforce_certificate, generate_prime_252, is_probable_prime_252,
    verify_certificate, AccumulatorTransition, CertifiedStateMap, MappingCertificate, MappingError,
    MappingRecord,
};
use num_bigint::BigUint;
use num_traits::One;
use plan_a_joint_circuit::poseidon::canonical_le_bytes;
use plan_a_joint_circuit::signature::SecretKey;
use std::collections::BTreeSet;

fn record(version: u64, epoch: u64, entropy_tag: u8) -> MappingRecord {
    let mut record = MappingRecord {
        deployment_id: Fr::from(9u64),
        owner_commitment: Fr::from(10u64),
        state_leaf: Fr::from(11u64 + version),
        position: 3,
        state_version: version,
        state_epoch: epoch,
        prime: Fr::from(0u64),
        mapping_version: 1,
    };
    record.prime = generate_prime_252(&record, [entropy_tag; 32]).unwrap();
    record
}

#[derive(Default)]
struct TestAccumulator {
    members: BTreeSet<[u8; 32]>,
    fail_transition: bool,
}

impl TestAccumulator {
    fn admit(&mut self, prime: Fr) {
        assert!(self.members.insert(canonical_le_bytes(prime)));
    }

    fn contains(&self, prime: Fr) -> bool {
        self.members.contains(&canonical_le_bytes(prime))
    }
}

impl AccumulatorTransition for TestAccumulator {
    fn replace_and_confirm(&mut self, old_prime: Fr, next_prime: Fr) -> bool {
        if self.fail_transition {
            return false;
        }
        let old = canonical_le_bytes(old_prime);
        let next = canonical_le_bytes(next_prime);
        if !self.members.remove(&old) || self.members.contains(&next) {
            self.members.insert(old);
            return false;
        }
        self.members.insert(next);
        !self.members.contains(&old) && self.members.contains(&next)
    }
}

#[test]
fn issue_replace_and_replay_rules() {
    let mut map = CertifiedStateMap::new(SecretKey(Scalar::from(900u64))).unwrap();
    let old = record(1, 10, 17);
    let old_certificate = map.issue(old.clone(), [1u8; 32]).unwrap();
    let mut accumulator = TestAccumulator::default();
    accumulator.admit(old.prime);
    assert!(verify_certificate(&map.public_key, &old_certificate));
    assert!(map.is_live(&old_certificate));
    assert_eq!(
        map.issue(old.clone(), [2u8; 32]),
        Err(MappingError::DuplicateGeneration)
    );

    let next = record(2, 11, 19);
    let next_certificate = map
        .replace_with_accumulator(&old, next.clone(), [3u8; 32], &mut accumulator)
        .unwrap();
    assert!(!accumulator.contains(old.prime));
    assert!(accumulator.contains(next.prime));
    assert!(!map.is_live(&old_certificate));
    assert!(map.is_live(&next_certificate));
    assert!(verify_certificate(&map.public_key, &next_certificate));
    assert_eq!(
        map.issue(old, [4u8; 32]),
        Err(MappingError::DuplicateGeneration)
    );
    let reused_retired_prime = MappingRecord {
        owner_commitment: Fr::from(55u64),
        position: 8,
        prime: old_certificate.record.prime,
        ..record(1, 12, 29)
    };
    assert_eq!(
        map.issue(reused_retired_prime, [9u8; 32]),
        Err(MappingError::DuplicatePrime)
    );
}

#[test]
fn native_issuer_generation_is_generation_bound_and_verifiable() {
    let mut map = CertifiedStateMap::new(SecretKey(Scalar::from(905u64))).unwrap();
    let mut template = record(4, 14, 53);
    template.prime = Fr::from(0u64);
    let certificate = map
        .generate_and_issue(template, [54u8; 32], [55u8; 32])
        .unwrap();
    assert!(canonical_prime_252(certificate.record.prime));
    assert!(is_probable_prime_252(certificate.record.prime));
    assert!(verify_certificate(&map.public_key, &certificate));
}

#[test]
fn duplicate_prime_and_nonadvancing_replacement_fail_closed() {
    let mut map = CertifiedStateMap::new(SecretKey(Scalar::from(901u64))).unwrap();
    let old = record(1, 10, 21);
    map.issue(old.clone(), [5u8; 32]).unwrap();
    let duplicate = MappingRecord {
        owner_commitment: Fr::from(99u64),
        position: 7,
        prime: old.prime,
        ..record(1, 10, 31)
    };
    assert_eq!(
        map.issue(duplicate, [6u8; 32]),
        Err(MappingError::DuplicatePrime)
    );
    let mut accumulator = TestAccumulator::default();
    accumulator.admit(old.prime);
    assert_eq!(
        map.replace_with_accumulator(&old, record(1, 11, 23), [7u8; 32], &mut accumulator),
        Err(MappingError::InvalidReplacement)
    );

    let mut distinct_deployment = record(1, 10, 37);
    distinct_deployment.deployment_id = Fr::from(77u64);
    assert!(map.issue(distinct_deployment, [12u8; 32]).is_ok());
}

#[test]
fn primality_is_native_and_range_is_not_enough() {
    let composite = ((BigUint::one() << 126usize) + BigUint::one())
        * ((BigUint::one() << 125usize) + BigUint::one());
    let candidate = Fr::from_le_bytes_mod_order(&composite.to_bytes_le());
    assert!(canonical_prime_252(candidate));
    assert!(!is_probable_prime_252(candidate));
    let mut map = CertifiedStateMap::new(SecretKey(Scalar::from(903u64))).unwrap();
    let mut invalid = record(1, 10, 41);
    invalid.prime = candidate;
    assert_eq!(
        map.issue(invalid, [9u8; 32]),
        Err(MappingError::PrimeEncoding)
    );
}

#[test]
fn failed_accumulator_removal_does_not_retire_mapping() {
    let mut map = CertifiedStateMap::new(SecretKey(Scalar::from(904u64))).unwrap();
    let old = record(1, 10, 43);
    let old_certificate = map.issue(old.clone(), [10u8; 32]).unwrap();
    let next = record(2, 11, 47);
    let mut accumulator = TestAccumulator {
        fail_transition: true,
        ..Default::default()
    };
    accumulator.admit(old.prime);
    assert_eq!(
        map.replace_with_accumulator(&old, next.clone(), [11u8; 32], &mut accumulator),
        Err(MappingError::AccumulatorTransition)
    );
    assert!(map.is_live(&old_certificate));
    assert!(accumulator.contains(old.prime));
    assert!(!accumulator.contains(next.prime));
}

fn certificate_circuit_satisfied(
    certificate: &MappingCertificate,
    map: &CertifiedStateMap,
    leaf_override: Option<Fr>,
) -> bool {
    let cs = ConstraintSystem::new_ref();
    let pk_x = FpVar::new_input(cs.clone(), || Ok(map.public_key.0.x)).unwrap();
    let pk_y = FpVar::new_input(cs.clone(), || Ok(map.public_key.0.y)).unwrap();
    let r = &certificate.record;
    let values = [
        r.deployment_id,
        r.owner_commitment,
        leaf_override.unwrap_or(r.state_leaf),
        Fr::from(r.position),
        Fr::from(r.state_version),
        Fr::from(r.state_epoch),
        r.prime,
        Fr::from(r.mapping_version),
    ];
    let variables = values.map(|value| FpVar::new_witness(cs.clone(), || Ok(value)).unwrap());
    enforce_certificate(
        cs.clone(),
        (&pk_x, &pk_y),
        [
            &variables[0],
            &variables[1],
            &variables[2],
            &variables[3],
            &variables[4],
            &variables[5],
            &variables[6],
            &variables[7],
        ],
        &certificate.signature,
    )
    .unwrap();
    cs.is_satisfied().unwrap()
}

#[test]
fn certificate_gadget_binds_the_typed_record() {
    let mut map = CertifiedStateMap::new(SecretKey(Scalar::from(902u64))).unwrap();
    let certificate = map.issue(record(1, 10, 25), [8u8; 32]).unwrap();
    assert!(certificate_circuit_satisfied(&certificate, &map, None));
    assert!(!certificate_circuit_satisfied(
        &certificate,
        &map,
        Some(certificate.record.state_leaf + Fr::from(1u64)),
    ));
}
