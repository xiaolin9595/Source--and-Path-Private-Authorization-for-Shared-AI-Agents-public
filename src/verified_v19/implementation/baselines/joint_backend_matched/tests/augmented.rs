use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use joint_backend_matched::{
    augmented_core_public_inputs, augmented_membership_public_inputs,
    certified_map::{CertifiedStateMap, MappingCertificate, MappingRecord},
    inline_augmented_from_joint, prove_augmented, setup_augmented, split_augmented_from_joint,
    state_leaf, verify_augmented, verify_augmented_with_inputs, AugmentedLinkedProof,
};
use plan_a_joint_circuit::{
    fixture::fixed,
    joint::JointCircuit,
    signature::{PublicKey, SecretKey},
};

fn mapping_for<const L: usize>(
    joint: &JointCircuit<L>,
    entropy_tag: u8,
) -> (MappingCertificate, PublicKey) {
    let mut issuer = CertifiedStateMap::new(SecretKey(Scalar::from(0x4538u64))).unwrap();
    let template = MappingRecord {
        deployment_id: Fr::from(0x4538_0001u64),
        owner_commitment: joint.state.owner_commitment,
        state_leaf: state_leaf(&joint.state),
        position: joint.state.position,
        state_version: joint.state.state_version,
        state_epoch: joint.state.state_epoch,
        prime: Fr::from(0u64),
        mapping_version: 1,
    };
    let certificate = issuer
        .generate_and_issue(
            template,
            [entropy_tag; 32],
            [entropy_tag.wrapping_add(1); 32],
        )
        .unwrap();
    (certificate, issuer.public_key)
}

fn matrices<C: ConstraintSynthesizer<Fr>>(circuit: C) -> ConstraintMatrices<Fr> {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    cs.finalize();
    cs.to_matrices().unwrap()
}

fn same_shape(a: &ConstraintMatrices<Fr>, b: &ConstraintMatrices<Fr>) {
    assert_eq!(a.num_instance_variables, b.num_instance_variables);
    assert_eq!(a.num_witness_variables, b.num_witness_variables);
    assert_eq!(a.num_constraints, b.num_constraints);
    assert_eq!(a.a, b.a);
    assert_eq!(a.b, b.b);
    assert_eq!(a.c, b.c);
}

#[test]
fn augmented_relation_is_fixed_shape_and_binds_the_mapping_record() {
    let one = fixed::<3>(1, 41, 20, 20, 32);
    let three = fixed::<3>(3, 43, 20, 20, 32);
    let (mapping, mapping_pk) = mapping_for(&one, 61);
    let (core_one, membership_one) = split_augmented_from_joint(&one, &mapping, &mapping_pk);
    let (core_three, membership_three) = split_augmented_from_joint(&three, &mapping, &mapping_pk);
    same_shape(&matrices(core_one), &matrices(core_three));
    same_shape(&matrices(membership_one), &matrices(membership_three));

    let inline = inline_augmented_from_joint(&one, &mapping, &mapping_pk);
    let cs = ConstraintSystem::new_ref();
    inline.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());

    let mut wrong_leaf = mapping.clone();
    wrong_leaf.record.state_leaf += Fr::from(1u64);
    let invalid = inline_augmented_from_joint(&one, &wrong_leaf, &mapping_pk);
    let cs = ConstraintSystem::new_ref();
    invalid.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());

    let mut wrong_owner = mapping.clone();
    wrong_owner.record.owner_commitment += Fr::from(1u64);
    let invalid = inline_augmented_from_joint(&one, &wrong_owner, &mapping_pk);
    let cs = ConstraintSystem::new_ref();
    invalid.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());

    let mut wrong_position = mapping.clone();
    wrong_position.record.position ^= 1;
    let invalid = inline_augmented_from_joint(&one, &wrong_position, &mapping_pk);
    let cs = ConstraintSystem::new_ref();
    invalid.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());

    // Even an otherwise valid certificate from the configured key cannot
    // move the same typed state leaf to a different circuit position.
    let mut wrong_position_issuer =
        CertifiedStateMap::new(SecretKey(Scalar::from(0x4538u64))).unwrap();
    let mut wrong_position_record = mapping.record.clone();
    wrong_position_record.position ^= 1;
    wrong_position_record.prime = Fr::from(0u64);
    let signed_wrong_position = wrong_position_issuer
        .generate_and_issue(wrong_position_record, [73; 32], [74; 32])
        .unwrap();
    let invalid = inline_augmented_from_joint(
        &one,
        &signed_wrong_position,
        &wrong_position_issuer.public_key,
    );
    let cs = ConstraintSystem::new_ref();
    invalid.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());

    let mut wrong_prime = mapping.clone();
    wrong_prime.record.prime += Fr::from(2u64);
    let invalid = inline_augmented_from_joint(&one, &wrong_prime, &mapping_pk);
    let cs = ConstraintSystem::new_ref();
    invalid.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
}

#[test]
fn augmented_inline_and_poseidon_split_verify_and_reject_splicing() {
    let setup_fixture = fixed::<3>(3, 47, 20, 20, 32);
    let (mapping, mapping_pk) = mapping_for(&setup_fixture, 67);
    let mut rng = StdRng::seed_from_u64(0x4538_4155_474d_454e);

    let linked = setup_augmented(&setup_fixture, &mapping, &mapping_pk, &mut rng).unwrap();
    let inline_setup = inline_augmented_from_joint(&setup_fixture, &mapping, &mapping_pk);
    let (inline_pk, inline_vk) = Groth16::<Bls12_381>::setup(inline_setup, &mut rng).unwrap();

    let inline = Groth16::<Bls12_381>::prove(
        &inline_pk,
        inline_augmented_from_joint(&setup_fixture, &mapping, &mapping_pk),
        &mut rng,
    )
    .unwrap();
    let core_inputs = augmented_core_public_inputs(&setup_fixture, &mapping, &mapping_pk);
    assert!(Groth16::<Bls12_381>::verify(&inline_vk, &core_inputs, &inline).unwrap());

    let first = prove_augmented(&linked, &setup_fixture, &mapping, &mapping_pk, &mut rng).unwrap();
    verify_augmented(&linked, &setup_fixture, &mapping, &mapping_pk, &first).unwrap();
    let second = prove_augmented(&linked, &setup_fixture, &mapping, &mapping_pk, &mut rng).unwrap();
    verify_augmented(&linked, &setup_fixture, &mapping, &mapping_pk, &second).unwrap();

    let spliced = AugmentedLinkedProof {
        core: first.core.clone(),
        membership: second.membership.clone(),
    };
    assert!(verify_augmented(&linked, &setup_fixture, &mapping, &mapping_pk, &spliced).is_err());

    let mut wrong_root = augmented_membership_public_inputs(&setup_fixture);
    wrong_root[0] += Fr::from(1u64);
    assert!(verify_augmented_with_inputs(&linked, &core_inputs, &wrong_root, &first).is_err());

    let mut wrong_deployment = core_inputs.clone();
    wrong_deployment[23] += Fr::from(1u64);
    assert!(verify_augmented_with_inputs(
        &linked,
        &wrong_deployment,
        &augmented_membership_public_inputs(&setup_fixture),
        &first,
    )
    .is_err());
}
