use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use joint_backend_matched::{
    core_public_inputs, membership_public_inputs, prove_linked, setup_linked, split_from_joint,
    verify_linked, verify_linked_inputs, LinkedProof,
};
use plan_a_joint_circuit::fixture::{fixed, public_inputs};

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
fn split_union_is_satisfied_and_fixed_shape() {
    let one = fixed::<3>(1, 11, 20, 20, 32);
    let three = fixed::<3>(3, 33, 20, 20, 32);
    let (core_one, member_one) = split_from_joint(&one);
    let (core_three, member_three) = split_from_joint(&three);
    same_shape(&matrices(core_one), &matrices(core_three));
    same_shape(&matrices(member_one), &matrices(member_three));
    assert_eq!(core_public_inputs(&one), public_inputs(&one));
    assert_eq!(
        membership_public_inputs(&one),
        vec![one.snapshot.root_state]
    );
}

#[test]
fn one_crs_handles_all_enabled_lengths_and_rejects_splicing() {
    let setup_fixture = fixed::<3>(3, 0, 20, 20, 32);
    let mut rng = StdRng::seed_from_u64(0x4538_4d41_5443_4845);
    let linked = setup_linked(&setup_fixture, &mut rng).unwrap();
    let (inline_pk, inline_vk) =
        Groth16::<Bls12_381>::setup(setup_fixture.clone(), &mut rng).unwrap();

    let mut linked_proofs = Vec::new();
    for active in 1..=3 {
        let fixture = fixed::<3>(active, 100 + active as u64, 20, 20, 32);
        let inline = Groth16::<Bls12_381>::prove(&inline_pk, fixture.clone(), &mut rng).unwrap();
        assert!(
            Groth16::<Bls12_381>::verify(&inline_vk, &public_inputs(&fixture), &inline).unwrap()
        );
        let proof = prove_linked(&linked, &fixture, &mut rng).unwrap();
        verify_linked(&linked, &fixture, &proof).unwrap();
        linked_proofs.push((fixture, proof));
    }

    let spliced = LinkedProof {
        core: linked_proofs[0].1.core.clone(),
        membership: linked_proofs[1].1.membership.clone(),
    };
    assert!(verify_linked(&linked, &linked_proofs[0].0, &spliced).is_err());

    let core_inputs = core_public_inputs(&linked_proofs[0].0);
    let mut mismatched_root = membership_public_inputs(&linked_proofs[0].0);
    mismatched_root[0] += Fr::from(1u64);
    assert!(
        verify_linked_inputs(&linked, &core_inputs, &mismatched_root, &linked_proofs[0].1,)
            .is_err()
    );
}
