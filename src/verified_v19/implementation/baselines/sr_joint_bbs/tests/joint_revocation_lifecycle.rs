use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use plan_a_joint_circuit::{fixture::public_inputs, joint::grant_digest};
use plan_a_sr_joint_bbs::fixtures::{
    revoke_source_b, source_b_revocation_capability, two_source_same_terminal,
};

#[test]
fn capability_revokes_the_actual_middle_grant_only() {
    let [a0, b0] = two_source_same_terminal();
    let (rk, counter, serial) = source_b_revocation_capability();
    assert_eq!(b0.grants[1].grant.serial, serial);
    let signed_before = b0
        .grants
        .iter()
        .map(|s| (grant_digest(&s.grant), s.grant.signature.clone()))
        .collect::<Vec<_>>();
    let mut rng = StdRng::seed_from_u64(0x5245_564f_4b45);
    let (pk, vk) = Groth16::<Bls12_381>::setup(a0.clone(), &mut rng).unwrap();
    for c in [a0.clone(), b0.clone()] {
        let p = Groth16::<Bls12_381>::prove(&pk, c.clone(), &mut rng).unwrap();
        assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs(&c), &p).unwrap());
    }
    let [a1, b1] = revoke_source_b(a0, b0);
    assert_eq!((rk, counter, serial), source_b_revocation_capability());
    let signed_after = b1
        .grants
        .iter()
        .map(|s| (grant_digest(&s.grant), s.grant.signature.clone()))
        .collect::<Vec<_>>();
    assert_eq!(signed_before, signed_after);
    let cs = ConstraintSystem::new_ref();
    b1.clone().generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
    let proof = Groth16::<Bls12_381>::prove(&pk, a1.clone(), &mut rng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs(&a1), &proof).unwrap());
}
