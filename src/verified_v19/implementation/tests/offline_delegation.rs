use ark_bls12_381::Bls12_381;
use ark_groth16::Groth16;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use plan_a_joint_circuit::{
    fixture::{offline_child_to_new_terminal, public_inputs},
    joint::{grant_digest, snapshot_digest},
};

#[test]
fn unchanged_snapshot_accepts_offline_child_to_new_terminal() {
    let (initial, child) = offline_child_to_new_terminal();
    assert_eq!(
        snapshot_digest(&initial.snapshot),
        snapshot_digest(&child.snapshot)
    );
    assert_eq!(
        grant_digest(&initial.grants[0].grant),
        grant_digest(&child.grants[0].grant)
    );
    assert_eq!(
        initial.grants[0].grant.signature,
        child.grants[0].grant.signature
    );
    assert_ne!(initial.request.terminal, child.request.terminal);
    let mut rng = StdRng::seed_from_u64(0x0ff1_1e);
    let (pk, vk) = Groth16::<Bls12_381>::setup(initial.clone(), &mut rng).unwrap();
    for circuit in [initial, child] {
        let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng).unwrap();
        assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs(&circuit), &proof).unwrap());
    }
}
