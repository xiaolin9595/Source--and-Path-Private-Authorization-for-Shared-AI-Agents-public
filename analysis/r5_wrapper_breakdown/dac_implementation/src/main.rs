use ark_bls12_377::{Bls12_377, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_bw6_761::BW6_761;
use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::SNARK;
use ark_std::{
    rand::{rngs::StdRng, Rng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use delegatable_credentials::{
    msbm::{
        issuance::Credential,
        keys::{
            PreparedRootIssuerPublicKey, RootIssuerPublicKey, RootIssuerSecretKey, UserPublicKey,
            UserSecretKey,
        },
    },
    set_commitment::{SetCommitmentOpening, SetCommitmentSRS},
};
use plan_a_dac_fixed_wrapper::{
    public_inputs, DeploymentConstants, RootCredentialCircuit, RootCredentialWitness,
};
use serde::Serialize;
use std::time::Instant;

#[derive(Serialize)]
struct GateResult {
    relation: &'static str,
    lower_curve: &'static str,
    wrapper_curve: &'static str,
    nominal_generic_security_target_bits: u32,
    constraints: usize,
    setup_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    accepted: bool,
    mutated_public_attribute_rejected: bool,
    identity_witness_rejected: bool,
    non_subgroup_g2_rejected: bool,
    scope_complete: bool,
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn sample_non_subgroup_g2(rng: &mut StdRng) -> G2Affine {
    loop {
        let x = Fq2::new(Fq::rand(rng), Fq::rand(rng));
        if let Some(point) = G2Affine::get_point_from_x_unchecked(x, rng.gen()) {
            if !point.is_zero() && !point.is_in_correct_subgroup_assuming_on_curve() {
                return point;
            }
        }
    }
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0x4441_4357_5241_5031);
    let public_attribute = 0x504c_414e_u64;
    let max_attributes = 4u32;

    let (srs, _) = SetCommitmentSRS::<Bls12_377>::generate_with_random_trapdoor::<StdRng, Blake2b512>(
        &mut rng,
        max_attributes + 8,
        Some(b"plan-a-dac-wrapper-v1"),
    );
    let issuer_sk = RootIssuerSecretKey::<Bls12_377>::new(&mut rng, max_attributes).unwrap();
    let issuer_pk = RootIssuerPublicKey::new(&issuer_sk, srs.get_P1(), srs.get_P2());
    let holder_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let holder_pk = UserPublicKey::new(&holder_sk, srs.get_P1());

    let (credential, _) = Credential::issue_root(
        &mut rng,
        vec![vec![Fr::from(public_attribute)]],
        &holder_pk,
        Some(3),
        &issuer_sk,
        max_attributes,
        &srs,
    )
    .unwrap();

    // Keep a native verification before constructing the wrapper witness.  It
    // is a diagnostic guard, not a substitute for the circuit constraints.
    credential
        .signature
        .verify(
            &credential.commitments,
            credential.attributes.clone(),
            &credential.openings,
            &holder_pk,
            PreparedRootIssuerPublicKey::from(issuer_pk.clone()),
            &srs,
        )
        .unwrap();

    let opening_randomness = match &credential.openings[0] {
        SetCommitmentOpening::SetWithoutTrapdoor(r) => *r,
        SetCommitmentOpening::SetWithTrapdoor(_, _) => {
            panic!("deterministic fixture unexpectedly hit the SRS trapdoor")
        }
    };
    let circuit = RootCredentialCircuit {
        deployment: DeploymentConstants {
            p1: *srs.get_P1(),
            s_p1: *srs.get_s_P1(),
            p2: *srs.get_P2(),
            issuer_pk,
        },
        public_attribute,
        witness: RootCredentialWitness {
            commitment: credential.commitments[0].clone(),
            opening_randomness,
            signature: credential.signature,
            holder_pk,
        },
    };

    let measurement_cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(measurement_cs.clone())
        .unwrap();
    assert!(measurement_cs.is_satisfied().unwrap());
    let constraints = measurement_cs.num_constraints();

    let mut identity_circuit = circuit.clone();
    identity_circuit.witness.commitment.0 = G1Affine::zero();
    identity_circuit.witness.opening_randomness = Fr::zero();
    identity_circuit.witness.signature.comm_sig.Z = G1Affine::zero();
    identity_circuit.witness.signature.comm_sig.Y = G1Affine::zero();
    identity_circuit.witness.signature.comm_sig.Y_tilde = G2Affine::zero();
    identity_circuit.witness.signature.T = G1Affine::zero();
    identity_circuit.witness.holder_pk.0 = G1Affine::zero();
    let identity_cs = ConstraintSystem::<Fq>::new_ref();
    identity_circuit
        .generate_constraints(identity_cs.clone())
        .unwrap();
    let identity_witness_rejected = !identity_cs.is_satisfied().unwrap();

    let mut non_subgroup_circuit = circuit.clone();
    non_subgroup_circuit.witness.signature.comm_sig.Y_tilde = sample_non_subgroup_g2(&mut rng);
    let non_subgroup_cs = ConstraintSystem::<Fq>::new_ref();
    non_subgroup_circuit
        .generate_constraints(non_subgroup_cs.clone())
        .unwrap();
    let non_subgroup_g2_rejected = !non_subgroup_cs.is_satisfied().unwrap();

    let started = Instant::now();
    let (pk, vk) = Groth16::<BW6_761>::circuit_specific_setup(circuit.clone(), &mut rng).unwrap();
    let setup_ms = elapsed_ms(started);

    let started = Instant::now();
    let proof = Groth16::<BW6_761>::prove(&pk, circuit, &mut rng).unwrap();
    let prove_ms = elapsed_ms(started);

    let started = Instant::now();
    let accepted =
        Groth16::<BW6_761>::verify(&vk, &public_inputs(public_attribute), &proof).unwrap();
    let verify_ms = elapsed_ms(started);
    let mutated_public_attribute_rejected =
        !Groth16::<BW6_761>::verify(&vk, &public_inputs(public_attribute + 1), &proof).unwrap();

    assert!(accepted);
    assert!(mutated_public_attribute_rejected);
    assert!(identity_witness_rejected);
    assert!(non_subgroup_g2_rejected);

    println!(
        "{}",
        serde_json::to_string_pretty(&GateResult {
            relation: "mir_dac_root_signature_and_singleton_commitment_v1",
            lower_curve: "BLS12-377",
            wrapper_curve: "BW6-761 Groth16",
            nominal_generic_security_target_bits: 128,
            constraints,
            setup_ms,
            prove_ms,
            verify_ms,
            accepted,
            mutated_public_attribute_rejected,
            identity_witness_rejected,
            non_subgroup_g2_rejected,
            scope_complete: false,
        })
        .unwrap()
    );
}
