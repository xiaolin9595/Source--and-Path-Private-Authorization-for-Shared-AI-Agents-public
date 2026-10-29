use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as Scalar};
use ark_ff::{PrimeField, Zero};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use plan_a_joint_circuit::{
    blind_update::{
        authorization_digest, public_inputs, state_leaf, BlindUpdateCircuit, BlindUpdateStatement,
        StateOpening,
    },
    blind_update_sr::{
        proof_sha256_limbs, Admission, BlindStateRecord, BlindStateRegistry, BlindUpdateError,
        BlindUpdateRequest,
    },
    signature::{public_key, sign, PublicKey, SecretKey},
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{sync::Arc, thread};

fn test_identity(tag: &[u8]) -> Fr {
    let mut digest = Sha256::new();
    digest.update(b"plan-a-r3-test-identity-v1");
    digest.update([0]);
    digest.update(tag);
    Fr::from_be_bytes_mod_order(&digest.finalize())
}

fn fixture() -> (BlindUpdateCircuit, SecretKey) {
    let sk = SecretKey(Scalar::from(17u64));
    let old = StateOpening {
        grant_root: Fr::from(100u64),
        expiry: 800,
        active: true,
        salt: Fr::from(101u64),
    };
    let new = StateOpening {
        grant_root: Fr::from(200u64),
        expiry: 900,
        active: true,
        salt: Fr::from(201u64),
    };
    let mut statement = BlindUpdateStatement {
        config_digest: test_identity(b"config"),
        deployment: test_identity(b"deployment"),
        circuit_id: test_identity(b"circuit"),
        owner: Fr::from(4u64),
        position: 5,
        expiry_cap: 1_000,
        admission_version: 7,
        old_leaf: Fr::zero(),
        new_leaf: Fr::zero(),
        old_version: 8,
        new_version: 9,
        old_epoch: 10,
        new_epoch: 11,
    };
    statement.old_leaf = state_leaf(
        statement.owner,
        statement.old_version,
        statement.old_epoch,
        statement.position,
        &old,
    );
    statement.new_leaf = state_leaf(
        statement.owner,
        statement.new_version,
        statement.new_epoch,
        statement.position,
        &new,
    );
    (
        BlindUpdateCircuit {
            statement,
            old,
            new,
        },
        sk,
    )
}

fn satisfied(circuit: BlindUpdateCircuit) -> bool {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.is_satisfied().unwrap()
}

#[test]
fn relation_accepts_root_replacement_and_deactivation() {
    let (circuit, _) = fixture();
    assert!(satisfied(circuit.clone()));
    let mut stopped = circuit;
    stopped.new.active = false;
    stopped.statement.new_leaf = state_leaf(
        stopped.statement.owner,
        stopped.statement.new_version,
        stopped.statement.new_epoch,
        stopped.statement.position,
        &stopped.new,
    );
    assert!(satisfied(stopped));
}

#[test]
fn relation_rejects_all_transition_invariant_breaks() {
    let (base, _) = fixture();
    let mut cases = Vec::new();

    let mut wrong_owner = base.clone();
    wrong_owner.statement.owner += Fr::from(1u64);
    cases.push(wrong_owner);
    let mut wrong_position = base.clone();
    wrong_position.statement.position += 1;
    cases.push(wrong_position);
    let mut wrong_old_leaf = base.clone();
    wrong_old_leaf.statement.old_leaf += Fr::from(1u64);
    cases.push(wrong_old_leaf);
    let mut overflow = base.clone();
    overflow.statement.old_version = u64::MAX;
    overflow.statement.new_version = 0;
    overflow.statement.old_leaf = state_leaf(
        overflow.statement.owner,
        overflow.statement.old_version,
        overflow.statement.old_epoch,
        overflow.statement.position,
        &overflow.old,
    );
    overflow.statement.new_leaf = state_leaf(
        overflow.statement.owner,
        overflow.statement.new_version,
        overflow.statement.new_epoch,
        overflow.statement.position,
        &overflow.new,
    );
    cases.push(overflow);
    let mut epoch_equal = base.clone();
    epoch_equal.statement.new_epoch = epoch_equal.statement.old_epoch;
    epoch_equal.statement.new_leaf = state_leaf(
        epoch_equal.statement.owner,
        epoch_equal.statement.new_version,
        epoch_equal.statement.new_epoch,
        epoch_equal.statement.position,
        &epoch_equal.new,
    );
    cases.push(epoch_equal);
    let mut expiry = base.clone();
    expiry.new.expiry = expiry.statement.expiry_cap + 1;
    expiry.statement.new_leaf = state_leaf(
        expiry.statement.owner,
        expiry.statement.new_version,
        expiry.statement.new_epoch,
        expiry.statement.position,
        &expiry.new,
    );
    cases.push(expiry);
    let mut recovery = base;
    recovery.old.active = false;
    recovery.statement.old_leaf = state_leaf(
        recovery.statement.owner,
        recovery.statement.old_version,
        recovery.statement.old_epoch,
        recovery.statement.position,
        &recovery.old,
    );
    cases.push(recovery);

    for circuit in cases {
        assert!(!satisfied(circuit));
    }
}

#[test]
fn real_proof_signature_admission_and_atomic_cas() {
    let (circuit, sk) = fixture();
    let (pk, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut OsRng).unwrap();
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut OsRng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs(&circuit.statement), &proof).unwrap());
    for mutation in 0..5 {
        let mut changed = circuit.statement.clone();
        match mutation {
            0 => changed.deployment += Fr::from(1u64),
            1 => changed.owner += Fr::from(1u64),
            2 => changed.position += 1,
            3 => changed.expiry_cap += 1,
            _ => changed.admission_version += 1,
        }
        assert!(!Groth16::<Bls12_381>::verify(&vk, &public_inputs(&changed), &proof).unwrap());
    }
    let signature = sign(
        &sk,
        authorization_digest(&circuit.statement, proof_sha256_limbs(&proof).unwrap()),
        [9u8; 32],
    )
    .unwrap();
    let registry = Arc::new(BlindStateRegistry::new(
        circuit.statement.config_digest,
        circuit.statement.deployment,
        circuit.statement.circuit_id,
        vk.clone(),
    ));
    registry
        .enroll(
            Admission {
                deployment: circuit.statement.deployment,
                owner: circuit.statement.owner,
                position: circuit.statement.position,
                owner_public_key: public_key(&sk).unwrap(),
                expiry_cap: circuit.statement.expiry_cap,
                admission_version: circuit.statement.admission_version,
            },
            BlindStateRecord {
                leaf: circuit.statement.old_leaf,
                version: circuit.statement.old_version,
                epoch: circuit.statement.old_epoch,
                active_hint: Some(circuit.old.active),
            },
        )
        .unwrap();
    let request = BlindUpdateRequest {
        statement: circuit.statement.clone(),
        proof,
        owner_signature: signature,
    };

    let wrong_signature = BlindUpdateRequest {
        statement: request.statement.clone(),
        proof: request.proof.clone(),
        owner_signature: sign(&sk, Fr::from(999u64), [8u8; 32]).unwrap(),
    };
    assert_eq!(
        registry.apply(&wrong_signature).unwrap_err(),
        BlindUpdateError::Signature
    );

    let mut other_circuit = circuit.clone();
    other_circuit.statement.new_epoch += 1;
    other_circuit.statement.new_leaf = state_leaf(
        other_circuit.statement.owner,
        other_circuit.statement.new_version,
        other_circuit.statement.new_epoch,
        other_circuit.statement.position,
        &other_circuit.new,
    );
    let wrong_proof = Groth16::<Bls12_381>::prove(&pk, other_circuit, &mut OsRng).unwrap();
    let wrong_proof_request = BlindUpdateRequest {
        statement: request.statement.clone(),
        owner_signature: sign(
            &sk,
            authorization_digest(
                &request.statement,
                proof_sha256_limbs(&wrong_proof).unwrap(),
            ),
            [6u8; 32],
        )
        .unwrap(),
        proof: wrong_proof,
    };
    assert_eq!(
        registry.apply(&wrong_proof_request).unwrap_err(),
        BlindUpdateError::Proof
    );

    let a_registry = Arc::clone(&registry);
    let a_request = request.clone();
    let a = thread::spawn(move || a_registry.apply(&a_request));
    let b_registry = Arc::clone(&registry);
    let b_request = request.clone();
    let b = thread::spawn(move || b_registry.apply(&b_request));
    let results = [a.join().unwrap(), b.join().unwrap()];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(BlindUpdateError::CompareAndSwap)))
            .count(),
        1
    );
    assert_eq!(
        registry.apply(&request).unwrap_err(),
        BlindUpdateError::CompareAndSwap
    );
    let current = registry
        .record(circuit.statement.owner, circuit.statement.position)
        .unwrap();
    assert_eq!(current.leaf, circuit.statement.new_leaf);
    assert_eq!(current.active_hint, None);
}

#[test]
fn service_rejects_wrong_bindings_signature_and_illegal_key() {
    let (circuit, sk) = fixture();
    let (_, vk) = Groth16::<Bls12_381>::setup(circuit.clone(), &mut OsRng).unwrap();
    let registry = BlindStateRegistry::new(
        circuit.statement.config_digest,
        circuit.statement.deployment,
        circuit.statement.circuit_id,
        vk,
    );
    let illegal = Admission {
        deployment: circuit.statement.deployment,
        owner: circuit.statement.owner,
        position: circuit.statement.position,
        owner_public_key: PublicKey(EdwardsAffine::zero()),
        expiry_cap: circuit.statement.expiry_cap,
        admission_version: circuit.statement.admission_version,
    };
    assert_eq!(
        registry
            .enroll(
                illegal,
                BlindStateRecord {
                    leaf: circuit.statement.old_leaf,
                    version: circuit.statement.old_version,
                    epoch: circuit.statement.old_epoch,
                    active_hint: Some(true),
                },
            )
            .unwrap_err(),
        BlindUpdateError::Admission
    );

    // The full transcript is covered directly: any deployment/cap/admission mutation
    // changes the digest, so a signature for the original transition cannot verify.
    let fake_proof = Groth16::<Bls12_381>::prove(
        &Groth16::<Bls12_381>::setup(circuit.clone(), &mut OsRng)
            .unwrap()
            .0,
        circuit.clone(),
        &mut OsRng,
    )
    .unwrap();
    let digest = authorization_digest(&circuit.statement, proof_sha256_limbs(&fake_proof).unwrap());
    let sig = sign(&sk, digest, [3u8; 32]).unwrap();
    for mutate in [0, 1, 2] {
        let mut statement = circuit.statement.clone();
        match mutate {
            0 => statement.deployment += Fr::from(1u64),
            1 => statement.expiry_cap += 1,
            _ => statement.admission_version += 1,
        }
        assert!(!plan_a_joint_circuit::signature::verify(
            &public_key(&sk).unwrap(),
            authorization_digest(&statement, proof_sha256_limbs(&fake_proof).unwrap()),
            &sig,
        ));
    }
}
