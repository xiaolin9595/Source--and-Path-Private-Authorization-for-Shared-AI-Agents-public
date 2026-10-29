use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    blind_update::{
        authorization_digest, public_inputs, state_leaf, BlindUpdateCircuit, BlindUpdateStatement,
        StateOpening,
    },
    blind_update_sr::proof_sha256_limbs,
    poseidon::{canonical_le_bytes, descriptor, parameter_fingerprint},
    signature::{encode_signature, public_key, sign, SecretKey},
};
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf};

fn hex_field(value: Fr) -> String {
    let mut bytes = canonical_le_bytes(value);
    bytes.reverse();
    hex::encode(bytes)
}

fn domain_field(tag: &[u8], payload: &[u8]) -> Fr {
    let mut hash = Sha256::new();
    hash.update(tag);
    hash.update([0]);
    hash.update(payload);
    Fr::from_be_bytes_mod_order(&hash.finalize())
}

fn matrix_sha256(circuit: BlindUpdateCircuit) -> String {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    cs.finalize();
    let matrices = cs.to_matrices().unwrap();
    let mut encoded = Vec::new();
    for matrix in [&matrices.a, &matrices.b, &matrices.c] {
        encoded.extend_from_slice(&(matrix.len() as u64).to_le_bytes());
        for row in matrix {
            encoded.extend_from_slice(&(row.len() as u64).to_le_bytes());
            for (coefficient, index) in row {
                coefficient.serialize_compressed(&mut encoded).unwrap();
                encoded.extend_from_slice(&(*index as u64).to_le_bytes());
            }
        }
    }
    hex::encode(Sha256::digest(encoded))
}

fn main() {
    let output = PathBuf::from(
        env::args()
            .nth(1)
            .expect("usage: blind_update_fixture OUTPUT_DIR"),
    );
    fs::create_dir_all(&output).unwrap();
    let sk = SecretKey(Scalar::from(17u64));
    let owner_pk = public_key(&sk).unwrap();
    let registration_salt = Fr::from(18u64);
    let owner = plan_a_joint_circuit::state_registry::owner_commitment(
        owner_pk.0.x,
        owner_pk.0.y,
        registration_salt,
    );
    let old = StateOpening {
        grant_root: Fr::from(100u64),
        expiry: 800,
        active: true,
        salt: Fr::from(101u64),
    };
    let new = StateOpening {
        grant_root: Fr::from(200u64),
        expiry: 900,
        active: false,
        salt: Fr::from(201u64),
    };
    let config_material = format!(
        "plan-a-r3-blind-update-config-v1|{}|poseidon-fingerprint={}|public-inputs=config,deployment,circuit,owner,position,cap,admission,old-leaf,new-leaf,old-version,new-version,old-epoch,new-epoch,identity-binding|state-leaf=owner,grant-root,version,epoch,expiry,active,salt,position",
        descriptor(), parameter_fingerprint()
    );
    let config_digest = domain_field(b"plan-a-r3-config-v1", config_material.as_bytes());
    let deployment = domain_field(
        b"plan-a-deployment-v1",
        b"r3-functional-gate-isolated-deployment-2026-10-29",
    );
    let mut statement = BlindUpdateStatement {
        config_digest,
        deployment,
        circuit_id: Fr::from(0u64),
        owner,
        position: 5,
        expiry_cap: 1_000,
        admission_version: 0,
        old_leaf: Fr::from(0u64),
        new_leaf: Fr::from(0u64),
        old_version: 8,
        new_version: 9,
        old_epoch: 10,
        new_epoch: 11,
    };
    statement.old_leaf = state_leaf(
        owner,
        statement.old_version,
        statement.old_epoch,
        statement.position,
        &old,
    );
    statement.new_leaf = state_leaf(
        owner,
        statement.new_version,
        statement.new_epoch,
        statement.position,
        &new,
    );
    let setup_circuit = BlindUpdateCircuit {
        statement: statement.clone(),
        old: old.clone(),
        new: new.clone(),
    };
    let cs = ConstraintSystem::new_ref();
    setup_circuit.clone().generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap());
    let constraints = cs.num_constraints();
    let matrix_sha256 = matrix_sha256(setup_circuit.clone());
    let (pk, vk) = Groth16::<Bls12_381>::setup(setup_circuit, &mut OsRng).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    let vk_sha256 = hex::encode(Sha256::digest(&vk_bytes));
    let circuit_material = format!(
        "plan-a-r3-blind-update-relation-v1|matrix-sha256={matrix_sha256}|vk-sha256={vk_sha256}"
    );
    statement.circuit_id = domain_field(b"plan-a-r3-circuit-v1", circuit_material.as_bytes());
    let circuit = BlindUpdateCircuit { statement: statement.clone(), old, new };
    let proof = Groth16::<Bls12_381>::prove(&pk, circuit, &mut OsRng).unwrap();
    assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs(&statement), &proof).unwrap());
    let signature = sign(
        &sk,
        authorization_digest(&statement, proof_sha256_limbs(&proof).unwrap()),
        [7u8; 32],
    )
    .unwrap();
    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let mut owner_pk_bytes = Vec::new();
    owner_pk
        .0
        .serialize_compressed(&mut owner_pk_bytes)
        .unwrap();
    fs::write(output.join("blind_update.vk"), &vk_bytes).unwrap();
    let statement_json = json!({
        "config_digest":hex_field(statement.config_digest),"deployment_id":hex_field(statement.deployment),
        "circuit_id":hex_field(statement.circuit_id),"owner_commitment":hex_field(statement.owner),
        "position":statement.position,"expiry_cap":statement.expiry_cap,"admission_version":statement.admission_version,
        "old_leaf":hex_field(statement.old_leaf),"new_leaf":hex_field(statement.new_leaf),
        "old_version":statement.old_version,"new_version":statement.new_version,
        "old_epoch":statement.old_epoch,"new_epoch":statement.new_epoch
    });
    let request = json!({"command":"blind-state-update-verify","statement":statement_json,"proof_b64":STANDARD.encode(&proof_bytes),"signature_b64":STANDARD.encode(encode_signature(&signature))});
    let seed = json!({"owner_public_key":STANDARD.encode(owner_pk_bytes),"registration_salt":hex_field(registration_salt),"owner_commitment":hex_field(owner),"position":statement.position,"max_expiry":statement.expiry_cap,"admission_version":statement.admission_version,"old_leaf":hex_field(statement.old_leaf),"old_version":statement.old_version,"old_epoch":statement.old_epoch});
    fs::write(
        output.join("request.json"),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    fs::write(output.join("seed.json"), serde_json::to_vec(&seed).unwrap()).unwrap();
    println!(
        "{}",
        json!({"constraints":constraints,"proof_bytes":proof_bytes.len(),"vk_sha256":vk_sha256,"matrix_sha256":matrix_sha256,"deployment_id":hex_field(statement.deployment),"config_digest":hex_field(statement.config_digest),"circuit_id":hex_field(statement.circuit_id),"identity_derivation":"domain-separated SHA-256 reduced canonically to BLS12-381 Fr; circuit binds frozen matrix and VK hashes"})
    );
}
