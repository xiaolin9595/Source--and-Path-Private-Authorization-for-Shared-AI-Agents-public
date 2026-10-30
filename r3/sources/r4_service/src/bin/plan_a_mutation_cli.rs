//! Synthetic owner/revoker request generator for service integration tests.
use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    fixture::fixed,
    indexed_revocation::derive_serial,
    joint::grant_digest,
    merkle::build_tree,
    poseidon::{canonical_le_bytes, hash, Domain},
    signature::{encode_signature, public_key, sign, SecretKey},
    state_registry::{owner_commitment, update_digest, StateLeafOpening},
};
use serde_json::json;
use sha2::{Digest, Sha256};
fn fh(x: Fr) -> String {
    let mut b = canonical_le_bytes(x);
    b.reverse();
    hex::encode(b)
}
fn pk64(p: &plan_a_joint_circuit::signature::PublicKey) -> String {
    let mut b = vec![];
    p.0.serialize_compressed(&mut b).unwrap();
    STANDARD.encode(b)
}
fn main() {
    let command = std::env::args().nth(1).unwrap_or_default();
    match command.as_str() {
        "enroll" => {
            let owner_sk = SecretKey(Scalar::from(7u64));
            let owner_pk = public_key(&owner_sk).unwrap();
            let registry_sk = SecretKey(Scalar::from(900u64));
            let registration_salt = Fr::from(8u64);
            let owner = owner_commitment(owner_pk.0.x, owner_pk.0.y, registration_salt);
            let deployment = Fr::from(9u64);
            let position = 3u64;
            let max_expiry = 300u64;
            let version = 0u64;
            let epoch = 1u64;
            let opening = StateLeafOpening {
                grant_root: Fr::from(1u64),
                state_expiry: 200,
                active: true,
                salt: Fr::from(2u64),
            };
            let msg = plan_a_joint_circuit::poseidon::hash(
                plan_a_joint_circuit::poseidon::Domain::StateUpdate,
                &[
                    Fr::from(0u64),
                    deployment,
                    owner,
                    Fr::from(position),
                    Fr::from(max_expiry),
                    Fr::from(version),
                    Fr::from(epoch),
                    opening.grant_root,
                    Fr::from(opening.state_expiry),
                    Fr::from(opening.active as u64),
                    opening.salt,
                ],
            );
            let sig = sign(&registry_sk, msg, [0x21; 32]).unwrap();
            println!(
                "{}",
                json!({"command":"admission-verify","deployment_id":fh(deployment),"owner_commitment":fh(owner),"position":position,"owner_public_key":pk64(&owner_pk),"registration_salt":fh(registration_salt),"max_expiry":max_expiry,"initial_opening":{"grant_root":fh(opening.grant_root),"state_expiry":opening.state_expiry,"active":opening.active,"salt":fh(opening.salt)},"initial_version":version,"initial_epoch":epoch,"signature_b64":STANDARD.encode(encode_signature(&sig))})
            )
        }
        "enroll-position-conflict" => {
            let owner_sk = SecretKey(Scalar::from(8u64));
            let owner_pk = public_key(&owner_sk).unwrap();
            let registry_sk = SecretKey(Scalar::from(900u64));
            let registration_salt = Fr::from(9u64);
            let owner = owner_commitment(owner_pk.0.x, owner_pk.0.y, registration_salt);
            let deployment = Fr::from(9u64);
            let position = 3u64;
            let max_expiry = 300u64;
            let version = 0u64;
            let epoch = 1u64;
            let opening = StateLeafOpening {
                grant_root: Fr::from(2u64),
                state_expiry: 200,
                active: true,
                salt: Fr::from(3u64),
            };
            let msg = plan_a_joint_circuit::poseidon::hash(
                plan_a_joint_circuit::poseidon::Domain::StateUpdate,
                &[
                    Fr::from(0u64),
                    deployment,
                    owner,
                    Fr::from(position),
                    Fr::from(max_expiry),
                    Fr::from(version),
                    Fr::from(epoch),
                    opening.grant_root,
                    Fr::from(opening.state_expiry),
                    Fr::from(opening.active as u64),
                    opening.salt,
                ],
            );
            let sig = sign(&registry_sk, msg, [0x22; 32]).unwrap();
            println!(
                "{}",
                json!({"command":"admission-verify","deployment_id":fh(deployment),"owner_commitment":fh(owner),"position":position,"owner_public_key":pk64(&owner_pk),"registration_salt":fh(registration_salt),"max_expiry":max_expiry,"initial_opening":{"grant_root":fh(opening.grant_root),"state_expiry":opening.state_expiry,"active":opening.active,"salt":fh(opening.salt)},"initial_version":version,"initial_epoch":epoch,"signature_b64":STANDARD.encode(encode_signature(&sig))})
            )
        }
        "state-update" => {
            let sk = SecretKey(Scalar::from(7u64));
            let pk = public_key(&sk).unwrap();
            let registration_salt = Fr::from(8u64);
            let owner = owner_commitment(pk.0.x, pk.0.y, registration_salt);
            let deployment = Fr::from(9u64);
            let opening = StateLeafOpening {
                grant_root: Fr::from(1u64),
                state_expiry: 200,
                active: false,
                salt: Fr::from(2u64),
            };
            let sig = sign(
                &sk,
                update_digest(deployment, owner, 3, 0, 2, &opening),
                [0x31; 32],
            )
            .unwrap();
            println!(
                "{}",
                json!({"command":"state-update-verify","deployment_id":fh(deployment),"owner_commitment":fh(owner),"position":3,"expected_version":0,"new_epoch":2,"opening":{"grant_root":fh(opening.grant_root),"state_expiry":opening.state_expiry,"active":opening.active,"salt":fh(opening.salt)},"signature_b64":STANDARD.encode(encode_signature(&sig))})
            )
        }
        "holder-state-update" => {
            let circuit = fixed::<3>(2, 77, 10, 10, 32);
            let sk = SecretKey(Scalar::from(11u64));
            let deployment = Fr::from(9u64);
            let root_grant_leaf =
                hash(Domain::GrantLeaf, &[grant_digest(&circuit.grants[0].grant)]);
            let mut rotated_grant_leaves = vec![Fr::from(0u64); 1usize << 3];
            rotated_grant_leaves[1] = root_grant_leaf;
            let (rotated_grant_root, _) =
                build_tree(rotated_grant_leaves, 3, Domain::TreeNode).unwrap();
            let opening = StateLeafOpening {
                grant_root: rotated_grant_root,
                state_expiry: circuit.state.state_expiry,
                active: true,
                salt: circuit.state.salt + Fr::from(1u64),
            };
            let sig = sign(
                &sk,
                update_digest(
                    deployment,
                    circuit.state.owner_commitment,
                    circuit.state.position,
                    circuit.state.state_version,
                    64,
                    &opening,
                ),
                [0x34; 32],
            )
            .unwrap();
            println!(
                "{}",
                json!({"command":"state-update-verify","holder_profile":"fixed-root-position-1-v1","deployment_id":fh(deployment),"owner_commitment":fh(circuit.state.owner_commitment),"position":circuit.state.position,"expected_version":circuit.state.state_version,"new_epoch":64,"opening":{"grant_root":fh(opening.grant_root),"state_expiry":opening.state_expiry,"active":opening.active,"salt":fh(opening.salt)},"signature_b64":STANDARD.encode(encode_signature(&sig))})
            )
        }
        "state-update-expiry" => {
            let sk = SecretKey(Scalar::from(7u64));
            let pk = public_key(&sk).unwrap();
            let owner = owner_commitment(pk.0.x, pk.0.y, Fr::from(8u64));
            let deployment = Fr::from(9u64);
            let opening = StateLeafOpening {
                grant_root: Fr::from(1u64),
                state_expiry: 301,
                active: true,
                salt: Fr::from(2u64),
            };
            let sig = sign(
                &sk,
                update_digest(deployment, owner, 3, 0, 2, &opening),
                [0x32; 32],
            )
            .unwrap();
            println!(
                "{}",
                json!({"command":"state-update-verify","deployment_id":fh(deployment),"owner_commitment":fh(owner),"position":3,"expected_version":0,"new_epoch":2,"opening":{"grant_root":fh(opening.grant_root),"state_expiry":opening.state_expiry,"active":opening.active,"salt":fh(opening.salt)},"signature_b64":STANDARD.encode(encode_signature(&sig))})
            )
        }
        "state-reactivate" => {
            let sk = SecretKey(Scalar::from(7u64));
            let pk = public_key(&sk).unwrap();
            let owner = owner_commitment(pk.0.x, pk.0.y, Fr::from(8u64));
            let deployment = Fr::from(9u64);
            let opening = StateLeafOpening {
                grant_root: Fr::from(1u64),
                state_expiry: 200,
                active: true,
                salt: Fr::from(3u64),
            };
            let sig = sign(
                &sk,
                update_digest(deployment, owner, 3, 1, 3, &opening),
                [0x33; 32],
            )
            .unwrap();
            println!(
                "{}",
                json!({"command":"state-update-verify","deployment_id":fh(deployment),"owner_commitment":fh(owner),"position":3,"expected_version":1,"new_epoch":3,"opening":{"grant_root":fh(opening.grant_root),"state_expiry":opening.state_expiry,"active":opening.active,"salt":fh(opening.salt)},"signature_b64":STANDARD.encode(encode_signature(&sig))})
            )
        }
        "revoke" => {
            let rk = [0x44u8; 32];
            let counter = 7u32;
            let sn = derive_serial(rk, counter).unwrap();
            println!(
                "{}",
                json!({"command":"revoke-authorize","rk_b64":STANDARD.encode(rk),"counter":counter,"sn":fh(sn)})
            )
        }
        "sign-header" => {
            let raw = std::env::args().nth(2).unwrap_or_default();
            let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
            let bytes = serde_json::to_vec(&value).unwrap();
            let mut h = Sha256::new();
            h.update(b"plan-a-snapshot-v1");
            h.update([0]);
            h.update(bytes);
            let d: [u8; 32] = h.finalize().into();
            let a = Fr::from(u128::from_be_bytes(d[..16].try_into().unwrap()));
            let b = Fr::from(u128::from_be_bytes(d[16..].try_into().unwrap()));
            let sig = sign(
                &SecretKey(Scalar::from(900u64)),
                plan_a_joint_circuit::poseidon::hash(
                    plan_a_joint_circuit::poseidon::Domain::Terminal,
                    &[a, b],
                ),
                [0x74; 32],
            )
            .unwrap();
            println!(
                "{}",
                json!({"signature_b64":STANDARD.encode(encode_signature(&sig))})
            )
        }
        _ => {
            eprintln!("usage: plan_a_mutation_cli enroll|enroll-position-conflict|state-update|state-update-expiry|state-reactivate|revoke");
            std::process::exit(2)
        }
    }
}
