use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    poseidon::{canonical_le_bytes, hash, Domain},
    signature::{encode_signature, public_key, sign, SecretKey},
};
use plan_a_sr_joint_bbs::fixtures::{
    revoke_source_b, source_b_revocation_capability, two_source_same_terminal,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
fn fh(x: Fr) -> String {
    let mut b = canonical_le_bytes(x);
    b.reverse();
    hex::encode(b)
}
fn snapshot(c: &plan_a_joint_circuit::joint::JointCircuit<3>) -> Value {
    json!({"deployment_id":fh(Fr::from(9u64)),"issued_at":c.snapshot.issued_at,"ra_root":fh(c.snapshot.root_ra),"revocation_epoch":c.snapshot.revocation_epoch,"revocation_root":fh(c.snapshot.root_rev),"state_epoch":c.snapshot.state_epoch,"state_root":fh(c.snapshot.root_state),"tuple_version":c.snapshot.tuple_version})
}
fn signed(v: &Value) -> String {
    let bytes = serde_json::to_vec(v).unwrap();
    let mut h = Sha256::new();
    h.update(b"plan-a-snapshot-v1");
    h.update([0]);
    h.update(bytes);
    let d: [u8; 32] = h.finalize().into();
    let a = Fr::from(u128::from_be_bytes(d[..16].try_into().unwrap()));
    let b = Fr::from(u128::from_be_bytes(d[16..].try_into().unwrap()));
    let sig = sign(
        &SecretKey(Scalar::from(900u64)),
        hash(Domain::Terminal, &[a, b]),
        [0x73; 32],
    )
    .unwrap();
    STANDARD.encode(encode_signature(&sig))
}
fn admission(c: &plan_a_joint_circuit::joint::JointCircuit<3>, owner_scalar: u64) -> Value {
    let owner_pk = public_key(&SecretKey(Scalar::from(owner_scalar))).unwrap();
    let mut pk = vec![];
    owner_pk.0.serialize_compressed(&mut pk).unwrap();
    let deployment = Fr::from(9u64);
    let max = c.state.state_expiry;
    let msg = hash(
        Domain::StateUpdate,
        &[
            Fr::from(0u64),
            deployment,
            c.state.owner_commitment,
            Fr::from(c.state.position),
            Fr::from(max),
            Fr::from(c.state.state_version),
            Fr::from(c.state.state_epoch),
            c.state.grant_root,
            Fr::from(c.state.state_expiry),
            Fr::from(c.state.active as u64),
            c.state.salt,
        ],
    );
    let sig = sign(&SecretKey(Scalar::from(900u64)), msg, [0x75; 32]).unwrap();
    json!({"command":"admission-verify","deployment_id":fh(deployment),"owner_commitment":fh(c.state.owner_commitment),"position":c.state.position,"owner_public_key":STANDARD.encode(pk),"registration_salt":fh(c.registration_salt),"max_expiry":max,"initial_opening":{"grant_root":fh(c.state.grant_root),"state_expiry":c.state.state_expiry,"active":c.state.active,"salt":fh(c.state.salt)},"initial_version":c.state.state_version,"initial_epoch":c.state.state_epoch,"signature_b64":STANDARD.encode(encode_signature(&sig))})
}
fn ra(c: &plan_a_joint_circuit::joint::JointCircuit<3>) -> Value {
    let e = &c.entitlement;
    let leaf = hash(
        Domain::RaLeaf,
        &[
            e.owner_commitment,
            e.resource,
            Fr::from(e.action_mask as u64),
            Fr::from(e.interval_lo),
            Fr::from(e.interval_hi),
            Fr::from(e.permit_expiry),
            e.admission_id,
        ],
    );
    let position = e
        .path
        .directions
        .iter()
        .enumerate()
        .fold(0u64, |v, (i, b)| v | ((*b as u64) << i));
    let sig = sign(&SecretKey(Scalar::from(900u64)), leaf, [0x76; 32]).unwrap();
    json!({"command":"ra-register-verify","deployment_id":fh(Fr::from(9u64)),"position":position,"owner_commitment":fh(e.owner_commitment),"resource":fh(e.resource),"action_mask":e.action_mask,"interval_lo":e.interval_lo,"interval_hi":e.interval_hi,"permit_expiry":e.permit_expiry,"admission_id":fh(e.admission_id),"signature_b64":STANDARD.encode(encode_signature(&sig))})
}
fn main() {
    let [a0, b0] = two_source_same_terminal();
    let (rk, counter, sn) = source_b_revocation_capability();
    assert_eq!(b0.grants[1].grant.serial, sn);
    let [a1, b1] = revoke_source_b(a0.clone(), b0.clone());
    let h0 = snapshot(&a0);
    let h1 = snapshot(&a1);
    assert_eq!(a1.snapshot.root_rev, b1.snapshot.root_rev);
    println!(
        "{}",
        json!({"bootstrap_admissions":[admission(&a0,11),admission(&b0,21)],"bootstrap_ra_registrations":[ra(&a0),ra(&b0)],"h0":h0,"h0_signature_b64":signed(&h0),"h1":h1,"h1_signature_b64":signed(&h1),"revoke":{"command":"revoke-authorize","rk_b64":STANDARD.encode(rk),"counter":counter,"sn":fh(sn)},"revoked_grant_serial":fh(b0.grants[1].grant.serial)})
    )
}
