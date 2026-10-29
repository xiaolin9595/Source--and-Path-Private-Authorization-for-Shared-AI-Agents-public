//! Deterministic, signed background-population generator for the E4 lifecycle
//! grid.  Every emitted row traverses the normal HTTP admission/mutation path.
use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_serialize::CanonicalSerialize;
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    indexed_revocation::derive_serial,
    poseidon::{canonical_le_bytes, hash, Domain},
    signature::{encode_signature, public_key, sign, SecretKey},
    state_registry::{owner_commitment, update_digest, StateLeafOpening},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn field_hex(value: Fr) -> String {
    let mut bytes = canonical_le_bytes(value);
    bytes.reverse();
    hex::encode(bytes)
}
fn public_key_b64(key: &plan_a_joint_circuit::signature::PublicKey) -> String {
    let mut bytes = Vec::new();
    key.0.serialize_compressed(&mut bytes).unwrap();
    STANDARD.encode(bytes)
}
fn owner_secret(seed: u64, index: usize) -> SecretKey {
    SecretKey(Scalar::from(10_000u64 + seed * 2_000 + index as u64))
}
fn state_position(index: usize) -> u32 {
    if index < 2 {
        index as u32
    } else {
        index as u32 + 1
    }
}
fn ra_position(index: usize) -> u32 {
    index as u32 + 1
}
fn opening(seed: u64, index: usize, updated: bool) -> StateLeafOpening {
    StateLeafOpening {
        grant_root: Fr::from(100_000u64 + seed * 2_000 + index as u64),
        state_expiry: 300,
        active: true,
        salt: Fr::from(200_000u64 + seed * 4_000 + index as u64 * 2 + updated as u64),
    }
}
fn admission(seed: u64, index: usize) -> Value {
    let deployment = Fr::from(9u64);
    let secret = owner_secret(seed, index);
    let public = public_key(&secret).unwrap();
    let registration_salt = Fr::from(300_000u64 + seed * 2_000 + index as u64);
    let owner = owner_commitment(public.0.x, public.0.y, registration_salt);
    let position = state_position(index);
    let state = opening(seed, index, false);
    let message = hash(
        Domain::StateUpdate,
        &[
            Fr::from(0u64),
            deployment,
            owner,
            Fr::from(position),
            Fr::from(300u64),
            Fr::from(0u64),
            Fr::from(55u64),
            state.grant_root,
            Fr::from(state.state_expiry),
            Fr::from(state.active as u64),
            state.salt,
        ],
    );
    let signature = sign(&SecretKey(Scalar::from(900u64)), message, [0x81; 32]).unwrap();
    json!({
        "command":"admission-verify","deployment_id":field_hex(deployment),
        "owner_commitment":field_hex(owner),"position":position,
        "owner_public_key":public_key_b64(&public),"registration_salt":field_hex(registration_salt),
        "max_expiry":300,"initial_opening":{"grant_root":field_hex(state.grant_root),
        "state_expiry":state.state_expiry,"active":state.active,"salt":field_hex(state.salt)},
        "initial_version":0,"initial_epoch":55,
        "signature_b64":STANDARD.encode(encode_signature(&signature))
    })
}
fn ra_payload(seed: u64, index: usize, updated: bool) -> (Value, Fr) {
    let secret = owner_secret(seed, index);
    let public = public_key(&secret).unwrap();
    let registration_salt = Fr::from(300_000u64 + seed * 2_000 + index as u64);
    let owner = owner_commitment(public.0.x, public.0.y, registration_salt);
    let admission_id = Fr::from(400_000u64 + seed * 4_000 + index as u64 * 2 + updated as u64);
    let fields = [
        owner,
        Fr::from(700u64),
        Fr::from(31u64),
        Fr::from(100u64),
        Fr::from(300u64),
        Fr::from(300u64),
        admission_id,
    ];
    let leaf = hash(Domain::RaLeaf, &fields);
    let signature = sign(&SecretKey(Scalar::from(900u64)), leaf, [0x82; 32]).unwrap();
    (
        json!({
            "command":"ra-register-verify","deployment_id":field_hex(Fr::from(9u64)),
            "position":ra_position(index),"owner_commitment":field_hex(owner),
            "resource":field_hex(Fr::from(700u64)),"action_mask":31,"interval_lo":100,
            "interval_hi":300,"permit_expiry":300,"admission_id":field_hex(admission_id),
            "signature_b64":STANDARD.encode(encode_signature(&signature))
        }),
        leaf,
    )
}
fn state_update(seed: u64, index: usize, ordinal: usize) -> Value {
    let deployment = Fr::from(9u64);
    let secret = owner_secret(seed, index);
    let public = public_key(&secret).unwrap();
    let registration_salt = Fr::from(300_000u64 + seed * 2_000 + index as u64);
    let owner = owner_commitment(public.0.x, public.0.y, registration_salt);
    let state = opening(seed, index, true);
    let new_epoch = 56 + ordinal as u64;
    let signature = sign(
        &secret,
        update_digest(
            deployment,
            owner,
            state_position(index),
            0,
            new_epoch,
            &state,
        ),
        [0x83; 32],
    )
    .unwrap();
    json!({
        "command":"state-update-verify","deployment_id":field_hex(deployment),
        "owner_commitment":field_hex(owner),"position":state_position(index),
        "expected_version":0,"new_epoch":new_epoch,
        "opening":{"grant_root":field_hex(state.grant_root),"state_expiry":state.state_expiry,
        "active":state.active,"salt":field_hex(state.salt)},
        "signature_b64":STANDARD.encode(encode_signature(&signature))
    })
}
fn revocation(seed: u64, index: usize) -> Value {
    let digest = Sha256::digest(format!("plan-a-e4-revocation-{seed}-{index}").as_bytes());
    let rk: [u8; 32] = digest.into();
    let mut counter = 0u32;
    let serial = loop {
        if let Ok(value) = derive_serial(rk, counter) {
            break value;
        }
        counter += 1;
    };
    json!({"command":"revoke-authorize","rk_b64":STANDARD.encode(rk),"counter":counter,"sn":field_hex(serial)})
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let mode = args.get(1).map(String::as_str).unwrap_or("");
    let population = args
        .get(2)
        .and_then(|x| x.parse::<usize>().ok())
        .unwrap_or(0);
    let seed = args.get(3).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
    if population < 2 || population > 1024 {
        eprintln!("population must be in 2..=1024");
        std::process::exit(2);
    }
    let background = population - 1;
    let value = match mode {
        "population" if args.len() == 4 => {
            let rows = (0..background)
                .map(|index| {
                    let (ra, _) = ra_payload(seed, index, false);
                    json!({"admission":admission(seed,index),"ra_registration":ra})
                })
                .collect::<Vec<_>>();
            json!({"schema":"plan-a-e4-population-v1","population":population,"seed":seed,"background_rows":rows})
        }
        "updates" if args.len() == 5 => {
            let count = args[4].parse::<usize>().unwrap_or(0);
            if count == 0 || count > background {
                eprintln!("bad update count");
                std::process::exit(2);
            }
            let rows = (0..count).map(|index| {
                let (mut ra, _) = ra_payload(seed, index, true);
                let (_, old_leaf) = ra_payload(seed, index, false);
                ra["expected_leaf"] = json!(field_hex(old_leaf));
                json!({"ra_update":ra,"state_update":state_update(seed,index,index),"revocation":revocation(seed,index)})
            }).collect::<Vec<_>>();
            json!({"schema":"plan-a-e4-updates-v1","population":population,"seed":seed,"update_count":count,"rows":rows})
        }
        _ => {
            eprintln!("usage: plan_a_population_cli population N SEED | updates N SEED COUNT");
            std::process::exit(2);
        }
    };
    println!("{value}");
}
