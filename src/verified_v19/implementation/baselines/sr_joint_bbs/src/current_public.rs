//! Reconstruct one current-profile Joint source from signed public leaves and
//! an explicit synthetic holder support bundle, for the SR issuer adapter.
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    fixture::fixed,
    indexed_revocation::IndexedRevocationTree,
    joint::{grant_digest, JointCircuit},
    merkle::{build_tree, leaf_hash, path_for},
    poseidon::{hash, Domain},
    signature::{decode_public_key, decode_signature, verify},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

fn parse_field_hex(value: &str) -> Result<Fr, String> {
    let bytes = hex::decode(value).map_err(|_| "bad-field-hex")?;
    if bytes.len() != 32 {
        return Err("bad-field-length".into());
    }
    let field = Fr::from_be_bytes_mod_order(&bytes);
    let mut canonical = plan_a_joint_circuit::poseidon::canonical_le_bytes(field);
    canonical.reverse();
    if bytes != canonical {
        return Err("noncanonical-field".into());
    }
    Ok(field)
}

fn canonical(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}

fn tagged(tag: &[u8], value: &Value) -> Result<[u8; 32], String> {
    let mut digest = Sha256::new();
    digest.update(tag);
    digest.update([0]);
    digest.update(canonical(value)?);
    Ok(digest.finalize().into())
}

fn limbs_be(value: [u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u128::from_be_bytes(value[..16].try_into().unwrap())),
        Fr::from(u128::from_be_bytes(value[16..].try_into().unwrap())),
    )
}

fn public_rows(value: &Value, tree: &str, depth: usize) -> Result<Vec<Fr>, String> {
    let capacity = 1usize << depth;
    let mut leaves = vec![Fr::from(0u64); capacity];
    let mut seen = vec![false; capacity];
    for row in value
        .get(tree)
        .and_then(|x| x.get("leaves"))
        .and_then(Value::as_array)
        .ok_or("bad-public-leaves")?
    {
        let position = row
            .get("position")
            .and_then(Value::as_u64)
            .ok_or("bad-public-position")? as usize;
        if position >= capacity || seen[position] {
            return Err("duplicate-or-out-of-range-public-position".into());
        }
        seen[position] = true;
        leaves[position] = parse_field_hex(
            row.get("leaf")
                .and_then(Value::as_str)
                .ok_or("bad-public-leaf")?,
        )?;
    }
    Ok(leaves)
}

fn apply_holder_profile(circuit: &mut JointCircuit<3>, profile: &str) -> Result<u64, String> {
    match profile {
        "fixed-root-position-0-v1" => Ok(0),
        "fixed-root-position-1-v1" => {
            let leaf = leaf_hash(Domain::GrantLeaf, &[grant_digest(&circuit.grants[0].grant)]);
            let mut leaves = vec![Fr::from(0u64); 1usize << 3];
            leaves[1] = leaf;
            let (root, levels) =
                build_tree(leaves, 3, Domain::TreeNode).map_err(|e| e.to_string())?;
            circuit.state.grant_root = root;
            circuit.grants[0].grant_path = path_for(&levels, 1).map_err(|e| e.to_string())?;
            Ok(1)
        }
        _ => Err("unsupported-holder-profile".into()),
    }
}

pub struct Reconstructed {
    pub circuit: JointCircuit<3>,
    pub public_bytes: usize,
    pub private_bytes: usize,
    pub reconstructed_paths_bytes: usize,
    pub snapshot: Value,
    pub snapshot_digest: String,
}

#[allow(clippy::too_many_arguments)]
pub fn reconstruct(
    public_path: &str,
    private_path: &str,
    registry_pk_b64: &str,
    ds: usize,
    dra: usize,
    drev: usize,
) -> Result<Reconstructed, String> {
    if (ds, dra, drev) != (10, 10, 32) {
        return Err("untrusted-current-profile-shape".into());
    }
    let public_bytes = fs::read(public_path).map_err(|e| e.to_string())?;
    let private_bytes = fs::read(private_path).map_err(|e| e.to_string())?;
    let published: Value = serde_json::from_slice(&public_bytes).map_err(|_| "bad-public-json")?;
    let private: Value = serde_json::from_slice(&private_bytes).map_err(|_| "bad-private-json")?;
    if published.get("schema").and_then(Value::as_str) != Some("plan-a-public-leaves-v1")
        || private.get("schema").and_then(Value::as_str) != Some("plan-a-private-holder-v1")
        || private.get("support_model").and_then(Value::as_str)
            != Some("explicit-deterministic-signed-synthetic-profile-v1")
    {
        return Err("bad-support-schema".into());
    }
    let snapshot = published
        .get("snapshot")
        .cloned()
        .ok_or("missing-snapshot")?;
    let snapshot_hash = tagged(b"plan-a-snapshot-v1", &snapshot)?;
    let snapshot_digest = hex::encode(snapshot_hash);
    if published.get("snapshot_digest").and_then(Value::as_str) != Some(snapshot_digest.as_str()) {
        return Err("public-snapshot-digest-mismatch".into());
    }
    if snapshot.get("deployment_id") != private.get("deployment_id")
        || private
            .get("expected_snapshot_digest")
            .and_then(Value::as_str)
            != Some(snapshot_digest.as_str())
        || snapshot
            .get("tuple_version")
            .and_then(Value::as_u64)
            .ok_or("bad-tuple")?
            < private
                .get("minimum_tuple_version")
                .and_then(Value::as_u64)
                .ok_or("bad-minimum-tuple")?
    {
        return Err("untrusted-public-version".into());
    }
    let registry_pk = decode_public_key(
        &STANDARD
            .decode(registry_pk_b64)
            .map_err(|_| "bad-registry-key-base64")?,
    )
    .map_err(|_| "bad-registry-key")?;
    let signature = decode_signature(
        &STANDARD
            .decode(
                published
                    .get("header_signature_b64")
                    .and_then(Value::as_str)
                    .ok_or("missing-header-signature")?,
            )
            .map_err(|_| "bad-header-signature-base64")?,
    )
    .map_err(|_| "bad-header-signature")?;
    let (lo, hi) = limbs_be(snapshot_hash);
    if !verify(&registry_pk, hash(Domain::Terminal, &[lo, hi]), &signature) {
        return Err("invalid-header-signature".into());
    }

    let mut circuit = fixed::<3>(2, 1, ds, dra, drev);
    let profile = private
        .get("holder_profile")
        .and_then(Value::as_str)
        .ok_or("missing-holder-profile")?;
    let grant_position = apply_holder_profile(&mut circuit, profile)?;
    let private_index = private
        .get("private_index")
        .ok_or("missing-private-index")?;
    if private_index.get("grant_position").and_then(Value::as_u64) != Some(grant_position) {
        return Err("private-grant-index-mismatch".into());
    }
    let state = private.get("state").ok_or("missing-private-state")?;
    circuit.state.owner_commitment = parse_field_hex(
        state
            .get("owner_commitment")
            .and_then(Value::as_str)
            .ok_or("bad-owner")?,
    )?;
    circuit.state.grant_root = parse_field_hex(
        state
            .get("grant_root")
            .and_then(Value::as_str)
            .ok_or("bad-grant-root")?,
    )?;
    circuit.state.state_version = state
        .get("state_version")
        .and_then(Value::as_u64)
        .ok_or("bad-version")?;
    circuit.state.state_epoch = state
        .get("state_epoch")
        .and_then(Value::as_u64)
        .ok_or("bad-state-epoch")?;
    circuit.state.state_expiry = state
        .get("state_expiry")
        .and_then(Value::as_u64)
        .ok_or("bad-state-expiry")?;
    circuit.state.active = state
        .get("active")
        .and_then(Value::as_bool)
        .ok_or("bad-active")?;
    circuit.state.salt = parse_field_hex(
        state
            .get("salt")
            .and_then(Value::as_str)
            .ok_or("bad-salt")?,
    )?;
    circuit.state.position = state
        .get("position")
        .and_then(Value::as_u64)
        .ok_or("bad-position")? as u32;
    if private_index.get("state_position").and_then(Value::as_u64)
        != Some(circuit.state.position as u64)
    {
        return Err("private-state-index-mismatch".into());
    }

    circuit.snapshot.tuple_version = snapshot
        .get("tuple_version")
        .and_then(Value::as_u64)
        .ok_or("bad-tuple")?;
    circuit.snapshot.root_ra = parse_field_hex(
        snapshot
            .get("ra_root")
            .and_then(Value::as_str)
            .ok_or("bad-ra-root")?,
    )?;
    circuit.snapshot.root_state = parse_field_hex(
        snapshot
            .get("state_root")
            .and_then(Value::as_str)
            .ok_or("bad-state-root")?,
    )?;
    circuit.snapshot.root_rev = parse_field_hex(
        snapshot
            .get("revocation_root")
            .and_then(Value::as_str)
            .ok_or("bad-rev-root")?,
    )?;
    circuit.snapshot.state_epoch = snapshot
        .get("state_epoch")
        .and_then(Value::as_u64)
        .ok_or("bad-state-epoch")?;
    circuit.snapshot.revocation_epoch = snapshot
        .get("revocation_epoch")
        .and_then(Value::as_u64)
        .ok_or("bad-rev-epoch")?;
    circuit.snapshot.issued_at = snapshot
        .get("issued_at")
        .and_then(Value::as_u64)
        .ok_or("bad-issued-at")?;

    let ra_leaves = public_rows(&published, "ra", dra)?;
    let entitlement_leaf = hash(
        Domain::RaLeaf,
        &[
            circuit.entitlement.owner_commitment,
            circuit.entitlement.resource,
            Fr::from(circuit.entitlement.action_mask as u64),
            Fr::from(circuit.entitlement.interval_lo),
            Fr::from(circuit.entitlement.interval_hi),
            Fr::from(circuit.entitlement.permit_expiry),
            circuit.entitlement.admission_id,
        ],
    );
    let ra_position = ra_leaves
        .iter()
        .position(|leaf| *leaf == entitlement_leaf)
        .ok_or("holder-ra-leaf-not-published")?;
    if private_index.get("ra_position").and_then(Value::as_u64) != Some(ra_position as u64) {
        return Err("private-ra-index-mismatch".into());
    }
    let (ra_root, ra_levels) =
        build_tree(ra_leaves, dra, Domain::TreeNode).map_err(|e| e.to_string())?;
    if ra_root != circuit.snapshot.root_ra {
        return Err("downloaded-ra-root-mismatch".into());
    }
    circuit.entitlement.path = path_for(&ra_levels, ra_position).map_err(|e| e.to_string())?;

    let state_leaves = public_rows(&published, "state", ds)?;
    let state_leaf = hash(
        Domain::StateLeaf,
        &[
            circuit.state.owner_commitment,
            circuit.state.grant_root,
            Fr::from(circuit.state.state_version),
            Fr::from(circuit.state.state_epoch),
            Fr::from(circuit.state.state_expiry),
            Fr::from(circuit.state.active as u64),
            circuit.state.salt,
            Fr::from(circuit.state.position),
        ],
    );
    if state_leaves.get(circuit.state.position as usize) != Some(&state_leaf) {
        return Err("holder-state-leaf-not-published".into());
    }
    let (state_root, state_levels) =
        build_tree(state_leaves, ds, Domain::TreeNode).map_err(|e| e.to_string())?;
    if state_root != circuit.snapshot.root_state {
        return Err("downloaded-state-root-mismatch".into());
    }
    circuit.state.path =
        path_for(&state_levels, circuit.state.position as usize).map_err(|e| e.to_string())?;

    let mut revocation = IndexedRevocationTree::new(drev).map_err(|_| "bad-revocation-depth")?;
    for serial in published
        .get("revocation")
        .and_then(|x| x.get("inserted_serials"))
        .and_then(Value::as_array)
        .ok_or("bad-public-revocations")?
    {
        revocation
            .insert(parse_field_hex(
                serial.as_str().ok_or("bad-public-serial")?,
            )?)
            .map_err(|_| "bad-public-revocation-set")?;
    }
    if revocation.root() != circuit.snapshot.root_rev {
        return Err("downloaded-revocation-root-mismatch".into());
    }
    for slot in circuit.grants.iter_mut().filter(|slot| slot.enabled) {
        slot.revocation = revocation
            .prove_nonmember(slot.grant.serial)
            .map_err(|_| "holder-grant-revoked")?;
    }
    let reconstructed_paths_bytes = serde_json::to_vec(&serde_json::json!({
        "ra_siblings": circuit.entitlement.path.siblings.len(),
        "state_siblings": circuit.state.path.siblings.len(),
        "revocation_paths": circuit.grants.iter().filter(|slot| slot.enabled).map(|slot| slot.revocation.path.siblings.len()).collect::<Vec<_>>(),
    }))
    .map_err(|e| e.to_string())?
    .len();
    Ok(Reconstructed {
        circuit,
        public_bytes: public_bytes.len(),
        private_bytes: private_bytes.len(),
        reconstructed_paths_bytes,
        snapshot,
        snapshot_digest,
    })
}
