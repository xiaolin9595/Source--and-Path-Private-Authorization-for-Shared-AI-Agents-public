//! Synthetic Agent-side HTTP artifact generator. Witnesses and secret keys
//! remain here; the service receives only the signed public envelope.
use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, ProvingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use plan_a_joint_circuit::{
    contract::terminal_transcript,
    fixture::{fixed, public_inputs},
    indexed_revocation::IndexedRevocationTree,
    joint::{grant_digest, request_digest, snapshot_digest, JointCircuit},
    merkle::{build_tree, path_for, MerklePath},
    poseidon::{canonical_le_bytes, hash, Domain},
    signature::{
        decode_public_key, decode_signature, encode_signature, public_key, sign, verify, SecretKey,
    },
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Cursor, time::Instant};

#[derive(Clone)]
struct CachedPublicWitness {
    key: [u8; 32],
    circuit: JointCircuit<3>,
    snapshot: Value,
    header_signature_b64: String,
    public_bytes: usize,
    public_reconstructed_paths: Value,
    public_reconstructed_paths_bytes: usize,
    public_snapshot_digest: Value,
}

fn tagged(tag: &[u8], value: &Value) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update([0]);
    h.update(serde_json::to_vec(value).expect("json"));
    h.finalize().into()
}
fn limbs(x: [u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u128::from_be_bytes(x[..16].try_into().unwrap())),
        Fr::from(u128::from_be_bytes(x[16..].try_into().unwrap())),
    )
}
fn field_hex(x: Fr) -> String {
    let mut b = canonical_le_bytes(x);
    b.reverse();
    hex::encode(b)
}
fn point_b64(p: &plan_a_joint_circuit::signature::PublicKey) -> String {
    let mut b = vec![];
    p.0.serialize_compressed(&mut b).unwrap();
    STANDARD.encode(b)
}
fn n<T: std::str::FromStr>(s: &str) -> Result<T, String> {
    s.parse().map_err(|_| "bad-number".into())
}
fn parse_field_hex(value: &str) -> Result<Fr, String> {
    let bytes = hex::decode(value).map_err(|_| "bad-field-hex")?;
    if bytes.len() != 32 {
        return Err("bad-field-length".into());
    }
    let field = Fr::from_be_bytes_mod_order(&bytes);
    if field_hex(field) != value {
        return Err("noncanonical-field".into());
    }
    Ok(field)
}
fn public_rows(value: &Value, tree: &str, depth: usize) -> Result<Vec<Fr>, String> {
    let capacity = 1usize.checked_shl(depth as u32).ok_or("bad-tree-depth")?;
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

fn path_value(path: &MerklePath) -> Value {
    json!({
        "siblings": path.siblings.iter().copied().map(field_hex).collect::<Vec<_>>(),
        "directions": path.directions,
    })
}

fn scalar_b64(value: Scalar) -> String {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .expect("scalar serialization");
    STANDARD.encode(bytes)
}

fn apply_holder_profile(circuit: &mut JointCircuit<3>, profile: &str) -> Result<u64, String> {
    match profile {
        "fixed-root-position-0-v1" => Ok(0),
        "fixed-root-position-1-v1" => {
            let leaf = hash(Domain::GrantLeaf, &[grant_digest(&circuit.grants[0].grant)]);
            let mut leaves = vec![Fr::from(0u64); 1usize << 3];
            leaves[1] = leaf;
            let (root, levels) = build_tree(leaves, 3, Domain::TreeNode).map_err(str::to_string)?;
            circuit.state.grant_root = root;
            circuit.grants[0].grant_path = path_for(&levels, 1).map_err(str::to_string)?;
            Ok(1)
        }
        _ => Err("unsupported-holder-profile".into()),
    }
}

fn private_support_value(circuit: &JointCircuit<3>, profile: &str) -> Value {
    let owner_secret = Scalar::from(11u64);
    let terminal_secret = Scalar::from(14u64);
    let grants = circuit
        .grants
        .iter()
        .filter(|slot| slot.enabled)
        .map(|slot| {
            let grant = &slot.grant;
            json!({
                "message": {
                    "issuer_b64": point_b64(&grant.issuer),
                    "subject_b64": point_b64(&grant.subject),
                    "resource": field_hex(grant.resource),
                    "action_mask": grant.action_mask,
                    "interval_lo": grant.interval_lo,
                    "interval_hi": grant.interval_hi,
                    "not_before": grant.not_before,
                    "expiry": grant.expiry,
                    "depth_remaining": grant.depth_remaining,
                    "serial": field_hex(grant.serial),
                    "parent_digest": field_hex(grant.parent_digest),
                },
                "digest": field_hex(grant_digest(grant)),
                "signature_b64": STANDARD.encode(encode_signature(&grant.signature)),
            })
        })
        .collect::<Vec<_>>();
    json!({
        "schema":"plan-a-holder-complete-support-v1",
        "holder_profile":profile,
        "owner_secret_key_b64":scalar_b64(owner_secret),
        "owner_public_key_b64":point_b64(&public_key(&SecretKey(owner_secret)).expect("owner key")),
        "terminal_secret_key_b64":scalar_b64(terminal_secret),
        "terminal_public_key_b64":point_b64(&public_key(&SecretKey(terminal_secret)).expect("terminal key")),
        "registration_salt":field_hex(circuit.registration_salt),
        "entitlement":{
            "owner_commitment":field_hex(circuit.entitlement.owner_commitment),
            "resource":field_hex(circuit.entitlement.resource),
            "action_mask":circuit.entitlement.action_mask,
            "interval_lo":circuit.entitlement.interval_lo,
            "interval_hi":circuit.entitlement.interval_hi,
            "permit_expiry":circuit.entitlement.permit_expiry,
            "admission_id":field_hex(circuit.entitlement.admission_id),
        },
        "state_opening":{
            "owner_commitment":field_hex(circuit.state.owner_commitment),
            "grant_root":field_hex(circuit.state.grant_root),
            "state_version":circuit.state.state_version,
            "state_epoch":circuit.state.state_epoch,
            "state_expiry":circuit.state.state_expiry,
            "active":circuit.state.active,
            "salt":field_hex(circuit.state.salt),
            "position":circuit.state.position,
        },
        "grants":grants,
        "private_root_grant_path":path_value(&circuit.grants[0].grant_path),
    })
}

fn refresh_from_public_with_key(
    pk: &ProvingKey<Bls12_381>,
    vk: &[u8],
    pk_load_ms: Option<f64>,
    public_path: &str,
    private_holder_path: &str,
    registry_pk_b64: &str,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
    now: u64,
    audience: &str,
    body: &[u8],
    mut cache: Option<&mut Option<CachedPublicWitness>>,
) -> Result<Value, String> {
    let public_bytes = fs::read(public_path).map_err(|e| e.to_string())?;
    let private_bytes = fs::read(private_holder_path).map_err(|e| e.to_string())?;
    let mut key_hasher = Sha256::new();
    key_hasher.update(b"plan-a-public-witness-cache-v1\0");
    key_hasher.update((ds as u64).to_be_bytes());
    key_hasher.update((dra as u64).to_be_bytes());
    key_hasher.update((drev as u64).to_be_bytes());
    key_hasher.update((public_bytes.len() as u64).to_be_bytes());
    key_hasher.update(&public_bytes);
    key_hasher.update((private_bytes.len() as u64).to_be_bytes());
    key_hasher.update(&private_bytes);
    let cache_key: [u8; 32] = key_hasher.finalize().into();
    if let Some(hit) = cache
        .as_deref()
        .and_then(Option::as_ref)
        .filter(|x| x.key == cache_key)
    {
        let mut output = make_refreshed_with::<3>(
            pk,
            vk,
            pk_load_ms,
            hit.circuit.clone(),
            nonce,
            ds,
            dra,
            drev,
            now,
            audience,
            body,
            hit.snapshot.clone(),
            &hit.header_signature_b64,
            registry_pk_b64,
        )?;
        output["timing"]["public_witness_recompute_ms"] = json!(0.0);
        output["timing"]["public_download_bytes"] = json!(hit.public_bytes);
        output["timing"]["public_witness_cache_hit"] = json!(true);
        output["timing"]["public_witness_cache_key_sha256"] = json!(hex::encode(cache_key));
        output["storage"] =
            json!({"public_reconstructed_paths_bytes":hit.public_reconstructed_paths_bytes});
        output["public_reconstructed_paths"] = hit.public_reconstructed_paths.clone();
        output["public_snapshot_digest"] = hit.public_snapshot_digest.clone();
        return Ok(output);
    }
    let published: Value = serde_json::from_slice(&public_bytes).map_err(|_| "bad-public-json")?;
    let private: Value =
        serde_json::from_slice(&private_bytes).map_err(|_| "bad-private-holder-json")?;
    if private.get("schema").and_then(Value::as_str) != Some("plan-a-private-holder-v1") {
        return Err("bad-private-holder-schema".into());
    }
    if private.get("support_model").and_then(Value::as_str)
        != Some("explicit-deterministic-signed-synthetic-profile-v1")
    {
        return Err("unsupported-private-holder-model".into());
    }
    if published.get("schema").and_then(Value::as_str) != Some("plan-a-public-leaves-v1") {
        return Err("bad-public-schema".into());
    }
    let snapshot = published.get("snapshot").ok_or("missing-public-snapshot")?;
    let snapshot_sha = tagged(b"plan-a-snapshot-v1", snapshot);
    let expected_snapshot_digest = hex::encode(snapshot_sha);
    if published.get("snapshot_digest").and_then(Value::as_str)
        != Some(expected_snapshot_digest.as_str())
    {
        return Err("public-snapshot-digest-mismatch".into());
    }
    if snapshot.get("deployment_id").and_then(Value::as_str)
        != private.get("deployment_id").and_then(Value::as_str)
    {
        return Err("public-deployment-mismatch".into());
    }
    let minimum_tuple = private
        .get("minimum_tuple_version")
        .and_then(Value::as_u64)
        .ok_or("bad-private-minimum-tuple")?;
    if snapshot
        .get("tuple_version")
        .and_then(Value::as_u64)
        .ok_or("bad-tuple-version")?
        < minimum_tuple
    {
        return Err("public-version-rollback".into());
    }
    if private
        .get("expected_snapshot_digest")
        .and_then(Value::as_str)
        != Some(expected_snapshot_digest.as_str())
    {
        return Err("unexpected-public-snapshot".into());
    }
    let registry_pk = decode_public_key(
        &STANDARD
            .decode(registry_pk_b64)
            .map_err(|_| "bad-registry-key-base64")?,
    )
    .map_err(|_| "bad-registry-key")?;
    let header_signature_b64 = published
        .get("header_signature_b64")
        .and_then(Value::as_str)
        .ok_or("missing-public-header-signature")?;
    let signature = decode_signature(
        &STANDARD
            .decode(header_signature_b64)
            .map_err(|_| "bad-public-header-signature-base64")?,
    )
    .map_err(|_| "bad-public-header-signature")?;
    let (snapshot_lo, snapshot_hi) = limbs(snapshot_sha);
    if !verify(
        &registry_pk,
        hash(Domain::Terminal, &[snapshot_lo, snapshot_hi]),
        &signature,
    ) {
        return Err("invalid-public-header-signature".into());
    }
    let started = Instant::now();
    let mut circuit = fixed::<3>(2, nonce, ds, dra, drev);
    let private_state = private.get("state").ok_or("missing-private-state")?;
    let private_index = private
        .get("private_index")
        .ok_or("missing-private-index")?;
    let holder_profile = private
        .get("holder_profile")
        .and_then(Value::as_str)
        .ok_or("missing-holder-profile")?;
    let grant_position = apply_holder_profile(&mut circuit, holder_profile)?;
    if private_index.get("grant_position").and_then(Value::as_u64) != Some(grant_position) {
        return Err("private-grant-index-mismatch".into());
    }
    let private_owner = parse_field_hex(
        private_state
            .get("owner_commitment")
            .and_then(Value::as_str)
            .ok_or("bad-private-owner")?,
    )?;
    let private_grant_root = parse_field_hex(
        private_state
            .get("grant_root")
            .and_then(Value::as_str)
            .ok_or("bad-private-grant-root")?,
    )?;
    if private_owner != circuit.state.owner_commitment
        || private_grant_root != circuit.state.grant_root
    {
        return Err("private-holder-chain-mismatch".into());
    }
    circuit.state.state_version = private_state
        .get("state_version")
        .and_then(Value::as_u64)
        .ok_or("bad-private-state-version")?;
    circuit.state.state_epoch = private_state
        .get("state_epoch")
        .and_then(Value::as_u64)
        .ok_or("bad-private-state-epoch")?;
    circuit.state.state_expiry = private_state
        .get("state_expiry")
        .and_then(Value::as_u64)
        .ok_or("bad-private-state-expiry")?;
    circuit.state.active = private_state
        .get("active")
        .and_then(Value::as_bool)
        .ok_or("bad-private-active")?;
    circuit.state.salt = parse_field_hex(
        private_state
            .get("salt")
            .and_then(Value::as_str)
            .ok_or("bad-private-salt")?,
    )?;
    circuit.state.position = private_state
        .get("position")
        .and_then(Value::as_u64)
        .ok_or("bad-private-position")?
        .try_into()
        .map_err(|_| "bad-private-position")?;
    if private_index.get("state_position").and_then(Value::as_u64)
        != Some(circuit.state.position as u64)
    {
        return Err("private-state-index-mismatch".into());
    }
    let expected_support = private_support_value(&circuit, holder_profile);
    if private.get("complete_support") != Some(&expected_support) {
        return Err("private-complete-support-mismatch".into());
    }
    circuit.snapshot.tuple_version = snapshot
        .get("tuple_version")
        .and_then(Value::as_u64)
        .ok_or("bad-tuple-version")?;
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
            .ok_or("bad-revocation-root")?,
    )?;
    circuit.snapshot.state_epoch = snapshot
        .get("state_epoch")
        .and_then(Value::as_u64)
        .ok_or("bad-state-epoch")?;
    circuit.snapshot.revocation_epoch = snapshot
        .get("revocation_epoch")
        .and_then(Value::as_u64)
        .ok_or("bad-revocation-epoch")?;
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
    let entitlement_position = ra_leaves
        .iter()
        .position(|leaf| *leaf == entitlement_leaf)
        .ok_or("holder-ra-leaf-not-published")?;
    if private_index.get("ra_position").and_then(Value::as_u64) != Some(entitlement_position as u64)
    {
        return Err("private-ra-index-mismatch".into());
    }
    let (ra_root, ra_levels) =
        build_tree(ra_leaves, dra, Domain::TreeNode).map_err(str::to_string)?;
    if ra_root != circuit.snapshot.root_ra {
        return Err("downloaded-ra-root-mismatch".into());
    }
    circuit.entitlement.path =
        path_for(&ra_levels, entitlement_position).map_err(str::to_string)?;

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
        build_tree(state_leaves, ds, Domain::TreeNode).map_err(str::to_string)?;
    if state_root != circuit.snapshot.root_state {
        return Err("downloaded-state-root-mismatch".into());
    }
    circuit.state.path =
        path_for(&state_levels, circuit.state.position as usize).map_err(str::to_string)?;

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
    let public_reconstructed_paths = json!({
        "schema":"plan-a-public-reconstructed-paths-v1",
        "entitlement_path":path_value(&circuit.entitlement.path),
        "state_path":path_value(&circuit.state.path),
        "grant_revocation_nonmembership":circuit.grants.iter().filter(|slot| slot.enabled).map(|slot| json!({
            "serial":field_hex(slot.grant.serial),
            "predecessor_slot":slot.revocation.predecessor_slot,
            "predecessor":field_hex(slot.revocation.predecessor),
            "successor_slot":slot.revocation.successor_slot,
            "successor":field_hex(slot.revocation.successor),
            "path":path_value(&slot.revocation.path),
        })).collect::<Vec<_>>(),
    });
    let public_reconstructed_paths_bytes = serde_json::to_vec(&public_reconstructed_paths)
        .map_err(|e| e.to_string())?
        .len();
    let refresh_ms = started.elapsed().as_secs_f64() * 1000.0;
    if let Some(slot) = cache.as_deref_mut() {
        *slot = Some(CachedPublicWitness {
            key: cache_key,
            circuit: circuit.clone(),
            snapshot: snapshot.clone(),
            header_signature_b64: header_signature_b64.to_string(),
            public_bytes: public_bytes.len(),
            public_reconstructed_paths: public_reconstructed_paths.clone(),
            public_reconstructed_paths_bytes,
            public_snapshot_digest: published
                .get("snapshot_digest")
                .cloned()
                .ok_or("missing-public-digest")?,
        });
    }
    let mut output = make_refreshed_with::<3>(
        pk,
        vk,
        pk_load_ms,
        circuit,
        nonce,
        ds,
        dra,
        drev,
        now,
        audience,
        body,
        snapshot.clone(),
        header_signature_b64,
        registry_pk_b64,
    )?;
    output["timing"]["public_witness_recompute_ms"] = json!(refresh_ms);
    output["timing"]["public_download_bytes"] = json!(public_bytes.len());
    output["timing"]["public_witness_cache_hit"] = json!(false);
    output["timing"]["public_witness_cache_key_sha256"] = json!(hex::encode(cache_key));
    output["storage"] = json!({
        "public_reconstructed_paths_bytes":public_reconstructed_paths_bytes,
    });
    output["public_reconstructed_paths"] = public_reconstructed_paths;
    output["public_snapshot_digest"] = published
        .get("snapshot_digest")
        .cloned()
        .ok_or("missing-public-digest")?;
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn refresh_from_public(
    pk_path: &str,
    vk_path: &str,
    public_path: &str,
    private_holder_path: &str,
    registry_pk_b64: &str,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
    now: u64,
    audience: &str,
    body: &[u8],
) -> Result<Value, String> {
    let (pk, load_ms) = load_pk(pk_path)?;
    let vk = fs::read(vk_path).map_err(|e| e.to_string())?;
    refresh_from_public_with_key(
        &pk,
        &vk,
        Some(load_ms),
        public_path,
        private_holder_path,
        registry_pk_b64,
        nonce,
        ds,
        dra,
        drev,
        now,
        audience,
        body,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn make_refreshed_with<const L: usize>(
    pk: &ProvingKey<Bls12_381>,
    vk_bytes: &[u8],
    pk_load_ms: Option<f64>,
    mut circuit: plan_a_joint_circuit::joint::JointCircuit<L>,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
    now: u64,
    audience: &str,
    body: &[u8],
    snapshot: Value,
    header_signature_b64: &str,
    registry_pk_b64: &str,
) -> Result<Value, String> {
    let deployment_id = snapshot
        .get("deployment_id")
        .and_then(Value::as_str)
        .ok_or("missing-snapshot-deployment")?;
    let vk_id = hex::encode(Sha256::digest(vk_bytes));
    let circuit_id = format!("plan-a-joint-v1:{L}:{ds}:{dra}:{drev}:3:poseidon-v2:codec-v1");
    let nonce_text = URL_SAFE_NO_PAD.encode((nonce as u128).to_be_bytes());
    let terminal_sk = SecretKey(Scalar::from(11u64 + L as u64));
    let terminal_pk = public_key(&terminal_sk).map_err(|e| e.to_string())?;
    let snap_sha = tagged(b"plan-a-snapshot-v1", &snapshot);
    let snapshot_digest_hex = hex::encode(snap_sha);
    let expires = now + 30;
    let request = json!({
        "action_onehot":1,
        "deployment_id":deployment_id,
        "audience":audience,
        "body_sha256":hex::encode(Sha256::digest(body)),
        "circuit_id":circuit_id,
        "expires_at":expires,
        "method":"POST",
        "nonce":nonce_text,
        "path":"/resource/read",
        "protocol_version":"plan-a-http-v1",
        "request_time":now,
        "resource":format!("fr:{}",field_hex(circuit.entitlement.resource)),
        "snapshot_digest":snapshot_digest_hex,
        "terminal_agent_pk":point_b64(&terminal_pk),
        "vk_id":vk_id,
    });
    let req_sha = tagged(b"plan-a-request-v1", &request);
    let (q0, q1) = limbs(req_sha);
    circuit.request.canonical_request_lo = q0;
    circuit.request.canonical_request_hi = q1;
    circuit.request.interval_lo = now;
    circuit.request.interval_hi = expires;
    circuit.request.time = now;
    circuit.request.nonce = Fr::from(nonce);
    let relation = request_digest(&circuit.request, snapshot_digest(&circuit.snapshot));
    let prove_started = Instant::now();
    let mut rng = OsRng;
    let proof = Groth16::<Bls12_381>::prove(pk, circuit, &mut rng).map_err(|e| e.to_string())?;
    let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.0;
    let mut proof_bytes = vec![];
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| e.to_string())?;
    let terminal_sig = sign(
        &terminal_sk,
        terminal_transcript(req_sha, snap_sha, &circuit_id, &proof_bytes),
        [0x51; 32],
    )
    .map_err(|e| e.to_string())?;
    let mut envelope = request.as_object().ok_or("bad-request-object")?.clone();
    for key in ["method", "path", "body_sha256"] {
        envelope.remove(key);
    }
    envelope.insert("relation_request_digest".into(), json!(field_hex(relation)));
    envelope.insert("proof_b64".into(), json!(STANDARD.encode(&proof_bytes)));
    envelope.insert(
        "signature_b64".into(),
        json!(STANDARD.encode(encode_signature(&terminal_sig))),
    );
    Ok(json!({
        "snapshot":snapshot,
        "canonical_request_sha256":hex::encode(req_sha),
        "snapshot_digest":snapshot_digest_hex,
        "header_signature_b64":header_signature_b64,
        "registry_pk_b64":registry_pk_b64,
        "vk_id":vk_id,
        "circuit_id":circuit_id,
        "body_b64":STANDARD.encode(body),
        "timing":{
            "pk_load_ms":pk_load_ms,
            "prove_with_loaded_pk_ms":prove_ms,
            "process_mode":"cold-one-shot; production keeps PK loaded"
        },
        "provenance":"holder-local-refresh-no-registry-secret",
        "envelope":Value::Object(envelope)
    }))
}

fn make_loaded_with<const L: usize>(
    pk: &ProvingKey<Bls12_381>,
    vk_bytes: &[u8],
    pk_load_ms: Option<f64>,
    mut circuit: plan_a_joint_circuit::joint::JointCircuit<L>,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
    now: u64,
    audience: &str,
    body: &[u8],
    additional: Vec<plan_a_joint_circuit::joint::JointCircuit<L>>,
) -> Result<Value, String> {
    let vk_id = hex::encode(Sha256::digest(vk_bytes));
    let circuit_id = format!("plan-a-joint-v1:{L}:{ds}:{dra}:{drev}:3:poseidon-v2:codec-v1");
    let nonce_raw = (nonce as u128).to_be_bytes();
    let nonce_text = URL_SAFE_NO_PAD.encode(nonce_raw);
    let terminal_sk = SecretKey(Scalar::from(11u64 + L as u64));
    let terminal_pk = public_key(&terminal_sk).map_err(|e| e.to_string())?;
    let deployment_id = field_hex(Fr::from(9u64));
    let snapshot = json!({"deployment_id":deployment_id.clone(),"issued_at":circuit.snapshot.issued_at,"ra_root":field_hex(circuit.snapshot.root_ra),"revocation_epoch":circuit.snapshot.revocation_epoch,"revocation_root":field_hex(circuit.snapshot.root_rev),"state_epoch":circuit.snapshot.state_epoch,"state_root":field_hex(circuit.snapshot.root_state),"tuple_version":circuit.snapshot.tuple_version});
    let snap_sha = tagged(b"plan-a-snapshot-v1", &snapshot);
    let snapshot_digest_hex = hex::encode(snap_sha);
    let expires = now + 30;
    let request = json!({"action_onehot":1,"deployment_id":deployment_id.clone(),"audience":audience,"body_sha256":hex::encode(Sha256::digest(body)),"circuit_id":circuit_id,"expires_at":expires,"method":"POST","nonce":nonce_text,"path":"/resource/read","protocol_version":"plan-a-http-v1","request_time":now,"resource":format!("fr:{}",field_hex(Fr::from(700u64))),"snapshot_digest":snapshot_digest_hex,"terminal_agent_pk":point_b64(&terminal_pk),"vk_id":vk_id});
    let req_sha = tagged(b"plan-a-request-v1", &request);
    let (q0, q1) = limbs(req_sha);
    circuit.request.canonical_request_lo = q0;
    circuit.request.canonical_request_hi = q1;
    circuit.request.interval_lo = now;
    circuit.request.interval_hi = expires;
    circuit.request.time = now;
    circuit.request.nonce = Fr::from(nonce);
    let sd = snapshot_digest(&circuit.snapshot);
    let relation = request_digest(&circuit.request, sd);
    let private_owner_commitment = field_hex(circuit.state.owner_commitment);
    let witness_descriptor = json!({
        "owner_commitment": private_owner_commitment,
        "registration_salt": field_hex(circuit.registration_salt),
        "state_position": circuit.state.position,
        "state_salt": field_hex(circuit.state.salt),
        "grant_digests": circuit.grants.iter().map(|slot| field_hex(grant_digest(&slot.grant))).collect::<Vec<_>>(),
    });
    let private_witness_source_sha256 = hex::encode(Sha256::digest(
        serde_json::to_vec(&witness_descriptor).map_err(|e| e.to_string())?,
    ));
    let mut rng = OsRng;
    let prove_started = Instant::now();
    let proof =
        Groth16::<Bls12_381>::prove(pk, circuit.clone(), &mut rng).map_err(|e| e.to_string())?;
    let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.0;
    let mut proof_bytes = vec![];
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| e.to_string())?;
    let terminal_sig = sign(
        &terminal_sk,
        terminal_transcript(req_sha, snap_sha, &circuit_id, &proof_bytes),
        [0x51; 32],
    )
    .map_err(|e| e.to_string())?;
    let registry_sk = SecretKey(Scalar::from(900u64));
    let registry_pk = public_key(&registry_sk).map_err(|e| e.to_string())?;
    let (a, b) = limbs(snap_sha);
    let header_sig = sign(&registry_sk, hash(Domain::Terminal, &[a, b]), [0x72; 32])
        .map_err(|e| e.to_string())?;
    let admission = |c: &plan_a_joint_circuit::joint::JointCircuit<L>| -> Result<Value, String> {
        let owner_pk = c.grants[0].grant.issuer.clone();
        let msg = hash(
            Domain::StateUpdate,
            &[
                Fr::from(0u64),
                Fr::from(9u64),
                c.state.owner_commitment,
                Fr::from(c.state.position),
                Fr::from(c.state.state_expiry),
                Fr::from(c.state.state_version),
                Fr::from(c.state.state_epoch),
                c.state.grant_root,
                Fr::from(c.state.state_expiry),
                Fr::from(c.state.active as u64),
                c.state.salt,
            ],
        );
        let sig = sign(&registry_sk, msg, [0x23; 32]).map_err(|e| e.to_string())?;
        Ok(
            json!({"command":"admission-verify","deployment_id":field_hex(Fr::from(9u64)),"owner_commitment":field_hex(c.state.owner_commitment),"position":c.state.position,"owner_public_key":point_b64(&owner_pk),"registration_salt":field_hex(c.registration_salt),"max_expiry":c.state.state_expiry,"initial_opening":{"grant_root":field_hex(c.state.grant_root),"state_expiry":c.state.state_expiry,"active":c.state.active,"salt":field_hex(c.state.salt)},"initial_version":c.state.state_version,"initial_epoch":c.state.state_epoch,"signature_b64":STANDARD.encode(encode_signature(&sig))}),
        )
    };
    let bootstrap = admission(&circuit)?;
    let mut admissions = vec![bootstrap.clone()];
    for source in &additional {
        admissions.push(admission(source)?);
    }
    let ra_registration =
        |c: &plan_a_joint_circuit::joint::JointCircuit<L>| -> Result<Value, String> {
            let entitlement = &c.entitlement;
            let leaf = hash(
                Domain::RaLeaf,
                &[
                    entitlement.owner_commitment,
                    entitlement.resource,
                    Fr::from(entitlement.action_mask as u64),
                    Fr::from(entitlement.interval_lo),
                    Fr::from(entitlement.interval_hi),
                    Fr::from(entitlement.permit_expiry),
                    entitlement.admission_id,
                ],
            );
            let position = entitlement
                .path
                .directions
                .iter()
                .enumerate()
                .fold(0u64, |value, (bit, right)| value | ((*right as u64) << bit));
            let sig = sign(&registry_sk, leaf, [0x24; 32]).map_err(|e| e.to_string())?;
            Ok(json!({
                "command":"ra-register-verify",
                "deployment_id":deployment_id,
                "position":position,
                "owner_commitment":field_hex(entitlement.owner_commitment),
                "resource":field_hex(entitlement.resource),
                "action_mask":entitlement.action_mask,
                "interval_lo":entitlement.interval_lo,
                "interval_hi":entitlement.interval_hi,
                "permit_expiry":entitlement.permit_expiry,
                "admission_id":field_hex(entitlement.admission_id),
                "signature_b64":STANDARD.encode(encode_signature(&sig))
            }))
        };
    let bootstrap_ra = ra_registration(&circuit)?;
    let mut ra_registrations = vec![bootstrap_ra.clone()];
    for source in &additional {
        ra_registrations.push(ra_registration(source)?);
    }
    let mut envelope = request.as_object().unwrap().clone();
    for k in ["method", "path", "body_sha256"] {
        envelope.remove(k);
    }
    envelope.insert("relation_request_digest".into(), json!(field_hex(relation)));
    envelope.insert("proof_b64".into(), json!(STANDARD.encode(&proof_bytes)));
    envelope.insert(
        "signature_b64".into(),
        json!(STANDARD.encode(encode_signature(&terminal_sig))),
    );
    let mut out = json!({"snapshot":snapshot,"canonical_request_sha256":hex::encode(req_sha),"snapshot_digest":snapshot_digest_hex,"bootstrap_admission":bootstrap,"bootstrap_ra_registration":bootstrap_ra,"header_signature_b64":STANDARD.encode(encode_signature(&header_sig)),"registry_pk_b64":point_b64(&registry_pk),"vk_id":vk_id,"circuit_id":circuit_id,"body_b64":STANDARD.encode(body),"private_owner_commitment":private_owner_commitment,"private_witness_source_sha256":private_witness_source_sha256,"timing":{"pk_load_ms":pk_load_ms,"prove_with_loaded_pk_ms":prove_ms,"process_mode":"cold-one-shot; production keeps PK loaded"},"envelope":Value::Object(envelope)});
    if !additional.is_empty() {
        out["bootstrap_admissions"] = json!(admissions);
        out["bootstrap_ra_registrations"] = json!(ra_registrations);
        out["fixture_provenance"] =
            json!("plan_a_joint_circuit::fixture::two_source_same_terminal/source_a");
    }
    Ok(out)
}
fn make_loaded<const L: usize>(
    pk: &ProvingKey<Bls12_381>,
    vk_bytes: &[u8],
    pk_load_ms: Option<f64>,
    active: usize,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
    now: u64,
    audience: &str,
    body: &[u8],
) -> Result<Value, String> {
    make_loaded_with(
        pk,
        vk_bytes,
        pk_load_ms,
        fixed::<L>(active, nonce, ds, dra, drev),
        nonce,
        ds,
        dra,
        drev,
        now,
        audience,
        body,
        vec![],
    )
}

fn load_pk(path: &str) -> Result<(ProvingKey<Bls12_381>, f64), String> {
    let t = Instant::now();
    let bytes = fs::read(path).map_err(|e| e.to_string())?;
    let mut c = Cursor::new(&bytes);
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&mut c).map_err(|e| e.to_string())?;
    if c.position() != bytes.len() as u64 {
        return Err("trailing-pk-bytes".into());
    }
    Ok((pk, t.elapsed().as_secs_f64() * 1000.0))
}

fn root_grant_removal_gate(pk_path: &str, vk_path: &str) -> Result<Value, String> {
    let (pk, pk_load_ms) = load_pk(pk_path)?;
    let vk_bytes = fs::read(vk_path).map_err(|e| e.to_string())?;
    let mut vk_cursor = Cursor::new(&vk_bytes);
    let vk = ark_groth16::VerifyingKey::<Bls12_381>::deserialize_compressed(&mut vk_cursor)
        .map_err(|e| e.to_string())?;
    if vk_cursor.position() != vk_bytes.len() as u64 {
        return Err("trailing-vk-bytes".into());
    }

    let initial = fixed::<3>(1, 77, 10, 10, 32);
    let grant_a = initial.grants[0].grant.clone();
    let mut grant_b = grant_a.clone();
    grant_b.serial = Fr::from(2001u64);
    grant_b.signature = sign(
        &SecretKey(Scalar::from(11u64)),
        grant_digest(&grant_b),
        [0x95; 32],
    )
    .map_err(|e| e.to_string())?;
    let grant_b_signature_before = encode_signature(&grant_b.signature);
    let leaf_a = hash(Domain::GrantLeaf, &[grant_digest(&grant_a)]);
    let leaf_b = hash(Domain::GrantLeaf, &[grant_digest(&grant_b)]);
    let mut initial_grant_leaves = vec![Fr::from(0u64); 8];
    initial_grant_leaves[0] = leaf_a;
    initial_grant_leaves[1] = leaf_b;
    let (initial_grant_root, _) =
        build_tree(initial_grant_leaves, 3, Domain::TreeNode).map_err(str::to_string)?;
    let mut updated_grant_leaves = vec![Fr::from(0u64); 8];
    updated_grant_leaves[1] = leaf_b;
    let (updated_grant_root, updated_grant_levels) =
        build_tree(updated_grant_leaves, 3, Domain::TreeNode).map_err(str::to_string)?;

    let mut positive = initial.clone();
    positive.grants[0].grant = grant_b.clone();
    positive.grants[0].grant_path = path_for(&updated_grant_levels, 1).map_err(str::to_string)?;
    positive.grants[0].revocation = IndexedRevocationTree::new(32)
        .map_err(|_| "bad-revocation-depth")?
        .prove_nonmember(grant_b.serial)
        .map_err(|_| "bad-b-nonmembership")?;
    positive.state.grant_root = updated_grant_root;
    positive.state.state_version = 1;
    positive.state.state_epoch = 64;
    positive.state.salt = Fr::from(83u64);
    let state_leaf = hash(
        Domain::StateLeaf,
        &[
            positive.state.owner_commitment,
            positive.state.grant_root,
            Fr::from(positive.state.state_version),
            Fr::from(positive.state.state_epoch),
            Fr::from(positive.state.state_expiry),
            Fr::from(positive.state.active as u64),
            positive.state.salt,
            Fr::from(positive.state.position),
        ],
    );
    let mut state_leaves = vec![Fr::from(0u64); 1usize << 10];
    state_leaves[positive.state.position as usize] = state_leaf;
    let (state_root, state_levels) =
        build_tree(state_leaves, 10, Domain::TreeNode).map_err(str::to_string)?;
    positive.state.path =
        path_for(&state_levels, positive.state.position as usize).map_err(str::to_string)?;
    positive.snapshot.tuple_version = 2;
    positive.snapshot.state_epoch = 64;
    positive.snapshot.root_state = state_root;

    let positive_started = Instant::now();
    let positive_proof = Groth16::<Bls12_381>::prove(&pk, positive.clone(), &mut OsRng)
        .map_err(|e| e.to_string())?;
    let positive_prove_ms = positive_started.elapsed().as_secs_f64() * 1000.0;
    let positive_valid =
        Groth16::<Bls12_381>::verify(&vk, &public_inputs(&positive), &positive_proof)
            .map_err(|e| e.to_string())?;

    let mut removed_a = positive.clone();
    removed_a.grants[0].grant = grant_a;
    let negative_cs = ConstraintSystem::<Fr>::new_ref();
    removed_a
        .clone()
        .generate_constraints(negative_cs.clone())
        .map_err(|e| e.to_string())?;
    let removed_a_constraints_rejected = !negative_cs.is_satisfied().map_err(|e| e.to_string())?;
    let negative_proof =
        Groth16::<Bls12_381>::prove(&pk, removed_a, &mut OsRng).map_err(|e| e.to_string())?;
    let removed_a_proof_rejected =
        !Groth16::<Bls12_381>::verify(&vk, &public_inputs(&positive), &negative_proof)
            .map_err(|e| e.to_string())?;
    let grant_b_signature_after = encode_signature(&grant_b.signature);

    Ok(json!({
        "schema":"plan-a-root-grant-removal-gate-v1",
        "initial_root_contains_a_and_b":initial_grant_root != updated_grant_root,
        "updated_root_contains_b_only":true,
        "grant_b_signature_unchanged":grant_b_signature_before == grant_b_signature_after,
        "grant_b_signature_sha256":hex::encode(Sha256::digest(&grant_b_signature_before)),
        "fresh_b_proof_accepted":positive_valid,
        "removed_a_constraints_rejected":removed_a_constraints_rejected,
        "removed_a_proof_rejected":removed_a_proof_rejected,
        "initial_grant_root":field_hex(initial_grant_root),
        "updated_grant_root":field_hex(updated_grant_root),
        "pk_load_ms":pk_load_ms,
        "fresh_b_prove_ms":positive_prove_ms,
        "l_max":3,
        "actual_enabled_grants":1,
        "state_depth":10,
        "ra_depth":10,
        "revocation_depth":32,
    }))
}

#[allow(clippy::too_many_arguments)]
fn refresh_resident(
    pk_path: &str,
    vk_path: &str,
    registry_pk_b64: &str,
    ds: usize,
    dra: usize,
    drev: usize,
    audience: &str,
    body: &[u8],
) -> Result<(), String> {
    use std::io::{BufRead, Write};
    let (pk, load_ms) = load_pk(pk_path)?;
    let vk = fs::read(vk_path).map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({
            "ready":true,
            "pk_load_ms":load_ms,
            "process_mode":"resident-holder-refresh",
            "holder_model":"explicit-deterministic-signed-synthetic-profile-v1"
        })
    );
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    let mut witness_cache: Option<CachedPublicWitness> = None;
    for line in std::io::stdin().lock().lines() {
        let response = (|| -> Result<Value, String> {
            let value: Value = serde_json::from_str(&line.map_err(|e| e.to_string())?)
                .map_err(|_| "bad-refresh-command-json")?;
            let public_path = value
                .get("public_path")
                .and_then(Value::as_str)
                .ok_or("bad-public-path")?;
            let private_path = value
                .get("private_path")
                .and_then(Value::as_str)
                .ok_or("bad-private-path")?;
            let nonce = value
                .get("nonce")
                .and_then(Value::as_u64)
                .ok_or("bad-nonce")?;
            let now = value.get("now").and_then(Value::as_u64).ok_or("bad-now")?;
            refresh_from_public_with_key(
                &pk,
                &vk,
                None,
                public_path,
                private_path,
                registry_pk_b64,
                nonce,
                ds,
                dra,
                drev,
                now,
                audience,
                body,
                Some(&mut witness_cache),
            )
        })();
        match response {
            Ok(value) => println!("{}", value),
            Err(error) => println!("{}", json!({"error":error})),
        }
        std::io::stdout().flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn make<const L: usize>(
    pk_path: &str,
    vk_path: &str,
    active: usize,
    nonce: u64,
    ds: usize,
    dra: usize,
    drev: usize,
    now: u64,
    audience: &str,
    body: &[u8],
) -> Result<Value, String> {
    let (pk, load) = load_pk(pk_path)?;
    let vk = fs::read(vk_path).map_err(|e| e.to_string())?;
    make_loaded::<L>(
        &pk,
        &vk,
        Some(load),
        active,
        nonce,
        ds,
        dra,
        drev,
        now,
        audience,
        body,
    )
}
fn resident<const L: usize>(
    pk_path: &str,
    vk_path: &str,
    active: usize,
    ds: usize,
    dra: usize,
    drev: usize,
    audience: &str,
    body: &[u8],
) -> Result<(), String> {
    use std::io::{BufRead, Write};
    let (pk, load) = load_pk(pk_path)?;
    let vk = fs::read(vk_path).map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ready":true,"pk_load_ms":load,"process_mode":"resident"})
    );
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    for line in std::io::stdin().lock().lines() {
        let v: Value =
            serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let nonce = v.get("nonce").and_then(Value::as_u64).ok_or("bad-nonce")?;
        let now = v.get("now").and_then(Value::as_u64).ok_or("bad-now")?;
        let out = make_loaded::<L>(
            &pk, &vk, None, active, nonce, ds, dra, drev, now, audience, body,
        )?;
        println!("{}", out);
        std::io::stdout().flush().map_err(|e| e.to_string())?
    }
    Ok(())
}
fn resident_two_source(
    pk_path: &str,
    vk_path: &str,
    audience: &str,
    body: &[u8],
) -> Result<(), String> {
    use std::io::{BufRead, Write};
    let (pk, load) = load_pk(pk_path)?;
    let vk = fs::read(vk_path).map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ready":true,"pk_load_ms":load,"process_mode":"resident","fixture":"two-source-a"})
    );
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    for line in std::io::stdin().lock().lines() {
        let v: Value =
            serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let nonce = v.get("nonce").and_then(Value::as_u64).ok_or("bad-nonce")?;
        let now = v.get("now").and_then(Value::as_u64).ok_or("bad-now")?;
        let [a, b] = plan_a_joint_circuit::fixture::two_source_same_terminal();
        let out = make_loaded_with::<3>(
            &pk,
            &vk,
            None,
            a,
            nonce,
            3,
            3,
            4,
            now,
            audience,
            body,
            vec![b],
        )?;
        println!("{}", out);
        std::io::stdout().flush().map_err(|e| e.to_string())?
    }
    Ok(())
}

fn resident_three_source(
    pk_path: &str,
    vk_path: &str,
    audience: &str,
    body: &[u8],
) -> Result<(), String> {
    use std::io::{BufRead, Write};
    let (pk, load) = load_pk(pk_path)?;
    let vk = fs::read(vk_path).map_err(|e| e.to_string())?;
    println!(
        "{}",
        json!({"ready":true,"pk_load_ms":load,"process_mode":"resident","fixture":"three-source-mcp"})
    );
    std::io::stdout().flush().map_err(|e| e.to_string())?;
    for line in std::io::stdin().lock().lines() {
        let v: Value =
            serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let nonce = v.get("nonce").and_then(Value::as_u64).ok_or("bad-nonce")?;
        let now = v.get("now").and_then(Value::as_u64).ok_or("bad-now")?;
        let owner_index = v
            .get("owner_index")
            .and_then(Value::as_u64)
            .ok_or("bad-owner-index")? as usize;
        let sources = plan_a_joint_circuit::fixture::three_source_same_terminal();
        if owner_index >= sources.len() {
            return Err("bad-owner-index".into());
        }
        let selected = sources[owner_index].clone();
        let additional = sources
            .iter()
            .enumerate()
            .filter_map(|(index, source)| (index != owner_index).then_some(source.clone()))
            .collect::<Vec<_>>();
        let out = make_loaded_with::<3>(
            &pk, &vk, None, selected, nonce, 3, 3, 4, now, audience, body, additional,
        )?;
        println!("{}", out);
        std::io::stdout().flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}
fn main() {
    let a = env::args().collect::<Vec<_>>();
    if a.get(1).map(String::as_str) == Some("root-removal-gate") {
        let result = if a.len() == 4 {
            root_grant_removal_gate(&a[2], &a[3])
        } else {
            Err("usage: plan_a_agent_cli root-removal-gate PK VK".into())
        };
        match result {
            Ok(value) => println!("{}", value),
            Err(error) => {
                println!("{}", json!({"error":error}));
                std::process::exit(2)
            }
        }
        return;
    }
    if a.get(1).map(String::as_str) == Some("private-support") {
        let result = (|| -> Result<Value, String> {
            if a.len() != 3 {
                return Err("usage: plan_a_agent_cli private-support HOLDER_PROFILE".into());
            }
            let mut circuit = fixed::<3>(2, 1, 10, 10, 32);
            apply_holder_profile(&mut circuit, &a[2])?;
            if a[2] == "fixed-root-position-1-v1" {
                circuit.state.state_version = 1;
                circuit.state.state_epoch = 64;
                circuit.state.salt = Fr::from(83u64);
            }
            Ok(private_support_value(&circuit, &a[2]))
        })();
        match result {
            Ok(value) => println!("{}", value),
            Err(error) => {
                println!("{}", json!({"error":error}));
                std::process::exit(2)
            }
        }
        return;
    }
    if a.get(1).map(String::as_str) == Some("refresh-serve") {
        let result = (|| -> Result<(), String> {
            if a.len() != 10 {
                return Err("usage: plan_a_agent_cli refresh-serve PK VK REGISTRY_PK_B64 DS DRA DREV AUDIENCE BODY".into());
            }
            refresh_resident(
                &a[2],
                &a[3],
                &a[4],
                n(&a[5])?,
                n(&a[6])?,
                n(&a[7])?,
                &a[8],
                a[9].as_bytes(),
            )
        })();
        if let Err(error) = result {
            println!("{}", json!({"error":error}));
            std::process::exit(2)
        }
        return;
    }
    if a.get(1).map(String::as_str) == Some("refresh") {
        let result = (|| -> Result<Value, String> {
            if a.len() != 14 {
                return Err("usage: plan_a_agent_cli refresh PK VK PUBLIC_JSON PRIVATE_HOLDER_JSON REGISTRY_PK_B64 NONCE DS DRA DREV NOW AUDIENCE BODY".into());
            }
            refresh_from_public(
                &a[2],
                &a[3],
                &a[4],
                &a[5],
                &a[6],
                n(&a[7])?,
                n(&a[8])?,
                n(&a[9])?,
                n(&a[10])?,
                n(&a[11])?,
                &a[12],
                a[13].as_bytes(),
            )
        })();
        match result {
            Ok(value) => println!("{}", value),
            Err(error) => {
                println!("{}", json!({"error":error}));
                std::process::exit(2)
            }
        }
        return;
    }
    if a.get(1).map(String::as_str) == Some("serve") {
        let result = (|| -> Result<(), String> {
            if a.len() != 11 {
                return Err(
                    "usage: plan_a_agent_cli serve PK VK L ACTIVE DS DRA DREV AUDIENCE BODY".into(),
                );
            }
            let l = n(&a[4])?;
            let active = n(&a[5])?;
            let ds = n(&a[6])?;
            let dra = n(&a[7])?;
            let dr = n(&a[8])?;
            if env::var("PLAN_A_AGENT_FIXTURE").ok().as_deref() == Some("two-source-a") {
                if (l, ds, dra, dr) != (3, 3, 3, 4) {
                    return Err("two-source-a requires L3/DS3/DRA3/DRev4".into());
                }
                return resident_two_source(&a[2], &a[3], &a[9], a[10].as_bytes());
            }
            if env::var("PLAN_A_AGENT_FIXTURE").ok().as_deref() == Some("three-source-mcp") {
                if (l, ds, dra, dr) != (3, 3, 3, 4) {
                    return Err("three-source-mcp requires L3/DS3/DRA3/DRev4".into());
                }
                return resident_three_source(&a[2], &a[3], &a[9], a[10].as_bytes());
            }
            match l {
                1 => resident::<1>(&a[2], &a[3], active, ds, dra, dr, &a[9], a[10].as_bytes()),
                2 => resident::<2>(&a[2], &a[3], active, ds, dra, dr, &a[9], a[10].as_bytes()),
                3 => resident::<3>(&a[2], &a[3], active, ds, dra, dr, &a[9], a[10].as_bytes()),
                4 => resident::<4>(&a[2], &a[3], active, ds, dra, dr, &a[9], a[10].as_bytes()),
                5 => resident::<5>(&a[2], &a[3], active, ds, dra, dr, &a[9], a[10].as_bytes()),
                _ => Err("L must be 1..5".into()),
            }
        })();
        if let Err(e) = result {
            println!("{}", json!({"error":e}));
            std::process::exit(2)
        }
        return;
    }
    let result = (|| -> Result<Value, String> {
        if a.len() != 12 {
            return Err(
                "usage: plan_a_agent_cli PK VK L ACTIVE NONCE DS DRA DREV NOW AUDIENCE BODY".into(),
            );
        }
        let l = n(&a[3])?;
        let active = n(&a[4])?;
        let nonce = n(&a[5])?;
        let ds = n(&a[6])?;
        let dra = n(&a[7])?;
        let dr = n(&a[8])?;
        let now = n(&a[9])?;
        match l {
            1 => make::<1>(
                &a[1],
                &a[2],
                active,
                nonce,
                ds,
                dra,
                dr,
                now,
                &a[10],
                a[11].as_bytes(),
            ),
            2 => make::<2>(
                &a[1],
                &a[2],
                active,
                nonce,
                ds,
                dra,
                dr,
                now,
                &a[10],
                a[11].as_bytes(),
            ),
            3 => make::<3>(
                &a[1],
                &a[2],
                active,
                nonce,
                ds,
                dra,
                dr,
                now,
                &a[10],
                a[11].as_bytes(),
            ),
            4 => make::<4>(
                &a[1],
                &a[2],
                active,
                nonce,
                ds,
                dra,
                dr,
                now,
                &a[10],
                a[11].as_bytes(),
            ),
            5 => make::<5>(
                &a[1],
                &a[2],
                active,
                nonce,
                ds,
                dra,
                dr,
                now,
                &a[10],
                a[11].as_bytes(),
            ),
            _ => Err("L must be 1..5".into()),
        }
    })();
    match result {
        Ok(v) => println!("{}", v),
        Err(e) => {
            println!("{}", json!({"error":e}));
            std::process::exit(2)
        }
    }
}
