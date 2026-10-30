//! JSON verification core for the HTTP service. VK and registry key are
//! trusted process configuration; callers cannot select either one.
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use plan_a_joint_circuit::{
    blind_update::{
        authorization_digest, public_inputs as blind_public_inputs, BlindUpdateStatement,
    },
    blind_update_sr::proof_sha256_limbs,
    contract::{terminal_transcript, Request, Snapshot},
    indexed_revocation::{derive_serial, IndexedRevocationTree},
    joint::{request_digest, snapshot_digest},
    merkle::node_hash,
    poseidon::{hash, Domain},
    signature::{decode_public_key, decode_signature, verify},
    state_registry::{owner_commitment, update_digest, StateLeafOpening},
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::{
    env,
    fs::File,
    io::{self, BufReader, Read},
    time::Instant,
};

fn sha(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update([0]);
    h.update(bytes);
    h.finalize().into()
}
fn limbs(x: [u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u128::from_be_bytes(x[..16].try_into().unwrap())),
        Fr::from(u128::from_be_bytes(x[16..].try_into().unwrap())),
    )
}
fn semantic_field(s: &str) -> Result<Fr, String> {
    s.strip_prefix("fr:")
        .ok_or_else(|| "resource-must-be-canonical-field".into())
        .and_then(field_hex)
}
fn nonce_field(s: &str) -> Result<Fr, String> {
    let bytes = URL_SAFE_NO_PAD.decode(s).map_err(|_| "bad-nonce")?;
    Ok(Fr::from_be_bytes_mod_order(&bytes))
}
fn field_hex(s: &str) -> Result<Fr, String> {
    let b = hex::decode(s).map_err(|_| "bad-field-hex")?;
    if b.len() != 32 {
        return Err("bad-field-length".into());
    }
    let f = Fr::from_be_bytes_mod_order(&b);
    let mut canonical = plan_a_joint_circuit::poseidon::canonical_le_bytes(f);
    canonical.reverse();
    if canonical.as_slice() != b {
        return Err("noncanonical-field".into());
    }
    Ok(f)
}
fn b64(s: &str) -> Result<Vec<u8>, String> {
    STANDARD.decode(s).map_err(|_| "bad-base64".into())
}
fn u(v: &Value, k: &str) -> Result<u64, String> {
    v.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("bad-{k}"))
}
fn s<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("bad-{k}"))
}
fn canonical(v: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| e.to_string())
}
fn configured() -> Result<(String, String, usize, usize, usize, VerifyingKey<Bls12_381>), String> {
    let vk_path = env::var("PLAN_A_VK_PATH").map_err(|_| "missing-vk-path")?;
    let claimed = env::var("PLAN_A_VK_ID").map_err(|_| "missing-vk-id")?;
    let bytes = std::fs::read(vk_path).map_err(|e| e.to_string())?;
    let actual = hex::encode(Sha256::digest(&bytes));
    if claimed != actual {
        return Err("vk-id-mismatch".into());
    }
    let mut cursor = &bytes[..];
    let vk = VerifyingKey::deserialize_compressed(&mut cursor).map_err(|e| e.to_string())?;
    if !cursor.is_empty() {
        return Err("trailing-vk-bytes".into());
    }
    let l = env::var("PLAN_A_L")
        .map_err(|_| "missing-L")?
        .parse::<usize>()
        .map_err(|_| "bad-L")?;
    let ds = env::var("PLAN_A_DS")
        .map_err(|_| "missing-DS")?
        .parse::<usize>()
        .map_err(|_| "bad-DS")?;
    let dra = env::var("PLAN_A_DRA")
        .map_err(|_| "missing-DRA")?
        .parse::<usize>()
        .map_err(|_| "bad-DRA")?;
    let dr = env::var("PLAN_A_DREV")
        .map_err(|_| "missing-DREV")?
        .parse::<usize>()
        .map_err(|_| "bad-DREV")?;
    let circuit = format!("plan-a-joint-v1:{l}:{ds}:{dra}:{dr}:3:poseidon-v2:codec-v1");
    Ok((actual, circuit, l, ds, dra, vk))
}
fn verify_proof(v: &Value) -> Result<bool, String> {
    let (vk_id, circuit, l, ds, dra, vk) = configured()?;
    let statement = v.get("public_statement").ok_or("missing-statement")?;
    let request = statement.get("request").ok_or("missing-request")?;
    let snap = statement.get("snapshot").ok_or("missing-snapshot")?;
    let deployment = env::var("PLAN_A_DEPLOYMENT_ID").map_err(|_| "missing-deployment")?;
    if s(request, "deployment_id")? != deployment || s(snap, "deployment_id")? != deployment {
        return Ok(false);
    }
    if s(v, "vk_id")? != vk_id
        || s(request, "vk_id")? != vk_id
        || s(request, "circuit_id")? != circuit
    {
        return Ok(false);
    }
    let request_sha = sha(b"plan-a-request-v1", &canonical(request)?);
    if hex::encode(request_sha) != s(statement, "canonical_request_sha256")? {
        return Ok(false);
    }
    let snapshot_sha = sha(b"plan-a-snapshot-v1", &canonical(snap)?);
    if hex::encode(snapshot_sha) != s(request, "snapshot_digest")? {
        return Ok(false);
    }
    let action = u(request, "action_onehot")?;
    if action == 0 || action > u16::MAX as u64 || (action & (action - 1)) != 0 {
        return Ok(false);
    }
    let dr = env::var("PLAN_A_DREV").unwrap().parse::<usize>().unwrap();
    let desc: [u8; 32] =
        Sha256::digest(plan_a_joint_circuit::poseidon::descriptor().as_bytes()).into();
    let (dl, dh) = limbs(desc);
    let expected_cid = hash(
        Domain::Request,
        &[
            Fr::from(1u64),
            Fr::from(l as u64),
            Fr::from(ds as u64),
            Fr::from(dra as u64),
            Fr::from(dr as u64),
            Fr::from(3u64),
            dl,
            dh,
            Fr::from(1u64),
        ],
    );
    let snapshot = Snapshot {
        tuple_version: u(snap, "tuple_version")?,
        root_ra: field_hex(s(snap, "ra_root")?)?,
        root_state: field_hex(s(snap, "state_root")?)?,
        root_rev: field_hex(s(snap, "revocation_root")?)?,
        state_epoch: u(snap, "state_epoch")?,
        revocation_epoch: u(snap, "revocation_epoch")?,
        issued_at: u(snap, "issued_at")?,
    };
    let sha_hex = s(statement, "canonical_request_sha256")?;
    let sha_bytes: [u8; 32] = hex::decode(sha_hex)
        .map_err(|_| "bad-request-sha")?
        .try_into()
        .map_err(|_| "bad-request-sha")?;
    let (q0, q1) = limbs(sha_bytes);
    let terminal = decode_public_key(&b64(s(request, "terminal_agent_pk")?)?)
        .map_err(|_| "bad-terminal-pk")?;
    let req = Request {
        canonical_request_lo: q0,
        canonical_request_hi: q1,
        circuit_id: expected_cid,
        verifier_id: Fr::from(78u64),
        pep_id: Fr::from(79u64),
        resource: semantic_field(s(request, "resource")?)?,
        action_onehot: u(request, "action_onehot")? as u16,
        interval_lo: u(request, "request_time")?,
        interval_hi: u(request, "expires_at")?,
        time: u(request, "request_time")?,
        nonce: nonce_field(s(request, "nonce")?)?,
        context: Fr::from(80u64),
        terminal,
    };
    let sd = snapshot_digest(&snapshot);
    let rd = request_digest(&req, sd);
    if field_hex(s(statement, "relation_request_digest")?)? != rd {
        return Ok(false);
    }
    let inputs = vec![
        Fr::from(snapshot.tuple_version),
        snapshot.root_ra,
        snapshot.root_state,
        snapshot.root_rev,
        Fr::from(snapshot.state_epoch),
        Fr::from(snapshot.revocation_epoch),
        Fr::from(snapshot.issued_at),
        sd,
        q0,
        q1,
        req.circuit_id,
        req.verifier_id,
        req.pep_id,
        req.resource,
        Fr::from(req.action_onehot as u64),
        Fr::from(req.interval_lo),
        Fr::from(req.interval_hi),
        Fr::from(req.time),
        req.nonce,
        req.context,
        req.terminal.0.x,
        req.terminal.0.y,
        rd,
    ];
    let proof_bytes = b64(s(v, "proof_b64")?)?;
    let mut proof_cursor = &proof_bytes[..];
    let proof = Proof::deserialize_compressed(&mut proof_cursor).map_err(|_| "bad-proof")?;
    if !proof_cursor.is_empty() {
        return Err("trailing-proof-bytes".into());
    }
    Groth16::<Bls12_381>::verify(&vk, &inputs, &proof).map_err(|e| e.to_string())
}
fn terminal(v: &Value) -> Result<bool, String> {
    let (_, circuit, _, _, _, _) = configured()?;
    let deployment = env::var("PLAN_A_DEPLOYMENT_ID").map_err(|_| "missing-deployment")?;
    if s(v, "deployment_id")? != deployment || s(v, "circuit_id")? != circuit {
        return Ok(false);
    }
    let req: [u8; 32] = hex::decode(s(v, "canonical_request_sha256")?)
        .map_err(|_| "bad-request-sha")?
        .try_into()
        .map_err(|_| "bad-request-sha")?;
    let snap: [u8; 32] = hex::decode(s(v, "snapshot_digest")?)
        .map_err(|_| "bad-snapshot-sha")?
        .try_into()
        .map_err(|_| "bad-snapshot-sha")?;
    let proof = b64(s(v, "proof_b64")?)?;
    let pk = decode_public_key(&b64(s(v, "terminal_agent_pk")?)?).map_err(|_| "bad-terminal-pk")?;
    let sig =
        decode_signature(&b64(s(v, "signature_b64")?)?).map_err(|_| "bad-terminal-signature")?;
    Ok(verify(
        &pk,
        terminal_transcript(req, snap, &circuit, &proof),
        &sig,
    ))
}
fn header(v: &Value) -> Result<bool, String> {
    let deployment = env::var("PLAN_A_DEPLOYMENT_ID").map_err(|_| "missing-deployment")?;
    let snapshot = v.get("snapshot").ok_or("missing-snapshot")?;
    if s(snapshot, "deployment_id")? != deployment {
        return Ok(false);
    }
    let pk = decode_public_key(&b64(
        &env::var("PLAN_A_REGISTRY_PK_B64").map_err(|_| "missing-registry-key")?
    )?)
    .map_err(|_| "bad-registry-key")?;
    let digest = sha(b"plan-a-snapshot-v1", &canonical(snapshot)?);
    let (a, b) = limbs(digest);
    let msg = hash(Domain::Terminal, &[a, b]);
    let sig =
        decode_signature(&b64(s(v, "signature_b64")?)?).map_err(|_| "bad-header-signature")?;
    Ok(verify(&pk, msg, &sig))
}
fn admission(v: &Value) -> Result<Value, String> {
    let trusted_deployment = env::var("PLAN_A_DEPLOYMENT_ID").map_err(|_| "missing-deployment")?;
    if s(v, "deployment_id")? != trusted_deployment {
        return Ok(json!({"valid":false}));
    }
    let registry = decode_public_key(&b64(
        &env::var("PLAN_A_REGISTRY_PK_B64").map_err(|_| "missing-registry-key")?
    )?)
    .map_err(|_| "bad-registry-key")?;
    let owner_pk =
        decode_public_key(&b64(s(v, "owner_public_key")?)?).map_err(|_| "bad-owner-key")?;
    let deployment = field_hex(s(v, "deployment_id")?)?;
    let registration_salt = field_hex(s(v, "registration_salt")?)?;
    let owner = field_hex(s(v, "owner_commitment")?)?;
    if owner_commitment(owner_pk.0.x, owner_pk.0.y, registration_salt) != owner {
        return Ok(json!({"valid":false}));
    }
    let position = u(v, "position")?;
    if position > u32::MAX as u64 {
        return Err("bad-position".into());
    }
    let max_expiry = u(v, "max_expiry")?;
    let version = u(v, "initial_version")?;
    if version != 0 {
        return Ok(json!({"valid":false}));
    }
    let epoch = u(v, "initial_epoch")?;
    let opening_v = v.get("initial_opening").ok_or("missing-initial-opening")?;
    let opening = StateLeafOpening {
        grant_root: field_hex(s(opening_v, "grant_root")?)?,
        state_expiry: u(opening_v, "state_expiry")?,
        active: opening_v
            .get("active")
            .and_then(Value::as_bool)
            .ok_or("bad-active")?,
        salt: field_hex(s(opening_v, "salt")?)?,
    };
    if opening.state_expiry > max_expiry {
        return Ok(json!({"valid":false}));
    }
    let msg = hash(
        Domain::StateUpdate,
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
    let sig =
        decode_signature(&b64(s(v, "signature_b64")?)?).map_err(|_| "bad-admission-signature")?;
    if !verify(&registry, msg, &sig) {
        return Ok(json!({"valid":false}));
    }
    let leaf = hash(
        Domain::StateLeaf,
        &[
            owner,
            opening.grant_root,
            Fr::from(version),
            Fr::from(epoch),
            Fr::from(opening.state_expiry),
            Fr::from(opening.active as u64),
            opening.salt,
            Fr::from(position),
        ],
    );
    Ok(
        json!({"valid":true,"owner_commitment":field_hex_out(owner),"position":position,"initial_leaf":field_hex_out(leaf),"initial_version":version,"initial_epoch":epoch,"active":opening.active,"max_expiry":max_expiry}),
    )
}
fn ra_register(v: &Value) -> Result<Value, String> {
    let trusted_deployment = env::var("PLAN_A_DEPLOYMENT_ID").map_err(|_| "missing-deployment")?;
    if s(v, "deployment_id")? != trusted_deployment {
        return Ok(json!({"valid":false}));
    }
    let registry = decode_public_key(&b64(
        &env::var("PLAN_A_REGISTRY_PK_B64").map_err(|_| "missing-registry-key")?
    )?)
    .map_err(|_| "bad-registry-key")?;
    let position = u(v, "position")?;
    let dra = env::var("PLAN_A_DRA")
        .map_err(|_| "missing-DRA")?
        .parse::<usize>()
        .map_err(|_| "bad-DRA")?;
    if position >= 1u64.checked_shl(dra as u32).unwrap_or(0) {
        return Err("bad-ra-position".into());
    }
    let owner = field_hex(s(v, "owner_commitment")?)?;
    let resource = field_hex(s(v, "resource")?)?;
    let action_mask = u(v, "action_mask")?;
    if action_mask == 0 || action_mask > u16::MAX as u64 {
        return Err("bad-action-mask".into());
    }
    let interval_lo = u(v, "interval_lo")?;
    let interval_hi = u(v, "interval_hi")?;
    let permit_expiry = u(v, "permit_expiry")?;
    if interval_lo > interval_hi || interval_hi > permit_expiry {
        return Ok(json!({"valid":false}));
    }
    let admission_id = field_hex(s(v, "admission_id")?)?;
    let leaf = hash(
        Domain::RaLeaf,
        &[
            owner,
            resource,
            Fr::from(action_mask),
            Fr::from(interval_lo),
            Fr::from(interval_hi),
            Fr::from(permit_expiry),
            admission_id,
        ],
    );
    let signature =
        decode_signature(&b64(s(v, "signature_b64")?)?).map_err(|_| "bad-ra-signature")?;
    if !verify(&registry, leaf, &signature) {
        return Ok(json!({"valid":false}));
    }
    Ok(json!({"valid":true,"position":position,"leaf":field_hex_out(leaf)}))
}
fn state_update(v: &Value) -> Result<Value, String> {
    let trusted_deployment = env::var("PLAN_A_DEPLOYMENT_ID").map_err(|_| "missing-deployment")?;
    if s(v, "deployment_id")? != trusted_deployment {
        return Ok(json!({"valid":false}));
    }
    let pk = decode_public_key(&b64(s(v, "owner_public_key")?)?).map_err(|_| "bad-owner-key")?;
    let registration_salt = field_hex(s(v, "registration_salt")?)?;
    let owner = field_hex(s(v, "owner_commitment")?)?;
    if owner_commitment(pk.0.x, pk.0.y, registration_salt) != owner {
        return Ok(json!({"valid":false}));
    }
    let position = u(v, "position")?;
    if position > u32::MAX as u64 {
        return Err("bad-position".into());
    }
    let version = u(v, "expected_version")?;
    let old_epoch = u(v, "current_epoch")?;
    let new_epoch = u(v, "new_epoch")?;
    let old_active = v
        .get("current_active")
        .and_then(Value::as_bool)
        .ok_or("bad-current-active")?;
    let opening_v = v.get("opening").ok_or("missing-opening")?;
    let opening = StateLeafOpening {
        grant_root: field_hex(s(opening_v, "grant_root")?)?,
        state_expiry: u(opening_v, "state_expiry")?,
        active: opening_v
            .get("active")
            .and_then(Value::as_bool)
            .ok_or("bad-active")?,
        salt: field_hex(s(opening_v, "salt")?)?,
    };
    if new_epoch <= old_epoch
        || opening.state_expiry > u(v, "max_expiry")?
        || (!old_active && opening.active)
    {
        return Ok(json!({"valid":false}));
    }
    let deployment = field_hex(s(v, "deployment_id")?)?;
    let sig =
        decode_signature(&b64(s(v, "signature_b64")?)?).map_err(|_| "bad-update-signature")?;
    if !verify(
        &pk,
        update_digest(
            deployment,
            owner,
            position as u32,
            version,
            new_epoch,
            &opening,
        ),
        &sig,
    ) {
        return Ok(json!({"valid":false}));
    }
    let next_version = version.checked_add(1).ok_or("version-overflow")?;
    let leaf = hash(
        Domain::StateLeaf,
        &[
            owner,
            opening.grant_root,
            Fr::from(next_version),
            Fr::from(new_epoch),
            Fr::from(opening.state_expiry),
            Fr::from(opening.active as u64),
            opening.salt,
            Fr::from(position),
        ],
    );
    Ok(
        json!({"valid":true,"new_leaf":field_hex_out(leaf),"new_version":next_version,"new_epoch":new_epoch,"active":opening.active}),
    )
}
fn blind_state_update(v: &Value) -> Result<Value, String> {
    let trusted_deployment =
        field_hex(&env::var("PLAN_A_DEPLOYMENT_ID").map_err(|_| "missing-deployment")?)?;
    let trusted_config =
        field_hex(&env::var("PLAN_A_BLIND_CONFIG_DIGEST").map_err(|_| "missing-blind-config")?)?;
    let trusted_circuit =
        field_hex(&env::var("PLAN_A_BLIND_CIRCUIT_ID").map_err(|_| "missing-blind-circuit")?)?;
    let statement_v = v.get("statement").ok_or("missing-statement")?;
    let admission = v
        .get("trusted_admission")
        .ok_or("missing-trusted-admission")?;
    let position = u(statement_v, "position")?;
    if position > u32::MAX as u64 {
        return Err("bad-position".into());
    }
    let statement = BlindUpdateStatement {
        config_digest: field_hex(s(statement_v, "config_digest")?)?,
        deployment: field_hex(s(statement_v, "deployment_id")?)?,
        circuit_id: field_hex(s(statement_v, "circuit_id")?)?,
        owner: field_hex(s(statement_v, "owner_commitment")?)?,
        position: position as u32,
        expiry_cap: u(statement_v, "expiry_cap")?,
        admission_version: u(statement_v, "admission_version")?,
        old_leaf: field_hex(s(statement_v, "old_leaf")?)?,
        new_leaf: field_hex(s(statement_v, "new_leaf")?)?,
        old_version: u(statement_v, "old_version")?,
        new_version: u(statement_v, "new_version")?,
        old_epoch: u(statement_v, "old_epoch")?,
        new_epoch: u(statement_v, "new_epoch")?,
    };
    if statement.config_digest != trusted_config
        || statement.deployment != trusted_deployment
        || statement.circuit_id != trusted_circuit
        || s(admission, "owner_commitment")? != s(statement_v, "owner_commitment")?
        || u(admission, "position")? != position
        || u(admission, "expiry_cap")? != statement.expiry_cap
        || u(admission, "admission_version")? != statement.admission_version
    {
        return Ok(json!({"valid":false}));
    }
    let vk_path = env::var("PLAN_A_BLIND_UPDATE_VK_PATH").map_err(|_| "missing-blind-vk")?;
    let vk_bytes = std::fs::read(vk_path).map_err(|e| e.to_string())?;
    let actual_vk_id = hex::encode(Sha256::digest(&vk_bytes));
    if actual_vk_id != env::var("PLAN_A_BLIND_UPDATE_VK_ID").map_err(|_| "missing-blind-vk-id")? {
        return Err("blind-vk-id-mismatch".into());
    }
    let mut vk_cursor = &vk_bytes[..];
    let vk = VerifyingKey::deserialize_compressed(&mut vk_cursor).map_err(|_| "bad-blind-vk")?;
    if !vk_cursor.is_empty() {
        return Err("trailing-blind-vk".into());
    }
    let proof_bytes = b64(s(v, "proof_b64")?)?;
    let mut proof_cursor = &proof_bytes[..];
    let proof = Proof::deserialize_compressed(&mut proof_cursor).map_err(|_| "bad-blind-proof")?;
    if !proof_cursor.is_empty() {
        return Err("trailing-blind-proof".into());
    }
    let blind_inputs = blind_public_inputs(&statement);
    let proof_verify_started = Instant::now();
    let proof_valid = Groth16::<Bls12_381>::verify(&vk, &blind_inputs, &proof)
        .map_err(|e| e.to_string())?
    ;
    let pure_proof_verify_ns = proof_verify_started.elapsed().as_nanos() as u64;
    if !proof_valid {
        return Ok(json!({"valid":false}));
    }
    let owner_pk =
        decode_public_key(&b64(s(admission, "owner_public_key")?)?).map_err(|_| "bad-owner-key")?;
    let signature = decode_signature(&b64(s(v, "signature_b64")?)?)
        .map_err(|_| "bad-blind-update-signature")?;
    if !verify(
        &owner_pk,
        authorization_digest(
            &statement,
            proof_sha256_limbs(&proof).map_err(|e| e.to_string())?,
        ),
        &signature,
    ) {
        return Ok(json!({"valid":false}));
    }
    let mut output = json!({
        "valid":true,
        "owner_commitment":s(statement_v,"owner_commitment")?,
        "position":position,
        "old_leaf":s(statement_v,"old_leaf")?,
        "new_leaf":s(statement_v,"new_leaf")?,
        "old_version":statement.old_version,
        "new_version":statement.new_version,
        "old_epoch":statement.old_epoch,
        "new_epoch":statement.new_epoch,
        "expiry_cap":statement.expiry_cap,
        "admission_version":statement.admission_version
    });
    // This field is emitted only on the private child-process channel used by
    // the frozen E2 measurement driver.  The HTTP service strips it before
    // validating the normal core response and before replying on the wire.
    if env::var("PLAN_A_E2_TIMING").as_deref() == Ok("1") {
        output.as_object_mut().unwrap().insert("_e2_pure_proof_verify_ns".into(), json!(pure_proof_verify_ns));
    }
    Ok(output)
}
fn revoke_authorize(v: &Value) -> Result<Value, String> {
    let rk = b64(s(v, "rk_b64")?)?;
    let rk: [u8; 32] = rk.try_into().map_err(|_| "bad-rk-length")?;
    let counter = u(v, "counter")?;
    if counter > u32::MAX as u64 {
        return Err("bad-counter".into());
    }
    let claimed = field_hex(s(v, "sn")?)?;
    let derived = derive_serial(rk, counter as u32).map_err(|_| "invalid-serial")?;
    Ok(json!({"valid":derived==claimed,"serial":field_hex_out(derived)}))
}
fn sparse_state_root(depth: usize, records: &BTreeMap<u32, Fr>) -> Result<Fr, String> {
    if depth == 0 || depth > 32 {
        return Err("bad-state-depth".into());
    }
    let mut defaults = vec![Fr::from(0u64)];
    for i in 0..depth {
        defaults.push(node_hash(Domain::TreeNode, defaults[i], defaults[i]));
    }
    let mut level = records.clone();
    for d in 0..depth {
        let mut next = BTreeMap::new();
        for index in level
            .keys()
            .map(|x| x >> 1)
            .collect::<std::collections::BTreeSet<_>>()
        {
            let left = *level.get(&(index * 2)).unwrap_or(&defaults[d]);
            let right = *level.get(&(index * 2 + 1)).unwrap_or(&defaults[d]);
            next.insert(index, node_hash(Domain::TreeNode, left, right));
        }
        level = next
    }
    Ok(*level.get(&0).unwrap_or(&defaults[depth]))
}
fn materialize(v: &Value) -> Result<Value, String> {
    let ds = env::var("PLAN_A_DS")
        .map_err(|_| "missing-DS")?
        .parse::<usize>()
        .map_err(|_| "bad-DS")?;
    let dr = env::var("PLAN_A_DREV")
        .map_err(|_| "missing-DREV")?
        .parse::<usize>()
        .map_err(|_| "bad-DREV")?;
    let dra = env::var("PLAN_A_DRA")
        .map_err(|_| "missing-DRA")?
        .parse::<usize>()
        .map_err(|_| "bad-DRA")?;
    let mut ra = BTreeMap::new();
    for row in v
        .get("ra_leaves")
        .and_then(Value::as_array)
        .ok_or("bad-ra-leaves")?
    {
        let p = u(row, "position")?;
        if p >= 1u64.checked_shl(dra as u32).unwrap_or(0)
            || ra.insert(p as u32, field_hex(s(row, "leaf")?)?).is_some()
        {
            return Err("bad-ra-position".into());
        }
    }
    let ra_root = sparse_state_root(dra, &ra)?;
    let mut states = BTreeMap::new();
    for row in v
        .get("states")
        .and_then(Value::as_array)
        .ok_or("bad-states")?
    {
        let p = u(row, "position")?;
        if p >= 1u64.checked_shl(ds as u32).unwrap_or(0)
            || states
                .insert(p as u32, field_hex(s(row, "leaf")?)?)
                .is_some()
        {
            return Err("bad-state-position".into());
        }
    }
    let state_root = sparse_state_root(ds, &states)?;
    let mut rev = IndexedRevocationTree::new(dr).map_err(|_| "bad-rev-depth")?;
    for serial in v
        .get("revoked_serials")
        .and_then(Value::as_array)
        .ok_or("bad-revocations")?
    {
        rev.insert(field_hex(serial.as_str().ok_or("bad-serial")?)?)
            .map_err(|_| "bad-revocation-set")?
    }
    let revocation_leaves = rev
        .public_leaves()
        .into_iter()
        .map(|record| {
            json!({
                "position":record.slot,
                "value":field_hex_out(record.value),
                "next_position":record.next_slot,
                "next_value":field_hex_out(record.next),
                "leaf":field_hex_out(record.leaf)
            })
        })
        .collect::<Vec<_>>();
    Ok(
        json!({"valid":true,"ra_root":field_hex_out(ra_root),"state_root":field_hex_out(state_root),"revocation_root":field_hex_out(rev.root()),"ra_count":ra.len(),"state_count":states.len(),"revocation_count":v.get("revoked_serials").and_then(Value::as_array).unwrap().len(),"revocation_leaves":revocation_leaves}),
    )
}
fn field_hex_out(x: Fr) -> String {
    let mut b = plan_a_joint_circuit::poseidon::canonical_le_bytes(x);
    b.reverse();
    hex::encode(b)
}
fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let result = (|| -> Result<Value, String> {
        let v: Value = serde_json::from_str(&input).map_err(|_| "bad-json")?;
        match s(&v, "command")? {
            "verify" => Ok(json!({"valid":verify_proof(&v)?})),
            "terminal-verify" => Ok(json!({"valid":terminal(&v)?})),
            "header-verify" => Ok(json!({"valid":header(&v)?})),
            "admission-verify" => admission(&v),
            "ra-register-verify" => ra_register(&v),
            "state-update-verify" => state_update(&v),
            "blind-state-update-verify" => blind_state_update(&v),
            "revoke-authorize" => revoke_authorize(&v),
            "materialize-roots" => materialize(&v),
            _ => Err("bad-command".into()),
        }
    })();
    match result {
        Ok(value) => println!("{}", value),
        Err(e) => println!("{}", json!({"valid":false,"error":e})),
    }
}
