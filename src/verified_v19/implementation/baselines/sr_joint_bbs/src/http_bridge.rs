//! Trusted SR/BBS HTTP bridge shared by the Agent and verifier CLIs.
//!
//! This is a deterministic benchmark deployment.  Its identifier selects one
//! complete configuration; request JSON never supplies verifier material.
use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use hrada_sr_full_f_bbs::{encode_complete_q, Issuer, PublicCredentialFields, RequestContext};
use plan_a_joint_circuit::{
    merkle::{build_tree, path_for},
    poseidon::{canonical_le_bytes, hash, Domain},
    signature::{decode_public_key, encode_signature, public_key, sign, SecretKey},
    state_registry::{update_digest, StateLeafOpening},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::fixtures::{revoke_source_b, two_source_same_terminal};

pub const CONFIG_ID: &str = "plan-a-sr-bbs23-cdl-fixture-l3-v1";
pub const CURRENT_CONFIG_ID: &str = "plan-a-sr-bbs23-cdl-current-l3-ds10-dra10-drev32-v1";
pub const PROOF_SCHEME: &str = "sr-bbs23-cdl-v1";
pub const PROTOCOL_VERSION: &str = "plan-a-http-v1";
pub const ISSUER_SEED: u64 = 0x5352_4854_5450_0001;
pub const CURRENT_ISSUER_SEED: u64 = 0x5352_4355_5252_4854;
pub const DEPLOYMENT_U64: u64 = 9;
pub const SYSTEM: u64 = 0;
pub const LEGACY_CIRCUIT_VERSION: u64 = 1;

pub fn canonical(v: &Value) -> Result<Vec<u8>, String> {
    // serde_json Map is a BTreeMap without preserve_order, matching service.py.
    serde_json::to_vec(v).map_err(|e| e.to_string())
}
pub fn tagged(tag: &[u8], v: &Value) -> Result<[u8; 32], String> {
    let mut h = Sha256::new();
    h.update(tag);
    h.update([0]);
    h.update(canonical(v)?);
    Ok(h.finalize().into())
}
pub fn limbs_be(x: [u8; 32]) -> (Fr, Fr) {
    (
        Fr::from(u128::from_be_bytes(x[..16].try_into().unwrap())),
        Fr::from(u128::from_be_bytes(x[16..].try_into().unwrap())),
    )
}
pub fn limbs_le(x: [u8; 32]) -> (Fr, Fr) {
    (
        Fr::from_le_bytes_mod_order(&x[..16]),
        Fr::from_le_bytes_mod_order(&x[16..]),
    )
}
pub fn field_hex(x: Fr) -> String {
    let mut b = canonical_le_bytes(x);
    b.reverse();
    hex::encode(b)
}
pub fn snapshot_value(s: &plan_a_joint_circuit::contract::Snapshot) -> Value {
    json!({"deployment_id":deployment_id(),"issued_at":s.issued_at,"ra_root":field_hex(s.root_ra),"revocation_epoch":s.revocation_epoch,"revocation_root":field_hex(s.root_rev),"state_epoch":s.state_epoch,"state_root":field_hex(s.root_state),"tuple_version":s.tuple_version})
}
fn state_leaf(c: &plan_a_joint_circuit::joint::JointCircuit<3>) -> Fr {
    let s = &c.state;
    hash(
        Domain::StateLeaf,
        &[
            s.owner_commitment,
            s.grant_root,
            Fr::from(s.state_version),
            Fr::from(s.state_epoch),
            Fr::from(s.state_expiry),
            Fr::from(s.active as u64),
            s.salt,
            Fr::from(s.position),
        ],
    )
}
pub fn lifecycle_sources() -> (
    [plan_a_joint_circuit::joint::JointCircuit<3>; 2],
    [plan_a_joint_circuit::joint::JointCircuit<3>; 2],
    [plan_a_joint_circuit::joint::JointCircuit<3>; 2],
) {
    let h0 = two_source_same_terminal();
    let h1 = revoke_source_b(h0[0].clone(), h0[1].clone());
    let mut h2 = h1.clone();
    h2[0].state.active = false;
    h2[0].state.state_version += 1;
    h2[0].state.state_epoch += 1;
    h2[0].state.salt = Fr::from(84u64);
    let epoch = h2[0].state.state_epoch;
    let mut leaves = vec![Fr::from(0u64); 8];
    leaves[h2[0].state.position as usize] = state_leaf(&h2[0]);
    leaves[h2[1].state.position as usize] = state_leaf(&h2[1]);
    let (root, levels) = build_tree(leaves, 3, Domain::TreeNode).unwrap();
    for c in &mut h2 {
        c.snapshot.root_state = root;
        c.snapshot.state_epoch = epoch;
        c.snapshot.tuple_version += 1;
        c.snapshot.issued_at += 1;
        c.state.path = path_for(&levels, c.state.position as usize).unwrap();
    }
    (h0, h1, h2)
}
pub fn snapshot_json() -> Value {
    snapshot_value(&lifecycle_sources().0[0].snapshot)
}
pub fn circuit_id() -> String {
    field_hex(lifecycle_sources().0[0].request.circuit_id)
}
pub fn deployment_id() -> String {
    field_hex(Fr::from(DEPLOYMENT_U64))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SnapshotBinding {
    pub tuple_version: u64,
    pub snapshot: Value,
    pub snapshot_digest: String,
    pub credential_available: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrustedConfig {
    pub format: String,
    pub config_id: String,
    pub proof_scheme: String,
    pub deployment_id: String,
    pub circuit_id: String,
    pub system: u64,
    pub legacy_circuit_version: u64,
    pub l: usize,
    pub state_depth: usize,
    pub ra_depth: usize,
    pub revocation_depth: usize,
    pub grant_depth: usize,
    pub params_digest: String,
    pub verifier_material_b64: String,
    pub snapshots: Vec<SnapshotBinding>,
}
fn shape_preflight(sources: &[plan_a_joint_circuit::joint::JointCircuit<3>]) -> Result<(), String> {
    for c in sources {
        if c.state.path.siblings.len() != 3
            || c.state.path.directions.len() != 3
            || c.entitlement.path.siblings.len() != 3
            || c.entitlement.path.directions.len() != 3
            || c.grants.len() != 3
            || c.grants.iter().any(|s| {
                s.grant_path.siblings.len() != 3
                    || s.grant_path.directions.len() != 3
                    || s.revocation.path.siblings.len() != 4
                    || s.revocation.path.directions.len() != 4
            })
        {
            return Err("trusted-shape-mismatch".into());
        }
    }
    Ok(())
}
pub fn make_trusted_config() -> Result<TrustedConfig, String> {
    let (h0, h1, h2) = lifecycle_sources();
    let mut rng = StdRng::seed_from_u64(ISSUER_SEED);
    let issuer = Issuer::generate(&mut rng);
    let verifier = issuer.verifier_params();
    let vb = verifier.canonical_bytes().map_err(|e| e.to_string())?;
    let pd = issuer.params_digest().map_err(|e| e.to_string())?;
    let mut snapshots = vec![];
    for sources in [&h0[..], &h1[..], &h2[..]] {
        shape_preflight(sources)?;
        let compiled = crate::compile(sources).map_err(|e| e.to_string())?;
        let snapshot = snapshot_value(&sources[0].snapshot);
        snapshots.push(SnapshotBinding {
            tuple_version: num(&snapshot, "tuple_version")?,
            snapshot_digest: hex::encode(tagged(b"plan-a-snapshot-v1", &snapshot)?),
            snapshot,
            credential_available: !compiled.issuance.credentials.is_empty(),
        })
    }
    if !snapshots[0].credential_available
        || !snapshots[1].credential_available
        || snapshots[2].credential_available
    {
        return Err("lifecycle-compile-invariant".into());
    }
    Ok(TrustedConfig {
        format: "PLAN-A-SR-TRUSTED-CONFIG-V1".into(),
        config_id: CONFIG_ID.into(),
        proof_scheme: PROOF_SCHEME.into(),
        deployment_id: deployment_id(),
        circuit_id: circuit_id(),
        system: SYSTEM,
        legacy_circuit_version: LEGACY_CIRCUIT_VERSION,
        l: 3,
        state_depth: 3,
        ra_depth: 3,
        revocation_depth: 4,
        grant_depth: 3,
        params_digest: hex::encode(pd),
        verifier_material_b64: STANDARD.encode(vb),
        snapshots,
    })
}
pub fn validate_config(c: &TrustedConfig) -> Result<(), String> {
    let shape = (
        c.l,
        c.state_depth,
        c.ra_depth,
        c.revocation_depth,
        c.grant_depth,
    );
    let known_profile = (c.config_id == CONFIG_ID && shape == (3, 3, 3, 4, 3))
        || (c.config_id == CURRENT_CONFIG_ID && shape == (3, 10, 10, 32, 3));
    if c.format != "PLAN-A-SR-TRUSTED-CONFIG-V1"
        || !known_profile
        || c.proof_scheme != PROOF_SCHEME
        || c.system != SYSTEM
        || c.legacy_circuit_version != LEGACY_CIRCUIT_VERSION
        || c.deployment_id.len() != 64
        || c.circuit_id.len() != 64
    {
        return Err("untrusted-config".into());
    }
    let mut seen = std::collections::BTreeMap::new();
    for b in &c.snapshots {
        if text(&b.snapshot, "deployment_id")? != c.deployment_id
            || b.tuple_version != num(&b.snapshot, "tuple_version")?
            || b.snapshot_digest != hex::encode(tagged(b"plan-a-snapshot-v1", &b.snapshot)?)
            || seen.insert(b.tuple_version, &b.snapshot_digest).is_some()
        {
            return Err("non-unique-snapshot-binding".into());
        }
    }
    Ok(())
}
pub fn binding<'a>(c: &'a TrustedConfig, digest: &str) -> Result<&'a SnapshotBinding, String> {
    validate_config(c)?;
    c.snapshots
        .iter()
        .find(|x| x.snapshot_digest == digest)
        .ok_or("snapshot-not-configured".into())
}

fn object(v: &Value) -> Result<&Map<String, Value>, String> {
    v.as_object().ok_or("expected-object".into())
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("bad-{k}"))
}
fn num(v: &Value, k: &str) -> Result<u64, String> {
    v.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("bad-{k}"))
}
fn parse_resource(s: &str) -> Result<u64, String> {
    let h = s.strip_prefix("fr:").ok_or("bad-resource")?;
    if h.len() != 64
        || h.bytes()
            .any(|c| !c.is_ascii_digit() && !matches!(c, b'a'..=b'f'))
    {
        return Err("noncanonical-resource".into());
    }
    let b = hex::decode(h).map_err(|_| "bad-resource")?;
    let f = Fr::from_be_bytes_mod_order(&b);
    if field_hex(f) != h {
        return Err("resource-outside-field".into());
    }
    let le = f.into_bigint().to_bytes_le();
    if le.iter().skip(8).any(|x| *x != 0) {
        return Err("resource-not-u64".into());
    }
    let mut a = [0; 8];
    a[..le.len().min(8)].copy_from_slice(&le[..le.len().min(8)]);
    Ok(u64::from_le_bytes(a))
}
fn nonce_raw(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| "bad-nonce".into())
}
fn nonce_u64(raw: &[u8]) -> u64 {
    let d: [u8; 32] = Sha256::digest(raw).into();
    u64::from_be_bytes(d[..8].try_into().unwrap())
}
fn terminal_xy(bytes: &[u8]) -> Result<(Fr, Fr), String> {
    let p = decode_public_key(bytes).map_err(|_| "bad-terminal-key")?;
    Ok((p.0.x, p.0.y))
}
pub fn request_context(
    config: &TrustedConfig,
    request: &Value,
    snapshot: &Value,
    params: [u8; 32],
) -> Result<(RequestContext, PublicCredentialFields), String> {
    let keys = [
        "action_onehot",
        "audience",
        "body_sha256",
        "circuit_id",
        "config_id",
        "deployment_id",
        "expires_at",
        "method",
        "nonce",
        "path",
        "proof_scheme",
        "protocol_version",
        "request_time",
        "resource",
        "snapshot_digest",
        "terminal_agent_pk",
    ];
    let obj = object(request)?;
    if obj.len() != keys.len() || keys.iter().any(|k| !obj.contains_key(*k)) {
        return Err("bad-canonical-request-schema".into());
    }
    if text(request, "protocol_version")? != PROTOCOL_VERSION
        || text(request, "proof_scheme")? != config.proof_scheme
        || text(request, "config_id")? != config.config_id
        || text(request, "deployment_id")? != config.deployment_id
        || text(request, "circuit_id")? != config.circuit_id
    {
        return Err("untrusted-config".into());
    }
    let snap = tagged(b"plan-a-snapshot-v1", snapshot)?;
    if text(request, "snapshot_digest")? != hex::encode(snap) {
        return Err("snapshot-config-mismatch".into());
    }
    let terminal = STANDARD
        .decode(text(request, "terminal_agent_pk")?)
        .map_err(|_| "bad-terminal-key")?;
    let (tx, ty) = terminal_xy(&terminal)?;
    let nonce = nonce_raw(text(request, "nonce")?)?;
    let nu = nonce_u64(&nonce);
    let req_digest = tagged(b"plan-a-request-v1", request)?;
    let (q5, q6) = limbs_le(req_digest);
    let deployment_hash: [u8; 32] =
        Sha256::digest([config.deployment_id.as_bytes(), config.config_id.as_bytes()].concat())
            .into();
    let (q12, q13) = limbs_le(deployment_hash);
    let (h0, h1) = limbs_le(snap);
    let fields = [
        h0,
        h1,
        Fr::from(num(snapshot, "tuple_version")?),
        Fr::from(SYSTEM),
        Fr::from(LEGACY_CIRCUIT_VERSION),
        q5,
        q6,
        Fr::from(parse_resource(text(request, "resource")?)?),
        Fr::from(num(request, "action_onehot")?),
        Fr::from(num(request, "request_time")?),
        Fr::from(nu),
        Fr::from(num(request, "expires_at")?),
        q12,
        q13,
        tx,
        ty,
    ];
    let q = encode_complete_q(&fields).map_err(|e| e.to_string())?;
    let (ctx, public) =
        RequestContext::from_q16(q, snap, params, &terminal, nu).map_err(|e| e.to_string())?;
    Ok((
        RequestContext {
            verifier_nonce: nonce,
            ..ctx
        },
        public,
    ))
}
pub fn proof_message(req: [u8; 32], snap: [u8; 32], circuit: &str, proof: &[u8]) -> Fr {
    let (a, b) = limbs_be(req);
    let (c, d) = limbs_be(snap);
    let cid: [u8; 32] = Sha256::digest(circuit.as_bytes()).into();
    let (e, f) = limbs_be(cid);
    let mut xs = vec![a, b, c, d, e, f, Fr::from(proof.len() as u64)];
    xs.extend(proof.chunks(31).map(Fr::from_le_bytes_mod_order));
    hash(Domain::Terminal, &xs)
}
pub fn sign_terminal(circuit: &str, request: &Value, showing: &[u8]) -> Result<String, String> {
    let req = tagged(b"plan-a-request-v1", request)?;
    let snap: [u8; 32] = hex::decode(text(request, "snapshot_digest")?)
        .map_err(|_| "bad-snapshot-digest")?
        .try_into()
        .map_err(|_| "bad-snapshot-digest")?;
    let sig = sign(
        &SecretKey(Scalar::from(14u64)),
        proof_message(req, snap, circuit, showing),
        [0x53; 32],
    )
    .map_err(|e| e.to_string())?;
    Ok(STANDARD.encode(encode_signature(&sig)))
}
pub fn terminal_pk_b64() -> Result<String, String> {
    let p = public_key(&SecretKey(Scalar::from(14u64))).map_err(|e| e.to_string())?;
    let mut b = vec![];
    p.0.serialize_compressed(&mut b)
        .map_err(|e| e.to_string())?;
    Ok(STANDARD.encode(b))
}
pub fn admin_artifacts() -> Result<Value, String> {
    let (h0, _h1, h2) = lifecycle_sources();
    let registry_sk = SecretKey(Scalar::from(900u64));
    let registry_pk = public_key(&registry_sk).map_err(|e| e.to_string())?;
    let point = |p: &plan_a_joint_circuit::signature::PublicKey| -> Result<String, String> {
        let mut x = vec![];
        p.0.serialize_compressed(&mut x)
            .map_err(|e| e.to_string())?;
        Ok(STANDARD.encode(x))
    };
    let mut admissions = vec![];
    for (c, skn) in h0.iter().zip([11u64, 21u64]) {
        let owner_pk = public_key(&SecretKey(Scalar::from(skn))).map_err(|e| e.to_string())?;
        let msg = hash(
            Domain::StateUpdate,
            &[
                Fr::from(0u64),
                Fr::from(DEPLOYMENT_U64),
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
        let asig = sign(&registry_sk, msg, [0x23; 32]).map_err(|e| e.to_string())?;
        admissions.push(json!({"command":"admission-verify","deployment_id":deployment_id(),"owner_commitment":field_hex(c.state.owner_commitment),"position":c.state.position,"owner_public_key":point(&owner_pk)?,"registration_salt":field_hex(c.registration_salt),"max_expiry":c.state.state_expiry,"initial_opening":{"grant_root":field_hex(c.state.grant_root),"state_expiry":c.state.state_expiry,"active":c.state.active,"salt":field_hex(c.state.salt)},"initial_version":c.state.state_version,"initial_epoch":c.state.state_epoch,"signature_b64":STANDARD.encode(encode_signature(&asig))}));
    }
    let config = make_trusted_config()?;
    let mut headers = vec![];
    for b in &config.snapshots {
        let digest = tagged(b"plan-a-snapshot-v1", &b.snapshot)?;
        let (a, z) = limbs_be(digest);
        let hs = sign(&registry_sk, hash(Domain::Terminal, &[a, z]), [0x72; 32])
            .map_err(|e| e.to_string())?;
        headers.push(json!({"snapshot":b.snapshot,"snapshot_digest":b.snapshot_digest,"header_signature_b64":STANDARD.encode(encode_signature(&hs))}));
    }
    let (rk, counter, sn) = crate::fixtures::source_b_revocation_capability();
    let revoke = json!({"command":"revoke-authorize","rk_b64":STANDARD.encode(rk),"counter":counter,"sn":field_hex(sn)});
    let next = &h2[0].state;
    let opening = StateLeafOpening {
        grant_root: next.grant_root,
        state_expiry: next.state_expiry,
        active: next.active,
        salt: next.salt,
    };
    let usig = sign(
        &SecretKey(Scalar::from(11u64)),
        update_digest(
            Fr::from(DEPLOYMENT_U64),
            next.owner_commitment,
            next.position,
            h0[0].state.state_version,
            next.state_epoch,
            &opening,
        ),
        [0x35; 32],
    )
    .map_err(|e| e.to_string())?;
    let deactivate = json!({"command":"state-update-verify","deployment_id":deployment_id(),"owner_commitment":field_hex(next.owner_commitment),"position":next.position,"expected_version":h0[0].state.state_version,"new_epoch":next.state_epoch,"opening":{"grant_root":field_hex(opening.grant_root),"state_expiry":opening.state_expiry,"active":opening.active,"salt":field_hex(opening.salt)},"signature_b64":STANDARD.encode(encode_signature(&usig))});
    let mut rpk = vec![];
    registry_pk
        .0
        .serialize_compressed(&mut rpk)
        .map_err(|e| e.to_string())?;
    Ok(
        json!({"headers":headers,"bootstrap_admissions":admissions,"revoke_source_b":revoke,"deactivate_source_a":deactivate,"registry_pk_b64":STANDARD.encode(rpk),"deployment_id":deployment_id(),"circuit_id":circuit_id(),"terminal_agent_pk":terminal_pk_b64()?}),
    )
}
