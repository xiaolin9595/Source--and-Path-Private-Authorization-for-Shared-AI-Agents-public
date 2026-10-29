//! Resident verifier for the matched Joint HTTP path.
//! VK, manifest hash, registry key and profile are fixed at process startup.
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use plan_a_dac_fixed_wrapper::semantic_schema::{manifest_sha256, SemanticManifest};
use plan_a_joint_circuit::{
    contract::terminal_transcript,
    fixture::public_inputs,
    joint::snapshot_digest,
    poseidon::{hash, Domain},
    signature::{decode_public_key, decode_signature, verify, PublicKey, Signature},
};
use plan_a_matched_joint_service::{build_joint_actual1_bound, build_joint_actual1_bound_nonce};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    io::{self, BufRead},
    path::PathBuf,
};

struct Config {
    manifest: SemanticManifest,
    semantic_sha: String,
    vk: VerifyingKey<Bls12_381>,
    vk_sha256: String,
    registry_pk: PublicKey,
    circuit_id: String,
}

struct Ticket {
    binding: String,
    header_sha: [u8; 32],
    http_sha: [u8; 32],
    proof: Vec<u8>,
    terminal_pk: PublicKey,
    terminal_signature: Signature,
    envelope_sha: [u8; 32],
    used: bool,
}
struct State {
    config: Config,
    tickets: BTreeMap<String, Ticket>,
    counter: u64,
}

fn compact(value: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(value).map_err(|e| e.to_string())
}
fn sha_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    h.update(bytes);
    h.finalize().into()
}
fn hex_decode(label: &str, value: &str) -> Result<Vec<u8>, String> {
    if value
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(format!("bad-{label}-hex"));
    }
    hex::decode(value).map_err(|_| format!("bad-{label}-hex"))
}
fn canonical_decode<T: CanonicalDeserialize>(label: &str, value: &str) -> Result<T, String> {
    let bytes = hex_decode(label, value)?;
    let mut cursor = &bytes[..];
    let decoded = T::deserialize_compressed(&mut cursor).map_err(|_| format!("bad-{label}"))?;
    if !cursor.is_empty() {
        return Err(format!("trailing-{label}"));
    }
    Ok(decoded)
}
fn canonical_hex<T: CanonicalSerialize>(value: &T) -> Result<String, String> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(hex::encode(bytes))
}
fn public_inputs_sha256(
    circuit: &plan_a_joint_circuit::joint::JointCircuit<2>,
) -> Result<String, String> {
    let values = public_inputs(circuit)
        .iter()
        .map(canonical_hex)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(hex::encode(Sha256::digest(compact(&json!(values))?)))
}
fn object<'a>(v: &'a Value, key: &str) -> Result<&'a Value, String> {
    v.get(key).ok_or_else(|| format!("missing-{key}"))
}
fn string<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    object(v, key)?.as_str().ok_or_else(|| format!("bad-{key}"))
}
fn u64v(v: &Value, key: &str) -> Result<u64, String> {
    object(v, key)?.as_u64().ok_or_else(|| format!("bad-{key}"))
}
fn http_digest(expected: &Value) -> Result<[u8; 32], String> {
    let http = object(expected, "http")?;
    let map = http.as_object().ok_or("bad-http")?;
    if map.keys().map(String::as_str).collect::<Vec<_>>()
        != ["audience", "body_sha256", "method", "path"]
    {
        return Err("bad-http-schema".into());
    }
    let body = string(http, "body_sha256")?;
    if body.len() != 64 || hex_decode("body-sha256", body)?.len() != 32 {
        return Err("bad-body-sha256".into());
    }
    Ok(sha_domain(b"plan-a-matched-http-v1", &compact(http)?))
}
fn digest_limbs(digest: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_le_bytes(digest[i * 8..(i + 1) * 8].try_into().unwrap()))
}
fn expected_binding(expected: &Value) -> Result<String, String> {
    let mut copy = expected.clone();
    copy.as_object_mut()
        .ok_or("bad-expected")?
        .remove("trusted_now");
    Ok(hex::encode(sha_domain(
        b"plan-a-matched-ticket-v1",
        &compact(&copy)?,
    )))
}
fn validate_common(
    config: &Config,
    manifest_value: &Value,
    expected: &Value,
) -> Result<(usize, u64, [u8; 32]), String> {
    let manifest: SemanticManifest =
        serde_json::from_value(manifest_value.clone()).map_err(|_| "bad-manifest")?;
    if manifest != config.manifest
        || manifest_sha256(&manifest) != config.semantic_sha
        || string(expected, "semantic_input_sha256")? != config.semantic_sha
    {
        return Err("semantic-input-mismatch".into());
    }
    if string(expected, "backend")? != "joint-bls12-381" {
        return Err("wrong-backend".into());
    }
    let update = u64v(expected, "update_index")? as usize;
    if update >= manifest.updates.len() {
        return Err("bad-update-index".into());
    }
    let now = u64v(expected, "trusted_now")?;
    if now < manifest.request.interval_lo || now > manifest.request.interval_hi {
        return Err("expired".into());
    }
    Ok((update, now, http_digest(expected)?))
}
fn snapshot_json(
    circuit: &plan_a_joint_circuit::joint::JointCircuit<2>,
    semantic_sha: &str,
) -> Result<Value, String> {
    Ok(
        json!({"issued_at":circuit.snapshot.issued_at,"ra_root":canonical_hex(&circuit.snapshot.root_ra)?,
      "revocation_epoch":circuit.snapshot.revocation_epoch,"revocation_root":canonical_hex(&circuit.snapshot.root_rev)?,
      "semantic_input_sha256":semantic_sha,"state_epoch":circuit.snapshot.state_epoch,
      "state_root":canonical_hex(&circuit.snapshot.root_state)?,"tuple_version":circuit.snapshot.tuple_version}),
    )
}
fn header_message(header: &Value) -> Result<Fr, String> {
    let d = sha_domain(b"plan-a-matched-header-v1", &compact(header)?);
    let a = Fr::from(u128::from_be_bytes(d[..16].try_into().unwrap()));
    let b = Fr::from(u128::from_be_bytes(d[16..].try_into().unwrap()));
    Ok(hash(Domain::Terminal, &[a, b]))
}

impl State {
    fn materialize(&mut self, v: &Value) -> Result<Value, String> {
        let manifest_value = object(v, "canonical_manifest")?;
        let manifest: SemanticManifest =
            serde_json::from_value(manifest_value.clone()).map_err(|_| "bad-manifest")?;
        if manifest != self.config.manifest
            || string(v, "semantic_input_sha256")? != self.config.semantic_sha
        {
            return Err("semantic-input-mismatch".into());
        }
        let update = u64v(v, "update_index")? as usize;
        let fixture = build_joint_actual1_bound(&manifest, update, [0; 4])
            .map_err(|e| e.to_string())?
            .1;
        let header = snapshot_json(&fixture, &self.config.semantic_sha)?;
        let envelope = object(v, "header_envelope")?;
        if object(envelope, "header")? != &header {
            return Err("header-mismatch".into());
        }
        let sig = decode_signature(&hex_decode(
            "registry-signature",
            string(envelope, "registry_signature")?,
        )?)
        .map_err(|_| "bad-registry-signature")?;
        if !verify(&self.config.registry_pk, header_message(&header)?, &sig) {
            return Err("invalid-registry-signature".into());
        }
        Ok(json!({"valid":true,"header":header}))
    }
    fn verify_read(&mut self, v: &Value) -> Result<Value, String> {
        let expected = object(v, "expected")?;
        let (update, _now, http_sha) =
            validate_common(&self.config, object(v, "canonical_manifest")?, expected)?;
        let envelope = object(v, "envelope")?;
        if string(envelope, "semantic_input_sha256")? != self.config.semantic_sha {
            return Err("envelope-semantic-mismatch".into());
        }
        if u64v(envelope, "update_index")? as usize != update {
            return Err("update-mismatch".into());
        }
        let circuit = build_joint_actual1_bound_nonce(
            &self.config.manifest,
            update,
            digest_limbs(http_sha),
            u64v(expected, "nonce_u64")?,
        )
        .map_err(|e| e.to_string())?
        .1;
        if object(expected, "installed_header")?
            != &snapshot_json(&circuit, &self.config.semantic_sha)?
        {
            return Err("installed-header-mismatch".into());
        }
        if string(expected, "terminal_key")? != canonical_hex(&circuit.request.terminal.0)? {
            return Err("terminal-key-mismatch".into());
        }
        let proof_bytes = hex_decode("proof", string(envelope, "proof")?)?;
        let mut cursor = &proof_bytes[..];
        let proof = Proof::deserialize_compressed(&mut cursor).map_err(|_| "bad-proof")?;
        if !cursor.is_empty() {
            return Err("trailing-proof".into());
        }
        if !Groth16::<Bls12_381>::verify(&self.config.vk, &public_inputs(&circuit), &proof)
            .map_err(|e| e.to_string())?
        {
            return Err(format!(
                "invalid-proof update={} nonce={} http_digest={} public_inputs_sha256={} proof_sha256={} vk_sha256={}",
                update,
                u64v(expected, "nonce_u64")?,
                hex::encode(http_sha),
                public_inputs_sha256(&circuit)?,
                hex::encode(Sha256::digest(&proof_bytes)),
                self.config.vk_sha256,
            ));
        }
        let header_sha = sha_domain(
            b"plan-a-matched-header-v1",
            &compact(object(expected, "installed_header")?)?,
        );
        let terminal = decode_signature(&hex_decode(
            "terminal-signature",
            string(envelope, "terminal_signature")?,
        )?)
        .map_err(|_| "bad-terminal-signature")?;
        if !verify(
            &circuit.request.terminal,
            terminal_transcript(http_sha, header_sha, &self.config.circuit_id, &proof_bytes),
            &terminal,
        ) {
            return Err("invalid-terminal-signature".into());
        }
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or("ticket-counter-overflow")?;
        let binding = expected_binding(expected)?;
        let mut seed = Vec::new();
        seed.extend_from_slice(binding.as_bytes());
        seed.extend_from_slice(&self.counter.to_le_bytes());
        seed.extend_from_slice(&proof_bytes);
        let envelope_sha = sha_domain(b"plan-a-matched-envelope-v1", &compact(envelope)?);
        let id = hex::encode(sha_domain(b"plan-a-matched-ticket-id-v1", &seed));
        self.tickets.insert(
            id.clone(),
            Ticket {
                binding,
                header_sha,
                http_sha,
                proof: proof_bytes,
                terminal_pk: circuit.request.terminal,
                terminal_signature: terminal,
                envelope_sha,
                used: false,
            },
        );
        Ok(json!({"valid":true,"ticket":id}))
    }
    fn commit(&mut self, v: &Value) -> Result<Value, String> {
        let expected = object(v, "expected")?;
        let (_update, _now, _http_sha) =
            validate_common(&self.config, object(v, "canonical_manifest")?, expected)?;
        let id = string(v, "ticket")?;
        let binding = expected_binding(expected)?;
        let ticket = self.tickets.get_mut(id).ok_or("unknown-ticket")?;
        if ticket.used || ticket.binding != binding {
            return Err("ticket-binding-mismatch".into());
        }
        let envelope = object(v, "envelope")?;
        if hex_decode("proof", string(envelope, "proof")?)? != ticket.proof {
            return Err("proof-changed".into());
        }
        if sha_domain(b"plan-a-matched-envelope-v1", &compact(envelope)?) != ticket.envelope_sha {
            return Err("envelope-changed".into());
        }
        let current_header = sha_domain(
            b"plan-a-matched-header-v1",
            &compact(object(expected, "installed_header")?)?,
        );
        if current_header != ticket.header_sha {
            return Err("header-changed".into());
        }
        if !verify(
            &ticket.terminal_pk,
            terminal_transcript(
                ticket.http_sha,
                ticket.header_sha,
                &self.config.circuit_id,
                &ticket.proof,
            ),
            &ticket.terminal_signature,
        ) {
            return Err("terminal-recheck-failed".into());
        }
        ticket.used = true;
        Ok(json!({"valid":true}))
    }
    fn dispatch(&mut self, v: &Value) -> Result<Value, String> {
        match string(v, "command")? {
            "materialize-and-verify-header" => self.materialize(v),
            "verify-at-read" => self.verify_read(v),
            "commit" => self.commit(v),
            _ => Err("bad-command".into()),
        }
    }
}

fn load_config() -> Result<Config, String> {
    let manifest_path =
        PathBuf::from(env::var("MATCHED_MANIFEST_PATH").map_err(|_| "missing-manifest-path")?);
    let manifest: SemanticManifest =
        serde_json::from_slice(&std::fs::read(manifest_path).map_err(|e| e.to_string())?)
            .map_err(|_| "bad-trusted-manifest")?;
    let semantic_sha = env::var("MATCHED_SEMANTIC_SHA256").map_err(|_| "missing-semantic-sha")?;
    if manifest_sha256(&manifest) != semantic_sha {
        return Err("trusted-manifest-sha-mismatch".into());
    }
    let vk_bytes = std::fs::read(env::var("MATCHED_JOINT_VK_PATH").map_err(|_| "missing-vk-path")?)
        .map_err(|e| e.to_string())?;
    let vk_sha = hex::encode(Sha256::digest(&vk_bytes));
    if vk_sha != env::var("MATCHED_JOINT_VK_SHA256").map_err(|_| "missing-vk-sha")? {
        return Err("trusted-vk-sha-mismatch".into());
    }
    let mut cursor = &vk_bytes[..];
    let vk = VerifyingKey::deserialize_compressed(&mut cursor).map_err(|_| "bad-trusted-vk")?;
    if !cursor.is_empty() {
        return Err("trailing-trusted-vk".into());
    }
    let registry_pk = decode_public_key(&hex_decode(
        "registry-pk",
        &env::var("MATCHED_REGISTRY_PK_HEX").map_err(|_| "missing-registry-pk")?,
    )?)
    .map_err(|_| "bad-registry-pk")?;
    let circuit_id = env::var("MATCHED_JOINT_CIRCUIT_ID").map_err(|_| "missing-circuit-id")?;
    Ok(Config {
        manifest,
        semantic_sha,
        vk,
        vk_sha256: vk_sha,
        registry_pk,
        circuit_id,
    })
}
fn main() {
    let config = match load_config() {
        Ok(v) => v,
        Err(e) => {
            println!("{}", json!({"valid":false,"error":e}));
            return;
        }
    };
    let mut state = State {
        config,
        tickets: BTreeMap::new(),
        counter: 0,
    };
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(|e| e.to_string())
            .and_then(|line| serde_json::from_str::<Value>(&line).map_err(|_| "bad-json".into()))
            .and_then(|v| state.dispatch(&v));
        println!(
            "{}",
            match result {
                Ok(v) => v,
                Err(e) => json!({"valid":false,"error":e}),
            }
        );
    }
}
