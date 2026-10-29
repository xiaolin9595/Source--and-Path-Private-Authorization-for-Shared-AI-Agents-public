use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use base64::{engine::general_purpose::STANDARD, Engine};
use hrada_sr_full_f_bbs::{present, AtomicCredential, Issuer};
use plan_a_joint_circuit::{fixture::fixed, poseidon::canonical_le_bytes};
use plan_a_sr_joint_bbs::{
    compile_timed,
    current_public::reconstruct,
    http_bridge::{
        binding, deployment_id, request_context, sign_terminal, validate_config, SnapshotBinding,
        TrustedConfig, CURRENT_CONFIG_ID, CURRENT_ISSUER_SEED, LEGACY_CIRCUIT_VERSION,
        PROOF_SCHEME, SYSTEM,
    },
};
use serde_json::{json, Value};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, Write},
    time::Instant,
};

fn field_hex(value: ark_bls12_381::Fr) -> String {
    let mut bytes = canonical_le_bytes(value);
    bytes.reverse();
    hex::encode(bytes)
}

fn issuer() -> Issuer {
    let mut rng = StdRng::seed_from_u64(CURRENT_ISSUER_SEED);
    Issuer::generate(&mut rng)
}

fn setup() -> Result<Value, String> {
    let issuer = issuer();
    let verifier = issuer.verifier_params();
    let verifier_bytes = verifier.canonical_bytes().map_err(|e| e.to_string())?;
    let circuit = fixed::<3>(2, 1, 10, 10, 32);
    Ok(serde_json::to_value(TrustedConfig {
        format: "PLAN-A-SR-TRUSTED-CONFIG-V1".into(),
        config_id: CURRENT_CONFIG_ID.into(),
        proof_scheme: PROOF_SCHEME.into(),
        deployment_id: deployment_id(),
        circuit_id: field_hex(circuit.request.circuit_id),
        system: SYSTEM,
        legacy_circuit_version: LEGACY_CIRCUIT_VERSION,
        l: 3,
        state_depth: 10,
        ra_depth: 10,
        revocation_depth: 32,
        grant_depth: 3,
        params_digest: hex::encode(issuer.params_digest().map_err(|e| e.to_string())?),
        verifier_material_b64: STANDARD.encode(verifier_bytes),
        snapshots: Vec::<SnapshotBinding>::new(),
    })
    .map_err(|e| e.to_string())?)
}

struct Resident {
    issuer: Issuer,
    credentials: BTreeMap<u64, AtomicCredential>,
}

impl Resident {
    fn new() -> Self {
        Self {
            issuer: issuer(),
            credentials: BTreeMap::new(),
        }
    }

    fn refresh(&mut self, value: &Value) -> Result<Value, String> {
        let public_path = value
            .get("public_path")
            .and_then(Value::as_str)
            .ok_or("missing-public-path")?;
        let private_path = value
            .get("private_path")
            .and_then(Value::as_str)
            .ok_or("missing-private-path")?;
        let registry_pk = value
            .get("registry_pk_b64")
            .and_then(Value::as_str)
            .ok_or("missing-registry-key")?;
        let total = Instant::now();
        let acquisition = Instant::now();
        let reconstructed = reconstruct(public_path, private_path, registry_pk, 10, 10, 32)?;
        let support_acquisition_and_witness_rebuild_ns = acquisition.elapsed().as_nanos();
        let (compiled, stages) =
            compile_timed(&[reconstructed.circuit]).map_err(|e| e.to_string())?;
        compiled.issuance.validate().map_err(|e| e.to_string())?;
        if compiled.issuance.credentials.len() != 1 || compiled.valid_paths != 1 {
            return Err("unexpected-current-issuance-batch".into());
        }
        let input = &compiled.issuance.credentials[0];
        let public = input.public_fields().map_err(|e| e.to_string())?;
        let seed = CURRENT_ISSUER_SEED ^ input.key.epoch.rotate_left(17);
        let mut rng = StdRng::seed_from_u64(seed);
        let issue = Instant::now();
        let credential = self
            .issuer
            .issue(&mut rng, public, input.not_before, input.upper())
            .map_err(|e| e.to_string())?;
        let issue_ns = issue.elapsed().as_nanos();
        let credential_bytes = credential.canonical_bytes().map_err(|e| e.to_string())?;
        self.credentials.insert(input.key.epoch, credential);
        Ok(json!({
            "refreshed": true,
            "tuple_version": input.key.epoch,
            "snapshot_digest": reconstructed.snapshot_digest,
            "snapshot": reconstructed.snapshot,
            "support_acquisition_and_witness_rebuild_ns": support_acquisition_and_witness_rebuild_ns,
            "compiler": stages,
            "issue_ns": issue_ns,
            "credential_delivery_bytes": credential_bytes.len(),
            "credential_delivery_sha256": hex::encode(sha2::Sha256::digest(&credential_bytes)),
            "credential_b64": STANDARD.encode(&credential_bytes),
            "public_version_bytes": reconstructed.public_bytes,
            "private_support_bytes": reconstructed.private_bytes,
            "reconstructed_paths_descriptor_bytes": reconstructed.reconstructed_paths_bytes,
            "total_refresh_issue_serialize_ns": total.elapsed().as_nanos(),
            "delivery_mode": "serialized credential bytes returned over the local issuer-agent pipe",
            "local_credential_delivery_measured": true,
            "production_network_delivery_measured": false
        }))
    }

    fn show(&self, value: &Value) -> Result<Value, String> {
        let config_path = value
            .get("config_path")
            .and_then(Value::as_str)
            .ok_or("missing-config-path")?;
        let config: TrustedConfig =
            serde_json::from_slice(&fs::read(config_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        validate_config(&config)?;
        let request = value.get("request").ok_or("missing-request")?;
        let digest = request
            .get("snapshot_digest")
            .and_then(Value::as_str)
            .ok_or("missing-snapshot-digest")?;
        let bound = binding(&config, digest)?;
        let prover = self.issuer.prover_params();
        let (context, expected_public) =
            request_context(&config, request, &bound.snapshot, prover.params_digest)?;
        let stale_epoch = value.get("stale_credential_epoch").and_then(Value::as_u64);
        let epoch = stale_epoch.unwrap_or(bound.tuple_version);
        let credential = self
            .credentials
            .get(&epoch)
            .ok_or("credential-not-delivered")?;
        if stale_epoch.is_none() && credential.public != expected_public {
            return Err("credential-does-not-match-request".into());
        }
        let seed = value
            .get("show_seed")
            .and_then(Value::as_u64)
            .ok_or("missing-show-seed")?;
        let mut rng = StdRng::seed_from_u64(seed);
        let started = Instant::now();
        let showing =
            present(&mut rng, &prover, credential, &context).map_err(|e| e.to_string())?;
        let show_ns = started.elapsed().as_nanos();
        let showing_bytes = showing.canonical_bytes().map_err(|e| e.to_string())?;
        Ok(json!({
            "proof_scheme": config.proof_scheme,
            "config_id": config.config_id,
            "credential_epoch": epoch,
            "stale_credential_test": stale_epoch.is_some(),
            "showing_b64": STANDARD.encode(&showing_bytes),
            "signature_b64": sign_terminal(&config.circuit_id, request, &showing_bytes)?,
            "timing": {"show_ns": show_ns, "showing_bytes": showing_bytes.len()}
        }))
    }
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("setup") {
        match setup() {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(2)
            }
        }
        return;
    }
    if args.get(1).map(String::as_str) != Some("serve") {
        eprintln!("usage: sr_current_http_agent setup|serve");
        std::process::exit(2)
    }
    let mut resident = Resident::new();
    println!(
        "{}",
        json!({"ready": true, "config_id": CURRENT_CONFIG_ID, "proof_scheme": PROOF_SCHEME})
    );
    io::stdout().flush().unwrap();
    for line in io::stdin().lock().lines() {
        let result = line
            .map_err(|e| e.to_string())
            .and_then(|line| serde_json::from_str::<Value>(&line).map_err(|e| e.to_string()))
            .and_then(|value| match value.get("command").and_then(Value::as_str) {
                Some("refresh") => resident.refresh(&value),
                Some("show") => resident.show(&value),
                _ => Err("bad-command".into()),
            });
        println!(
            "{}",
            match result {
                Ok(value) => value,
                Err(error) => json!({"error": error}),
            }
        );
        io::stdout().flush().unwrap();
    }
}
