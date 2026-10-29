use ark_std::rand::{rngs::StdRng, SeedableRng};
use base64::{engine::general_purpose::STANDARD, Engine};
use hrada_sr_full_f_bbs::{verify, Showing, VerifierParams};
use plan_a_joint_circuit::signature::{
    decode_public_key, decode_signature, verify as verify_signature,
};
use plan_a_sr_joint_bbs::http_bridge::{
    binding, proof_message, request_context, tagged, validate_config, TrustedConfig,
};
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Read},
};
struct Trusted {
    config: TrustedConfig,
    verifier: VerifierParams,
    params: [u8; 32],
}
fn load(path: &str) -> Result<Trusted, String> {
    let config: TrustedConfig = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    validate_config(&config)?;
    let raw = STANDARD
        .decode(&config.verifier_material_b64)
        .map_err(|_| "bad-verifier-material")?;
    let verifier = VerifierParams::from_canonical_bytes(&raw).map_err(|e| e.to_string())?;
    let params = verifier.params_digest().map_err(|e| e.to_string())?;
    if hex::encode(params) != config.params_digest {
        return Err("params-digest-mismatch".into());
    }
    Ok(Trusted {
        config,
        verifier,
        params,
    })
}
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("bad-{k}"))
}
fn sr_verify(v: &Value, t: &Trusted) -> Result<bool, String> {
    if text(v, "config_id")? != t.config.config_id
        || text(v, "proof_scheme")? != t.config.proof_scheme
    {
        return Ok(false);
    }
    let statement = v
        .get("public_statement")
        .ok_or("missing-public-statement")?;
    let request = statement.get("request").ok_or("missing-request")?;
    let digest = text(request, "snapshot_digest")?;
    let b = binding(&t.config, digest)?;
    if statement.get("snapshot") != Some(&b.snapshot) {
        return Ok(false);
    }
    if text(statement, "canonical_request_sha256")?
        != hex::encode(tagged(b"plan-a-request-v1", request)?)
    {
        return Ok(false);
    }
    let (ctx, public) = request_context(&t.config, request, &b.snapshot, t.params)?;
    if public.global_epoch != b.tuple_version {
        return Ok(false);
    }
    let bytes = STANDARD
        .decode(text(v, "showing_b64")?)
        .map_err(|_| "bad-showing-b64")?;
    let showing = Showing::from_canonical_bytes(&bytes).map_err(|e| e.to_string())?;
    let mut rng = StdRng::seed_from_u64(0x5652_4659);
    Ok(verify(&mut rng, &t.verifier, &public, &ctx, &showing).is_ok())
}
fn terminal(v: &Value, t: &Trusted) -> Result<bool, String> {
    if text(v, "config_id")? != t.config.config_id
        || text(v, "proof_scheme")? != t.config.proof_scheme
        || text(v, "deployment_id")? != t.config.deployment_id
        || text(v, "circuit_id")? != t.config.circuit_id
    {
        return Ok(false);
    }
    let req: [u8; 32] = hex::decode(text(v, "canonical_request_sha256")?)
        .map_err(|_| "bad-request-digest")?
        .try_into()
        .map_err(|_| "bad-request-digest")?;
    let snap: [u8; 32] = hex::decode(text(v, "snapshot_digest")?)
        .map_err(|_| "bad-snapshot-digest")?
        .try_into()
        .map_err(|_| "bad-snapshot-digest")?;
    binding(&t.config, text(v, "snapshot_digest")?)?;
    let proof = STANDARD
        .decode(text(v, "showing_b64")?)
        .map_err(|_| "bad-showing-b64")?;
    let pk = decode_public_key(
        &STANDARD
            .decode(text(v, "terminal_agent_pk")?)
            .map_err(|_| "bad-terminal-key")?,
    )
    .map_err(|_| "bad-terminal-key")?;
    let sig = decode_signature(
        &STANDARD
            .decode(text(v, "signature_b64")?)
            .map_err(|_| "bad-signature")?,
    )
    .map_err(|_| "bad-signature")?;
    Ok(verify_signature(
        &pk,
        proof_message(req, snap, &t.config.circuit_id, &proof),
        &sig,
    ))
}
fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: sr_http_verifier TRUSTED_CONFIG");
        std::process::exit(2)
    });
    let t = match load(&path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    };
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let out = (|| -> Result<bool, String> {
        let v: Value = serde_json::from_str(&input).map_err(|_| "bad-json")?;
        match text(&v, "command")? {
            "sr-verify" => sr_verify(&v, &t),
            "sr-terminal-verify" => terminal(&v, &t),
            _ => Err("bad-command".into()),
        }
    })();
    println!(
        "{}",
        match out {
            Ok(valid) => json!({"valid":valid}),
            Err(e) => json!({"valid":false,"error":e}),
        }
    )
}
