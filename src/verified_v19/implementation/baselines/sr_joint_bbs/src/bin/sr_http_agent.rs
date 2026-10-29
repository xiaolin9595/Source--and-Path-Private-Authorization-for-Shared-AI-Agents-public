use ark_std::rand::{rngs::StdRng, SeedableRng};
use base64::{engine::general_purpose::STANDARD, Engine};
use hrada_sr_full_f_bbs::{present, AtomicCredential, Issuer, ProverParams};
use plan_a_sr_joint_bbs::{
    compile,
    http_bridge::{
        admin_artifacts, binding, lifecycle_sources, request_context, sign_terminal,
        validate_config, TrustedConfig, CONFIG_ID, ISSUER_SEED, PROOF_SCHEME,
    },
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, BufRead, Write},
    time::Instant,
};
struct Resident {
    config: TrustedConfig,
    issuer: Issuer,
    prover: ProverParams,
    credentials: BTreeMap<u64, AtomicCredential>,
    initialization: Value,
}
fn load(path: &str) -> Result<Resident, String> {
    let total = Instant::now();
    let config: TrustedConfig = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    validate_config(&config)?;
    let (h0, _, _) = lifecycle_sources();
    let mut rng = StdRng::seed_from_u64(ISSUER_SEED);
    let t = Instant::now();
    let issuer = Issuer::generate(&mut rng);
    let issuer_setup_ns = t.elapsed().as_nanos();
    let material = STANDARD.encode(
        issuer
            .verifier_params()
            .canonical_bytes()
            .map_err(|e| e.to_string())?,
    );
    if material != config.verifier_material_b64
        || hex::encode(issuer.params_digest().map_err(|e| e.to_string())?) != config.params_digest
    {
        return Err("agent-issuer-does-not-match-trusted-config".into());
    }
    let c = Instant::now();
    let compiled = compile(&h0).map_err(|e| e.to_string())?;
    let compile_ns = c.elapsed().as_nanos();
    let atom = compiled
        .issuance
        .credentials
        .first()
        .ok_or("no-h0-credential")?;
    let i = Instant::now();
    let credential = issuer
        .issue(
            &mut rng,
            atom.public_fields().map_err(|e| e.to_string())?,
            atom.not_before,
            atom.upper(),
        )
        .map_err(|e| e.to_string())?;
    let issue_ns = i.elapsed().as_nanos();
    let credential_bytes = credential
        .canonical_bytes()
        .map_err(|e| e.to_string())?
        .len();
    let mut credentials = BTreeMap::new();
    credentials.insert(atom.key.epoch, credential);
    let initialization = json!({"issuer_setup_ns":issuer_setup_ns,"h0_initial_issue":{"compile_ns":compile_ns,"issue_ns":issue_ns,"compile_plus_issue_ns":compile_ns+issue_ns,"credential_bytes":credential_bytes},"total_before_ready_ns":total.elapsed().as_nanos(),"h1_credential_present_at_ready":false});
    let prover = issuer.prover_params();
    Ok(Resident {
        config,
        issuer,
        prover,
        credentials,
        initialization,
    })
}
fn refresh_h1(r: &mut Resident) -> Result<Value, String> {
    if r.credentials.contains_key(&2) {
        return Err("h1-already-refreshed".into());
    }
    let total = Instant::now();
    let (_, h1, _) = lifecycle_sources();
    let c = Instant::now();
    let compiled = compile(&h1).map_err(|e| e.to_string())?;
    let compile_ns = c.elapsed().as_nanos();
    if compiled.issuance.credentials.len() != 1 {
        return Err("unexpected-h1-credential-count".into());
    }
    let atom = &compiled.issuance.credentials[0];
    let mut rng = StdRng::seed_from_u64(ISSUER_SEED ^ 0x4831);
    let i = Instant::now();
    let credential = r
        .issuer
        .issue(
            &mut rng,
            atom.public_fields().map_err(|e| e.to_string())?,
            atom.not_before,
            atom.upper(),
        )
        .map_err(|e| e.to_string())?;
    let issue_ns = i.elapsed().as_nanos();
    let credential_bytes = credential
        .canonical_bytes()
        .map_err(|e| e.to_string())?
        .len();
    r.credentials.insert(atom.key.epoch, credential);
    Ok(
        json!({"refreshed":true,"tuple_version":atom.key.epoch,"compile_ns":compile_ns,"issue_ns":issue_ns,"compile_plus_issue_ns":compile_ns+issue_ns,"total_command_wall_ns":total.elapsed().as_nanos(),"credential_serialized_bytes":credential_bytes,"delivery_mode":"trusted_issuer_emulation_in_resident_process","network_delivery_measured":false}),
    )
}
fn make(v: &Value, r: &Resident) -> Result<Value, String> {
    let request = v.get("request").ok_or("missing-request")?;
    let digest = request
        .get("snapshot_digest")
        .and_then(Value::as_str)
        .ok_or("bad-snapshot-digest")?;
    let b = binding(&r.config, digest)?;
    let stale = v.get("stale_credential_epoch").and_then(Value::as_u64);
    if !b.credential_available && stale.is_none() {
        return Err("no-credential-for-snapshot".into());
    }
    let (ctx, public) = request_context(&r.config, request, &b.snapshot, r.prover.params_digest)?;
    let epoch = stale.unwrap_or(b.tuple_version);
    let credential = r.credentials.get(&epoch).ok_or("credential-not-issued")?;
    if stale.is_none() && public != credential.public {
        return Err("credential-does-not-match-trusted-request".into());
    }
    let seed = v
        .get("show_seed")
        .and_then(Value::as_u64)
        .ok_or("bad-show-seed")?;
    let mut rng = StdRng::seed_from_u64(seed);
    let t = Instant::now();
    let showing = present(&mut rng, &r.prover, credential, &ctx).map_err(|e| e.to_string())?;
    let show_ns = t.elapsed().as_nanos();
    let bytes = showing.canonical_bytes().map_err(|e| e.to_string())?;
    Ok(
        json!({"config_id":CONFIG_ID,"proof_scheme":PROOF_SCHEME,"credential_epoch":epoch,"stale_credential_test":stale.is_some(),"showing_b64":STANDARD.encode(&bytes),"signature_b64":sign_terminal(&r.config.circuit_id,request,&bytes)?,"timing":{"show_ns":show_ns,"showing_bytes":bytes.len()}}),
    )
}
fn main() {
    let a = std::env::args().collect::<Vec<_>>();
    if a.get(1).map(String::as_str) == Some("describe") {
        match admin_artifacts() {
            Ok(v) => println!("{v}"),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2)
            }
        }
        return;
    }
    let serve = a.get(1).map(String::as_str) == Some("serve");
    let path = if serve { a.get(2) } else { a.get(1) }.unwrap_or_else(|| {
        eprintln!("usage: sr_http_agent [serve] TRUSTED_CONFIG");
        std::process::exit(2)
    });
    let mut resident = match load(path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    };
    if serve {
        println!(
            "{}",
            json!({"ready":true,"config_id":CONFIG_ID,"proof_scheme":PROOF_SCHEME,"initialization":resident.initialization})
        );
        io::stdout().flush().unwrap();
        for line in io::stdin().lock().lines() {
            let out = line
                .map_err(|e| e.to_string())
                .and_then(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
                .and_then(|v| {
                    if v.get("command").and_then(Value::as_str) == Some("refresh-h1") {
                        refresh_h1(&mut resident)
                    } else {
                        make(&v, &resident)
                    }
                });
            println!(
                "{}",
                match out {
                    Ok(v) => v,
                    Err(e) => json!({"error":e}),
                }
            );
            io::stdout().flush().unwrap()
        }
        return;
    }
    let mut s = String::new();
    io::Read::read_to_string(&mut io::stdin(), &mut s).unwrap();
    match serde_json::from_str(&s)
        .map_err(|e| e.to_string())
        .and_then(|v| make(&v, &resident))
    {
        Ok(v) => println!("{v}"),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2)
        }
    }
}
