use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use ipld_core::ipld::Ipld;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, Signer},
    delegation::{Delegation, Subject},
    invocation::Invocation,
    nonce::Nonce,
    policy::Policy,
    time::Timestamp,
    validate::{MemoryReplayGuard, MemoryStore, Validator},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeSet, fs::File, io::Read, time::Instant};

const TRIALS_PER_CONFIGURATION: usize = 10;
const NOW: i64 = 1_800_000_000;
const AS_ISSUER: &str = "https://as.plan-a.example";
const RS_AUDIENCE: &str = "urn:plan-a:resource-server";
const RESOURCE: &str = "urn:plan-a:resource:alpha";
const ACTION: &str = "read";
const HEADER: &str = "header-7";
const POLICY_VERSION: u64 = 3;
const REQUEST_DIGEST: &str = "sha256:plan-a-request-read-40-60-formal";
const JWT_REVOCATION_DOMAIN: &[u8] = b"plan-a-jwt-inactive-jti-registry-v1";
const UCAN_REVOCATION_DOMAIN: &[u8] = b"plan-a-ucan-revocation-registry-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Actor {
    sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    act: Option<Box<Actor>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    aud: String,
    sub: String,
    act: Actor,
    scope: String,
    resource: String,
    grant_lo: u64,
    grant_hi: u64,
    nbf: u64,
    exp: u64,
    jti: String,
    chain_jti: Vec<String>,
    header_id: String,
    policy_version: u64,
    request_digest: String,
}

#[derive(Debug, Serialize)]
struct Trial {
    protocol: &'static str,
    semantic_length: usize,
    paired_trial: usize,
    order_position: usize,
    order: String,
    request_lo: u64,
    request_hi: u64,
    setup_us: f64,
    initial_issuance_us: f64,
    attenuation_refresh_us: f64,
    issuance_us: f64,
    presentation_us: f64,
    verification_us: f64,
    revocation_update_us: f64,
    signed_artifact_bytes_by_level: Vec<usize>,
    signed_artifacts_total_bytes: usize,
    presentation_bytes: usize,
    terminal_binding_bytes: usize,
    revocation_state_bytes: usize,
    accepted: bool,
    revoked_path_rejected: bool,
    independent_path_survives: bool,
    visible_chain_length: usize,
}

#[derive(Clone, Copy)]
struct Workload {
    request_lo: u64,
    request_hi: u64,
}

#[derive(Clone)]
struct SignedRevocationRegistry {
    domain: &'static [u8],
    version: u64,
    revoked_proof_cids: BTreeSet<String>,
    signature: Signature,
}

#[derive(Default)]
struct RevocationRegistryState {
    version: Option<u64>,
    revoked_proof_cids: BTreeSet<String>,
}

impl RevocationRegistryState {
    fn install(&mut self, registry: &SignedRevocationRegistry, authority: &VerifyingKey) -> bool {
        if authority
            .verify(
                &revocation_message(
                    registry.domain,
                    registry.version,
                    &registry.revoked_proof_cids,
                ),
                &registry.signature,
            )
            .is_err()
            || self.version.map_or(false, |old| registry.version <= old)
        {
            return false;
        }
        self.version = Some(registry.version);
        self.revoked_proof_cids = registry.revoked_proof_cids.clone();
        true
    }

    fn allows(&self, proof_cids: &[String]) -> bool {
        self.version.is_some()
            && !proof_cids
                .iter()
                .any(|cid| self.revoked_proof_cids.contains(cid))
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .expect("fresh operating-system randomness");
    bytes
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

fn issue_jwt(claims: &AccessTokenClaims, key: &[u8]) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(key),
    )
    .unwrap()
}

fn decode_jwt(token: &str, key: &[u8]) -> Result<AccessTokenClaims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_issuer(&[AS_ISSUER]);
    validation.set_audience(&[RS_AUDIENCE]);
    decode::<AccessTokenClaims>(token, &DecodingKey::from_secret(key), &validation)
        .map(|data| data.claims)
        .map_err(|error| error.to_string())
}

fn exchange_jwt(
    token: &str,
    key: &[u8],
    caller: &str,
    actor: &str,
    lo: u64,
    hi: u64,
    nbf: u64,
    exp: u64,
    jti: String,
) -> Result<String, String> {
    let parent = decode_jwt(token, key)?;
    if caller != parent.act.sub
        || parent.nbf > NOW as u64
        || parent.exp < NOW as u64
        || lo < parent.grant_lo
        || hi > parent.grant_hi
        || lo > hi
        || nbf < parent.nbf
        || exp > parent.exp
        || nbf > exp
    {
        return Err("invalid attenuation".into());
    }
    let mut chain_jti = parent.chain_jti.clone();
    chain_jti.push(jti.clone());
    Ok(issue_jwt(
        &AccessTokenClaims {
            iss: AS_ISSUER.into(),
            aud: RS_AUDIENCE.into(),
            sub: parent.sub,
            act: Actor {
                sub: actor.into(),
                act: Some(Box::new(parent.act)),
            },
            scope: ACTION.into(),
            resource: RESOURCE.into(),
            grant_lo: lo,
            grant_hi: hi,
            nbf,
            exp,
            jti,
            chain_jti,
            header_id: HEADER.into(),
            policy_version: POLICY_VERSION,
            request_digest: REQUEST_DIGEST.into(),
        },
        key,
    ))
}

fn authorize_jwt(
    token: &str,
    key: &[u8],
    terminal: &str,
    inactive: &BTreeSet<String>,
    workload: Workload,
) -> Result<AccessTokenClaims, String> {
    let claims = decode_jwt(token, key)?;
    if claims.resource != RESOURCE
        || claims.scope != ACTION
        || claims.act.sub != terminal
        || claims.grant_lo > workload.request_lo
        || claims.grant_hi < workload.request_hi
        || claims.nbf > NOW as u64
        || claims.exp < NOW as u64
        || claims.header_id != HEADER
        || claims.policy_version != POLICY_VERSION
        || claims.request_digest != REQUEST_DIGEST
        || claims.chain_jti.iter().any(|jti| inactive.contains(jti))
    {
        return Err("authorization rejected".into());
    }
    Ok(claims)
}

fn append_bytes(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u64).to_le_bytes());
    message.extend_from_slice(value);
}

fn pop_message(token: &str, terminal: &str, nonce: &[u8], workload: Workload) -> Vec<u8> {
    let mut message = b"plan-a-jwt-terminal-pop-v1".to_vec();
    for value in [
        token.as_bytes(),
        terminal.as_bytes(),
        REQUEST_DIGEST.as_bytes(),
        HEADER.as_bytes(),
        nonce,
    ] {
        append_bytes(&mut message, value);
    }
    for value in [
        workload.request_lo,
        workload.request_hi,
        POLICY_VERSION,
        NOW as u64 - 10,
        NOW as u64 + 60,
    ] {
        message.extend_from_slice(&value.to_le_bytes());
    }
    message
}

fn jwt_trial(
    length: usize,
    trial: usize,
    order_position: usize,
    order: &str,
    workload: Workload,
) -> Trial {
    let setup_started = Instant::now();
    let hmac_key = random_bytes::<32>();
    let terminal_key = SigningKey::from_bytes(&random_bytes::<32>());
    let terminal_verify = terminal_key.verifying_key();
    let revocation_signer = SigningKey::from_bytes(&random_bytes::<32>());
    let revocation_verifier = revocation_signer.verifying_key();
    let run_nonce = hex(&random_bytes::<12>());
    let setup_us = setup_started.elapsed().as_secs_f64() * 1_000_000.0;
    let terminal = "did:example:terminal";

    let issuance_started = Instant::now();
    let first_actor = if length == 1 {
        terminal.to_string()
    } else {
        "did:example:delegate-1".to_string()
    };
    let first_jti = format!("jwt-{run_nonce}-0");
    let first_bounds = if length == 1 { (20, 80) } else { (0, 100) };
    let first_validity = if length == 1 {
        (NOW as u64 - 10, NOW as u64 + 60)
    } else {
        (NOW as u64 - 100, NOW as u64 + 100)
    };
    let initial_started = Instant::now();
    let root = issue_jwt(
        &AccessTokenClaims {
            iss: AS_ISSUER.into(),
            aud: RS_AUDIENCE.into(),
            sub: "did:example:owner".into(),
            act: Actor {
                sub: first_actor.clone(),
                act: None,
            },
            scope: ACTION.into(),
            resource: RESOURCE.into(),
            grant_lo: first_bounds.0,
            grant_hi: first_bounds.1,
            nbf: first_validity.0,
            exp: first_validity.1,
            jti: first_jti.clone(),
            chain_jti: vec![first_jti.clone()],
            header_id: HEADER.into(),
            policy_version: POLICY_VERSION,
            request_digest: REQUEST_DIGEST.into(),
        },
        &hmac_key,
    );
    let initial_issuance_us = initial_started.elapsed().as_secs_f64() * 1_000_000.0;
    let mut tokens = vec![root];
    let mut caller = first_actor;
    let refresh_started = Instant::now();
    for level in 1..length {
        let is_last = level + 1 == length;
        let actor = if is_last {
            terminal.to_string()
        } else {
            format!("did:example:delegate-{}", level + 1)
        };
        let (lo, hi, nbf, exp) = if is_last {
            (20, 80, NOW as u64 - 10, NOW as u64 + 60)
        } else {
            (10, 90, NOW as u64 - 50, NOW as u64 + 80)
        };
        let token = exchange_jwt(
            tokens.last().unwrap(),
            &hmac_key,
            &caller,
            &actor,
            lo,
            hi,
            nbf,
            exp,
            format!("jwt-{run_nonce}-{level}"),
        )
        .unwrap();
        tokens.push(token);
        caller = actor;
    }
    let attenuation_refresh_us = refresh_started.elapsed().as_secs_f64() * 1_000_000.0;
    let issuance_us = issuance_started.elapsed().as_secs_f64() * 1_000_000.0;
    let final_token = tokens.last().unwrap();

    let presentation_started = Instant::now();
    let nonce = random_bytes::<24>();
    let message = pop_message(final_token, terminal, &nonce, workload);
    let signature = terminal_key.sign(&message);
    let presentation_us = presentation_started.elapsed().as_secs_f64() * 1_000_000.0;

    let verification_started = Instant::now();
    let accepted = authorize_jwt(final_token, &hmac_key, terminal, &BTreeSet::new(), workload)
        .is_ok()
        && terminal_verify.verify(&message, &signature).is_ok();
    let verification_us = verification_started.elapsed().as_secs_f64() * 1_000_000.0;

    let active_registry = sign_registry(
        &revocation_signer,
        JWT_REVOCATION_DOMAIN,
        1,
        BTreeSet::new(),
    );
    let mut registry = RevocationRegistryState::default();
    assert!(registry.install(&active_registry, &revocation_verifier));
    let alternate_jti = format!("jwt-alt-{run_nonce}");
    let alternate = issue_jwt(
        &AccessTokenClaims {
            iss: AS_ISSUER.into(),
            aud: RS_AUDIENCE.into(),
            sub: "did:example:owner".into(),
            act: Actor {
                sub: terminal.into(),
                act: None,
            },
            scope: ACTION.into(),
            resource: RESOURCE.into(),
            grant_lo: 30,
            grant_hi: 70,
            nbf: NOW as u64 - 5,
            exp: NOW as u64 + 50,
            jti: alternate_jti.clone(),
            chain_jti: vec![alternate_jti],
            header_id: HEADER.into(),
            policy_version: POLICY_VERSION,
            request_digest: REQUEST_DIGEST.into(),
        },
        &hmac_key,
    );
    let alternate_before_revocation = alternate.as_bytes().to_vec();
    let revocation_started = Instant::now();
    let mut inactive = BTreeSet::new();
    inactive.insert(first_jti);
    let revoked_registry = sign_registry(&revocation_signer, JWT_REVOCATION_DOMAIN, 2, inactive);
    assert!(registry.install(&revoked_registry, &revocation_verifier));
    let revocation_update_us = revocation_started.elapsed().as_secs_f64() * 1_000_000.0;
    let revoked_path_rejected = authorize_jwt(
        final_token,
        &hmac_key,
        terminal,
        &registry.revoked_proof_cids,
        workload,
    )
    .is_err();
    let independent_path_survives = alternate.as_bytes() == alternate_before_revocation
        && authorize_jwt(
            &alternate,
            &hmac_key,
            terminal,
            &registry.revoked_proof_cids,
            workload,
        )
        .is_ok();
    let registry_bytes = revocation_message(
        revoked_registry.domain,
        revoked_registry.version,
        &revoked_registry.revoked_proof_cids,
    )
    .len()
        + revoked_registry.signature.to_bytes().len();
    let artifact_bytes: Vec<usize> = tokens.iter().map(String::len).collect();

    Trial {
        protocol: "JWT-RFC8693-local-profile",
        semantic_length: length,
        paired_trial: trial,
        order_position,
        order: order.into(),
        request_lo: workload.request_lo,
        request_hi: workload.request_hi,
        setup_us,
        initial_issuance_us,
        attenuation_refresh_us,
        issuance_us,
        presentation_us,
        verification_us,
        revocation_update_us,
        signed_artifacts_total_bytes: artifact_bytes.iter().sum(),
        signed_artifact_bytes_by_level: artifact_bytes,
        presentation_bytes: final_token.len() + signature.to_bytes().len() + nonce.len(),
        terminal_binding_bytes: signature.to_bytes().len() + nonce.len(),
        revocation_state_bytes: registry_bytes,
        accepted,
        revoked_path_rejected,
        independent_path_survives,
        visible_chain_length: length,
    }
}

fn text(value: &str) -> Ipld {
    Ipld::String(value.into())
}

fn statement(operator: &str, selector: &str, value: Ipld) -> Ipld {
    Ipld::List(vec![text(operator), text(selector), value])
}

fn grant_policy(lo: i128, hi: i128) -> Policy {
    Policy::from_ipld(&Ipld::List(vec![
        statement("==", ".resource", text(RESOURCE)),
        statement("==", ".action", text(ACTION)),
        statement(">=", ".request_lo", Ipld::Integer(lo)),
        statement("<=", ".request_hi", Ipld::Integer(hi)),
        statement("==", ".header_id", text(HEADER)),
        statement("==", ".request_digest", text(REQUEST_DIGEST)),
    ]))
    .unwrap()
}

fn make_invocation(
    owner: &Ed25519Keypair,
    terminal: &Ed25519Keypair,
    proofs: Vec<pq_ucan::Cid>,
    nonce: Vec<u8>,
    workload: Workload,
) -> Invocation {
    Invocation::builder(owner.did(), Command::parse("/crud/read").unwrap())
        .arg("resource", text(RESOURCE))
        .arg("action", text(ACTION))
        .arg("request_lo", Ipld::Integer(workload.request_lo.into()))
        .arg("request_hi", Ipld::Integer(workload.request_hi.into()))
        .arg("header_id", text(HEADER))
        .arg("request_digest", text(REQUEST_DIGEST))
        .proofs(proofs)
        .nonce(Nonce::from(nonce))
        .expires_at(Timestamp::from_unix(NOW + 30).unwrap())
        .sign(terminal)
        .unwrap()
}

fn validate_ucan(
    store: &MemoryStore,
    invocation: &Invocation,
    executor: &pq_ucan::did::Did,
) -> bool {
    Validator::new(store, Timestamp::from_unix(NOW).unwrap())
        .skew(0)
        .executor(executor)
        .validate(invocation)
        .is_ok()
}

fn revocation_message(domain: &[u8], version: u64, revoked: &BTreeSet<String>) -> Vec<u8> {
    let mut message = domain.to_vec();
    message.extend_from_slice(&version.to_le_bytes());
    message.extend_from_slice(&(revoked.len() as u64).to_le_bytes());
    for cid in revoked {
        append_bytes(&mut message, cid.as_bytes());
    }
    message
}

fn sign_registry(
    signer: &SigningKey,
    domain: &'static [u8],
    version: u64,
    revoked_proof_cids: BTreeSet<String>,
) -> SignedRevocationRegistry {
    let signature = signer.sign(&revocation_message(domain, version, &revoked_proof_cids));
    SignedRevocationRegistry {
        domain,
        version,
        revoked_proof_cids,
        signature,
    }
}

fn ucan_trial(
    length: usize,
    trial: usize,
    order_position: usize,
    order: &str,
    workload: Workload,
) -> Trial {
    let setup_started = Instant::now();
    let owner = Ed25519Keypair::from_seed(&random_bytes::<32>());
    let terminal = Ed25519Keypair::from_seed(&random_bytes::<32>());
    let intermediates: Vec<Ed25519Keypair> = (0..length.saturating_sub(1))
        .map(|_| Ed25519Keypair::from_seed(&random_bytes::<32>()))
        .collect();
    let registry_signer = SigningKey::from_bytes(&random_bytes::<32>());
    let registry_verifier = registry_signer.verifying_key();
    let run_nonce = random_bytes::<16>();
    let setup_us = setup_started.elapsed().as_secs_f64() * 1_000_000.0;
    let owner_did = owner.did();

    let issuance_started = Instant::now();
    let mut delegations = Vec::with_capacity(length);
    let mut initial_issuance_us = 0.0;
    for level in 0..length {
        let last = level + 1 == length;
        let audience = if last {
            terminal.did()
        } else {
            intermediates[level].did()
        };
        let subject = if level == 0 {
            Subject::Did(owner_did.clone())
        } else {
            Subject::Powerline
        };
        let signer = if level == 0 {
            &owner
        } else {
            &intermediates[level - 1]
        };
        let (lo, hi, not_before, expiry) = if last {
            (20, 80, NOW - 10, NOW + 60)
        } else if level == 0 {
            (0, 100, NOW - 100, NOW + 100)
        } else {
            (10, 90, NOW - 50, NOW + 80)
        };
        let mut nonce = run_nonce.to_vec();
        nonce.extend_from_slice(&(level as u64).to_le_bytes());
        let command = if level == 0 && !last {
            "/crud"
        } else {
            "/crud/read"
        };
        let delegation = Delegation::builder(audience, subject, Command::parse(command).unwrap())
            .policy(grant_policy(lo, hi))
            .not_before(Timestamp::from_unix(not_before).unwrap())
            .nonce(Nonce::from(nonce))
            .expires_at(Timestamp::from_unix(expiry).unwrap())
            .sign(signer)
            .unwrap();
        delegations.push(delegation);
        if level == 0 {
            initial_issuance_us = issuance_started.elapsed().as_secs_f64() * 1_000_000.0;
        }
    }
    let issuance_us = issuance_started.elapsed().as_secs_f64() * 1_000_000.0;
    let attenuation_refresh_us = (issuance_us - initial_issuance_us).max(0.0);
    let artifact_bytes: Vec<usize> = delegations
        .iter()
        .map(|delegation| delegation.bytes().len())
        .collect();
    let proof_cids: Vec<pq_ucan::Cid> = delegations.iter().map(|d| *d.cid()).collect();
    let proof_strings: Vec<String> = proof_cids.iter().map(ToString::to_string).collect();
    let mut store = MemoryStore::new();
    for delegation in &delegations {
        store.insert(delegation.clone());
    }

    let presentation_started = Instant::now();
    let invocation_nonce = random_bytes::<24>();
    let request = make_invocation(
        &owner,
        &terminal,
        proof_cids,
        invocation_nonce.to_vec(),
        workload,
    );
    let presentation_us = presentation_started.elapsed().as_secs_f64() * 1_000_000.0;
    let presentation_bytes = request.bytes().len();

    let verification_started = Instant::now();
    let mut replay = MemoryReplayGuard::new();
    let accepted = Validator::new(&store, Timestamp::from_unix(NOW).unwrap())
        .skew(0)
        .executor(&owner_did)
        .replay_guard(&mut replay)
        .validate(&request)
        .is_ok();
    let verification_us = verification_started.elapsed().as_secs_f64() * 1_000_000.0;

    let alternate_nonce = random_bytes::<24>();
    let alternate = Delegation::builder(
        terminal.did(),
        Subject::Did(owner_did.clone()),
        Command::parse("/crud/read").unwrap(),
    )
    .policy(grant_policy(30, 70))
    .not_before(Timestamp::from_unix(NOW - 5).unwrap())
    .nonce(Nonce::from(alternate_nonce.to_vec()))
    .expires_at(Timestamp::from_unix(NOW + 50).unwrap())
    .sign(&owner)
    .unwrap();
    let alternate_delegation_before_revocation = alternate.bytes().to_vec();
    let alternate_cid = *alternate.cid();
    let alternate_cid_string = alternate_cid.to_string();
    let mut alternate_store = MemoryStore::new();
    alternate_store.insert(alternate.clone());
    let alternate_request = make_invocation(
        &owner,
        &terminal,
        vec![alternate_cid],
        random_bytes::<24>().to_vec(),
        workload,
    );
    let alternate_invocation_before_revocation = alternate_request.bytes().to_vec();
    let active = sign_registry(&registry_signer, UCAN_REVOCATION_DOMAIN, 1, BTreeSet::new());
    let mut registry = RevocationRegistryState::default();
    assert!(registry.install(&active, &registry_verifier));
    let revocation_started = Instant::now();
    let mut revoked = BTreeSet::new();
    revoked.insert(proof_strings[0].clone());
    let revoked_registry = sign_registry(&registry_signer, UCAN_REVOCATION_DOMAIN, 2, revoked);
    assert!(registry.install(&revoked_registry, &registry_verifier));
    let revocation_update_us = revocation_started.elapsed().as_secs_f64() * 1_000_000.0;
    let revoked_path_rejected = !registry.allows(&proof_strings);
    let independent_path_survives = alternate_delegation_before_revocation == alternate.bytes()
        && alternate_invocation_before_revocation == alternate_request.bytes()
        && registry.allows(&[alternate_cid_string])
        && validate_ucan(&alternate_store, &alternate_request, &owner_did);
    let registry_bytes = revocation_message(
        revoked_registry.domain,
        revoked_registry.version,
        &revoked_registry.revoked_proof_cids,
    )
    .len()
        + revoked_registry.signature.to_bytes().len();

    Trial {
        protocol: "UCAN-1.0-DAG-CBOR-local-profile",
        semantic_length: length,
        paired_trial: trial,
        order_position,
        order: order.into(),
        request_lo: workload.request_lo,
        request_hi: workload.request_hi,
        setup_us,
        initial_issuance_us,
        attenuation_refresh_us,
        issuance_us,
        presentation_us,
        verification_us,
        revocation_update_us,
        signed_artifacts_total_bytes: artifact_bytes.iter().sum(),
        signed_artifact_bytes_by_level: artifact_bytes,
        presentation_bytes,
        terminal_binding_bytes: request.signature().as_bytes().len() + invocation_nonce.len(),
        revocation_state_bytes: registry_bytes,
        accepted,
        revoked_path_rejected,
        independent_path_survives,
        visible_chain_length: proof_strings.len(),
    }
}

fn main() {
    let run_id = hex(&random_bytes::<16>());
    let mut trials = Vec::with_capacity(2 * 3 * TRIALS_PER_CONFIGURATION);
    for length in 1..=3 {
        for paired_trial in 0..TRIALS_PER_CONFIGURATION {
            let workload_randomness = random_bytes::<2>();
            let workload = Workload {
                request_lo: 35 + u64::from(workload_randomness[0] % 6),
                request_hi: 60 + u64::from(workload_randomness[1] % 6),
            };
            let jwt_first = (length + paired_trial) % 2 == 0;
            let order = if jwt_first { "JWT,UCAN" } else { "UCAN,JWT" };
            if jwt_first {
                trials.push(jwt_trial(length, paired_trial, 0, order, workload));
                trials.push(ucan_trial(length, paired_trial, 1, order, workload));
            } else {
                trials.push(ucan_trial(length, paired_trial, 0, order, workload));
                trials.push(jwt_trial(length, paired_trial, 1, order, workload));
            }
        }
    }
    assert_eq!(trials.len(), 60);
    assert!(trials.iter().all(|trial| {
        trial.accepted
            && trial.revoked_path_rejected
            && trial.independent_path_survives
            && trial.visible_chain_length == trial.semantic_length
            && trial.signed_artifact_bytes_by_level.len() == trial.semantic_length
    }));
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "plan-a-b1-formal-trials-v1",
            "run_id": run_id,
            "trial_count_per_protocol_length": TRIALS_PER_CONFIGURATION,
            "protocols": ["JWT-RFC8693-local-profile", "UCAN-1.0-DAG-CBOR-local-profile"],
            "semantic_lengths": [1, 2, 3],
            "semantic_length_definition": "number of signed grant/delegation artifacts from owner to terminal; final presentation is measured separately",
            "setup_definition": "fresh OS-random HMAC/Ed25519 keys and per-trial nonces; setup time includes OS random reads and key construction",
            "workload_definition": "fixed resource/action/time/header/request-digest semantics; a fresh paired request interval is sampled inside [35,40]x[60,65] for each length/trial and shared by JWT and UCAN; keys, identifiers, nonces and signatures are fresh per protocol trial",
            "timing_definition": {
                "initial_issuance_us": "first owner-signed grant/delegation artifact",
                "attenuation_refresh_us": "all remaining signed attenuation/exchange artifacts; near-zero for semantic length one",
                "issuance_us": "complete first-through-final issuance chain measured as one interval",
                "presentation_us": "terminal PoP signing for JWT or signed invocation construction for UCAN",
                "verification_us": "JWT signature/business predicate plus terminal PoP, or UCAN full proof-chain validation with replay guard",
                "revocation_update_us": "Ed25519 signing and monotone installation of the authenticated inactive-JTI registry for JWT or authenticated CID-registry update for UCAN"
            },
            "order_control": "paired trial order alternates by parity of semantic_length + paired_trial; five trials per order for every length",
            "fresh_setup_each_trial": true,
            "functional_gate_required_before_formal_run": true,
            "provenance_private": false,
            "same_privacy_comparator": false,
            "visible_chain_depth_and_identifiers": true,
            "jwt_shared_as_rs_hmac_bearer_profile": true,
            "jwt_terminal_pop_is_deployment_extension": true,
            "jwt_authenticated_inactive_jti_registry_is_deployment_extension": true,
            "ucan_authenticated_cid_registry_is_deployment_extension": true,
            "raw_trials": trials
        }))
        .unwrap()
    );
}
