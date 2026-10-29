use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use plan_a_b1_protocols::service_adapter::{AdapterError, DeltaZeroAdapter, HeaderVersion};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::BTreeSet, time::Instant};

const AS_ISSUER: &str = "https://as.plan-a.example";
const RS_AUDIENCE: &str = "urn:plan-a:resource-server";
const RESOURCE: &str = "urn:plan-a:resource:alpha";
const ACTION: &str = "read";
const NOW: u64 = 1_800_000_000;
const ACTIVE_HEADER: &str = "header-7";
const POLICY_VERSION: u64 = 3;
const REQUEST_DIGEST: &str = "sha256:plan-a-request-read-40-60-nonce-9";
const HMAC_KEY: &[u8] = b"plan-a-rfc8693-benchmark-shared-as-rs-key-32";
const POP_NONCE: &[u8] = b"jwt-terminal-pop-nonce-1";

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

#[derive(Clone)]
struct ExchangeRequest<'a> {
    caller: &'a str,
    actor: &'a str,
    scope: &'a str,
    grant_lo: u64,
    grant_hi: u64,
    nbf: u64,
    exp: u64,
    jti: &'a str,
}

fn decode_as(token: &str) -> Result<AccessTokenClaims, String> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.set_issuer(&[AS_ISSUER]);
    validation.set_audience(&[RS_AUDIENCE]);
    decode::<AccessTokenClaims>(token, &DecodingKey::from_secret(HMAC_KEY), &validation)
        .map(|data| data.claims)
        .map_err(|error| error.to_string())
}

fn issue(claims: &AccessTokenClaims) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(HMAC_KEY),
    )
    .unwrap()
}

fn append_bytes(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u64).to_le_bytes());
    message.extend_from_slice(value);
}

#[allow(clippy::too_many_arguments)]
fn terminal_pop_message(
    token: &str,
    terminal: &str,
    request_lo: u64,
    request_hi: u64,
    request_digest: &str,
    header_id: &str,
    policy_version: u64,
    nonce: &[u8],
    not_before: u64,
    expiry: u64,
) -> Vec<u8> {
    let mut message = b"plan-a-jwt-terminal-pop-v1".to_vec();
    for value in [
        token.as_bytes(),
        terminal.as_bytes(),
        request_digest.as_bytes(),
        header_id.as_bytes(),
        nonce,
    ] {
        append_bytes(&mut message, value);
    }
    for value in [request_lo, request_hi, policy_version, not_before, expiry] {
        message.extend_from_slice(&value.to_le_bytes());
    }
    message
}

fn verify_terminal_pop(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    key.verify(message, signature).is_ok()
}

fn exchange(
    subject_token: &str,
    request: ExchangeRequest<'_>,
    now: u64,
    inactive: &BTreeSet<String>,
) -> Result<String, String> {
    let parent = decode_as(subject_token)?;
    // Deployment extension around the RFC 8693 token shape: the AS authenticates
    // the caller as the current actor and checks current validity/revocation before
    // compiling an attenuated successor.
    if request.caller != parent.act.sub
        || parent.nbf > now
        || parent.exp < now
        || parent.chain_jti.iter().any(|jti| inactive.contains(jti))
        || request.scope != parent.scope
        || request.grant_lo < parent.grant_lo
        || request.grant_hi > parent.grant_hi
        || request.grant_lo > request.grant_hi
        || request.nbf < parent.nbf
        || request.exp > parent.exp
        || request.nbf > request.exp
    {
        return Err("exchange would widen authority".into());
    }
    let mut chain_jti = parent.chain_jti.clone();
    chain_jti.push(request.jti.into());
    Ok(issue(&AccessTokenClaims {
        iss: AS_ISSUER.into(),
        aud: RS_AUDIENCE.into(),
        sub: parent.sub,
        act: Actor {
            sub: request.actor.into(),
            act: Some(Box::new(parent.act)),
        },
        scope: request.scope.into(),
        resource: parent.resource,
        grant_lo: request.grant_lo,
        grant_hi: request.grant_hi,
        nbf: request.nbf,
        exp: request.exp,
        jti: request.jti.into(),
        chain_jti,
        header_id: parent.header_id,
        policy_version: parent.policy_version,
        request_digest: parent.request_digest,
    }))
}

#[allow(clippy::too_many_arguments)]
fn authorize(
    token: &str,
    terminal: &str,
    request_lo: u64,
    request_hi: u64,
    request_digest: &str,
    accepted_header: &str,
    expected_policy_version: u64,
    now: u64,
    inactive: &BTreeSet<String>,
    consumed: &mut BTreeSet<String>,
) -> Result<AccessTokenClaims, String> {
    let claims = decode_as(token)?;
    if request_lo > request_hi
        || claims.resource != RESOURCE
        || claims.scope != ACTION
        || claims.act.sub != terminal
        || claims.grant_lo > request_lo
        || claims.grant_hi < request_hi
        || claims.nbf > now
        || claims.exp < now
        || claims.header_id != accepted_header
        || claims.policy_version != expected_policy_version
        || claims.request_digest != request_digest
    {
        return Err("resource-server business predicate rejected".into());
    }
    if claims.chain_jti.iter().any(|jti| inactive.contains(jti)) {
        return Err("introspection reports inactive ancestor/current token".into());
    }
    if !consumed.insert(claims.jti.clone()) {
        return Err("replayed bearer token".into());
    }
    Ok(claims)
}

fn main() {
    let root = issue(&AccessTokenClaims {
        iss: AS_ISSUER.into(),
        aud: RS_AUDIENCE.into(),
        sub: "did:example:owner".into(),
        act: Actor {
            sub: "did:example:delegate-a".into(),
            act: None,
        },
        scope: ACTION.into(),
        resource: RESOURCE.into(),
        grant_lo: 0,
        grant_hi: 100,
        nbf: NOW - 100,
        exp: NOW + 100,
        jti: "grant-root".into(),
        chain_jti: vec!["grant-root".into()],
        header_id: ACTIVE_HEADER.into(),
        policy_version: POLICY_VERSION,
        request_digest: REQUEST_DIGEST.into(),
    });

    let started = Instant::now();
    let terminal_token = exchange(
        &root,
        ExchangeRequest {
            caller: "did:example:delegate-a",
            actor: "did:example:terminal",
            scope: ACTION,
            grant_lo: 20,
            grant_hi: 80,
            nbf: NOW - 10,
            exp: NOW + 60,
            jti: "grant-terminal",
        },
        NOW,
        &BTreeSet::new(),
    )
    .unwrap();
    let exchange_us = started.elapsed().as_secs_f64() * 1_000_000.0;

    let inactive = BTreeSet::new();
    let mut consumed = BTreeSet::new();
    let started = Instant::now();
    let accepted = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &inactive,
        &mut consumed,
    )
    .is_ok();
    let verify_us = started.elapsed().as_secs_f64() * 1_000_000.0;

    let replay_rejected = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &inactive,
        &mut consumed,
    )
    .is_err();
    let request_mutation_rejected = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        "sha256:mutated",
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &inactive,
        &mut BTreeSet::new(),
    )
    .is_err();
    let retired_header_rejected = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        "header-8",
        POLICY_VERSION,
        NOW,
        &inactive,
        &mut BTreeSet::new(),
    )
    .is_err();
    let expired_rejected = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW + 61,
        &inactive,
        &mut BTreeSet::new(),
    )
    .is_err();
    let mut revoked = BTreeSet::new();
    revoked.insert("grant-root".into());
    let revoked_ancestor_rejected = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &revoked,
        &mut BTreeSet::new(),
    )
    .is_err();
    let widening_exchange_rejected = exchange(
        &root,
        ExchangeRequest {
            caller: "did:example:delegate-a",
            actor: "did:example:terminal",
            scope: ACTION,
            grant_lo: 0,
            grant_hi: 101,
            nbf: NOW - 100,
            exp: NOW + 100,
            jti: "bad-widening",
        },
        NOW,
        &BTreeSet::new(),
    )
    .is_err();
    let unauthorized_exchange_rejected = exchange(
        &root,
        ExchangeRequest {
            caller: "did:example:not-current-actor",
            actor: "did:example:terminal",
            scope: ACTION,
            grant_lo: 20,
            grant_hi: 80,
            nbf: NOW,
            exp: NOW + 60,
            jti: "bad-caller",
        },
        NOW,
        &BTreeSet::new(),
    )
    .is_err();
    let mut inactive_parent = BTreeSet::new();
    inactive_parent.insert("grant-root".into());
    let inactive_parent_exchange_rejected = exchange(
        &root,
        ExchangeRequest {
            caller: "did:example:delegate-a",
            actor: "did:example:terminal",
            scope: ACTION,
            grant_lo: 20,
            grant_hi: 80,
            nbf: NOW,
            exp: NOW + 60,
            jti: "bad-inactive-parent",
        },
        NOW,
        &inactive_parent,
    )
    .is_err();
    let reversed_request_rejected = authorize(
        &terminal_token,
        "did:example:terminal",
        60,
        40,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &inactive,
        &mut BTreeSet::new(),
    )
    .is_err();
    let wrong_policy_version_rejected = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION + 1,
        NOW,
        &inactive,
        &mut BTreeSet::new(),
    )
    .is_err();

    // Deployment extension: keep RFC 8693/JWT authorization public, then bind
    // exact token/request bytes to an independently registered terminal key.
    // The shared adapter rechecks authentication, Delta=0 header, time, exact
    // bytes and nonce at commit.
    let terminal_signing_key = SigningKey::from_bytes(&[9u8; 32]);
    let terminal_verifying_key = terminal_signing_key.verifying_key();
    let pop_message = terminal_pop_message(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        POP_NONCE,
        NOW - 10,
        NOW + 60,
    );
    let pop_signature = terminal_signing_key.sign(&pop_message);
    let pop_authenticated =
        verify_terminal_pop(&terminal_verifying_key, &pop_message, &pop_signature);
    let mut commit_validation_consumed = BTreeSet::new();
    let currently_authorized = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &inactive,
        &mut commit_validation_consumed,
    )
    .is_ok();
    let artifact_authenticated = pop_authenticated && currently_authorized;
    let mut service_adapter = DeltaZeroAdapter::default();
    service_adapter
        .install_header(HeaderVersion {
            id: ACTIVE_HEADER.into(),
            version: 7,
        })
        .unwrap();
    let pop_ticket = service_adapter
        .verify_at_read(
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            NOW - 10,
            NOW + 60,
            terminal_token.as_bytes(),
            NOW,
        )
        .unwrap();
    let mut commit_authorization_consumed = BTreeSet::new();
    let currently_authorized_at_commit = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &inactive,
        &mut commit_authorization_consumed,
    )
    .is_ok();
    let artifact_authenticated_at_commit =
        verify_terminal_pop(&terminal_verifying_key, &pop_message, &pop_signature)
            && currently_authorized_at_commit;
    let atomic_commit_accepted = service_adapter
        .commit(
            &pop_ticket,
            artifact_authenticated_at_commit,
            ACTIVE_HEADER,
            POP_NONCE,
            terminal_token.as_bytes(),
            NOW,
        )
        .is_ok();
    let adapter_nonce_replay_rejected = matches!(
        service_adapter.commit(
            &pop_ticket,
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            terminal_token.as_bytes(),
            NOW,
        ),
        Err(AdapterError::Replay)
    );
    let mut bad_pop_bytes = pop_signature.to_bytes();
    bad_pop_bytes[0] ^= 1;
    let bad_pop_signature = Signature::from_bytes(&bad_pop_bytes);
    let bad_terminal_pop_rejected =
        !verify_terminal_pop(&terminal_verifying_key, &pop_message, &bad_pop_signature);
    let mut stale_adapter = DeltaZeroAdapter::default();
    stale_adapter
        .install_header(HeaderVersion {
            id: ACTIVE_HEADER.into(),
            version: 7,
        })
        .unwrap();
    let stale_ticket = stale_adapter
        .verify_at_read(
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            NOW - 10,
            NOW + 60,
            terminal_token.as_bytes(),
            NOW,
        )
        .unwrap();
    stale_adapter
        .install_header(HeaderVersion {
            id: "header-8".into(),
            version: 8,
        })
        .unwrap();
    let delta0_commit_rejected = matches!(
        stale_adapter.commit(
            &stale_ticket,
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            terminal_token.as_bytes(),
            NOW,
        ),
        Err(AdapterError::StaleHeader)
    );
    let mut revoked_commit_adapter = DeltaZeroAdapter::default();
    revoked_commit_adapter
        .install_header(HeaderVersion {
            id: ACTIVE_HEADER.into(),
            version: 7,
        })
        .unwrap();
    let revoked_commit_ticket = revoked_commit_adapter
        .verify_at_read(
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            NOW - 10,
            NOW + 60,
            terminal_token.as_bytes(),
            NOW,
        )
        .unwrap();
    let mut revoked_commit_consumed = BTreeSet::new();
    let currently_authorized_after_revocation = authorize(
        &terminal_token,
        "did:example:terminal",
        40,
        60,
        REQUEST_DIGEST,
        ACTIVE_HEADER,
        POLICY_VERSION,
        NOW,
        &revoked,
        &mut revoked_commit_consumed,
    )
    .is_ok();
    let authenticated_after_revocation =
        verify_terminal_pop(&terminal_verifying_key, &pop_message, &pop_signature)
            && currently_authorized_after_revocation;
    let revoked_between_read_and_commit_rejected = matches!(
        revoked_commit_adapter.commit(
            &revoked_commit_ticket,
            authenticated_after_revocation,
            ACTIVE_HEADER,
            POP_NONCE,
            terminal_token.as_bytes(),
            NOW,
        ),
        Err(AdapterError::UnauthenticatedArtifact)
    );
    let mut clock_adapter = DeltaZeroAdapter::default();
    clock_adapter
        .install_header(HeaderVersion {
            id: ACTIVE_HEADER.into(),
            version: 7,
        })
        .unwrap();
    let clock_ticket = clock_adapter
        .verify_at_read(
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            NOW - 10,
            NOW + 60,
            terminal_token.as_bytes(),
            NOW,
        )
        .unwrap();
    let commit_clock_expiry_rejected = matches!(
        clock_adapter.commit(
            &clock_ticket,
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            terminal_token.as_bytes(),
            NOW + 61,
        ),
        Err(AdapterError::OutsideValidityWindow)
    );
    let mut artifact_adapter = DeltaZeroAdapter::default();
    artifact_adapter
        .install_header(HeaderVersion {
            id: ACTIVE_HEADER.into(),
            version: 7,
        })
        .unwrap();
    let artifact_ticket = artifact_adapter
        .verify_at_read(
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            NOW - 10,
            NOW + 60,
            terminal_token.as_bytes(),
            NOW,
        )
        .unwrap();
    let changed_artifact_rejected = matches!(
        artifact_adapter.commit(
            &artifact_ticket,
            artifact_authenticated,
            ACTIVE_HEADER,
            POP_NONCE,
            b"mutated-token-bytes",
            NOW,
        ),
        Err(AdapterError::ArtifactChanged)
    );

    assert!(accepted);
    assert!(replay_rejected);
    assert!(request_mutation_rejected);
    assert!(retired_header_rejected);
    assert!(expired_rejected);
    assert!(revoked_ancestor_rejected);
    assert!(widening_exchange_rejected);
    assert!(unauthorized_exchange_rejected);
    assert!(inactive_parent_exchange_rejected);
    assert!(reversed_request_rejected);
    assert!(wrong_policy_version_rejected);
    assert!(pop_authenticated);
    assert!(atomic_commit_accepted);
    assert!(adapter_nonce_replay_rejected);
    assert!(bad_terminal_pop_rejected);
    assert!(delta0_commit_rejected);
    assert!(revoked_between_read_and_commit_rejected);
    assert!(commit_clock_expiry_rejected);
    assert!(changed_artifact_rejected);

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "profile": "RFC8693-JWT-nested-act-local-AS-v1",
            "jwt_library": "jsonwebtoken=9.3.1",
            "jws_algorithm": "HS256",
            "exchange_us": exchange_us,
            "verify_us": verify_us,
            "root_token_bytes": root.len(),
            "terminal_token_bytes": terminal_token.len(),
            "accepted": accepted,
            "widening_exchange_rejected": widening_exchange_rejected,
            "unauthorized_exchange_rejected": unauthorized_exchange_rejected,
            "inactive_parent_exchange_rejected": inactive_parent_exchange_rejected,
            "reversed_request_rejected": reversed_request_rejected,
            "wrong_policy_version_rejected": wrong_policy_version_rejected,
            "external_terminal_ed25519_pop_accepted": pop_authenticated,
            "bad_terminal_pop_rejected": bad_terminal_pop_rejected,
            "atomic_commit_accepted": atomic_commit_accepted,
            "adapter_nonce_replay_rejected": adapter_nonce_replay_rejected,
            "delta0_commit_rejected": delta0_commit_rejected,
            "revoked_between_read_and_commit_rejected": revoked_between_read_and_commit_rejected,
            "commit_clock_expiry_rejected": commit_clock_expiry_rejected,
            "changed_artifact_rejected": changed_artifact_rejected,
            "request_mutation_rejected": request_mutation_rejected,
            "retired_header_delta0_rejected": retired_header_rejected,
            "expired_rejected": expired_rejected,
            "revoked_ancestor_introspection_rejected": revoked_ancestor_rejected,
            "replay_rejected": replay_rejected,
            "rs_visible_actor_depth": 2,
            "rs_visible_chain_jti_count": 2,
            "provenance_private": false,
            "trust_note": "local authorization server compiles every exchange; AS and RS share an HS256 benchmark key",
            "local_nested_act_profile_gate_complete": true,
            "rfc8693_wire_exchange_complete": false,
            "terminal_pop_kind": "deployment Ed25519 extension over exact JWT/request/header/nonce/time bytes",
            "same_joint_commit_contract_complete": true,
            "rfc8693_profile_complete": false,
            "remaining_protocol_profile_gap": "RFC 8693 grant_type/subject_token_type request-response wire endpoint is not in this binary"
        }))
        .unwrap()
    );
}
