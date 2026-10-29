use ed25519_dalek::{
    Signature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use ipld_core::ipld::Ipld;
use plan_a_b1_protocols::service_adapter::{AdapterError, DeltaZeroAdapter, HeaderVersion};
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
use serde_json::json;
use std::{collections::BTreeSet, time::Instant};

const NOW: i64 = 1_800_000_000;
const RESOURCE: &str = "urn:plan-a:resource:alpha";
const ACTION: &str = "read";
const HEADER: &str = "header-7";
const REQUEST_DIGEST: &str = "sha256:plan-a-request-read-40-60-nonce-9";

#[derive(Clone)]
struct SignedRevocationRegistry {
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
        if !validate_revocation_registry(registry, authority)
            || self
                .version
                .map_or(false, |version| registry.version <= version)
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

fn revocation_message(version: u64, revoked: &BTreeSet<String>) -> Vec<u8> {
    let mut message = b"plan-a-ucan-revocation-registry-v1".to_vec();
    message.extend_from_slice(&version.to_le_bytes());
    message.extend_from_slice(&(revoked.len() as u64).to_le_bytes());
    for cid in revoked {
        message.extend_from_slice(&(cid.len() as u64).to_le_bytes());
        message.extend_from_slice(cid.as_bytes());
    }
    message
}

fn sign_revocation_registry(
    signer: &SigningKey,
    version: u64,
    revoked_proof_cids: BTreeSet<String>,
) -> SignedRevocationRegistry {
    let signature = signer.sign(&revocation_message(version, &revoked_proof_cids));
    SignedRevocationRegistry {
        version,
        revoked_proof_cids,
        signature,
    }
}

fn validate_revocation_registry(
    registry: &SignedRevocationRegistry,
    authority: &VerifyingKey,
) -> bool {
    authority
        .verify(
            &revocation_message(registry.version, &registry.revoked_proof_cids),
            &registry.signature,
        )
        .is_ok()
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

fn invocation(
    owner: &Ed25519Keypair,
    terminal: &Ed25519Keypair,
    proofs: Vec<pq_ucan::Cid>,
    nonce: &[u8],
    request_hi: i128,
) -> Invocation {
    Invocation::builder(owner.did(), Command::parse("/crud/read").unwrap())
        .arg("resource", text(RESOURCE))
        .arg("action", text(ACTION))
        .arg("request_lo", Ipld::Integer(40))
        .arg("request_hi", Ipld::Integer(request_hi))
        .arg("header_id", text(HEADER))
        .arg("request_digest", text(REQUEST_DIGEST))
        .proofs(proofs)
        .nonce(Nonce::from(nonce.to_vec()))
        .expires_at(Timestamp::from_unix(NOW + 30).unwrap())
        .sign(terminal)
        .unwrap()
}

fn validate(
    store: &MemoryStore,
    invocation: &Invocation,
    executor: &pq_ucan::did::Did,
    now: i64,
) -> bool {
    Validator::new(store, Timestamp::from_unix(now).unwrap())
        .skew(0)
        .executor(executor)
        .validate(invocation)
        .is_ok()
}

fn main() {
    let owner = Ed25519Keypair::from_seed(&[1; 32]);
    let delegate = Ed25519Keypair::from_seed(&[2; 32]);
    let terminal = Ed25519Keypair::from_seed(&[3; 32]);
    let owner_did = owner.did();

    let started = Instant::now();
    let root = Delegation::builder(
        delegate.did(),
        Subject::Did(owner_did.clone()),
        Command::parse("/crud").unwrap(),
    )
    .policy(grant_policy(0, 100))
    .not_before(Timestamp::from_unix(NOW - 100).unwrap())
    .nonce(Nonce::from(b"root-grant-nonce".to_vec()))
    .expires_at(Timestamp::from_unix(NOW + 100).unwrap())
    .sign(&owner)
    .unwrap();
    let child = Delegation::builder(
        terminal.did(),
        Subject::Powerline,
        Command::parse("/crud/read").unwrap(),
    )
    .policy(grant_policy(20, 80))
    .not_before(Timestamp::from_unix(NOW - 10).unwrap())
    .nonce(Nonce::from(b"child-grant-nonce".to_vec()))
    .expires_at(Timestamp::from_unix(NOW + 60).unwrap())
    .sign(&delegate)
    .unwrap();
    let issuance_us = started.elapsed().as_secs_f64() * 1_000_000.0;

    let root_cid = *root.cid();
    let child_cid = *child.cid();
    let proof_cids = vec![root_cid.to_string(), child_cid.to_string()];
    let root_bytes = root.bytes().len();
    let child_bytes = child.bytes().len();
    let mut store = MemoryStore::new();
    store.insert(root.clone());
    store.insert(child.clone());
    let request = invocation(
        &owner,
        &terminal,
        vec![root_cid, child_cid],
        b"invocation-nonce-1",
        60,
    );

    let mut replay = MemoryReplayGuard::new();
    let started = Instant::now();
    let accepted = Validator::new(&store, Timestamp::from_unix(NOW).unwrap())
        .skew(0)
        .executor(&owner_did)
        .replay_guard(&mut replay)
        .validate(&request)
        .is_ok();
    let verify_us = started.elapsed().as_secs_f64() * 1_000_000.0;
    let replay_rejected = Validator::new(&store, Timestamp::from_unix(NOW).unwrap())
        .skew(0)
        .executor(&owner_did)
        .replay_guard(&mut replay)
        .validate(&request)
        .is_err();

    let widened_request = invocation(
        &owner,
        &terminal,
        vec![root_cid, child_cid],
        b"invocation-nonce-2",
        81,
    );
    let policy_widening_rejected = !validate(&store, &widened_request, &owner_did, NOW);
    let expired_rejected = !validate(&store, &request, &owner_did, NOW + 61);
    let wrong_executor = delegate.did();
    let wrong_executor_rejected = !validate(&store, &request, &wrong_executor, NOW);

    let mut missing_store = store.clone();
    missing_store.remove(&child_cid);
    let missing_proof_rejected = !validate(&missing_store, &request, &owner_did, NOW);

    // This models resolver/store denial after learning that an ancestor is
    // revoked. pq-ucan 0.1.2 does not implement the signed UCAN Revocation
    // sub-specification, so this gate is not reported as native revocation.
    let mut revoked_store = store.clone();
    revoked_store.remove(&root_cid);
    let resolver_denied_ancestor_rejected = !validate(&revoked_store, &request, &owner_did, NOW);

    // A byte-independent direct path remains valid after the first path is
    // removed from the resolver store.
    let alternate = Delegation::builder(
        terminal.did(),
        Subject::Did(owner_did.clone()),
        Command::parse("/crud/read").unwrap(),
    )
    .policy(grant_policy(30, 70))
    .not_before(Timestamp::from_unix(NOW - 5).unwrap())
    .nonce(Nonce::from(b"alternate-grant".to_vec()))
    .expires_at(Timestamp::from_unix(NOW + 50).unwrap())
    .sign(&owner)
    .unwrap();
    let alternate_cid = *alternate.cid();
    let mut alternate_store = MemoryStore::new();
    alternate_store.insert(alternate);
    let alternate_request = invocation(
        &owner,
        &terminal,
        vec![alternate_cid],
        b"invocation-nonce-alt",
        60,
    );
    let independent_path_survives = validate(&alternate_store, &alternate_request, &owner_did, NOW);

    // Deployment extension around the signed UCAN invocation. This is an
    // authenticated public CID registry, not the UCAN Revocation sub-spec.
    let revocation_authority = SigningKey::from_bytes(&[7u8; 32]);
    let revocation_verifier = revocation_authority.verifying_key();
    let active_registry = sign_revocation_registry(&revocation_authority, 1, BTreeSet::new());
    let mut registry_state = RevocationRegistryState::default();
    let active_registry_installed = registry_state.install(&active_registry, &revocation_verifier);
    let signed_registry_accepts =
        registry_state.allows(&proof_cids) && validate(&store, &request, &owner_did, NOW);
    let mut revoked_cids = BTreeSet::new();
    revoked_cids.insert(root_cid.to_string());
    let revoked_registry = sign_revocation_registry(&revocation_authority, 2, revoked_cids);
    let revoked_registry_installed =
        registry_state.install(&revoked_registry, &revocation_verifier);
    let signed_registry_revoked_ancestor_rejected = !registry_state.allows(&proof_cids);
    let alternate_proof_cids = vec![alternate_cid.to_string()];
    let signed_registry_independent_path_survives = registry_state.allows(&alternate_proof_cids)
        && validate(&alternate_store, &alternate_request, &owner_did, NOW);
    let registry_rollback_rejected =
        !registry_state.install(&active_registry, &revocation_verifier);
    let mut tampered_registry = active_registry.clone();
    tampered_registry.version += 1;
    let tampered_registry_rejected =
        !validate_revocation_registry(&tampered_registry, &revocation_verifier);

    // The terminal signature is native to the invocation. The adapter takes a
    // successful full-chain validation as its authentication premise and binds
    // the exact invocation bytes, nonce, clock and active header at commit.
    let request_bytes = request.bytes();
    // The commit adapter is a separate lifecycle scenario. Install the signed
    // v1 registry as its current state rather than consulting an old registry
    // object after the rollback gate above has already advanced another state
    // machine to v2.
    let mut adapter_registry_state = RevocationRegistryState::default();
    let adapter_registry_installed =
        adapter_registry_state.install(&active_registry, &revocation_verifier);
    let invocation_authenticated =
        adapter_registry_state.allows(&proof_cids) && validate(&store, &request, &owner_did, NOW);
    let mut service_adapter = DeltaZeroAdapter::default();
    service_adapter
        .install_header(HeaderVersion {
            id: HEADER.into(),
            version: 7,
        })
        .unwrap();
    let ticket = service_adapter
        .verify_at_read(
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            (NOW - 10) as u64,
            (NOW + 30) as u64,
            &request_bytes,
            NOW as u64,
        )
        .unwrap();
    let invocation_authenticated_at_commit =
        adapter_registry_state.allows(&proof_cids) && validate(&store, &request, &owner_did, NOW);
    let ucan_atomic_commit_accepted = service_adapter
        .commit(
            &ticket,
            invocation_authenticated_at_commit,
            HEADER,
            b"invocation-nonce-1",
            &request_bytes,
            NOW as u64,
        )
        .is_ok();
    let ucan_adapter_replay_rejected = matches!(
        service_adapter.commit(
            &ticket,
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            &request_bytes,
            NOW as u64,
        ),
        Err(AdapterError::Replay)
    );
    let mut stale_adapter = DeltaZeroAdapter::default();
    stale_adapter
        .install_header(HeaderVersion {
            id: HEADER.into(),
            version: 7,
        })
        .unwrap();
    let stale_ticket = stale_adapter
        .verify_at_read(
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            (NOW - 10) as u64,
            (NOW + 30) as u64,
            &request_bytes,
            NOW as u64,
        )
        .unwrap();
    stale_adapter
        .install_header(HeaderVersion {
            id: "header-8".into(),
            version: 8,
        })
        .unwrap();
    let ucan_delta0_commit_rejected = matches!(
        stale_adapter.commit(
            &stale_ticket,
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            &request_bytes,
            NOW as u64,
        ),
        Err(AdapterError::StaleHeader)
    );
    let mut revoked_commit_adapter = DeltaZeroAdapter::default();
    revoked_commit_adapter
        .install_header(HeaderVersion {
            id: HEADER.into(),
            version: 7,
        })
        .unwrap();
    let mut revoked_commit_registry_state = RevocationRegistryState::default();
    let revoked_commit_active_registry_installed =
        revoked_commit_registry_state.install(&active_registry, &revocation_verifier);
    let revoked_commit_authenticated_at_read = revoked_commit_registry_state.allows(&proof_cids)
        && validate(&store, &request, &owner_did, NOW);
    let revoked_commit_ticket = revoked_commit_adapter
        .verify_at_read(
            revoked_commit_authenticated_at_read,
            HEADER,
            b"invocation-nonce-1",
            (NOW - 10) as u64,
            (NOW + 30) as u64,
            &request_bytes,
            NOW as u64,
        )
        .unwrap();
    let revoked_commit_registry_advanced =
        revoked_commit_registry_state.install(&revoked_registry, &revocation_verifier);
    let authenticated_after_revocation = revoked_commit_registry_state.allows(&proof_cids)
        && validate(&store, &request, &owner_did, NOW);
    let revoked_between_read_and_commit_rejected = matches!(
        revoked_commit_adapter.commit(
            &revoked_commit_ticket,
            authenticated_after_revocation,
            HEADER,
            b"invocation-nonce-1",
            &request_bytes,
            NOW as u64,
        ),
        Err(AdapterError::UnauthenticatedArtifact)
    );
    let mut clock_adapter = DeltaZeroAdapter::default();
    clock_adapter
        .install_header(HeaderVersion {
            id: HEADER.into(),
            version: 7,
        })
        .unwrap();
    let clock_ticket = clock_adapter
        .verify_at_read(
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            (NOW - 10) as u64,
            (NOW + 30) as u64,
            &request_bytes,
            NOW as u64,
        )
        .unwrap();
    let ucan_commit_clock_rejected = matches!(
        clock_adapter.commit(
            &clock_ticket,
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            &request_bytes,
            (NOW + 31) as u64,
        ),
        Err(AdapterError::OutsideValidityWindow)
    );
    let mut artifact_adapter = DeltaZeroAdapter::default();
    artifact_adapter
        .install_header(HeaderVersion {
            id: HEADER.into(),
            version: 7,
        })
        .unwrap();
    let artifact_ticket = artifact_adapter
        .verify_at_read(
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            (NOW - 10) as u64,
            (NOW + 30) as u64,
            &request_bytes,
            NOW as u64,
        )
        .unwrap();
    let ucan_changed_artifact_rejected = matches!(
        artifact_adapter.commit(
            &artifact_ticket,
            invocation_authenticated,
            HEADER,
            b"invocation-nonce-1",
            b"mutated-invocation-bytes",
            NOW as u64,
        ),
        Err(AdapterError::ArtifactChanged)
    );

    assert!(accepted);
    assert!(replay_rejected);
    assert!(policy_widening_rejected);
    assert!(expired_rejected);
    assert!(wrong_executor_rejected);
    assert!(missing_proof_rejected);
    assert!(resolver_denied_ancestor_rejected);
    assert!(independent_path_survives);
    assert!(signed_registry_accepts);
    assert!(active_registry_installed);
    assert!(revoked_registry_installed);
    assert!(signed_registry_revoked_ancestor_rejected);
    assert!(signed_registry_independent_path_survives);
    assert!(tampered_registry_rejected);
    assert!(registry_rollback_rejected);
    assert!(adapter_registry_installed);
    assert!(ucan_atomic_commit_accepted);
    assert!(ucan_adapter_replay_rejected);
    assert!(ucan_delta0_commit_rejected);
    assert!(revoked_commit_active_registry_installed);
    assert!(revoked_commit_registry_advanced);
    assert!(revoked_between_read_and_commit_rejected);
    assert!(ucan_commit_clock_rejected);
    assert!(ucan_changed_artifact_rejected);

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "profile": "UCAN-1.0-DAG-CBOR-delegation-invocation-v1",
            "library": "pq-ucan=0.1.2",
            "library_status": "pre-release; unaudited; README claims UCAN 1.0.0 wire compatibility",
            "signature": "Ed25519 did:key / Varsig / DAG-CBOR",
            "issuance_us": issuance_us,
            "verify_us": verify_us,
            "root_delegation_bytes": root_bytes,
            "child_delegation_bytes": child_bytes,
            "invocation_bytes": request.bytes().len(),
            "accepted": accepted,
            "policy_widening_rejected": policy_widening_rejected,
            "expired_rejected": expired_rejected,
            "wrong_executor_rejected": wrong_executor_rejected,
            "missing_proof_rejected": missing_proof_rejected,
            "replay_rejected": replay_rejected,
            "resolver_denied_ancestor_rejected": resolver_denied_ancestor_rejected,
            "independent_path_survives": independent_path_survives,
            "signed_registry_accepts": signed_registry_accepts,
            "active_registry_installed": active_registry_installed,
            "revoked_registry_installed": revoked_registry_installed,
            "signed_registry_revoked_ancestor_rejected": signed_registry_revoked_ancestor_rejected,
            "signed_registry_independent_path_survives": signed_registry_independent_path_survives,
            "tampered_registry_rejected": tampered_registry_rejected,
            "registry_rollback_rejected": registry_rollback_rejected,
            "adapter_registry_installed": adapter_registry_installed,
            "ucan_atomic_commit_accepted": ucan_atomic_commit_accepted,
            "ucan_adapter_replay_rejected": ucan_adapter_replay_rejected,
            "ucan_delta0_commit_rejected": ucan_delta0_commit_rejected,
            "revoked_commit_active_registry_installed": revoked_commit_active_registry_installed,
            "revoked_commit_registry_advanced": revoked_commit_registry_advanced,
            "revoked_between_read_and_commit_rejected": revoked_between_read_and_commit_rejected,
            "ucan_commit_clock_rejected": ucan_commit_clock_rejected,
            "ucan_changed_artifact_rejected": ucan_changed_artifact_rejected,
            "validator_visible_proof_depth": 2,
            "validator_visible_proof_cids": 2,
            "provenance_private": false,
            "signed_revocation_subspec_implemented": false,
            "authenticated_cid_revocation_registry_extension": true,
            "local_ucan_delegation_invocation_gate_complete": true,
            "same_joint_commit_contract_complete": true,
            "remaining_protocol_profile_gap": "the authenticated public CID registry is a deployment extension, not the UCAN signed-revocation sub-specification"
        }))
        .unwrap()
    );
}
