use ark_bls12_377::{Bls12_377, Fq as Fq377, Fr as Fr377, G1Affine};
use ark_bls12_381::Fr as Fr381;
use ark_bw6_761::BW6_761;
use ark_ed_on_bls12_381::Fr as JointScalar;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_groth16::Groth16;
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use blake2::Blake2b512;
use delegatable_credentials::{
    msbm::{
        issuance::Credential,
        keys::{
            PreparedRootIssuerPublicKey, RootIssuerPublicKey, RootIssuerSecretKey, UserPublicKey,
            UserSecretKey,
        },
    },
    set_commitment::SetCommitmentSRS,
};
use plan_a_dac_fixed_wrapper::fixed_policy::{
    compute_header_digest, compute_request_digest, encode_record,
    entitlement_leaf as dac_entitlement_leaf, issuer_key_digest, merkle_root,
    owner_commitment as dac_owner_commitment, poseidon_parameter_descriptor, public_inputs,
    record_digest, root_grant_leaf, split_record_digest, state_leaf as dac_state_leaf,
    tree_node_hash, DacEntitlementWitness, DacMerklePath, DacStateWitness, FixedPolicyCircuit,
    FixedPolicyDeployment, FixedPolicyStatement, GrantRecord,
};
use plan_a_dac_fixed_wrapper::matched_builder::{
    audit_matched_circuit, build_matched_circuit, MatchedCircuitInput,
};
use plan_a_dac_fixed_wrapper::semantic_schema::{
    bound_metadata, canonical_http_digest_limbs, canonical_http_sha256, manifest_sha256,
    metadata_digest_limbs, CanonicalHttpRequest, EntitlementSpec, LogicalIds, Profile, RawGrant,
    RequestSpec, SemanticManifest, StateSpec, UpdateSpec,
};
use plan_a_dac_fixed_wrapper::service_adapter::{sign_header, sign_terminal};
use plan_a_dac_fixed_wrapper::service_wire::{
    DacInstalledHeader, ExpectedServiceRequest, HeaderEnvelope, ResidentProofEnvelope,
    TrustedDacConfigWire,
};
use plan_a_joint_circuit::{
    contract::{Entitlement, Grant, Request, UserState},
    indexed_revocation::IndexedRevocationTree,
    joint::grant_digest,
    merkle::{build_tree, leaf_hash, path_for, root_from_path},
    poseidon::{descriptor as joint_poseidon_descriptor, hash, Domain},
    signature::{public_key, sign, PublicKey, SecretKey},
};
use rand::{rngs::OsRng, RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Write,
    path::{Path, PathBuf},
    time::Instant,
};
use vb_accumulator::{
    persistence::{InitialElementsStore, State, UniversalAccumulatorState},
    positive::Accumulator,
    setup::{Keypair, SetupParams},
    universal::UniversalAccumulator,
};

const L_MAX: usize = 2;
const TREE_DEPTH: usize = 3;
const REV_DEPTH: usize = 4;
const OWNER: u64 = 11;
const DELEGATE_A: u64 = 22;
const TERMINAL: u64 = 33;
const DELEGATE_B: u64 = 44;
const RESOURCE: u64 = 0x5245_534f_5552_4345;
const READ: u64 = 1;
const MAPPING_VERSION: u64 = 1;
const SCHEMA_VERSION: u64 = 4;
const POLICY_VERSION: u64 = 3;
const DEPLOYMENT_ID: u64 = 0x4441_4302;
const REGISTRATION_SALT: [u64; 2] = [0x91a2_b3c4_d5e6_f701, 0x1021_3243_5465_7687];
const STATE_SALT: [u64; 2] = [0x82a3_b4c5_d6e7_f809, 0x192a_3b4c_5d6e_7f80];

#[derive(Clone, Default)]
struct InitialStore(BTreeSet<Fr377>);

impl InitialElementsStore<Fr377> for InitialStore {
    fn add(&mut self, element: Fr377) {
        self.0.insert(element);
    }
    fn has(&self, element: &Fr377) -> bool {
        self.0.contains(element)
    }
}

#[derive(Clone, Default)]
struct AccumulatorState(BTreeSet<Fr377>);

impl State<Fr377> for AccumulatorState {
    fn add(&mut self, element: Fr377) {
        self.0.insert(element);
    }
    fn remove(&mut self, element: &Fr377) {
        self.0.remove(element);
    }
    fn has(&self, element: &Fr377) -> bool {
        self.0.contains(element)
    }
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

impl<'a> UniversalAccumulatorState<'a, Fr377> for AccumulatorState {
    type ElementIterator = std::collections::btree_set::Iter<'a, Fr377>;
    fn elements(&'a self) -> Self::ElementIterator {
        self.0.iter()
    }
}

fn scalar377(serial: [u64; 2]) -> Fr377 {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&serial[0].to_le_bytes());
    bytes[8..].copy_from_slice(&serial[1].to_le_bytes());
    Fr377::from_le_bytes_mod_order(&bytes)
}

fn scalar381(limbs: [u64; 2]) -> Fr381 {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&limbs[0].to_le_bytes());
    bytes[8..].copy_from_slice(&limbs[1].to_le_bytes());
    Fr381::from_le_bytes_mod_order(&bytes)
}

fn canonical_hex<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).expect("vec writer");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn deployment_parameter_sha256(deployment: &FixedPolicyDeployment) -> String {
    let mut bytes = b"plan-a-dac-fixed-wrapper-deployment-v1".to_vec();
    for value in [
        deployment.relation_version,
        u64::try_from(deployment.l_max).expect("l_max fits u64"),
        u64::try_from(deployment.ra_depth).expect("ra_depth fits u64"),
        u64::try_from(deployment.state_depth).expect("state_depth fits u64"),
        u64::try_from(deployment.grant_depth).expect("grant_depth fits u64"),
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    deployment
        .p1
        .serialize_compressed(&mut bytes)
        .expect("serialize deployment p1");
    deployment
        .p2
        .serialize_compressed(&mut bytes)
        .expect("serialize deployment p2");
    deployment
        .s_p2
        .serialize_compressed(&mut bytes)
        .expect("serialize deployment s_p2");
    deployment
        .accumulator_p
        .serialize_compressed(&mut bytes)
        .expect("serialize accumulator p");
    deployment
        .accumulator_p_tilde
        .serialize_compressed(&mut bytes)
        .expect("serialize accumulator p_tilde");
    deployment
        .accumulator_pk
        .serialize_compressed(&mut bytes)
        .expect("serialize accumulator public key");
    sha256_hex(bytes)
}

fn verification_failure_path(output_path: &Path) -> PathBuf {
    let mut failure_path = output_path.to_path_buf();
    failure_path.set_extension("verify-failure.json");
    failure_path
}

fn bind_operational_request(
    mut circuit: FixedPolicyCircuit,
    base_http: &CanonicalHttpRequest,
    body: &serde_json::Value,
) -> FixedPolicyCircuit {
    let body_bytes = serde_json::to_vec(body).expect("serialize canonical case body");
    let mut case_http = base_http.clone();
    case_http.body_sha256 = sha256_hex(&body_bytes);
    let limbs = canonical_http_digest_limbs(&case_http).expect("case HTTP digest");
    let nonce = body
        .get("nonce_u64")
        .and_then(serde_json::Value::as_u64)
        .expect("case body nonce_u64");
    circuit.statement.canonical_request_lo = [limbs[0], limbs[1]];
    circuit.statement.canonical_request_hi = [limbs[2], limbs[3]];
    circuit.statement.nonce = Fq377::from(nonce);
    circuit.statement.request_digest = compute_request_digest(&circuit.statement);
    circuit
}

fn raw_grant(
    id: &str,
    issuer: u64,
    subject: u64,
    actions: u64,
    lo: u64,
    hi: u64,
    remaining_depth: u64,
    serial: [u64; 2],
    parent: Option<&str>,
) -> RawGrant {
    RawGrant {
        id: id.to_owned(),
        issuer,
        subject,
        resource: RESOURCE,
        actions,
        lo,
        hi,
        not_before: lo,
        expiry: hi,
        remaining_depth,
        serial,
        parent: parent.map(str::to_owned),
        schema_version: SCHEMA_VERSION,
        policy_version: POLICY_VERSION,
    }
}

fn source_manifest() -> SemanticManifest {
    SemanticManifest {
        schema: "plan-a-paired-semantic-records-v2".to_owned(),
        profile: Profile {
            l_max: L_MAX,
            ra_depth: TREE_DEPTH,
            state_depth: TREE_DEPTH,
            grant_depth: TREE_DEPTH,
            revocation_depth: REV_DEPTH,
        },
        deployment_id: DEPLOYMENT_ID,
        logical_id_mapping_version: MAPPING_VERSION,
        policy_version: POLICY_VERSION,
        schema_version: SCHEMA_VERSION,
        logical_ids: LogicalIds {
            owner: OWNER,
            delegate_a: DELEGATE_A,
            delegate_b: DELEGATE_B,
            terminal: TERMINAL,
        },
        entitlement: EntitlementSpec {
            owner: OWNER,
            resource: RESOURCE,
            action_mask_u16: READ | 2,
            interval_lo: 0,
            interval_hi: 100,
            permit_expiry: 100,
            admission_id_u128_le_limbs: [44, 0],
            registration_salt_u128_le_limbs: REGISTRATION_SALT,
            position: 2,
            visibility: "private witness".to_owned(),
        },
        state: StateSpec {
            owner: OWNER,
            state_expiry: 90,
            state_position: 3,
            state_salt_u128_le_limbs: STATE_SALT,
            visibility: "private witness".to_owned(),
        },
        grants: vec![
            raw_grant(
                "root-a",
                OWNER,
                DELEGATE_A,
                READ | 2,
                0,
                100,
                1,
                [0x1001, 0x2001],
                None,
            ),
            raw_grant(
                "child-a",
                DELEGATE_A,
                TERMINAL,
                READ,
                20,
                80,
                0,
                [0x1002, 0x2002],
                Some("root-a"),
            ),
            raw_grant(
                "root-b",
                OWNER,
                DELEGATE_B,
                READ | 2,
                0,
                100,
                1,
                [0x3001, 0x4001],
                None,
            ),
            raw_grant(
                "child-b",
                DELEGATE_B,
                TERMINAL,
                READ,
                25,
                75,
                0,
                [0x3002, 0x4002],
                Some("root-b"),
            ),
            raw_grant(
                "root-c",
                OWNER,
                TERMINAL,
                READ,
                20,
                80,
                1,
                [0x5001, 0x6001],
                None,
            ),
        ],
        request: RequestSpec {
            resource: RESOURCE,
            one_hot_action_u16: READ,
            interval_lo: 40,
            interval_hi: 60,
            now: 50,
            nonce_u64: 0x0102_0304_0506_0708,
            terminal: TERMINAL,
            policy_version: POLICY_VERSION,
            schema_version: SCHEMA_VERSION,
        },
        updates: vec![
            UpdateSpec {
                tuple_version: 1,
                state_epoch: 55,
                revocation_epoch: 9,
                issued_at: 1_792_700_000,
                active_root_grants: vec!["root-a", "root-b", "root-c"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                revoked_serials: vec![],
            },
            UpdateSpec {
                tuple_version: 2,
                state_epoch: 56,
                revocation_epoch: 9,
                issued_at: 1_792_700_001,
                active_root_grants: vec!["root-b", "root-c"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                revoked_serials: vec![],
            },
            UpdateSpec {
                tuple_version: 3,
                state_epoch: 56,
                revocation_epoch: 10,
                issued_at: 1_792_700_002,
                active_root_grants: vec!["root-b", "root-c"]
                    .into_iter()
                    .map(str::to_owned)
                    .collect(),
                revoked_serials: vec!["child-b".to_owned()],
            },
        ],
    }
}

fn grant<'a>(manifest: &'a SemanticManifest, id: &str) -> &'a RawGrant {
    manifest
        .grants
        .iter()
        .find(|item| item.id == id)
        .expect("grant id")
}

fn root_grants(manifest: &SemanticManifest) -> Vec<&RawGrant> {
    manifest
        .grants
        .iter()
        .filter(|item| item.parent.is_none())
        .collect()
}

fn semantic_request_authorized(grant: &RawGrant, request: &RequestSpec) -> bool {
    grant.subject == request.terminal
        && grant.resource == request.resource
        && grant.actions & request.one_hot_action_u16 == request.one_hot_action_u16
        && grant.lo <= request.interval_lo
        && request.interval_lo <= request.interval_hi
        && request.interval_hi <= grant.hi
        && grant.not_before <= request.now
        && request.now <= grant.expiry
        && grant.policy_version == request.policy_version
        && grant.schema_version == request.schema_version
}

fn field_limbs_128<F: PrimeField>(value: F) -> [u64; 2] {
    let bytes = value.into_bigint().to_bytes_le();
    assert!(bytes.iter().skip(16).all(|byte| *byte == 0));
    let mut lo = [0u8; 8];
    let mut hi = [0u8; 8];
    lo.copy_from_slice(&bytes[..8]);
    hi.copy_from_slice(&bytes[8..16]);
    [u64::from_le_bytes(lo), u64::from_le_bytes(hi)]
}

fn field_u64<F: PrimeField>(value: F) -> u64 {
    let limbs = field_limbs_128(value);
    assert_eq!(limbs[1], 0);
    limbs[0]
}

fn joint_logical_id(keys: &[(u64, SecretKey, PublicKey)], key: &PublicKey) -> u64 {
    keys.iter()
        .find(|(_, _, candidate)| candidate == key)
        .map(|(id, _, _)| *id)
        .expect("mapped Joint key")
}

fn project_joint_grant(
    id: &str,
    native: &Grant,
    keys: &[(u64, SecretKey, PublicKey)],
    parents: &[(&str, Fr381)],
    schema_version: u64,
    policy_version: u64,
) -> RawGrant {
    let parent = if native.parent_digest.is_zero() {
        None
    } else {
        Some(
            parents
                .iter()
                .find(|(_, digest)| *digest == native.parent_digest)
                .map(|(parent_id, _)| (*parent_id).to_owned())
                .expect("mapped Joint parent digest"),
        )
    };
    RawGrant {
        id: id.to_owned(),
        issuer: joint_logical_id(keys, &native.issuer),
        subject: joint_logical_id(keys, &native.subject),
        resource: field_u64(native.resource),
        actions: native.action_mask as u64,
        lo: native.interval_lo,
        hi: native.interval_hi,
        not_before: native.not_before,
        expiry: native.expiry,
        remaining_depth: native.depth_remaining as u64,
        serial: field_limbs_128(native.serial),
        parent,
        schema_version,
        policy_version,
    }
}

fn project_dac_grant(
    id: &str,
    native: &GrantRecord,
    parents: &[(&str, ([u64; 3], [u64; 3]))],
) -> RawGrant {
    let zero = ([0; 3], [0; 3]);
    let digest = (native.parent_digest_lo, native.parent_digest_hi);
    let parent = if digest == zero {
        None
    } else {
        Some(
            parents
                .iter()
                .find(|(_, candidate)| *candidate == digest)
                .map(|(parent_id, _)| (*parent_id).to_owned())
                .expect("mapped DAC parent digest"),
        )
    };
    RawGrant {
        id: id.to_owned(),
        issuer: native.issuer,
        subject: native.subject,
        resource: native.resource,
        actions: native.actions,
        lo: native.lo,
        hi: native.hi,
        not_before: native.not_before,
        expiry: native.expiry,
        remaining_depth: native.remaining_depth,
        serial: [native.serial_lo, native.serial_hi],
        parent,
        schema_version: native.schema_version,
        policy_version: native.policy_version,
    }
}

fn joint_grant(
    raw: &RawGrant,
    keys: &[(u64, SecretKey, PublicKey)],
    parent_digest: Fr381,
) -> Grant {
    let public = |logical: u64| {
        keys.iter()
            .find(|(id, _, _)| *id == logical)
            .expect("logical key")
            .2
            .clone()
    };
    let secret = keys
        .iter()
        .find(|(id, _, _)| *id == raw.issuer)
        .expect("logical key")
        .1
        .clone();
    let mut grant = Grant {
        issuer: public(raw.issuer),
        subject: public(raw.subject),
        resource: Fr381::from(raw.resource),
        action_mask: raw.actions as u16,
        interval_lo: raw.lo,
        interval_hi: raw.hi,
        not_before: raw.not_before,
        expiry: raw.expiry,
        depth_remaining: raw.remaining_depth as u8,
        serial: scalar381(raw.serial),
        parent_digest,
        signature: plan_a_joint_circuit::signature::Signature {
            r: ark_ed_on_bls12_381::EdwardsAffine::zero(),
            s: JointScalar::zero(),
        },
    };
    let digest = grant_digest(&grant);
    grant.signature = sign(&secret, digest, [raw.serial[0] as u8; 32]).unwrap();
    grant
}

fn dac_record(raw: &RawGrant, parent: Option<&GrantRecord>) -> GrantRecord {
    let (parent_digest_lo, parent_digest_hi) = parent
        .map(|record| split_record_digest(record_digest(record, 0)))
        .unwrap_or(([0; 3], [0; 3]));
    GrantRecord {
        enabled: true,
        issuer: raw.issuer,
        subject: raw.subject,
        resource: raw.resource,
        actions: raw.actions,
        lo: raw.lo,
        hi: raw.hi,
        not_before: raw.not_before,
        expiry: raw.expiry,
        remaining_depth: raw.remaining_depth,
        serial_lo: raw.serial[0],
        serial_hi: raw.serial[1],
        parent_digest_lo,
        parent_digest_hi,
        schema_version: raw.schema_version,
        policy_version: raw.policy_version,
    }
}

fn joint_grant_bytes(grant: &Grant) -> Vec<u8> {
    let mut bytes = Vec::new();
    grant.issuer.0.serialize_compressed(&mut bytes).unwrap();
    grant.subject.0.serialize_compressed(&mut bytes).unwrap();
    grant.resource.serialize_compressed(&mut bytes).unwrap();
    bytes.extend_from_slice(&grant.action_mask.to_le_bytes());
    bytes.extend_from_slice(&grant.interval_lo.to_le_bytes());
    bytes.extend_from_slice(&grant.interval_hi.to_le_bytes());
    bytes.extend_from_slice(&grant.not_before.to_le_bytes());
    bytes.extend_from_slice(&grant.expiry.to_le_bytes());
    bytes.push(grant.depth_remaining);
    grant.serial.serialize_compressed(&mut bytes).unwrap();
    grant
        .parent_digest
        .serialize_compressed(&mut bytes)
        .unwrap();
    grant.signature.r.serialize_compressed(&mut bytes).unwrap();
    grant.signature.s.serialize_compressed(&mut bytes).unwrap();
    bytes
}

fn dac_credential_bytes(credential: &Credential<Bls12_377>) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&credential.max_attributes_per_commitment.to_le_bytes());
    bytes.extend_from_slice(&(credential.attributes.len() as u64).to_le_bytes());
    for attributes in &credential.attributes {
        bytes.extend_from_slice(&(attributes.len() as u64).to_le_bytes());
        for attribute in attributes {
            attribute.serialize_compressed(&mut bytes).unwrap();
        }
    }
    for commitment in &credential.commitments {
        commitment.serialize_compressed(&mut bytes).unwrap();
    }
    for opening in &credential.openings {
        opening.serialize_compressed(&mut bytes).unwrap();
    }
    credential
        .signature
        .serialize_compressed(&mut bytes)
        .unwrap();
    bytes
}

fn padding_record(previous: &GrantRecord) -> GrantRecord {
    let (parent_digest_lo, parent_digest_hi) = split_record_digest(record_digest(previous, 0));
    GrantRecord {
        enabled: false,
        issuer: previous.subject,
        subject: previous.subject,
        resource: previous.resource,
        actions: previous.actions,
        lo: previous.lo,
        hi: previous.hi,
        not_before: previous.not_before,
        expiry: previous.expiry,
        remaining_depth: previous.remaining_depth,
        serial_lo: 0,
        serial_hi: 0,
        parent_digest_lo,
        parent_digest_hi,
        schema_version: previous.schema_version,
        policy_version: previous.policy_version,
    }
}

fn dac_tree(mut leaves: Vec<Fq377>, depth: usize) -> (Fq377, Vec<Vec<Fq377>>) {
    leaves.resize(1usize << depth, Fq377::zero());
    let mut levels = vec![leaves];
    for _ in 0..depth {
        let next = levels
            .last()
            .unwrap()
            .chunks_exact(2)
            .map(|pair| tree_node_hash(pair[0], pair[1]))
            .collect();
        levels.push(next);
    }
    (levels[depth][0], levels)
}

fn dac_path(levels: &[Vec<Fq377>], mut index: usize) -> DacMerklePath {
    let mut siblings = Vec::new();
    let mut directions = Vec::new();
    for level in &levels[..levels.len() - 1] {
        directions.push(index & 1 == 1);
        siblings.push(level[index ^ 1]);
        index >>= 1;
    }
    DacMerklePath {
        siblings,
        directions,
    }
}

fn joint_state_root_and_path(
    manifest: &SemanticManifest,
    owner: Fr381,
    grant_root: Fr381,
    version: u64,
    epoch: u64,
) -> (Fr381, plan_a_joint_circuit::merkle::MerklePath) {
    let leaf = hash(
        Domain::StateLeaf,
        &[
            owner,
            grant_root,
            Fr381::from(version),
            Fr381::from(epoch),
            Fr381::from(manifest.state.state_expiry),
            Fr381::from(1u64),
            scalar381(manifest.state.state_salt_u128_le_limbs),
            Fr381::from(manifest.state.state_position as u64),
        ],
    );
    let mut leaves = vec![Fr381::zero(); manifest.state.state_position + 1];
    leaves[manifest.state.state_position] = leaf;
    let (root, levels) =
        build_tree(leaves, manifest.profile.state_depth, Domain::TreeNode).unwrap();
    let path = path_for(&levels, manifest.state.state_position).unwrap();
    (root, path)
}

fn dac_state_root_and_path(
    manifest: &SemanticManifest,
    deployment_id: Fq377,
    owner: Fq377,
    grant_root: Fq377,
    version: u64,
    epoch: u64,
) -> (Fq377, DacMerklePath) {
    let state = DacStateWitness {
        logical_owner: manifest.state.owner,
        owner_commitment: owner,
        grant_root,
        root_grant_position: 0,
        root_grant_path: DacMerklePath {
            siblings: vec![],
            directions: vec![],
        },
        state_version: version,
        state_epoch: epoch,
        state_expiry: manifest.state.state_expiry,
        active: true,
        salt_lo: manifest.state.state_salt_u128_le_limbs[0],
        salt_hi: manifest.state.state_salt_u128_le_limbs[1],
        position: manifest.state.state_position as u64,
        path: DacMerklePath {
            siblings: vec![],
            directions: vec![],
        },
    };
    let leaf = dac_state_leaf(
        deployment_id,
        manifest.logical_id_mapping_version,
        manifest.schema_version,
        manifest.policy_version,
        &state,
    );
    let mut leaves = vec![Fq377::zero(); manifest.state.state_position + 1];
    leaves[manifest.state.state_position] = leaf;
    let (root, levels) = dac_tree(leaves, manifest.profile.state_depth);
    let path = dac_path(&levels, manifest.state.state_position);
    (root, path)
}

fn main() {
    // The serialized bytes are deliberately parsed back before either backend
    // is constructed. No backend below receives the source constants or the
    // pre-serialization object.
    let source = source_manifest();
    let canonical_raw_bytes = serde_json::to_vec(&source).unwrap();
    let manifest: SemanticManifest = serde_json::from_slice(&canonical_raw_bytes).unwrap();
    assert_eq!(canonical_raw_bytes, serde_json::to_vec(&manifest).unwrap());
    let canonical_raw_sha256 = sha256_hex(&canonical_raw_bytes);
    let metadata = bound_metadata(&manifest);
    let metadata_sha256 = sha256_hex(serde_json::to_vec(&metadata).unwrap());
    let metadata_limbs = metadata_digest_limbs(&metadata);
    let canonical_http_body = serde_json::to_vec(&json!({
        "nonce_u64": manifest.request.nonce_u64,
        "operation": "read",
    }))
    .unwrap();
    let default_canonical_http = CanonicalHttpRequest {
        audience: "https://matched.service.example".to_owned(),
        body_sha256: sha256_hex(&canonical_http_body),
        method: "POST".to_owned(),
        path: "/resource/read".to_owned(),
    };
    let canonical_http = std::env::var_os("MATCHED_HTTP_JSON_PATH")
        .map(|path| {
            serde_json::from_slice::<CanonicalHttpRequest>(
                &std::fs::read(path).expect("read matched canonical HTTP request"),
            )
            .expect("parse matched canonical HTTP request")
        })
        .unwrap_or(default_canonical_http);
    let request_limbs = canonical_http_digest_limbs(&canonical_http).unwrap();
    let canonical_http_sha256 = canonical_http_sha256(&canonical_http).unwrap();
    let root_a = grant(&manifest, "root-a");
    let child_a = grant(&manifest, "child-a");
    let root_b = grant(&manifest, "root-b");
    let child_b = grant(&manifest, "child-b");
    let root_c = grant(&manifest, "root-c");

    let make_joint_key = |id: u64, scalar: u64| {
        let secret = SecretKey(JointScalar::from(scalar));
        let public = public_key(&secret).unwrap();
        (id, secret, public)
    };
    let joint_keys = vec![
        make_joint_key(manifest.logical_ids.owner, 11),
        make_joint_key(manifest.logical_ids.delegate_a, 22),
        make_joint_key(manifest.logical_ids.terminal, 33),
        make_joint_key(manifest.logical_ids.delegate_b, 44),
    ];
    let joint_root_a = joint_grant(root_a, &joint_keys, Fr381::zero());
    let joint_child_a = joint_grant(child_a, &joint_keys, grant_digest(&joint_root_a));
    let joint_root_b = joint_grant(root_b, &joint_keys, Fr381::zero());
    let joint_child_b = joint_grant(child_b, &joint_keys, grant_digest(&joint_root_b));
    let joint_root_c = joint_grant(root_c, &joint_keys, Fr381::zero());
    let joint_root_leaves = [
        joint_root_a.clone(),
        joint_root_b.clone(),
        joint_root_c.clone(),
    ]
    .map(|grant| leaf_hash(Domain::GrantLeaf, &[grant_digest(&grant)]));
    let joint_owner_pk = &joint_keys
        .iter()
        .find(|(id, _, _)| *id == manifest.entitlement.owner)
        .expect("entitlement owner key")
        .2;
    let joint_owner = hash(
        Domain::Owner,
        &[
            joint_owner_pk.0.x,
            joint_owner_pk.0.y,
            scalar381(manifest.entitlement.registration_salt_u128_le_limbs),
        ],
    );
    let joint_entitlement_leaf = hash(
        Domain::RaLeaf,
        &[
            joint_owner,
            Fr381::from(manifest.entitlement.resource),
            Fr381::from(manifest.entitlement.action_mask_u16),
            Fr381::from(manifest.entitlement.interval_lo),
            Fr381::from(manifest.entitlement.interval_hi),
            Fr381::from(manifest.entitlement.permit_expiry),
            scalar381(manifest.entitlement.admission_id_u128_le_limbs),
        ],
    );
    let mut joint_ra_leaves = vec![Fr381::zero(); manifest.entitlement.position + 1];
    joint_ra_leaves[manifest.entitlement.position] = joint_entitlement_leaf;
    let (joint_ra_root, joint_ra_levels) =
        build_tree(joint_ra_leaves, manifest.profile.ra_depth, Domain::TreeNode).unwrap();
    let joint_entitlement_native = Entitlement {
        owner_commitment: joint_owner,
        resource: Fr381::from(manifest.entitlement.resource),
        action_mask: manifest.entitlement.action_mask_u16 as u16,
        interval_lo: manifest.entitlement.interval_lo,
        interval_hi: manifest.entitlement.interval_hi,
        permit_expiry: manifest.entitlement.permit_expiry,
        admission_id: scalar381(manifest.entitlement.admission_id_u128_le_limbs),
        path: path_for(&joint_ra_levels, manifest.entitlement.position).unwrap(),
    };
    let joint_request_native = Request {
        canonical_request_lo: scalar381([request_limbs[0], request_limbs[1]]),
        canonical_request_hi: scalar381([request_limbs[2], request_limbs[3]]),
        circuit_id: Fr381::from(metadata_limbs[0]),
        verifier_id: Fr381::from(metadata_limbs[1]),
        pep_id: Fr381::from(metadata_limbs[2]),
        resource: Fr381::from(manifest.request.resource),
        action_onehot: manifest.request.one_hot_action_u16 as u16,
        interval_lo: manifest.request.interval_lo,
        interval_hi: manifest.request.interval_hi,
        time: manifest.request.now,
        nonce: Fr381::from(manifest.request.nonce_u64),
        context: Fr381::from(metadata_limbs[3]),
        terminal: joint_keys
            .iter()
            .find(|(id, _, _)| *id == manifest.request.terminal)
            .expect("Joint request terminal")
            .2
            .clone(),
    };
    let joint_b_bytes_before = [
        joint_grant_bytes(&joint_root_b),
        joint_grant_bytes(&joint_child_b),
    ]
    .concat();
    let joint_c_bytes_before = joint_grant_bytes(&joint_root_c);
    let joint_root_ids = root_grants(&manifest)
        .into_iter()
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    let mut joint_revocation =
        IndexedRevocationTree::new(manifest.profile.revocation_depth).unwrap();
    let mut joint_revoked = BTreeSet::new();
    let mut joint_phases = Vec::new();
    let mut joint_applied_updates = Vec::new();
    let mut joint_initial_state_native: Option<UserState> = None;
    let mut joint_state_version = 0u64;
    let mut previous_active: Option<Vec<String>> = None;
    for update in &manifest.updates {
        if previous_active
            .as_ref()
            .is_some_and(|previous| previous != &update.active_root_grants)
        {
            joint_state_version += 1;
        }
        previous_active = Some(update.active_root_grants.clone());
        for revoked in &update.revoked_serials {
            if joint_revoked.insert(revoked.clone()) {
                joint_revocation
                    .insert(scalar381(grant(&manifest, revoked).serial))
                    .unwrap();
            }
        }
        let active = update
            .active_root_grants
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let leaves = joint_root_ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                if active.contains(id) {
                    joint_root_leaves[index]
                } else {
                    Fr381::zero()
                }
            })
            .collect::<Vec<_>>();
        let (grant_root, levels) =
            build_tree(leaves, manifest.profile.grant_depth, Domain::TreeNode).unwrap();
        let membership = joint_root_leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| {
                root_from_path(*leaf, &path_for(&levels, index).unwrap(), Domain::TreeNode)
                    == Some(grant_root)
            })
            .collect::<Vec<_>>();
        let grant_path_depth = path_for(&levels, 1).unwrap().siblings.len();
        let nonmember_b = joint_revocation
            .prove_nonmember(joint_child_b.serial)
            .is_ok();
        let nonmember_c = joint_revocation
            .prove_nonmember(joint_root_c.serial)
            .is_ok();
        let request_acceptance_b = active.contains("root-b")
            && nonmember_b
            && child_b.parent.as_deref() == Some("root-b")
            && semantic_request_authorized(child_b, &manifest.request);
        let request_acceptance_c = active.contains("root-c")
            && nonmember_c
            && semantic_request_authorized(root_c, &manifest.request);
        let (state_root, state_path) = joint_state_root_and_path(
            &manifest,
            joint_owner,
            grant_root,
            joint_state_version,
            update.state_epoch,
        );
        let state_native = UserState {
            owner_commitment: joint_owner,
            grant_root,
            state_version: joint_state_version,
            state_epoch: update.state_epoch,
            state_expiry: manifest.state.state_expiry,
            active: true,
            salt: scalar381(manifest.state.state_salt_u128_le_limbs),
            position: manifest.state.state_position as u32,
            path: state_path,
        };
        if joint_initial_state_native.is_none() {
            joint_initial_state_native = Some(state_native.clone());
        }
        let applied_update = UpdateSpec {
            tuple_version: update.tuple_version,
            state_epoch: state_native.state_epoch,
            revocation_epoch: update.revocation_epoch,
            issued_at: update.issued_at,
            active_root_grants: joint_root_ids
                .iter()
                .filter(|id| active.contains(*id))
                .cloned()
                .collect(),
            revoked_serials: update
                .revoked_serials
                .iter()
                .filter(|id| joint_revoked.contains(*id))
                .cloned()
                .collect(),
        };
        joint_applied_updates.push(applied_update.clone());
        joint_phases.push(json!({
            "tuple_version": update.tuple_version,
            "state_epoch": update.state_epoch,
            "revocation_epoch": update.revocation_epoch,
            "grant_root": canonical_hex(&grant_root),
            "state_root": canonical_hex(&state_root),
            "revocation_root": canonical_hex(&joint_revocation.root()),
            "root_membership_abc": membership,
            "grant_path_depth": grant_path_depth,
            "state_path_depth": state_native.path.siblings.len(),
            "revocation_config_depth": manifest.profile.revocation_depth,
            "revocation_nonmember_b": nonmember_b,
            "revocation_nonmember_c": nonmember_c,
            "request_acceptance_b": request_acceptance_b,
            "request_acceptance_c": request_acceptance_c,
            "consumed_update": applied_update,
        }));
    }

    let fresh_deployment = std::env::var_os("MATCHED_DAC_PRODUCER_OUT").is_some()
        || std::env::var_os("PAIRED_DAC_PROOF_ENVELOPE_OUT").is_some();
    let mut deployment_seed = [0x42; 32];
    if fresh_deployment {
        OsRng.fill_bytes(&mut deployment_seed);
    }
    let mut rng = ChaCha20Rng::from_seed(deployment_seed);
    let dac_root_a = dac_record(root_a, None);
    let dac_child_a = dac_record(child_a, Some(&dac_root_a));
    let dac_root_b = dac_record(root_b, None);
    let dac_child_b = dac_record(child_b, Some(&dac_root_b));
    let dac_root_c = dac_record(root_c, None);
    let dac_padding_c = padding_record(&dac_root_c);
    let max_attributes_per_commitment = (encode_record(&dac_root_a, 0).len() as u32)
        .checked_add(1)
        .unwrap();
    let (set_srs, _) = SetCommitmentSRS::<Bls12_377>::generate_with_random_trapdoor::<_, Blake2b512>(
        &mut rng,
        max_attributes_per_commitment,
        Some(b"plan-a-paired-manifest-v2"),
    );
    let issuer_sk =
        RootIssuerSecretKey::<Bls12_377>::new(&mut rng, manifest.profile.l_max as u32).unwrap();
    let issuer_pk = RootIssuerPublicKey::new(&issuer_sk, set_srs.get_P1(), set_srs.get_P2());
    let delegate_a_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let delegate_a_pk = UserPublicKey::new(&delegate_a_sk, set_srs.get_P1());
    let delegate_b_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let delegate_b_pk = UserPublicKey::new(&delegate_b_sk, set_srs.get_P1());
    let terminal_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let terminal_pk = UserPublicKey::new(&terminal_sk, set_srs.get_P1());

    let (credential_a, update_a) = Credential::issue_root(
        &mut rng,
        vec![encode_record(&dac_root_a, 0)],
        &delegate_a_pk,
        Some((manifest.profile.l_max - 1) as u32),
        &issuer_sk,
        max_attributes_per_commitment,
        &set_srs,
    )
    .unwrap();
    let (mut credential_a, _) = credential_a
        .delegate_with_new_attributes(
            &mut rng,
            encode_record(&dac_child_a, 1),
            &delegate_a_sk,
            &issuer_pk.X_0,
            None,
            &update_a.unwrap(),
            &set_srs,
        )
        .unwrap();
    credential_a.convert_orphan_signature(&terminal_sk, &issuer_pk.X_0);

    let (credential_b, update_b) = Credential::issue_root(
        &mut rng,
        vec![encode_record(&dac_root_b, 0)],
        &delegate_b_pk,
        Some((manifest.profile.l_max - 1) as u32),
        &issuer_sk,
        max_attributes_per_commitment,
        &set_srs,
    )
    .unwrap();
    let (mut credential_b, _) = credential_b
        .delegate_with_new_attributes(
            &mut rng,
            encode_record(&dac_child_b, 1),
            &delegate_b_sk,
            &issuer_pk.X_0,
            None,
            &update_b.unwrap(),
            &set_srs,
        )
        .unwrap();
    credential_b.convert_orphan_signature(&terminal_sk, &issuer_pk.X_0);

    let (credential_c, update_c) = Credential::issue_root(
        &mut rng,
        vec![encode_record(&dac_root_c, 0)],
        &terminal_pk,
        Some((manifest.profile.l_max - 1) as u32),
        &issuer_sk,
        max_attributes_per_commitment,
        &set_srs,
    )
    .unwrap();
    let (mut credential_c, _) = credential_c
        .delegate_with_new_attributes(
            &mut rng,
            encode_record(&dac_padding_c, 1),
            &terminal_sk,
            &issuer_pk.X_0,
            None,
            &update_c.unwrap(),
            &set_srs,
        )
        .unwrap();
    credential_c.convert_orphan_signature(&terminal_sk, &issuer_pk.X_0);
    for credential in [&credential_a, &credential_b, &credential_c] {
        credential
            .verify(
                None,
                &terminal_pk,
                PreparedRootIssuerPublicKey::from(issuer_pk.clone()),
                &set_srs,
            )
            .unwrap();
    }
    let dac_commit_a = credential_a.commitments[0].clone();
    let dac_commit_b = credential_b.commitments[0].clone();
    let dac_commit_c = credential_c.commitments[0].clone();
    let dac_root_leaves = [
        root_grant_leaf(&dac_root_a, &dac_commit_a),
        root_grant_leaf(&dac_root_b, &dac_commit_b),
        root_grant_leaf(&dac_root_c, &dac_commit_c),
    ];
    let deployment_id = Fq377::from(manifest.deployment_id);
    let dac_owner = dac_owner_commitment(
        manifest.entitlement.owner,
        manifest.logical_id_mapping_version,
        manifest.entitlement.registration_salt_u128_le_limbs[0],
        manifest.entitlement.registration_salt_u128_le_limbs[1],
        &issuer_pk,
    );
    let mut dac_entitlement = DacEntitlementWitness {
        logical_owner: manifest.entitlement.owner,
        registration_salt_lo: manifest.entitlement.registration_salt_u128_le_limbs[0],
        registration_salt_hi: manifest.entitlement.registration_salt_u128_le_limbs[1],
        resource: manifest.entitlement.resource,
        action_mask: manifest.entitlement.action_mask_u16,
        interval_lo: manifest.entitlement.interval_lo,
        interval_hi: manifest.entitlement.interval_hi,
        permit_expiry: manifest.entitlement.permit_expiry,
        admission_id_lo: manifest.entitlement.admission_id_u128_le_limbs[0],
        admission_id_hi: manifest.entitlement.admission_id_u128_le_limbs[1],
        position: manifest.entitlement.position as u64,
        path: DacMerklePath {
            siblings: vec![],
            directions: vec![],
        },
    };
    let dac_ra_leaf = dac_entitlement_leaf(
        deployment_id,
        manifest.logical_id_mapping_version,
        manifest.schema_version,
        manifest.policy_version,
        &issuer_pk,
        &dac_entitlement,
    );
    let mut dac_ra_leaves = vec![Fq377::zero(); manifest.entitlement.position + 1];
    dac_ra_leaves[manifest.entitlement.position] = dac_ra_leaf;
    let (dac_ra_root, dac_ra_levels) = dac_tree(dac_ra_leaves, manifest.profile.ra_depth);
    dac_entitlement.path = dac_path(&dac_ra_levels, manifest.entitlement.position);
    let accumulator_params = SetupParams::<Bls12_377>::generate_using_rng(&mut rng);
    let accumulator_keys = Keypair::<Bls12_377>::generate_using_rng(&mut rng, &accumulator_params);
    let mut initial_store = InitialStore::default();
    let accumulator_0 = UniversalAccumulator::<G1Affine>::initialize_with_all_random(
        &mut rng,
        &accumulator_params,
        64,
        &accumulator_keys.secret_key,
        &mut initial_store,
    );
    let mut accumulator_state = AccumulatorState::default();
    let accumulator_0 = accumulator_0
        .add(
            Fr377::from(0xdead_beefu64),
            &accumulator_keys.secret_key,
            &initial_store,
            &mut accumulator_state,
        )
        .unwrap();
    let dac_deployment = FixedPolicyDeployment {
        relation_version: 2,
        l_max: manifest.profile.l_max,
        ra_depth: dac_entitlement.path.siblings.len(),
        state_depth: manifest.profile.state_depth,
        grant_depth: manifest.profile.grant_depth,
        p1: *set_srs.get_P1(),
        p2: *set_srs.get_P2(),
        s_p2: *set_srs.get_s_P2(),
        accumulator_p: accumulator_params.P,
        accumulator_p_tilde: accumulator_params.P_tilde,
        accumulator_pk: accumulator_keys.public_key.clone(),
    };
    let dynamic_initial_state = accumulator_state.clone();
    let dac_b_bytes_before = dac_credential_bytes(&credential_b);
    let dac_c_bytes_before = dac_credential_bytes(&credential_c);
    let mut dac_accumulator = accumulator_0.clone();
    let mut dac_accumulator_state = dynamic_initial_state;
    let mut dac_revoked = BTreeSet::new();
    let mut dac_phases = Vec::new();
    let mut dac_applied_updates = Vec::new();
    let mut dac_initial_state_native: Option<DacStateWitness> = None;
    let mut dac_last_state_root = Fq377::zero();
    let mut dac_state_version = 0u64;
    let mut previous_active: Option<Vec<String>> = None;
    let mut matched_state_native: Option<DacStateWitness> = None;
    let mut matched_accumulator_value: Option<G1Affine> = None;
    let mut lifecycle_circuits = Vec::new();
    for update in &manifest.updates {
        if previous_active
            .as_ref()
            .is_some_and(|previous| previous != &update.active_root_grants)
        {
            dac_state_version += 1;
        }
        previous_active = Some(update.active_root_grants.clone());
        for revoked in &update.revoked_serials {
            if dac_revoked.insert(revoked.clone()) {
                dac_accumulator = dac_accumulator
                    .add(
                        scalar377(grant(&manifest, revoked).serial),
                        &accumulator_keys.secret_key,
                        &initial_store,
                        &mut dac_accumulator_state,
                    )
                    .unwrap();
            }
        }
        let active = update
            .active_root_grants
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let leaves = joint_root_ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                if active.contains(id) {
                    dac_root_leaves[index]
                } else {
                    Fq377::zero()
                }
            })
            .collect::<Vec<_>>();
        let (grant_root, levels) = dac_tree(leaves, manifest.profile.grant_depth);
        let (state_root, state_path) = dac_state_root_and_path(
            &manifest,
            deployment_id,
            dac_owner,
            grant_root,
            dac_state_version,
            update.state_epoch,
        );
        dac_last_state_root = state_root;
        let membership = dac_root_leaves
            .iter()
            .enumerate()
            .map(|(index, leaf)| merkle_root(*leaf, &dac_path(&levels, index)) == Some(grant_root))
            .collect::<Vec<_>>();
        let grant_path_depth = dac_path(&levels, 1).siblings.len();
        let root_a_non_membership = dac_accumulator
            .get_non_membership_witness(
                &scalar377(root_a.serial),
                &accumulator_keys.secret_key,
                &dac_accumulator_state,
                &accumulator_params,
            )
            .ok();
        let child_a_non_membership = dac_accumulator
            .get_non_membership_witness(
                &scalar377(child_a.serial),
                &accumulator_keys.secret_key,
                &dac_accumulator_state,
                &accumulator_params,
            )
            .ok();
        let root_b_non_membership = dac_accumulator
            .get_non_membership_witness(
                &scalar377(root_b.serial),
                &accumulator_keys.secret_key,
                &dac_accumulator_state,
                &accumulator_params,
            )
            .ok();
        let child_b_non_membership = dac_accumulator
            .get_non_membership_witness(
                &scalar377(child_b.serial),
                &accumulator_keys.secret_key,
                &dac_accumulator_state,
                &accumulator_params,
            )
            .ok();
        let nonmember_b = child_b_non_membership.is_some();
        let root_c_non_membership = dac_accumulator
            .get_non_membership_witness(
                &scalar377(root_c.serial),
                &accumulator_keys.secret_key,
                &dac_accumulator_state,
                &accumulator_params,
            )
            .ok();
        let padding_c_non_membership = dac_accumulator
            .get_non_membership_witness(
                &Fr377::zero(),
                &accumulator_keys.secret_key,
                &dac_accumulator_state,
                &accumulator_params,
            )
            .ok();
        let nonmember_c = root_c_non_membership.is_some();
        let request_acceptance_b = active.contains("root-b")
            && nonmember_b
            && child_b.parent.as_deref() == Some("root-b")
            && semantic_request_authorized(child_b, &manifest.request);
        let request_acceptance_c = active.contains("root-c")
            && nonmember_c
            && semantic_request_authorized(root_c, &manifest.request);
        let state_native = DacStateWitness {
            logical_owner: manifest.state.owner,
            owner_commitment: dac_owner,
            grant_root,
            root_grant_position: 1,
            root_grant_path: dac_path(&levels, 1),
            state_version: dac_state_version,
            state_epoch: update.state_epoch,
            state_expiry: manifest.state.state_expiry,
            active: true,
            salt_lo: manifest.state.state_salt_u128_le_limbs[0],
            salt_hi: manifest.state.state_salt_u128_le_limbs[1],
            position: manifest.state.state_position as u64,
            path: state_path,
        };
        if dac_initial_state_native.is_none() {
            dac_initial_state_native = Some(state_native.clone());
        }
        let mut phase_statement = FixedPolicyStatement {
            deployment_id,
            tuple_version: update.tuple_version,
            ra_root: dac_ra_root,
            state_root,
            state_epoch: update.state_epoch,
            revocation_epoch: update.revocation_epoch,
            issued_at: update.issued_at,
            mapping_version: manifest.logical_id_mapping_version,
            header_digest: Fq377::zero(),
            canonical_request_lo: [request_limbs[0], request_limbs[1]],
            canonical_request_hi: [request_limbs[2], request_limbs[3]],
            circuit_id: Fq377::from(metadata_limbs[0]),
            verifier_id: Fq377::from(metadata_limbs[1]),
            pep_id: Fq377::from(metadata_limbs[2]),
            nonce: Fq377::from(manifest.request.nonce_u64),
            context: Fq377::from(metadata_limbs[3]),
            request_digest: Fq377::zero(),
            terminal: manifest.request.terminal,
            terminal_key: terminal_pk.0,
            resource: manifest.request.resource,
            one_hot_action: manifest.request.one_hot_action_u16,
            request_lo: manifest.request.interval_lo,
            request_hi: manifest.request.interval_hi,
            now: manifest.request.now,
            policy_version: manifest.request.policy_version,
            schema_version: manifest.request.schema_version,
            accumulator_value: *dac_accumulator.value(),
        };
        phase_statement.header_digest = compute_header_digest(&phase_statement);
        phase_statement.request_digest = compute_request_digest(&phase_statement);
        let state_for_root = |position: usize| {
            let mut state = state_native.clone();
            state.root_grant_position = position as u64;
            state.root_grant_path = dac_path(&levels, position);
            state
        };
        if active.contains("root-a") {
            lifecycle_circuits.push((
                update.tuple_version,
                "A",
                2u64,
                phase_statement.clone(),
                build_matched_circuit(
                    MatchedCircuitInput {
                        deployment: dac_deployment.clone(),
                        statement: phase_statement.clone(),
                        issuer_pk: issuer_pk.clone(),
                        credential: credential_a.clone(),
                        records: vec![dac_root_a.clone(), dac_child_a.clone()],
                        entitlement: dac_entitlement.clone(),
                        state: state_for_root(0),
                        non_membership_witnesses: vec![
                            root_a_non_membership
                                .clone()
                                .expect("active root-a is non-revoked"),
                            child_a_non_membership
                                .clone()
                                .expect("active child-a is non-revoked"),
                        ],
                    },
                    &set_srs,
                )
                .expect("same-manifest DAC A lifecycle circuit"),
            ));
        }
        if active.contains("root-b") && child_b_non_membership.is_some() {
            lifecycle_circuits.push((
                update.tuple_version,
                "B",
                2u64,
                phase_statement.clone(),
                build_matched_circuit(
                    MatchedCircuitInput {
                        deployment: dac_deployment.clone(),
                        statement: phase_statement.clone(),
                        issuer_pk: issuer_pk.clone(),
                        credential: credential_b.clone(),
                        records: vec![dac_root_b.clone(), dac_child_b.clone()],
                        entitlement: dac_entitlement.clone(),
                        state: state_for_root(1),
                        non_membership_witnesses: vec![
                            root_b_non_membership
                                .clone()
                                .expect("active root-b is non-revoked"),
                            child_b_non_membership
                                .clone()
                                .expect("active child-b is non-revoked"),
                        ],
                    },
                    &set_srs,
                )
                .expect("same-manifest DAC B lifecycle circuit"),
            ));
        }
        if active.contains("root-c") {
            lifecycle_circuits.push((
                update.tuple_version,
                "C",
                1u64,
                phase_statement.clone(),
                build_matched_circuit(
                    MatchedCircuitInput {
                        deployment: dac_deployment.clone(),
                        statement: phase_statement.clone(),
                        issuer_pk: issuer_pk.clone(),
                        credential: credential_c.clone(),
                        records: vec![dac_root_c.clone(), dac_padding_c.clone()],
                        entitlement: dac_entitlement.clone(),
                        state: state_for_root(2),
                        non_membership_witnesses: vec![
                            root_c_non_membership
                                .clone()
                                .expect("active root-c is non-revoked"),
                            padding_c_non_membership
                                .clone()
                                .expect("canonical padding serial is non-revoked"),
                        ],
                    },
                    &set_srs,
                )
                .expect("same-manifest DAC C lifecycle circuit"),
            ));
        }
        if update.tuple_version == 2 {
            matched_state_native = Some(state_native.clone());
            matched_accumulator_value = Some(*dac_accumulator.value());
        }
        let applied_update = UpdateSpec {
            tuple_version: update.tuple_version,
            state_epoch: state_native.state_epoch,
            revocation_epoch: update.revocation_epoch,
            issued_at: update.issued_at,
            active_root_grants: joint_root_ids
                .iter()
                .filter(|id| active.contains(*id))
                .cloned()
                .collect(),
            revoked_serials: update
                .revoked_serials
                .iter()
                .filter(|id| dac_revoked.contains(*id))
                .cloned()
                .collect(),
        };
        dac_applied_updates.push(applied_update.clone());
        dac_phases.push(json!({
            "tuple_version": update.tuple_version,
            "state_epoch": update.state_epoch,
            "revocation_epoch": update.revocation_epoch,
            "grant_root": canonical_hex(&grant_root),
            "state_root": canonical_hex(&state_root),
            "revocation_accumulator": canonical_hex(dac_accumulator.value()),
            "root_membership_abc": membership,
            "grant_path_depth": grant_path_depth,
            "state_path_depth": state_native.path.siblings.len(),
            "revocation_mechanism": "universal_accumulator_no_tree_depth",
            "revocation_nonmember_b": nonmember_b,
            "revocation_nonmember_c": nonmember_c,
            "request_acceptance_b": request_acceptance_b,
            "request_acceptance_c": request_acceptance_c,
            "consumed_update": applied_update,
        }));
    }

    let final_update = manifest.updates.last().unwrap();
    let mut dac_request_native = FixedPolicyStatement {
        deployment_id,
        tuple_version: final_update.tuple_version,
        ra_root: dac_ra_root,
        state_root: dac_last_state_root,
        state_epoch: final_update.state_epoch,
        revocation_epoch: final_update.revocation_epoch,
        issued_at: final_update.issued_at,
        mapping_version: manifest.logical_id_mapping_version,
        header_digest: Fq377::zero(),
        canonical_request_lo: [request_limbs[0], request_limbs[1]],
        canonical_request_hi: [request_limbs[2], request_limbs[3]],
        circuit_id: Fq377::from(metadata_limbs[0]),
        verifier_id: Fq377::from(metadata_limbs[1]),
        pep_id: Fq377::from(metadata_limbs[2]),
        nonce: Fq377::from(manifest.request.nonce_u64),
        context: Fq377::from(metadata_limbs[3]),
        request_digest: Fq377::zero(),
        terminal: manifest.request.terminal,
        terminal_key: terminal_pk.0,
        resource: manifest.request.resource,
        one_hot_action: manifest.request.one_hot_action_u16,
        request_lo: manifest.request.interval_lo,
        request_hi: manifest.request.interval_hi,
        now: manifest.request.now,
        policy_version: manifest.request.policy_version,
        schema_version: manifest.request.schema_version,
        accumulator_value: *dac_accumulator.value(),
    };
    dac_request_native.header_digest = compute_header_digest(&dac_request_native);
    dac_request_native.request_digest = compute_request_digest(&dac_request_native);

    let matched_update = &manifest.updates[1];
    let matched_state_native = matched_state_native.expect("matched phase state");
    let matched_state_root = merkle_root(
        dac_state_leaf(
            deployment_id,
            manifest.logical_id_mapping_version,
            manifest.schema_version,
            manifest.policy_version,
            &matched_state_native,
        ),
        &matched_state_native.path,
    )
    .expect("matched state path");
    let mut matched_statement = dac_request_native.clone();
    matched_statement.tuple_version = matched_update.tuple_version;
    matched_statement.state_root = matched_state_root;
    matched_statement.state_epoch = matched_update.state_epoch;
    matched_statement.revocation_epoch = matched_update.revocation_epoch;
    matched_statement.issued_at = matched_update.issued_at;
    matched_statement.accumulator_value =
        matched_accumulator_value.expect("matched phase accumulator");
    matched_statement.header_digest = compute_header_digest(&matched_statement);
    matched_statement.request_digest = compute_request_digest(&matched_statement);

    let joint_parent_digests = [
        ("root-a", grant_digest(&joint_root_a)),
        ("root-b", grant_digest(&joint_root_b)),
        ("root-c", grant_digest(&joint_root_c)),
    ];
    let joint_projected_grants = vec![
        project_joint_grant(
            "root-a",
            &joint_root_a,
            &joint_keys,
            &joint_parent_digests,
            manifest.schema_version,
            manifest.policy_version,
        ),
        project_joint_grant(
            "child-a",
            &joint_child_a,
            &joint_keys,
            &joint_parent_digests,
            manifest.schema_version,
            manifest.policy_version,
        ),
        project_joint_grant(
            "root-b",
            &joint_root_b,
            &joint_keys,
            &joint_parent_digests,
            manifest.schema_version,
            manifest.policy_version,
        ),
        project_joint_grant(
            "child-b",
            &joint_child_b,
            &joint_keys,
            &joint_parent_digests,
            manifest.schema_version,
            manifest.policy_version,
        ),
        project_joint_grant(
            "root-c",
            &joint_root_c,
            &joint_keys,
            &joint_parent_digests,
            manifest.schema_version,
            manifest.policy_version,
        ),
    ];
    let joint_initial_state_native = joint_initial_state_native.unwrap();
    let joint_projection = SemanticManifest {
        schema: manifest.schema.clone(),
        profile: Profile {
            l_max: [joint_root_b.clone(), joint_child_b.clone()].len(),
            ra_depth: joint_entitlement_native.path.siblings.len(),
            state_depth: joint_initial_state_native.path.siblings.len(),
            grant_depth: joint_phases[0]["grant_path_depth"].as_u64().unwrap() as usize,
            revocation_depth: manifest.profile.revocation_depth,
        },
        deployment_id: manifest.deployment_id,
        logical_id_mapping_version: manifest.logical_id_mapping_version,
        policy_version: joint_projected_grants[0].policy_version,
        schema_version: joint_projected_grants[0].schema_version,
        logical_ids: LogicalIds {
            owner: joint_projected_grants[0].issuer,
            delegate_a: joint_projected_grants[0].subject,
            delegate_b: joint_projected_grants[2].subject,
            terminal: joint_projected_grants[1].subject,
        },
        entitlement: EntitlementSpec {
            owner: joint_projected_grants[0].issuer,
            resource: field_u64(joint_entitlement_native.resource),
            action_mask_u16: joint_entitlement_native.action_mask as u64,
            interval_lo: joint_entitlement_native.interval_lo,
            interval_hi: joint_entitlement_native.interval_hi,
            permit_expiry: joint_entitlement_native.permit_expiry,
            admission_id_u128_le_limbs: field_limbs_128(joint_entitlement_native.admission_id),
            registration_salt_u128_le_limbs: field_limbs_128(scalar381(
                manifest.entitlement.registration_salt_u128_le_limbs,
            )),
            position: joint_entitlement_native
                .path
                .directions
                .iter()
                .enumerate()
                .fold(0usize, |index, (level, right)| {
                    index | ((*right as usize) << level)
                }),
            visibility: manifest.entitlement.visibility.clone(),
        },
        state: StateSpec {
            owner: joint_projected_grants[0].issuer,
            state_expiry: joint_initial_state_native.state_expiry,
            state_position: joint_initial_state_native.position as usize,
            state_salt_u128_le_limbs: field_limbs_128(joint_initial_state_native.salt),
            visibility: manifest.state.visibility.clone(),
        },
        grants: joint_projected_grants,
        request: RequestSpec {
            resource: field_u64(joint_request_native.resource),
            one_hot_action_u16: joint_request_native.action_onehot as u64,
            interval_lo: joint_request_native.interval_lo,
            interval_hi: joint_request_native.interval_hi,
            now: joint_request_native.time,
            nonce_u64: field_u64(joint_request_native.nonce),
            terminal: joint_logical_id(&joint_keys, &joint_request_native.terminal),
            policy_version: manifest.policy_version,
            schema_version: manifest.schema_version,
        },
        updates: joint_applied_updates,
    };

    let dac_parent_digests = [
        ("root-a", split_record_digest(record_digest(&dac_root_a, 0))),
        ("root-b", split_record_digest(record_digest(&dac_root_b, 0))),
        ("root-c", split_record_digest(record_digest(&dac_root_c, 0))),
    ];
    let dac_projected_grants = vec![
        project_dac_grant("root-a", &dac_root_a, &dac_parent_digests),
        project_dac_grant("child-a", &dac_child_a, &dac_parent_digests),
        project_dac_grant("root-b", &dac_root_b, &dac_parent_digests),
        project_dac_grant("child-b", &dac_child_b, &dac_parent_digests),
        project_dac_grant("root-c", &dac_root_c, &dac_parent_digests),
    ];
    let dac_initial_state_native = dac_initial_state_native.unwrap();
    let dac_projection = SemanticManifest {
        schema: manifest.schema.clone(),
        profile: Profile {
            l_max: credential_b.commitments.len(),
            ra_depth: dac_entitlement.path.siblings.len(),
            state_depth: dac_initial_state_native.path.siblings.len(),
            grant_depth: dac_phases[0]["grant_path_depth"].as_u64().unwrap() as usize,
            revocation_depth: manifest.profile.revocation_depth,
        },
        deployment_id: field_u64(dac_request_native.deployment_id),
        logical_id_mapping_version: dac_request_native.mapping_version,
        policy_version: dac_projected_grants[0].policy_version,
        schema_version: dac_projected_grants[0].schema_version,
        logical_ids: LogicalIds {
            owner: dac_projected_grants[0].issuer,
            delegate_a: dac_projected_grants[0].subject,
            delegate_b: dac_projected_grants[2].subject,
            terminal: dac_projected_grants[1].subject,
        },
        entitlement: EntitlementSpec {
            owner: dac_entitlement.logical_owner,
            resource: dac_entitlement.resource,
            action_mask_u16: dac_entitlement.action_mask,
            interval_lo: dac_entitlement.interval_lo,
            interval_hi: dac_entitlement.interval_hi,
            permit_expiry: dac_entitlement.permit_expiry,
            admission_id_u128_le_limbs: [
                dac_entitlement.admission_id_lo,
                dac_entitlement.admission_id_hi,
            ],
            registration_salt_u128_le_limbs: [
                dac_entitlement.registration_salt_lo,
                dac_entitlement.registration_salt_hi,
            ],
            position: dac_entitlement.position as usize,
            visibility: manifest.entitlement.visibility.clone(),
        },
        state: StateSpec {
            owner: dac_initial_state_native.logical_owner,
            state_expiry: dac_initial_state_native.state_expiry,
            state_position: dac_initial_state_native.position as usize,
            state_salt_u128_le_limbs: [
                dac_initial_state_native.salt_lo,
                dac_initial_state_native.salt_hi,
            ],
            visibility: manifest.state.visibility.clone(),
        },
        grants: dac_projected_grants,
        request: RequestSpec {
            resource: dac_request_native.resource,
            one_hot_action_u16: dac_request_native.one_hot_action,
            interval_lo: dac_request_native.request_lo,
            interval_hi: dac_request_native.request_hi,
            now: dac_request_native.now,
            nonce_u64: field_u64(dac_request_native.nonce),
            terminal: dac_request_native.terminal,
            policy_version: dac_request_native.policy_version,
            schema_version: dac_request_native.schema_version,
        },
        updates: dac_applied_updates,
    };
    let joint_metadata_limbs = [
        field_u64(joint_request_native.circuit_id),
        field_u64(joint_request_native.verifier_id),
        field_u64(joint_request_native.pep_id),
        field_u64(joint_request_native.context),
    ];
    let dac_metadata_limbs = [
        field_u64(dac_request_native.circuit_id),
        field_u64(dac_request_native.verifier_id),
        field_u64(dac_request_native.pep_id),
        field_u64(dac_request_native.context),
    ];
    let joint_request_lo = field_limbs_128(joint_request_native.canonical_request_lo);
    let joint_request_hi = field_limbs_128(joint_request_native.canonical_request_hi);
    let joint_request_limbs = [
        joint_request_lo[0],
        joint_request_lo[1],
        joint_request_hi[0],
        joint_request_hi[1],
    ];
    let dac_request_limbs = [
        dac_request_native.canonical_request_lo[0],
        dac_request_native.canonical_request_lo[1],
        dac_request_native.canonical_request_hi[0],
        dac_request_native.canonical_request_hi[1],
    ];
    let joint_metadata_binding_matches = joint_metadata_limbs == metadata_limbs;
    let dac_metadata_binding_matches = dac_metadata_limbs == metadata_limbs;
    let joint_request_binding_matches = joint_request_limbs == request_limbs;
    let dac_request_binding_matches = dac_request_limbs == request_limbs;
    let joint_registration_opening_matches = joint_owner
        == hash(
            Domain::Owner,
            &[
                joint_owner_pk.0.x,
                joint_owner_pk.0.y,
                scalar381(joint_projection.entitlement.registration_salt_u128_le_limbs),
            ],
        );
    let dac_registration_opening_matches = dac_owner
        == dac_owner_commitment(
            dac_projection.entitlement.owner,
            dac_projection.logical_id_mapping_version,
            dac_projection.entitlement.registration_salt_u128_le_limbs[0],
            dac_projection.entitlement.registration_salt_u128_le_limbs[1],
            &issuer_pk,
        );

    let joint_b_bytes_after = [
        joint_grant_bytes(&joint_root_b),
        joint_grant_bytes(&joint_child_b),
    ]
    .concat();
    let joint_c_bytes_after = joint_grant_bytes(&joint_root_c);
    let dac_b_bytes_after = dac_credential_bytes(&credential_b);
    let dac_c_bytes_after = dac_credential_bytes(&credential_c);
    let joint_original_credentials_unchanged =
        joint_b_bytes_before == joint_b_bytes_after && joint_c_bytes_before == joint_c_bytes_after;
    let dac_original_credentials_unchanged =
        dac_b_bytes_before == dac_b_bytes_after && dac_c_bytes_before == dac_c_bytes_after;

    let backend_profile = json!({
        "backend": "mir-dac-bls12-377-fixed-wrapper",
        "relation_version": 2,
        "l_max": manifest.profile.l_max,
        "ra_depth": manifest.profile.ra_depth,
        "state_depth": manifest.profile.state_depth,
        "grant_depth": manifest.profile.grant_depth,
        "revocation_depth": manifest.profile.revocation_depth,
        "lifecycle_update_indices": [0, 1, 2],
    });
    let matched_expected = ExpectedServiceRequest::from_semantic_manifest(
        &manifest,
        1,
        terminal_pk.0,
        canonical_http.clone(),
        manifest.request.now,
        DacInstalledHeader::from_statement(canonical_raw_sha256.clone(), &matched_statement),
        backend_profile.clone(),
    )
    .expect("same-manifest expected request");
    assert!(matched_expected.matches_statement(&manifest, &backend_profile, &matched_statement));
    let matched_expected_json = serde_json::to_vec(&matched_expected).unwrap();
    if let Some(path) = std::env::var_os("PAIRED_DAC_EXPECTED_OUT") {
        std::fs::write(path, &matched_expected_json).expect("write matched expected request");
    }
    let mut matched_proof_exported = false;
    let mut matched_proof_verified = false;
    let mut matched_envelope_sha256 = None;
    let producer_path = std::env::var_os("MATCHED_DAC_PRODUCER_OUT")
        .or_else(|| std::env::var_os("PAIRED_DAC_PROOF_ENVELOPE_OUT"));
    if let Some(path) = producer_path {
        let mut proof_rng = OsRng;
        let producer_mode =
            std::env::var("MATCHED_DAC_PRODUCER_MODE").unwrap_or_else(|_| "lifecycle".to_owned());
        assert!(matches!(producer_mode.as_str(), "lifecycle" | "formal-t1"));
        let case_plan_bytes = std::env::var_os("MATCHED_CASE_PLAN_PATH")
            .map(|path| std::fs::read(path).expect("read matched case plan"))
            .unwrap_or_else(|| {
                include_bytes!("../../../service/matched_case_plan_v1.json").to_vec()
            });
        let case_plan: serde_json::Value =
            serde_json::from_slice(&case_plan_bytes).expect("parse matched case plan");
        assert_eq!(case_plan["version"], "plan-a-matched-case-plan-v1");
        let case_plan_sha256 = sha256_hex(&case_plan_bytes);
        let header_statements = manifest
            .updates
            .iter()
            .map(|update| {
                lifecycle_circuits
                    .iter()
                    .find(|(tuple_version, _, _, _, _)| *tuple_version == update.tuple_version)
                    .expect("each phase has one accepted DAC circuit")
                    .3
                    .clone()
            })
            .collect::<Vec<_>>();
        let base_nonce = manifest.request.nonce_u64;
        let body = |offset: u64| {
            json!({
                "nonce_u64": base_nonce.checked_add(offset).expect("case nonce overflow"),
                "operation": "read",
            })
        };
        let find_circuit = |tuple_version: u64, grant_id: &str| {
            lifecycle_circuits
                .iter()
                .find(|(tuple, grant, _, _, _)| *tuple == tuple_version && *grant == grant_id)
                .expect("named lifecycle circuit")
        };
        let mut audit_specs = if producer_mode == "formal-t1" {
            vec![
                (
                    "formal_actual1".to_owned(),
                    1usize,
                    2u64,
                    "C".to_owned(),
                    0u64,
                ),
                (
                    "formal_actual2".to_owned(),
                    1usize,
                    2u64,
                    "B".to_owned(),
                    0u64,
                ),
            ]
        } else {
            case_plan["cases"]
                .as_object()
                .expect("case plan cases object")
                .iter()
                .map(|(name, definition)| {
                    let update_index = definition["update_index"]
                        .as_u64()
                        .expect("case update index")
                        as usize;
                    (
                        name.clone(),
                        update_index,
                        manifest.updates[update_index].tuple_version,
                        definition["chain"]
                            .as_str()
                            .expect("case chain")
                            .to_ascii_uppercase(),
                        definition["nonce_offset"]
                            .as_u64()
                            .expect("case nonce offset"),
                    )
                })
                .collect::<Vec<_>>()
        };
        if let Ok(case_filter) = std::env::var("MATCHED_DAC_SYNTHESIS_CASE") {
            audit_specs.retain(|(name, _, _, _, _)| name == &case_filter);
            assert!(
                !audit_specs.is_empty(),
                "MATCHED_DAC_SYNTHESIS_CASE did not name an available case"
            );
        }
        let mut synthesis_audits = Vec::new();
        let setup_template = lifecycle_circuits
            .first()
            .expect("lifecycle circuits")
            .4
            .clone();
        let setup_audit = audit_matched_circuit(&setup_template).expect("setup synthesis audit");
        let setup_case_audit = json!({
            "phase": "matched_dac_pre_setup_case",
            "case": "__setup_template__",
            "update_index": serde_json::Value::Null,
            "actual_offline_label": lifecycle_circuits.first().expect("lifecycle circuits").2,
            "satisfied": setup_audit.satisfied,
            "unsatisfied_constraint": setup_audit.unsatisfied_constraint,
            "public_inputs_equal_instance_assignment": setup_audit.public_inputs_equal_instance_assignment,
            "constraints": setup_audit.constraints,
            "canonical_matrix_blake2s": setup_audit.canonical_matrix_blake2s,
            "deployment_parameter_sha256": deployment_parameter_sha256(&setup_template.deployment),
            "setup_or_proof_executed": false,
        });
        eprintln!("{}", serde_json::to_string(&setup_case_audit).unwrap());
        std::io::stderr()
            .flush()
            .expect("flush setup synthesis diagnostic");
        synthesis_audits.push(setup_case_audit);
        for (name, update_index, tuple_version, grant_id, nonce_offset) in &audit_specs {
            let (_, _, actual, _, circuit) = find_circuit(*tuple_version, grant_id);
            let candidate =
                bind_operational_request(circuit.clone(), &canonical_http, &body(*nonce_offset));
            let audit = audit_matched_circuit(&candidate).expect("matched synthesis audit");
            let case_audit = json!({
                "phase": "matched_dac_pre_setup_case",
                "case": name,
                "update_index": update_index,
                "actual_offline_label": actual,
                "satisfied": audit.satisfied,
                "unsatisfied_constraint": audit.unsatisfied_constraint,
                "public_inputs_equal_instance_assignment": audit.public_inputs_equal_instance_assignment,
                "constraints": audit.constraints,
                "canonical_matrix_blake2s": audit.canonical_matrix_blake2s,
                "deployment_parameter_sha256": deployment_parameter_sha256(&candidate.deployment),
                "setup_or_proof_executed": false,
            });
            eprintln!("{}", serde_json::to_string(&case_audit).unwrap());
            std::io::stderr()
                .flush()
                .expect("flush matched synthesis case diagnostic");
            synthesis_audits.push(case_audit);
        }
        let matrix_digests = synthesis_audits
            .iter()
            .map(|audit| {
                audit["canonical_matrix_blake2s"]
                    .as_str()
                    .expect("matrix digest")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        let deployment_digests = synthesis_audits
            .iter()
            .map(|audit| {
                audit["deployment_parameter_sha256"]
                    .as_str()
                    .expect("deployment parameter digest")
                    .to_owned()
            })
            .collect::<BTreeSet<_>>();
        let all_cases_satisfied = synthesis_audits
            .iter()
            .all(|audit| audit["satisfied"] == json!(true));
        let all_public_inputs_equal = synthesis_audits
            .iter()
            .all(|audit| audit["public_inputs_equal_instance_assignment"] == json!(true));
        let synthesis_gate_passed = all_cases_satisfied
            && all_public_inputs_equal
            && matrix_digests.len() == 1
            && deployment_digests.len() == 1;
        let synthesis_result = json!({
            "phase": "matched_dac_pre_setup_synthesis",
            "producer_mode": producer_mode,
            "case_plan_sha256": case_plan_sha256,
            "cases": synthesis_audits,
            "all_cases_satisfied": all_cases_satisfied,
            "all_public_inputs_equal_instance_assignment": all_public_inputs_equal,
            "canonical_matrix_equal_for_same_pk": matrix_digests.len() == 1,
            "canonical_matrix_blake2s": matrix_digests.iter().next(),
            "deployment_parameters_equal_for_same_pk": deployment_digests.len() == 1,
            "deployment_parameter_sha256": deployment_digests.iter().next(),
            "synthesis_gate_passed": synthesis_gate_passed,
            "setup_or_proof_executed": false,
        });
        if std::env::var("MATCHED_DAC_PRODUCER_PHASE").as_deref() == Ok("synthesis") {
            let encoded = serde_json::to_vec_pretty(&synthesis_result).unwrap();
            std::fs::write(&path, &encoded).expect("write matched synthesis result");
            println!("{}", String::from_utf8(encoded).unwrap());
            return;
        }
        assert!(
            synthesis_gate_passed,
            "matched pre-setup synthesis gate failed"
        );
        let setup_started = Instant::now();
        let (proving_key, verifying_key) =
            Groth16::<BW6_761>::circuit_specific_setup(setup_template, &mut proof_rng)
                .expect("matched Groth16 setup");
        let setup_ms = setup_started.elapsed().as_secs_f64() * 1000.0;
        let registry_sk = UserSecretKey::<Bls12_377>::new(&mut proof_rng);
        let registry_pk = UserPublicKey::new(&registry_sk, set_srs.get_P1());
        let verify_failure_path = std::env::var_os("MATCHED_DAC_VERIFY_FAILURE_OUT")
            .map(PathBuf::from)
            .unwrap_or_else(|| verification_failure_path(Path::new(&path)));
        let prove_variant = |case_id: &str,
                             update_index: usize,
                             actual: u64,
                             body: serde_json::Value,
                             circuit: FixedPolicyCircuit,
                             proof_rng: &mut OsRng| {
            let circuit = bind_operational_request(circuit, &canonical_http, &body);
            let statement = circuit.statement.clone();
            let deployment_parameter_sha256 = deployment_parameter_sha256(&circuit.deployment);
            let prove_started = Instant::now();
            let proof = Groth16::<BW6_761>::prove(&proving_key, circuit, proof_rng)
                .expect("matched Groth16 proof");
            let prove_ms = prove_started.elapsed().as_secs_f64() * 1000.0;
            let verify_started = Instant::now();
            let verifier_inputs = public_inputs(&statement, 2);
            let verified = Groth16::<BW6_761>::verify(&verifying_key, &verifier_inputs, &proof)
                .expect("matched Groth16 verification");
            let verify_ms = verify_started.elapsed().as_secs_f64() * 1000.0;
            let mut proof_bytes = Vec::new();
            proof.serialize_compressed(&mut proof_bytes).unwrap();
            if !verified {
                let mut verifying_key_bytes = Vec::new();
                verifying_key
                    .serialize_compressed(&mut verifying_key_bytes)
                    .expect("serialize failing verification key");
                let public_inputs_hex = verifier_inputs
                    .iter()
                    .map(canonical_hex)
                    .collect::<Vec<_>>();
                let case_input = json!({
                    "case": case_id,
                    "update_index": update_index,
                    "actual_offline_label": actual,
                    "body": body,
                    "public_inputs": public_inputs_hex,
                    "deployment_parameter_sha256": deployment_parameter_sha256,
                });
                let case_input_bytes = serde_json::to_vec(&case_input).unwrap();
                let failure = json!({
                    "phase": "matched_dac_immediate_self_verify",
                    "verified": false,
                    "case_input_sha256": sha256_hex(&case_input_bytes),
                    "case_input": case_input,
                    "proof": canonical_hex(&proof),
                    "proof_sha256": sha256_hex(&proof_bytes),
                    "verifying_key": canonical_hex(&verifying_key),
                    "verifying_key_sha256": sha256_hex(&verifying_key_bytes),
                });
                let failure_bytes = serde_json::to_vec_pretty(&failure).unwrap();
                std::fs::write(&verify_failure_path, &failure_bytes)
                    .expect("write matched self-verification failure artifact");
                eprintln!("{}", String::from_utf8(failure_bytes).unwrap());
                std::io::stderr()
                    .flush()
                    .expect("flush matched self-verification failure diagnostic");
            }
            assert!(
                verified,
                "matched proof self-verification failed for {case_id}"
            );
            let terminal_signature = sign_terminal(
                proof_rng,
                set_srs.get_P1(),
                &terminal_sk.0,
                &statement,
                2,
                &proof_bytes,
            );
            let envelope = ResidentProofEnvelope::new(
                canonical_raw_sha256.clone(),
                update_index,
                2,
                &statement,
                &proof,
                &terminal_signature,
            );
            (
                statement,
                json!({
                    "update_index": update_index,
                    "actual": actual,
                    "actual_disclosed_in_envelope": false,
                    "body": body,
                    "proof_bytes": proof_bytes.len(),
                    "envelope": envelope,
                    "prove_ms": prove_ms,
                    "verify_ms": verify_ms,
                }),
            )
        };

        let mut trusted_statements = header_statements.clone();
        let mut rows = Vec::new();
        let mut cases = serde_json::Map::new();
        if producer_mode == "formal-t1" {
            for grant_id in ["C", "B"] {
                let (_, _, actual, _, circuit) = find_circuit(2, grant_id);
                let case_id = format!("formal_actual{actual}");
                let (statement, mut row) = prove_variant(
                    &case_id,
                    1,
                    *actual,
                    body(0),
                    circuit.clone(),
                    &mut proof_rng,
                );
                trusted_statements.push(statement);
                row.as_object_mut()
                    .expect("proof row object")
                    .remove("body");
                rows.push(row);
            }
        } else {
            let definitions = case_plan["cases"]
                .as_object()
                .expect("case plan cases object");
            assert_eq!(definitions.len(), 13);
            for (name, definition) in definitions {
                let update_index = definition["update_index"]
                    .as_u64()
                    .expect("case update index") as usize;
                let tuple_version = manifest.updates[update_index].tuple_version;
                let grant_id = definition["chain"]
                    .as_str()
                    .expect("case chain")
                    .to_ascii_uppercase();
                let nonce_offset = definition["nonce_offset"]
                    .as_u64()
                    .expect("case nonce offset");
                let (_, _, actual, _, circuit) = find_circuit(tuple_version, &grant_id);
                let (statement, row) = prove_variant(
                    name,
                    update_index,
                    *actual,
                    body(nonce_offset),
                    circuit.clone(),
                    &mut proof_rng,
                );
                trusted_statements.push(statement);
                let mut case = row.as_object().expect("proof row object").clone();
                case.remove("actual");
                case.remove("actual_disclosed_in_envelope");
                case.remove("proof_bytes");
                case.remove("prove_ms");
                case.remove("verify_ms");
                cases.insert(name.clone(), serde_json::Value::Object(case));
            }
        }
        matched_proof_verified = (producer_mode == "formal-t1" && rows.len() == 2)
            || (producer_mode == "lifecycle" && cases.len() == 13);
        let trusted_config = TrustedDacConfigWire::new(
            canonical_raw_sha256.clone(),
            2,
            &trusted_statements,
            set_srs.get_P1(),
            &registry_pk.0,
            &verifying_key,
            backend_profile.clone(),
        );
        let mut phases = Vec::new();
        let mut matched_header_envelope = None;
        for (update_index, statement) in header_statements.iter().enumerate() {
            if producer_mode == "formal-t1" && update_index != 1 {
                continue;
            }
            let header_signature =
                sign_header(&mut proof_rng, set_srs.get_P1(), &registry_sk.0, statement);
            let header_envelope =
                HeaderEnvelope::new(canonical_raw_sha256.clone(), statement, &header_signature);
            if update_index == 1 {
                matched_header_envelope = Some(header_envelope.clone());
            }
            phases.push(json!({
                "update_index": update_index,
                "header_envelope": header_envelope,
            }));
        }
        let mut verifying_key_bytes = Vec::new();
        verifying_key
            .serialize_compressed(&mut verifying_key_bytes)
            .unwrap();
        let mut proving_key_bytes = Vec::new();
        proving_key
            .serialize_compressed(&mut proving_key_bytes)
            .unwrap();
        let proving_key_sha256 = sha256_hex(&proving_key_bytes);
        let proving_key_size = proving_key_bytes.len();
        drop(proving_key_bytes);
        let vk_path = std::env::var_os("MATCHED_DAC_VK_OUT");
        if let Some(vk_path) = &vk_path {
            std::fs::write(vk_path, &verifying_key_bytes).expect("write trusted DAC VK");
        }
        let trusted_config_json = serde_json::to_vec_pretty(&trusted_config).unwrap();
        let trusted_config_sha256 = sha256_hex(&trusted_config_json);
        let config_path = std::env::var_os("MATCHED_DAC_TRUSTED_CONFIG_OUT");
        if let Some(config_path) = &config_path {
            std::fs::write(config_path, &trusted_config_json)
                .expect("write trusted DAC resident config");
        }
        let resident_env = config_path
            .as_ref()
            .map(|path| {
                json!({
                    "DAC_TRUSTED_CONFIG_PATH": path.to_string_lossy(),
                })
            })
            .unwrap_or_else(|| json!({}));
        let producer = json!({
            "semantic_input_sha256": canonical_raw_sha256.clone(),
            "producer_mode": producer_mode.clone(),
            "case_plan_sha256": case_plan_sha256,
            "setup_ms": setup_ms,
            "vk_sha256": trusted_config.verifying_key_sha256.clone(),
            "vk_bytes": verifying_key_bytes.len(),
            "pk_sha256": proving_key_sha256,
            "pk_bytes": proving_key_size,
            "deployment_parameter_sha256": synthesis_result["deployment_parameter_sha256"].clone(),
            "backend_profile": backend_profile,
            "vk_path": vk_path.as_ref().map(|path| path.to_string_lossy()),
            "trusted_config_sha256": trusted_config_sha256,
            "resident_env": resident_env,
            "registry_public_key": trusted_config.registry_public_key.clone(),
            "terminal_public_key": canonical_hex(&terminal_pk.0),
            "header_envelope": matched_header_envelope.expect("tuple-two header"),
            "http": canonical_http.clone(),
            "http_sha256": canonical_http_sha256.clone(),
            "expected": matched_expected.clone(),
            "trusted_config": trusted_config,
            "rows": rows,
            "phases": phases,
            "cases": cases,
        });
        let producer_json = serde_json::to_vec_pretty(&producer).unwrap();
        matched_envelope_sha256 = Some(sha256_hex(&producer_json));
        std::fs::write(path, producer_json).expect("write matched DAC producer output");
        matched_proof_exported = true;
    }

    let initial_members_ok = joint_phases[0]["root_membership_abc"] == json!([true, true, true])
        && dac_phases[0]["root_membership_abc"] == json!([true, true, true]);
    let deletion_members_ok = joint_phases[1]["root_membership_abc"] == json!([false, true, true])
        && dac_phases[1]["root_membership_abc"] == json!([false, true, true]);
    let revocation_members_ok = joint_phases[0]["revocation_nonmember_b"] == json!(true)
        && joint_phases[2]["revocation_nonmember_b"] == json!(false)
        && joint_phases[2]["revocation_nonmember_c"] == json!(true)
        && dac_phases[0]["revocation_nonmember_b"] == json!(true)
        && dac_phases[2]["revocation_nonmember_b"] == json!(false)
        && dac_phases[2]["revocation_nonmember_c"] == json!(true);
    let request_outcomes_match = [(true, true), (true, true), (false, true)]
        .iter()
        .enumerate()
        .all(|(index, (expected_b, expected_c))| {
            joint_phases[index]["request_acceptance_b"] == json!(expected_b)
                && joint_phases[index]["request_acceptance_c"] == json!(expected_c)
                && dac_phases[index]["request_acceptance_b"] == json!(expected_b)
                && dac_phases[index]["request_acceptance_c"] == json!(expected_c)
        });
    let same_request_terminal_updates = joint_projection.request == manifest.request
        && dac_projection.request == manifest.request
        && joint_projection.updates == manifest.updates
        && dac_projection.updates == manifest.updates
        && joint_projection.request == dac_projection.request
        && joint_projection.updates == dac_projection.updates
        && manifest.request.terminal == manifest.logical_ids.terminal
        && request_outcomes_match;
    let joint_projection_sha256 = manifest_sha256(&joint_projection);
    let dac_projection_sha256 = manifest_sha256(&dac_projection);
    let same_raw_records_and_update_order = joint_projection == manifest
        && dac_projection == manifest
        && joint_projection_sha256 == canonical_raw_sha256
        && dac_projection_sha256 == canonical_raw_sha256;
    let logical_ids = [
        manifest.logical_ids.owner,
        manifest.logical_ids.delegate_a,
        manifest.logical_ids.delegate_b,
        manifest.logical_ids.terminal,
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let no_trusted_mapper = logical_ids.len() == 4
        && manifest
            .grants
            .iter()
            .all(|item| logical_ids.contains(&item.issuer) && logical_ids.contains(&item.subject));
    let heterogeneous_root_encodings = canonical_hex(&joint_ra_root) != canonical_hex(&dac_ra_root);
    let sources = json!({
        "joint_poseidon_rs_sha256": sha256_hex(include_bytes!("../../../src/poseidon.rs")),
        "joint_joint_rs_sha256": sha256_hex(include_bytes!("../../../src/joint.rs")),
        "joint_merkle_rs_sha256": sha256_hex(include_bytes!("../../../src/merkle.rs")),
        "joint_revocation_rs_sha256": sha256_hex(include_bytes!("../../../src/indexed_revocation.rs")),
        "dac_fixed_policy_rs_sha256": sha256_hex(include_bytes!("../../dac_fixed_wrapper/src/fixed_policy.rs")),
        "dac_semantic_schema_rs_sha256": sha256_hex(include_bytes!("../../dac_fixed_wrapper/src/semantic_schema.rs")),
        "dac_matched_builder_rs_sha256": sha256_hex(include_bytes!("../../dac_fixed_wrapper/src/matched_builder.rs")),
        "dac_service_wire_rs_sha256": sha256_hex(include_bytes!("../../dac_fixed_wrapper/src/service_wire.rs")),
        "dac_resident_jsonl_rs_sha256": sha256_hex(include_bytes!("../../dac_fixed_wrapper/src/bin/dac_resident_jsonl.rs")),
        "schema_descriptor_sha256": sha256_hex(b"plan-a-paired-semantic-records-v2|typed-serde-roundtrip|logical-ids|ra|state|grants|request|ordered-updates")
    });
    let output = json!({
        "schema": "plan-a-paired-semantic-manifest-result-v2",
        "canonical_raw_manifest": &manifest,
        "canonical_raw_manifest_sha256": canonical_raw_sha256.clone(),
        "source_and_schema_hashes": sources,
        "mapping_contract": {
            "same_raw_records_and_update_order": same_raw_records_and_update_order,
            "independent_backend_keys": true,
            "independent_authenticated_roots": true,
            "root_bytes_required_equal": false,
            "trusted_mapper_added": !no_trusted_mapper,
            "joint_hash": joint_poseidon_descriptor(),
            "dac_hash": poseidon_parameter_descriptor(),
            "dac_reserved_accumulator_setup_element": "0xdeadbeef; outside the logical grant-serial set and disclosed as backend setup machinery"
        },
        "projection_contract": {
            "mode": "mixed native reverse projection plus explicitly classified request-bound metadata passthrough",
            "bound_metadata": &metadata,
            "bound_metadata_sha256": metadata_sha256,
            "native_reverse_fields": [
                "logical_ids through native key/record mapping",
                "entitlement business fields and admission id",
                "registration salt as a checked opening of the native owner commitment",
                "state expiry/position/salt",
                "grant issuer/subject/resource/action/range/time/depth/serial and parent-digest mapping",
                "request resource/action/range/time/terminal",
                "actually applied ordered updates"
            ],
            "request_bound_passthrough_fields": [
                "schema label",
                "profile capacities and backend tree depths",
                "deployment and mapping versions where absent from a native Joint credential",
                "policy/schema compiler versions where absent from a native Joint Grant or Request",
                "privacy visibility labels",
                "semantic record ids used to name native digest/key mappings"
            ],
            "canonical_http": &canonical_http,
            "canonical_http_body_utf8": String::from_utf8(canonical_http_body.clone()).unwrap(),
            "canonical_http_sha256": canonical_http_sha256.clone(),
            "limb_encoding": "SHA256(compact JSON(bound_metadata)), four consecutive little-endian u64 limbs in native circuit_id, verifier_id, pep_id, and context; canonical_request_lo/hi independently bind SHA256(plan-a-matched-http-v1\\0 || compact JSON({audience,body_sha256,method,path}))"
        },
        "joint381": {
            "consumed_projection": &joint_projection,
            "consumed_projection_sha256": joint_projection_sha256,
            "native_metadata_binding_limbs_u64_le": joint_metadata_limbs,
            "metadata_binding_matches": joint_metadata_binding_matches,
            "native_request_binding_limbs_u64_le": joint_request_limbs,
            "request_binding_matches": joint_request_binding_matches,
            "registration_salt_owner_commitment_opening_matches": joint_registration_opening_matches,
            "key_mapping": joint_keys.iter().map(|(id,_,pk)| json!({"logical_id":id,"public_key":canonical_hex(&pk.0)})).collect::<Vec<_>>(),
            "ra_root": canonical_hex(&joint_ra_root),
            "phases": joint_phases,
            "original_b_c_credential_bytes_unchanged": joint_original_credentials_unchanged,
            "credential_b_before_sha256": sha256_hex(&joint_b_bytes_before),
            "credential_b_after_sha256": sha256_hex(&joint_b_bytes_after),
            "credential_c_before_sha256": sha256_hex(&joint_c_bytes_before),
            "credential_c_after_sha256": sha256_hex(&joint_c_bytes_after),
            "grant_digests": {"root_a":canonical_hex(&grant_digest(&joint_root_a)),"child_a":canonical_hex(&grant_digest(&joint_child_a)),"root_b":canonical_hex(&grant_digest(&joint_root_b)),"child_b":canonical_hex(&grant_digest(&joint_child_b)),"root_c":canonical_hex(&grant_digest(&joint_root_c))}
        },
        "dac377": {
            "consumed_projection": &dac_projection,
            "consumed_projection_sha256": dac_projection_sha256,
            "native_metadata_binding_limbs_u64_le": dac_metadata_limbs,
            "metadata_binding_matches": dac_metadata_binding_matches,
            "native_request_binding_limbs_u64_le": dac_request_limbs,
            "request_binding_matches": dac_request_binding_matches,
            "registration_salt_owner_commitment_opening_matches": dac_registration_opening_matches,
            "issuer_key_digest": canonical_hex(&issuer_key_digest(&issuer_pk)),
            "ra_root": canonical_hex(&dac_ra_root),
            "phases": dac_phases,
            "original_b_c_credential_bytes_unchanged": dac_original_credentials_unchanged,
            "credential_b_before_sha256": sha256_hex(&dac_b_bytes_before),
            "credential_b_after_sha256": sha256_hex(&dac_b_bytes_after),
            "credential_c_before_sha256": sha256_hex(&dac_c_bytes_before),
            "credential_c_after_sha256": sha256_hex(&dac_c_bytes_after),
            "record_digests": {"root_a":canonical_hex(&record_digest(&dac_root_a,0)),"child_a":canonical_hex(&record_digest(&dac_child_a,1)),"root_b":canonical_hex(&record_digest(&dac_root_b,0)),"child_b":canonical_hex(&record_digest(&dac_child_b,1)),"root_c":canonical_hex(&record_digest(&dac_root_c,0))},
            "root_commitments": {"root_a":canonical_hex(&dac_commit_a),"root_b":canonical_hex(&dac_commit_b),"root_c":canonical_hex(&dac_commit_c)},
            "deterministic_manifest_rng_only": !fresh_deployment,
            "fresh_native_deployment_rng": fresh_deployment,
            "deployable_setup": false
        },
        "matched_dac_fixture": {
            "semantic_input_sha256": canonical_raw_sha256,
            "selected_update_index": 1,
            "selected_tuple_version": matched_statement.tuple_version,
            "canonical_http": &canonical_http,
            "canonical_http_sha256": canonical_http_sha256,
            "same_manifest_circuit_built": true,
            "expected_request_from_same_manifest_matches_statement": true,
            "expected_request": &matched_expected,
            "expected_request_sha256": sha256_hex(&matched_expected_json),
            "proof_envelope_exported": matched_proof_exported,
            "proof_verified": matched_proof_verified,
            "proof_envelope_sha256": matched_envelope_sha256,
            "proof_setup_rng": if matched_proof_exported { "OsRng" } else { "not run" },
            "credential_setup_rng": "deterministic manifest-only fixture; not deployable",
        },
        "required_predicates": {
            "canonical_manifest_hashed": !canonical_raw_sha256.is_empty(),
            "typed_roundtrip_is_backend_input": same_raw_records_and_update_order,
            "initial_membership_abc_true_both": initial_members_ok,
            "delete_a_preserve_b_c_both": deletion_members_ok,
            "revoke_b_preserve_c_both": revocation_members_ok,
            "heterogeneous_root_encodings": heterogeneous_root_encodings,
            "same_request_terminal_updates": same_request_terminal_updates,
            "request_outcomes_match": request_outcomes_match,
            "original_b_c_credential_bytes_unchanged_both": joint_original_credentials_unchanged && dac_original_credentials_unchanged,
            "classified_metadata_bound_in_native_requests_both": joint_metadata_binding_matches && dac_metadata_binding_matches,
            "canonical_request_bound_in_native_requests_both": joint_request_binding_matches && dac_request_binding_matches,
            "registration_salt_opening_matches_both": joint_registration_opening_matches && dac_registration_opening_matches,
            "same_manifest_dac_circuit_built": true,
            "same_manifest_expected_request_built": true,
            "no_trusted_mapper": no_trusted_mapper,
            "full_proof_claimed": matched_proof_exported && matched_proof_verified,
            "service_acceptance_claimed": false
        }
    });
    assert!(initial_members_ok);
    assert!(deletion_members_ok);
    assert!(revocation_members_ok);
    assert!(heterogeneous_root_encodings);
    assert!(same_raw_records_and_update_order);
    assert!(same_request_terminal_updates);
    assert!(request_outcomes_match);
    assert!(joint_original_credentials_unchanged);
    assert!(dac_original_credentials_unchanged);
    assert!(joint_metadata_binding_matches);
    assert!(dac_metadata_binding_matches);
    assert!(joint_request_binding_matches);
    assert!(dac_request_binding_matches);
    assert!(joint_registration_opening_matches);
    assert!(dac_registration_opening_matches);
    assert!(no_trusted_mapper);
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
