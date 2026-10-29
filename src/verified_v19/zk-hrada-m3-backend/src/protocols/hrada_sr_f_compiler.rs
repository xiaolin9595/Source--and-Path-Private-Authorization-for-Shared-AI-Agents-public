//! Honest-SR native validator and compiler for the full per-request interval contract.
//!
//! This module does not issue an anonymous credential.  It validates the original
//! signed state and all candidate chains, then emits source-neutral, serializable
//! atomic authority records for a credential backend.

use crate::protocols::{
    hrada_admission::{validate_published_state_roots, AdmissionAuthority, EntitlementSource},
    hrada_auth::{AuthCircuit, Grant, Hash, Scheme, TREE_DEPTH},
};
use ark_bls12_381::Fr;
use ark_crypto_primitives::{
    signature::schnorr::{SecretKey, Signature},
    SignatureScheme,
};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    convert::TryFrom,
    time::Instant,
};

const MAX_CHAIN_GRANTS: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AtomicPermission {
    pub resource: u64,
    /// Exactly one of the 16 action bits.
    pub action: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CompilationKey {
    pub system: u64,
    pub circuit_version: u64,
    pub epoch: u64,
    pub terminal: Vec<u8>,
    pub permission: AtomicPermission,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportDependency {
    /// SR-private stable identifier. Credential backends must not disclose it.
    pub path_id: Hash,
    pub grant_ids: Vec<Hash>,
    pub not_before: u64,
    pub not_after: u64,
    pub dominated_by: Option<Hash>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AtomicCredentialInput {
    pub format: String,
    pub key: CompilationKey,
    pub not_before: u64,
    /// A backend may sign this instead of `not_after` to express closed u64
    /// upper bounds without requiring UINT64_MAX + 1.
    pub not_after_complement: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompileStats {
    pub scan_ns: u128,
    pub validation_ns: u128,
    pub dominance_ns: u128,
    pub ineligible_sources: usize,
    pub scanned_grants: usize,
    pub invalid_grant_records: usize,
    pub unreachable_active_records: usize,
    pub scanned_candidates: usize,
    pub invalid_candidates: usize,
    pub valid_paths: usize,
    pub path_atom_supports: usize,
    pub permission_count: usize,
    pub distinct_group_atoms: usize,
    pub exact_duplicate_supports: usize,
    pub dominated_supports: usize,
    pub interval_fragment_count: usize,
    /// All maximal atomic intervals found after validating the portfolio.
    pub total_compiled_credentials: usize,
    /// Credentials eligible for the fixed issuance scope. Equal to total for
    /// an unscoped compilation.
    pub eligible_atomic_credentials: usize,
    pub issued_atomic_credentials: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledEpoch {
    pub format: String,
    pub epoch: u64,
    pub credentials: Vec<AtomicCredentialInput>,
    /// Private lifecycle ledger, serialized separately from presentations.
    pub dependencies: BTreeMap<Hash, Vec<SupportDependency>>,
    pub stats: CompileStats,
}

/// The only serialized object handed to an anonymous-credential issuer.
/// It intentionally excludes dependency, path, grant and source identifiers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialIssuanceBatch {
    pub format: String,
    pub epoch: u64,
    pub credentials: Vec<AtomicCredentialInput>,
}

impl CompiledEpoch {
    pub fn issuance_batch(&self) -> CredentialIssuanceBatch {
        CredentialIssuanceBatch {
            format: "HRADA-SR-F-ISSUANCE-BATCH-V1".into(),
            epoch: self.epoch,
            credentials: self.credentials.clone(),
        }
    }

    /// Select one Agent terminal after full portfolio validation and dominance.
    /// This models a matched one-Agent issuance workload while retaining scan
    /// and validation counts for the complete trusted portfolio.
    pub fn select_terminal(mut self, terminal: &[u8]) -> Self {
        let selected = self
            .credentials
            .iter()
            .filter(|credential| credential.key.terminal == terminal)
            .cloned()
            .collect::<Vec<_>>();
        let selected_ids = selected
            .iter()
            .map(|credential| {
                authority_id(
                    &credential.key,
                    credential.not_before,
                    u64::MAX - credential.not_after_complement,
                )
            })
            .collect::<BTreeSet<_>>();
        self.dependencies
            .retain(|authority, _| selected_ids.contains(authority));
        self.credentials = selected;
        self.stats.eligible_atomic_credentials = self.credentials.len();
        self.stats.interval_fragment_count = self.credentials.len();
        self.stats.issued_atomic_credentials = self.credentials.len();
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedPath {
    grant_ids: Vec<Hash>,
    terminal: Vec<u8>,
    resource: u64,
    actions: u16,
    not_before: u64,
    not_after: u64,
}

/// SR-owned immutable view of one installed global header and all source
/// snapshots admitted beneath it. There is deliberately no epoch mutator:
/// advancing the header requires installing a fresh registry.
#[derive(Clone)]
pub struct TrustedSnapshotRegistry {
    epoch: u64,
    header_limbs: [Fr; 2],
    snapshots: Vec<(AuthCircuit, Vec<Grant>)>,
    current_identities: BTreeMap<Hash, SnapshotIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotIdentity {
    prime: Fr,
    auth_root: Hash,
    state_version: u64,
    state_hash: Hash,
}

fn snapshot_identity(state: &AuthCircuit) -> SnapshotIdentity {
    SnapshotIdentity {
        prime: state.prime,
        auth_root: state.auth_root,
        state_version: state.state_version,
        state_hash: state.state_hash(),
    }
}

impl TrustedSnapshotRegistry {
    /// Install exact snapshots under the global header carried by their public
    /// request fields. The caller is the trusted state service, not a presenter.
    pub fn install(sources: &[(&AuthCircuit, &[Grant])]) -> Result<Self, String> {
        let (first, _) = sources.first().ok_or("empty_source_set")?;
        let epoch = field_u64(first.request.fields[2], "global_epoch")?;
        let header_limbs = [first.request.fields[0], first.request.fields[1]];
        Self::install_under(epoch, header_limbs, sources)
    }

    /// Install snapshots under a header association supplied by the trusted
    /// current-state service. Q fields are checked for consistency, but are not
    /// themselves a signature over this association.
    pub fn install_under(
        epoch: u64,
        header_limbs: [Fr; 2],
        sources: &[(&AuthCircuit, &[Grant])],
    ) -> Result<Self, String> {
        if sources.is_empty() {
            return Err("empty_source_set".into());
        }
        let mut snapshots = Vec::with_capacity(sources.len());
        let mut current_identities = BTreeMap::new();
        for (state, grants) in sources {
            if field_u64(state.request.fields[2], "global_epoch")? != epoch
                || state.request.fields[0] != header_limbs[0]
                || state.request.fields[1] != header_limbs[1]
            {
                return Err("source_global_header_mismatch".into());
            }
            if current_identities
                .insert(state.user_commitment(), snapshot_identity(state))
                .is_some()
            {
                return Err("duplicate_current_user_state".into());
            }
            snapshots.push(((*state).clone(), grants.to_vec()));
        }
        Ok(Self {
            epoch,
            header_limbs,
            snapshots,
            current_identities,
        })
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn header_limbs(&self) -> [Fr; 2] {
        self.header_limbs
    }

    /// Compare an offered source snapshot with the identity pinned by the
    /// authoritative current-state service at registry installation.
    pub fn snapshot_is_current(&self, state: &AuthCircuit) -> bool {
        self.current_identities
            .get(&state.user_commitment())
            .map(|expected| expected == &snapshot_identity(state))
            .unwrap_or(false)
    }
}

fn field_u64(value: Fr, label: &'static str) -> Result<u64, String> {
    let repr = value.into_repr();
    let limbs = repr.as_ref();
    if limbs.iter().skip(1).any(|limb| *limb != 0) {
        Err(format!("{}_not_u64", label))
    } else {
        Ok(limbs[0])
    }
}

fn field_u16(value: Fr, label: &'static str) -> Result<u16, String> {
    u16::try_from(field_u64(value, label)?).map_err(|_| format!("{}_not_u16", label))
}

fn point(x: Fr, y: Fr, label: &'static str) -> Result<EdwardsAffine, String> {
    let point = EdwardsAffine::new(x, y);
    if point.is_zero() || !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve()
    {
        return Err(format!("{}_point_invalid", label));
    }
    Ok(point)
}

fn point_bytes(point: &EdwardsAffine) -> Vec<u8> {
    let mut bytes = Vec::new();
    point.serialize(&mut bytes).expect("vec serialization");
    bytes
}

fn hash(domain: u8, parts: &[&[u8]]) -> Hash {
    let mut hasher = Blake2s::new();
    hasher.update(&[domain]);
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Canonical source-neutral Q16 encoding used by the terminal binding.
pub fn encode_complete_q(fields: &[Fr]) -> Result<Vec<u8>, String> {
    if fields.len() != 16 {
        return Err("complete_q_arity".into());
    }
    let mut out = b"HRADA-Q16-V1".to_vec();
    for field in fields {
        let mut encoded = Vec::new();
        field
            .serialize(&mut encoded)
            .map_err(|_| "complete_q_encoding")?;
        out.extend((encoded.len() as u32).to_le_bytes());
        out.extend(encoded);
    }
    Ok(out)
}

/// Digest authorized by the existing terminal Agent after an anonymous proof
/// is complete. This binds every public request field and prevents proof/key
/// recombination. The anonymous proof verifier still runs independently.
pub fn terminal_binding_digest(
    params_digest: &Hash,
    current_header_digest: &Hash,
    complete_q: &[Fr],
    anonymous_proof: &[u8],
) -> Result<Hash, String> {
    let q = encode_complete_q(complete_q)?;
    Ok(hash(
        42,
        &[
            b"HRADA-SR-F-TERMINAL-V1",
            params_digest,
            current_header_digest,
            &q,
            anonymous_proof,
        ],
    ))
}

pub fn terminal_sign_showing(
    state: &AuthCircuit,
    terminal_secret: &SecretKey<EdwardsProjective>,
    params_digest: &Hash,
    current_header_digest: &Hash,
    complete_q: &[Fr],
    anonymous_proof: &[u8],
) -> Result<Signature<EdwardsProjective>, String> {
    let digest = terminal_binding_digest(
        params_digest,
        current_header_digest,
        complete_q,
        anonymous_proof,
    )?;
    Scheme::sign(&state.params, terminal_secret, &digest, &mut OsRng)
        .map_err(|_| "terminal_signing_failed".into())
}

pub fn terminal_verify_showing(
    state: &AuthCircuit,
    terminal_public: &EdwardsAffine,
    signature: &Signature<EdwardsProjective>,
    params_digest: &Hash,
    current_header_digest: &Hash,
    complete_q: &[Fr],
    anonymous_proof: &[u8],
) -> Result<bool, String> {
    let digest = terminal_binding_digest(
        params_digest,
        current_header_digest,
        complete_q,
        anonymous_proof,
    )?;
    Scheme::verify(&state.params, terminal_public, &digest, signature)
        .map_err(|_| "terminal_verification_failed".into())
}

fn merkle_root(grants: &[Grant]) -> Result<Hash, String> {
    let mut leaves = vec![[0u8; 32]; 1 << TREE_DEPTH];
    let mut occupied = vec![false; leaves.len()];
    for grant in grants {
        let index = field_u64(grant.fields[14], "leaf_index")? as usize;
        if index >= leaves.len() || occupied[index] {
            return Err("grant_tree_index_invalid".into());
        }
        occupied[index] = true;
        leaves[index] = grant.leaf();
    }
    for _ in 0..TREE_DEPTH {
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| hash(7, &[&pair[0], &pair[1]]))
            .collect();
    }
    Ok(leaves[0])
}

fn validate_public_state(state: &AuthCircuit, grants: &[Grant], now: u64) -> Result<(), String> {
    for (label, candidate) in [
        ("generator", state.params.generator),
        ("ra", state.ra_pk),
        ("sr", state.sr_pk),
        ("user", state.user_pk),
    ] {
        let _ = point(candidate.x, candidate.y, label)?;
    }
    if state.prime.into_repr().num_bits() != 252 {
        return Err("state_prime_not_252_bits".into());
    }
    if !Scheme::verify(
        &state.params,
        &state.ra_pk,
        &state.reg_hash(),
        &state.ra_sig,
    )
    .map_err(|_| "registration_signature_error")?
    {
        return Err("registration_signature_invalid".into());
    }
    if merkle_root(grants)? != state.auth_root {
        return Err("auth_root_mismatch".into());
    }
    if !Scheme::verify(
        &state.params,
        &state.sr_pk,
        &state.state_hash(),
        &state.sr_sig,
    )
    .map_err(|_| "state_signature_error")?
    {
        return Err("state_signature_invalid".into());
    }
    if state.reg_serial == 0 || now > state.reg_expiry {
        return Err("registration_inactive".into());
    }
    if state.state_status != 1 || state.state_version > u32::MAX as u64 || now > state.state_expiry
    {
        return Err("state_inactive".into());
    }
    Ok(())
}

fn validate_grant_shape(state: &AuthCircuit, grant: &Grant) -> Result<(), String> {
    let issuer = point(grant.fields[3], grant.fields[4], "issuer")?;
    let _ = point(grant.fields[5], grant.fields[6], "subject")?;
    let kind = field_u64(grant.fields[0], "grant_kind")?;
    let actions = field_u16(grant.fields[8], "actions")?;
    let not_before = field_u64(grant.fields[9], "not_before")?;
    let not_after = field_u64(grant.fields[10], "not_after")?;
    let delegable = field_u64(grant.fields[11], "delegable")?;
    let depth = field_u64(grant.fields[12], "depth")?;
    let serial = field_u64(grant.fields[13], "serial")?;
    let index = field_u64(grant.fields[14], "leaf_index")?;
    field_u64(grant.fields[7], "resource")?;
    field_u64(grant.fields[16], "record_version")?;
    if kind > 1
        || actions == 0
        || not_before > not_after
        || delegable > 1
        || depth > 15
        || serial == 0
        || index >= (1u64 << TREE_DEPTH)
    {
        return Err("grant_shape_invalid".into());
    }
    if !Scheme::verify(&state.params, &issuer, &grant.core(), &grant.signature)
        .map_err(|_| "grant_signature_error")?
    {
        return Err("grant_signature_invalid".into());
    }
    Ok(())
}

fn validate_path(
    state: &AuthCircuit,
    chain: &[&Grant],
    validated_grants: &BTreeSet<Hash>,
) -> Result<ValidatedPath, String> {
    if chain.is_empty() || chain.len() > MAX_CHAIN_GRANTS {
        return Err("chain_length_invalid".into());
    }
    let commitment = state.user_commitment();
    let commitment_limbs = [
        Fr::from_le_bytes_mod_order(&commitment[..16]),
        Fr::from_le_bytes_mod_order(&commitment[16..]),
    ];
    let mut lower = 0u64;
    let mut upper = state.reg_expiry.min(state.state_expiry);
    let mut previous: Option<&Grant> = None;
    for (position, grant) in chain.iter().enumerate() {
        if !grant.active {
            return Err("inactive_grant".into());
        }
        if !validated_grants.contains(&grant.id()) {
            return Err("grant_record_invalid".into());
        }
        if grant.fields[1] != commitment_limbs[0] || grant.fields[2] != commitment_limbs[1] {
            return Err("user_commitment_mismatch".into());
        }
        let kind = field_u64(grant.fields[0], "grant_kind")?;
        let depth = field_u64(grant.fields[12], "depth")?;
        if position == 0 {
            if kind != 0
                || grant.fields[3] != state.user_pk.x
                || grant.fields[4] != state.user_pk.y
                || grant.parent != state.reg_hash()
                || depth > 2
            {
                return Err("root_binding_invalid".into());
            }
        } else {
            let parent = previous.expect("position checked");
            let parent_actions = field_u16(parent.fields[8], "parent_actions")?;
            let child_actions = field_u16(grant.fields[8], "child_actions")?;
            if kind != 1
                || grant.parent != parent.id()
                || grant.fields[3] != parent.fields[5]
                || grant.fields[4] != parent.fields[6]
                || grant.fields[7] != parent.fields[7]
                || grant.fields[15] != parent.fields[15]
                || (child_actions & !parent_actions) != 0
                || field_u64(parent.fields[11], "parent_delegable")? != 1
                || field_u64(parent.fields[12], "parent_depth")? != depth + 1
                || field_u64(parent.fields[9], "parent_not_before")?
                    > field_u64(grant.fields[9], "child_not_before")?
                || field_u64(grant.fields[10], "child_not_after")?
                    > field_u64(parent.fields[10], "parent_not_after")?
            {
                return Err("delegation_relation_invalid".into());
            }
        }
        lower = lower.max(field_u64(grant.fields[9], "not_before")?);
        upper = upper.min(field_u64(grant.fields[10], "not_after")?);
        previous = Some(grant);
    }
    if lower > upper {
        return Err("empty_effective_interval".into());
    }
    let terminal_grant = chain.last().expect("nonempty chain");
    let terminal = point(
        terminal_grant.fields[5],
        terminal_grant.fields[6],
        "terminal",
    )?;
    Ok(ValidatedPath {
        grant_ids: chain.iter().map(|grant| grant.id()).collect(),
        terminal: point_bytes(&terminal),
        resource: field_u64(terminal_grant.fields[7], "resource")?,
        actions: field_u16(terminal_grant.fields[8], "actions")?,
        not_before: lower,
        not_after: upper,
    })
}

fn candidate_chains<'a>(grants: &'a [Grant]) -> Vec<Vec<&'a Grant>> {
    let mut by_parent: HashMap<Hash, Vec<&Grant>> = HashMap::new();
    for grant in grants {
        by_parent.entry(grant.parent).or_default().push(grant);
    }
    let mut out = Vec::new();
    for root in grants
        .iter()
        .filter(|grant| field_u64(grant.fields[0], "kind").ok() == Some(0))
    {
        let mut stack = vec![vec![root]];
        while let Some(chain) = stack.pop() {
            out.push(chain.clone());
            if chain.len() == MAX_CHAIN_GRANTS {
                continue;
            }
            if let Some(children) = by_parent.get(&chain.last().expect("nonempty").id()) {
                for child in children {
                    let mut extended = chain.clone();
                    extended.push(*child);
                    stack.push(extended);
                }
            }
        }
    }
    out
}

fn authority_id(key: &CompilationKey, lower: u64, upper: u64) -> Hash {
    let encoded = serde_json::to_vec(&(key, lower, upper)).expect("serializable authority");
    hash(41, &[&encoded])
}

fn path_id(grant_ids: &[Hash]) -> Hash {
    let mut encoded = Vec::with_capacity(grant_ids.len() * 32);
    for id in grant_ids {
        encoded.extend(id);
    }
    hash(40, &[&encoded])
}

fn maximal_intervals(paths: &[ValidatedPath]) -> BTreeSet<(u64, u64)> {
    let mut intervals = paths
        .iter()
        .map(|path| (path.not_before, path.not_after))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    intervals.sort_by(|left, right| left.0.cmp(&right.0).then(right.1.cmp(&left.1)));
    let mut maximal = BTreeSet::new();
    let mut greatest_upper = None;
    for (lower, upper) in intervals {
        if greatest_upper.map(|seen| seen >= upper).unwrap_or(false) {
            continue;
        }
        maximal.insert((lower, upper));
        greatest_upper = Some(upper);
    }
    maximal
}

/// Validate a complete native snapshot and compile source-neutral atomic records.
/// The returned dependency map is SR-private and must not accompany presentations.
pub fn compile_epoch<S: EntitlementSource>(
    authority: &AdmissionAuthority,
    entitlements: &S,
    state: &AuthCircuit,
    grants: &[Grant],
    now: u64,
) -> Result<CompiledEpoch, String> {
    let registry = TrustedSnapshotRegistry::install(&[(state, grants)])?;
    compile_portfolio(authority, entitlements, &registry, now)
}

/// Compile several independently signed source snapshots into one existential
/// authority set. All snapshots must use the trusted authority and the same
/// system/circuit version; source identities remain only in private dependencies.
pub fn compile_portfolio<S: EntitlementSource>(
    authority: &AdmissionAuthority,
    entitlements: &S,
    registry: &TrustedSnapshotRegistry,
    now: u64,
) -> Result<CompiledEpoch, String> {
    let epoch = registry.epoch;
    let mut stats = CompileStats::default();
    let mut supports: BTreeMap<CompilationKey, Vec<ValidatedPath>> = BTreeMap::new();
    let mut expected_domain = None;
    let mut permissions = BTreeSet::new();
    for (state, grants) in &registry.snapshots {
        let validation_start = Instant::now();
        if !registry.snapshot_is_current(state) {
            return Err("snapshot_not_current".into());
        }
        match validate_public_state(state, grants, now) {
            Ok(()) => {
                validate_published_state_roots(authority, entitlements, state, grants)
                    .map_err(|error| format!("admission:{:?}", error))?;
            }
            Err(reason) if reason == "registration_inactive" || reason == "state_inactive" => {
                // Expiry/status only removes this source from the existential
                // authority set.  Its immutable registry/tree admission must
                // still be authentic; an ineligible source is not a way to
                // smuggle an untrusted snapshot through the portfolio gate.
                validate_published_state_roots(authority, entitlements, state, grants)
                    .map_err(|error| format!("admission:{:?}", error))?;
                stats.ineligible_sources += 1;
                stats.validation_ns += validation_start.elapsed().as_nanos();
                continue;
            }
            Err(reason) => return Err(reason),
        }
        stats.validation_ns += validation_start.elapsed().as_nanos();
        let system = field_u64(state.request.fields[3], "system")?;
        let circuit_version = field_u64(state.request.fields[4], "circuit_version")?;
        if let Some(expected) = expected_domain {
            if expected != (system, circuit_version) {
                return Err("source_compilation_domain_mismatch".into());
            }
        } else {
            expected_domain = Some((system, circuit_version));
        }
        let scan_start = Instant::now();
        let candidates = candidate_chains(grants);
        stats.scan_ns += scan_start.elapsed().as_nanos();
        stats.scanned_grants += grants.len();
        stats.scanned_candidates += candidates.len();
        let candidate_validation_start = Instant::now();
        let mut validated_grants = BTreeSet::new();
        for grant in grants {
            if validate_grant_shape(state, grant).is_ok() {
                validated_grants.insert(grant.id());
            } else {
                stats.invalid_grant_records += 1;
            }
        }
        let mut reached = BTreeSet::new();
        for candidate in candidates {
            match validate_path(state, &candidate, &validated_grants) {
                Ok(path) => {
                    stats.valid_paths += 1;
                    if let Some(last) = path.grant_ids.last() {
                        reached.insert(*last);
                    }
                    for bit in 0..16 {
                        let action = 1u16 << bit;
                        if path.actions & action == 0 {
                            continue;
                        }
                        stats.path_atom_supports += 1;
                        permissions.insert(AtomicPermission {
                            resource: path.resource,
                            action,
                        });
                        supports
                            .entry(CompilationKey {
                                system,
                                circuit_version,
                                epoch,
                                terminal: path.terminal.clone(),
                                permission: AtomicPermission {
                                    resource: path.resource,
                                    action,
                                },
                            })
                            .or_default()
                            .push(path.clone());
                    }
                }
                Err(_) => stats.invalid_candidates += 1,
            }
        }
        stats.unreachable_active_records += grants
            .iter()
            .filter(|grant| grant.active && !reached.contains(&grant.id()))
            .count();
        stats.validation_ns += candidate_validation_start.elapsed().as_nanos();
    }
    stats.permission_count = permissions.len();
    stats.distinct_group_atoms = supports.len();
    let mut credentials = Vec::new();
    let mut dependencies: BTreeMap<Hash, Vec<SupportDependency>> = BTreeMap::new();
    let dominance_start = Instant::now();
    for (key, paths) in supports {
        let distinct_intervals = paths
            .iter()
            .map(|path| (path.not_before, path.not_after))
            .collect::<BTreeSet<_>>();
        stats.exact_duplicate_supports += paths.len() - distinct_intervals.len();
        let maximal = maximal_intervals(&paths);
        stats.dominated_supports += paths
            .iter()
            .filter(|path| !maximal.contains(&(path.not_before, path.not_after)))
            .count();
        for (lower, upper) in maximal {
            let id = authority_id(&key, lower, upper);
            let mut ledger = Vec::new();
            for path in &paths {
                let covering_id = if path.not_before >= lower && path.not_after <= upper {
                    Some(id)
                } else {
                    None
                };
                if covering_id.is_some() {
                    ledger.push(SupportDependency {
                        path_id: path_id(&path.grant_ids),
                        grant_ids: path.grant_ids.clone(),
                        not_before: path.not_before,
                        not_after: path.not_after,
                        dominated_by: if (path.not_before, path.not_after) == (lower, upper) {
                            None
                        } else {
                            covering_id
                        },
                    });
                }
            }
            dependencies.insert(id, ledger);
            credentials.push(AtomicCredentialInput {
                format: "HRADA-SR-F-ATOMIC-V1".into(),
                key: key.clone(),
                not_before: lower,
                not_after_complement: u64::MAX - upper,
            });
        }
    }
    credentials.sort_by(|left, right| {
        left.key
            .cmp(&right.key)
            .then(left.not_before.cmp(&right.not_before))
            .then(left.not_after_complement.cmp(&right.not_after_complement))
    });
    stats.issued_atomic_credentials = credentials.len();
    stats.total_compiled_credentials = credentials.len();
    stats.eligible_atomic_credentials = credentials.len();
    stats.interval_fragment_count = credentials.len();
    stats.dominance_ns = dominance_start.elapsed().as_nanos();
    Ok(CompiledEpoch {
        format: "HRADA-SR-F-COMPILED-EPOCH-V1".into(),
        epoch,
        credentials,
        dependencies,
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{
        hrada_admission::{BusinessEntitlement, InMemoryEntitlementLedger},
        hrada_auth::AuthFixture,
    };
    use ark_ff::One;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    fn authority(fixture: &AuthFixture) -> AdmissionAuthority {
        AdmissionAuthority::new(
            fixture.base.params.clone(),
            fixture.base.ra_pk,
            fixture.base.sr_pk,
            1,
            1,
        )
    }

    fn ledger(fixtures: &[&AuthFixture]) -> InMemoryEntitlementLedger {
        InMemoryEntitlementLedger {
            records: fixtures
                .iter()
                .map(|fixture| BusinessEntitlement {
                    user_commitment: fixture.base.user_commitment(),
                    system: 1,
                    resource: 42,
                    action_mask: 3,
                    not_before: 0,
                    not_after: 2000,
                    active: true,
                    max_delegation_depth: 2,
                })
                .collect(),
        }
    }

    fn satisfied(fixture: &AuthFixture, path: &str) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        fixture
            .circuit_for(path)
            .generate_constraints(cs.clone())
            .unwrap();
        cs.is_satisfied().unwrap()
    }

    fn archive_ids(fixture: &AuthFixture) -> Vec<Hash> {
        fixture.all_grants.iter().map(Grant::id).collect()
    }

    #[test]
    fn native_decision_agrees_with_controlled_original_paths() {
        let fixture = AuthFixture::new(1201);
        assert!(satisfied(&fixture, "P"));
        assert!(satisfied(&fixture, "P2"));
        assert!(satisfied(&fixture, "Q"));
        assert!(satisfied(&fixture, "short_Q"));
        let compiled = compile_epoch(
            &authority(&fixture),
            &ledger(&[&fixture]),
            &fixture.base,
            &fixture.all_grants,
            500,
        )
        .unwrap();
        assert_eq!(compiled.stats.scanned_grants, 8);
        assert_eq!(compiled.stats.invalid_candidates, 0);
        assert!(compiled.stats.valid_paths >= 4);
        assert!(compiled
            .credentials
            .iter()
            .all(|item| item.not_before == 100));
        assert!(compiled
            .credentials
            .iter()
            .all(|item| item.not_after_complement == u64::MAX - 1000));
    }

    #[test]
    fn global_epoch_recompile_preserves_grants_and_surviving_path() {
        let mut fixture = AuthFixture::new(1202);
        let old_state = fixture.base.clone();
        let old_grants = fixture.all_grants.clone();
        let old_registry =
            TrustedSnapshotRegistry::install(&[(&old_state, old_grants.as_slice())]).unwrap();
        let before_ids = archive_ids(&fixture);
        let before = compile_epoch(
            &authority(&fixture),
            &ledger(&[&fixture]),
            &fixture.base,
            &fixture.all_grants,
            500,
        )
        .unwrap();
        fixture.revoke_middle(fixture.base.prime + Fr::one());
        let successor_registry =
            TrustedSnapshotRegistry::install(&[(&fixture.base, fixture.all_grants.as_slice())])
                .unwrap();
        assert!(old_registry.snapshot_is_current(&old_state));
        assert!(!successor_registry.snapshot_is_current(&old_state));
        assert!(!satisfied(&fixture, "P"));
        assert!(!satisfied(&fixture, "P2"));
        assert!(satisfied(&fixture, "Q"));
        assert!(satisfied(&fixture, "short_Q"));
        let after = compile_epoch(
            &authority(&fixture),
            &ledger(&[&fixture]),
            &fixture.base,
            &fixture.all_grants,
            500,
        )
        .unwrap();
        assert_eq!(before_ids, archive_ids(&fixture));
        assert!(before.credentials.iter().all(|item| item.key.epoch == 1));
        assert!(after.credentials.iter().all(|item| item.key.epoch == 2));
        assert!(after.stats.invalid_candidates > 0);
        assert!(!after.credentials.is_empty());
    }

    #[test]
    fn rejects_native_signature_parent_and_state_mutations() {
        let original = AuthFixture::new(1203);
        let mut bad_signature = original.clone();
        bad_signature.all_grants[5].signature = Default::default();
        let compiled = compile_epoch(
            &authority(&original),
            &ledger(&[&original]),
            &bad_signature.base,
            &bad_signature.all_grants,
            500,
        )
        .unwrap();
        assert!(compiled.stats.invalid_candidates > 0);

        let mut bad_parent = original.clone();
        bad_parent.all_grants[5].parent = [9u8; 32];
        let core = bad_parent.all_grants[5].core();
        bad_parent.all_grants[5].signature = bad_parent.issuer_sign(3, core).unwrap();
        bad_parent.refresh_state(bad_parent.base.prime);
        let orphaned = compile_epoch(
            &authority(&original),
            &ledger(&[&original]),
            &bad_parent.base,
            &bad_parent.all_grants,
            500,
        )
        .unwrap();
        assert!(orphaned.stats.unreachable_active_records >= 2);
        assert!(!orphaned.credentials.is_empty());

        let mut bad_state = original.clone();
        bad_state.base.sr_sig = Default::default();
        assert!(compile_epoch(
            &authority(&original),
            &ledger(&[&original]),
            &bad_state.base,
            &bad_state.all_grants,
            500,
        )
        .is_err());
    }

    #[test]
    fn interval_dominance_keeps_private_support_without_unioning() {
        let mut fixture = AuthFixture::new(1204);
        // Q's three-grant path narrows to [200, 800], while short_Q remains [100, 1000].
        fixture.all_grants[5].fields[9] = Fr::from(200u64);
        fixture.all_grants[5].fields[10] = Fr::from(800u64);
        let core = fixture.all_grants[5].core();
        fixture.all_grants[5].signature = fixture.issuer_sign(3, core).unwrap();
        fixture.all_grants[6].fields[9] = Fr::from(200u64);
        fixture.all_grants[6].fields[10] = Fr::from(800u64);
        fixture.all_grants[6].parent = fixture.all_grants[5].id();
        let core = fixture.all_grants[6].core();
        fixture.all_grants[6].signature = fixture.issuer_sign(4, core).unwrap();
        fixture.refresh_state(fixture.base.prime);
        let compiled = compile_epoch(
            &authority(&fixture),
            &ledger(&[&fixture]),
            &fixture.base,
            &fixture.all_grants,
            500,
        )
        .unwrap();
        assert!(compiled.stats.dominated_supports > 0);
        assert!(compiled.dependencies.values().any(|supports| {
            supports
                .iter()
                .any(|support| support.dominated_by.is_some())
        }));
        assert!(compiled.credentials.iter().any(|item| {
            item.not_before == 100 && item.not_after_complement == u64::MAX - 1000
        }));
        let terminal = point_bytes(&fixture.keys[5].0);
        assert!(!compiled.credentials.iter().any(|item| {
            item.key.terminal == terminal
                && item.not_before == 200
                && item.not_after_complement == u64::MAX - 800
        }));
    }

    #[test]
    fn portfolio_deduplicates_cross_source_support_under_pinned_header() {
        let one = AuthFixture::new(1205);
        let two = one.second_user(1206);
        let policies = ledger(&[&one, &two]);
        let single =
            compile_epoch(&authority(&one), &policies, &one.base, &one.all_grants, 500).unwrap();
        let registry = TrustedSnapshotRegistry::install(&[
            (&one.base, one.all_grants.as_slice()),
            (&two.base, two.all_grants.as_slice()),
        ])
        .unwrap();
        let combined = compile_portfolio(&authority(&one), &policies, &registry, 500).unwrap();
        assert_eq!(combined.stats.scanned_grants, 16);
        // Internal prefix terminals differ between users, while their final
        // terminal is shared. Only matching group+atom authority is merged.
        assert!(combined.credentials.len() < 2 * single.credentials.len());
        assert!(combined.credentials.len() > single.credentials.len());
        assert!(combined.stats.exact_duplicate_supports > 0);
        assert!(combined
            .dependencies
            .values()
            .any(|supports| supports.len() >= 2));
        let issuance_json = serde_json::to_string(&combined.issuance_batch()).unwrap();
        assert!(!issuance_json.contains("path_id"));
        assert!(!issuance_json.contains("grant_ids"));
        assert!(!issuance_json.contains("dependencies"));

        let mut stale = one.clone();
        stale.base.request.fields[2] += Fr::one();
        assert!(TrustedSnapshotRegistry::install(&[
            (&one.base, one.all_grants.as_slice()),
            (&stale.base, stale.all_grants.as_slice()),
        ])
        .is_err());
        assert!(TrustedSnapshotRegistry::install(&[
            (&one.base, one.all_grants.as_slice()),
            (&one.base, one.all_grants.as_slice()),
        ])
        .is_err());
    }

    #[test]
    fn overlapping_intervals_remain_separate_fragments() {
        let template = |not_before, not_after| ValidatedPath {
            grant_ids: vec![[not_before as u8; 32]],
            terminal: vec![1, 2, 3],
            resource: 42,
            actions: 1,
            not_before,
            not_after,
        };
        let paths = vec![template(1, 5), template(4, 10), template(2, 4)];
        let maximal = maximal_intervals(&paths);
        assert_eq!(maximal, [(1, 5), (4, 10)].iter().copied().collect());
        assert!(!maximal.contains(&(1, 10)));
    }

    #[test]
    fn closed_u64_interval_encoding_preserves_zero_and_max() {
        let path = ValidatedPath {
            grant_ids: vec![[9u8; 32]],
            terminal: vec![1, 2, 3],
            resource: u64::MAX,
            actions: u16::MAX,
            not_before: 0,
            not_after: u64::MAX,
        };
        assert_eq!(
            maximal_intervals(&[path]),
            [(0, u64::MAX)].iter().copied().collect()
        );
        assert_eq!(u64::MAX - u64::MAX, 0);
        assert_eq!(u64::MAX - 0, u64::MAX);
    }

    #[test]
    fn unrelated_expired_root_does_not_remove_current_valid_path() {
        let mut fixture = AuthFixture::new(1208);
        for (index, issuer, parent) in [
            (0usize, 0usize, None),
            (1, 1, Some(0)),
            (2, 2, Some(1)),
            (3, 2, Some(1)),
        ] {
            fixture.all_grants[index].fields[10] = Fr::from(400u64);
            fixture.all_grants[index].parent = parent
                .map(|parent| fixture.all_grants[parent].id())
                .unwrap_or_else(|| fixture.base.reg_hash());
            let core = fixture.all_grants[index].core();
            fixture.all_grants[index].signature = fixture.issuer_sign(issuer, core).unwrap();
        }
        fixture.refresh_state(fixture.base.prime);
        let compiled = compile_epoch(
            &authority(&fixture),
            &ledger(&[&fixture]),
            &fixture.base,
            &fixture.all_grants,
            500,
        )
        .unwrap();
        let target = point_bytes(&fixture.keys[5].0);
        assert!(compiled
            .credentials
            .iter()
            .any(|credential| credential.key.terminal == target));
    }

    #[test]
    fn expired_source_is_ineligible_while_valid_source_survives() {
        let valid = AuthFixture::new(1209);
        let mut expired = valid.second_user(1210);
        expired.base.state_expiry = 400;
        expired.refresh_state(expired.base.prime);
        let policies = ledger(&[&valid, &expired]);
        let registry = TrustedSnapshotRegistry::install(&[
            (&valid.base, valid.all_grants.as_slice()),
            (&expired.base, expired.all_grants.as_slice()),
        ])
        .unwrap();
        let compiled = compile_portfolio(&authority(&valid), &policies, &registry, 500).unwrap();
        assert_eq!(compiled.stats.ineligible_sources, 1);
        assert_eq!(compiled.stats.scanned_grants, valid.all_grants.len());
        assert!(!compiled.credentials.is_empty());

        // Eligibility must not bypass immutable publication integrity.
        expired.all_grants[0].signature = Default::default();
        expired.refresh_state(expired.base.prime);
        let bad_registry = TrustedSnapshotRegistry::install(&[
            (&valid.base, valid.all_grants.as_slice()),
            (&expired.base, expired.all_grants.as_slice()),
        ])
        .unwrap();
        assert!(compile_portfolio(&authority(&valid), &policies, &bad_registry, 500).is_err());
    }

    #[test]
    fn terminal_binding_covers_complete_q_header_params_and_proof() {
        let fixture = AuthFixture::new(1207);
        let circuit = fixture.circuit_for("Q");
        let params_digest = [3u8; 32];
        let header_digest = [4u8; 32];
        let proof = b"synthetic-anonymous-proof";
        let signature = terminal_sign_showing(
            &circuit,
            &fixture.keys[5].1,
            &params_digest,
            &header_digest,
            &circuit.request.fields,
            proof,
        )
        .unwrap();
        assert!(terminal_verify_showing(
            &circuit,
            &fixture.keys[5].0,
            &signature,
            &params_digest,
            &header_digest,
            &circuit.request.fields,
            proof,
        )
        .unwrap());
        assert!(!terminal_verify_showing(
            &circuit,
            &fixture.keys[5].0,
            &signature,
            &params_digest,
            &header_digest,
            &circuit.request.fields,
            b"substituted-proof",
        )
        .unwrap());
        let mut substituted_q = circuit.request.fields;
        substituted_q[10] += Fr::one();
        assert!(!terminal_verify_showing(
            &circuit,
            &fixture.keys[5].0,
            &signature,
            &params_digest,
            &header_digest,
            &substituted_q,
            proof,
        )
        .unwrap());
    }
}
