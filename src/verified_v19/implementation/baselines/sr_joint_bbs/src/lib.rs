//! Honest-SR compiler from validated Joint paths to the existing BBS23-CDL backend.
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use hrada_sr_full_f_bbs::{
    AtomicCredentialInput, AtomicPermissionInput, CompilationKeyInput, CredentialIssuanceBatch,
};
use plan_a_joint_circuit::{joint::JointCircuit, plain::verify_plain, Fr};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;
use thiserror::Error;
pub mod current_public;
pub mod fixtures;
pub mod http_bridge;
pub mod portfolio;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Group {
    circuit_version: u64,
    tuple_version: u64,
    terminal: Vec<u8>,
    resource: u64,
    action: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dependency {
    pub source_index: usize,
    pub serials: Vec<String>,
    pub lower: u64,
    pub upper: u64,
    pub dominated_by: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Compiled {
    pub issuance: CredentialIssuanceBatch,
    pub dependencies: BTreeMap<String, Vec<Dependency>>,
    pub scanned_paths: usize,
    pub valid_paths: usize,
    pub invalid_paths: usize,
    pub exact_duplicates: usize,
    pub dominated: usize,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CompileTimings {
    pub native_path_validation_ns: u128,
    pub support_derivation_ns: u128,
    pub maximal_containment_dedup_ns: u128,
}
#[derive(Debug, Error)]
pub enum CompileError {
    #[error("invalid joint path {0}")]
    InvalidPath(usize),
    #[error("field is not canonical u64")]
    NotU64,
    #[error("empty interval")]
    EmptyInterval,
    #[error("portfolio paths do not share one exact atomic snapshot")]
    MixedSnapshot,
    #[error("portfolio paths do not share one full Joint circuit id")]
    MixedCircuit,
}

fn u64_field(x: Fr) -> Result<u64, CompileError> {
    let b = x.into_bigint().to_bytes_le();
    if b.iter().skip(8).any(|x| *x != 0) {
        return Err(CompileError::NotU64);
    }
    let mut lo = [0; 8];
    lo[..b.len().min(8)].copy_from_slice(&b[..b.len().min(8)]);
    Ok(u64::from_le_bytes(lo))
}
fn terminal_bytes<const L: usize>(c: &JointCircuit<L>) -> Vec<u8> {
    let mut b = Vec::new();
    c.request.terminal.0.serialize_compressed(&mut b).unwrap();
    b
}
fn id(group: &Group, lo: u64, hi: u64) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}",
        group.circuit_version,
        group.tuple_version,
        hex(&group.terminal),
        group.resource,
        group.action,
        lo,
        hi
    )
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|x| format!("{x:02x}")).collect()
}
fn maximal_intervals(distinct: &BTreeSet<(u64, u64)>) -> Vec<(u64, u64)> {
    let mut ordered = distinct.iter().copied().collect::<Vec<_>>();
    ordered.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| b.1.cmp(&a.1)));
    let mut maximum_upper = None;
    let mut maximal = Vec::new();
    for interval in ordered {
        if match maximum_upper {
            None => true,
            Some(upper) => interval.1 > upper,
        } {
            maximum_upper = Some(interval.1);
            maximal.push(interval);
        }
    }
    maximal
}

/// Compile only after independently validating every original Joint path.
/// Source identifiers and serials remain solely in the returned private ledger.
pub fn compile<const L: usize>(sources: &[JointCircuit<L>]) -> Result<Compiled, CompileError> {
    compile_inner(sources, None)
}

/// Run the same compiler while observing its three internal CPU stages.
/// The ordinary `compile` path does not read a clock or collect measurements.
pub fn compile_timed<const L: usize>(
    sources: &[JointCircuit<L>],
) -> Result<(Compiled, CompileTimings), CompileError> {
    let mut timings = CompileTimings::default();
    let compiled = compile_inner(sources, Some(&mut timings))?;
    Ok((compiled, timings))
}

fn compile_inner<const L: usize>(
    sources: &[JointCircuit<L>],
    mut timings: Option<&mut CompileTimings>,
) -> Result<Compiled, CompileError> {
    let first = sources.first().map(|c| c.snapshot.clone());
    let epoch = first.as_ref().map(|s| s.tuple_version).unwrap_or(0);
    if let Some(s) = first.as_ref() {
        if sources.iter().any(|c| {
            s.tuple_version != c.snapshot.tuple_version
                || s.root_ra != c.snapshot.root_ra
                || s.root_state != c.snapshot.root_state
                || s.root_rev != c.snapshot.root_rev
                || s.state_epoch != c.snapshot.state_epoch
                || s.revocation_epoch != c.snapshot.revocation_epoch
                || s.issued_at != c.snapshot.issued_at
        }) {
            return Err(CompileError::MixedSnapshot);
        }
    }
    let circuit_id = sources.first().map(|c| c.request.circuit_id);
    if sources
        .iter()
        .any(|c| Some(c.request.circuit_id) != circuit_id)
    {
        return Err(CompileError::MixedCircuit);
    }
    let mut grouped: BTreeMap<Group, Vec<(usize, u64, u64, Vec<String>)>> = BTreeMap::new();
    let (mut valid, mut invalid) = (0, 0);
    for (index, c) in sources.iter().enumerate() {
        let validation_start = timings.as_ref().map(|_| Instant::now());
        let enabled = c
            .grants
            .iter()
            .take_while(|s| s.enabled)
            .collect::<Vec<_>>();
        let mut lo = c.entitlement.interval_lo;
        let mut hi = c
            .entitlement
            .interval_hi
            .min(c.entitlement.permit_expiry)
            .min(c.state.state_expiry);
        for s in &enabled {
            lo = lo.max(s.grant.interval_lo).max(s.grant.not_before);
            hi = hi.min(s.grant.interval_hi).min(s.grant.expiry)
        }
        if lo > hi {
            return Err(CompileError::EmptyInterval);
        }
        // Compilation validates the whole support interval, independently of the
        // particular external request later shown to the BBS verifier.
        let mut validation_request = c.request.clone();
        validation_request.interval_lo = lo;
        validation_request.interval_hi = hi;
        validation_request.time = lo;
        let validation = verify_plain(
            &c.snapshot,
            &validation_request,
            &c.entitlement,
            &c.state,
            c.registration_salt,
            &c.grants,
        );
        if let (Some(start), Some(t)) = (validation_start, timings.as_deref_mut()) {
            t.native_path_validation_ns += start.elapsed().as_nanos();
        }
        if validation.is_err() {
            invalid += 1;
            continue;
        }
        valid += 1;
        let support_start = timings.as_ref().map(|_| Instant::now());
        // The legacy BBS backend exposes only a u64 circuit-version slot. This
        // adapter uses deployment registry value 1 after requiring the full Joint
        // circuit_id field to be identical across the portfolio.
        let group = Group {
            circuit_version: 1,
            tuple_version: epoch,
            terminal: terminal_bytes(c),
            resource: u64_field(c.request.resource)?,
            action: c.request.action_onehot,
        };
        grouped.entry(group).or_default().push((
            index,
            lo,
            hi,
            enabled
                .iter()
                .map(|s| format!("{:?}", s.grant.serial.into_bigint()))
                .collect(),
        ));
        if let (Some(start), Some(t)) = (support_start, timings.as_deref_mut()) {
            t.support_derivation_ns += start.elapsed().as_nanos();
        }
    }
    let mut credentials = Vec::new();
    let mut dependencies = BTreeMap::new();
    let (mut duplicates, mut dominated) = (0, 0);
    for (group, supports) in grouped {
        let dedup_start = timings.as_ref().map(|_| Instant::now());
        let distinct = supports.iter().map(|x| (x.1, x.2)).collect::<BTreeSet<_>>();
        duplicates += supports.len() - distinct.len();
        let maximal = maximal_intervals(&distinct);
        dominated += distinct.len() - maximal.len();
        for (lo, hi) in maximal {
            let authority = id(&group, lo, hi);
            let ledger = supports
                .iter()
                .filter(|x| lo <= x.1 && x.2 <= hi)
                .map(|x| Dependency {
                    source_index: x.0,
                    serials: x.3.clone(),
                    lower: x.1,
                    upper: x.2,
                    dominated_by: if (x.1, x.2) == (lo, hi) {
                        None
                    } else {
                        Some(authority.clone())
                    },
                })
                .collect();
            dependencies.insert(authority, ledger);
            credentials.push(AtomicCredentialInput {
                format: "HRADA-SR-F-ATOMIC-V1".into(),
                key: CompilationKeyInput {
                    system: 0,
                    circuit_version: group.circuit_version,
                    epoch: group.tuple_version,
                    terminal: group.terminal.clone(),
                    permission: AtomicPermissionInput {
                        resource: group.resource,
                        action: group.action,
                    },
                },
                not_before: lo,
                not_after_complement: u64::MAX - hi,
            });
        }
        if let (Some(start), Some(t)) = (dedup_start, timings.as_deref_mut()) {
            t.maximal_containment_dedup_ns += start.elapsed().as_nanos();
        }
    }
    credentials.sort_by_key(|c| {
        (
            c.key.circuit_version,
            c.key.epoch,
            c.key.permission.resource,
            c.key.permission.action,
            c.not_before,
            c.not_after_complement,
        )
    });
    Ok(Compiled {
        issuance: CredentialIssuanceBatch {
            format: "HRADA-SR-F-ISSUANCE-BATCH-V1".into(),
            epoch,
            credentials,
        },
        dependencies,
        scanned_paths: sources.len(),
        valid_paths: valid,
        invalid_paths: invalid,
        exact_duplicates: duplicates,
        dominated,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use plan_a_joint_circuit::{
        fixture,
        joint::grant_digest,
        merkle::{build_tree, leaf_hash, path_for},
        poseidon::{hash, Domain},
    };
    #[test]
    fn exact_duplicate_dedup_and_last_support() {
        let a = fixture::fixed::<3>(2, 9, 3, 3, 4);
        let two = compile(&[a.clone(), a.clone()]).unwrap();
        assert_eq!(two.issuance.credentials.len(), 1);
        assert_eq!(two.exact_duplicates, 1);
        assert_eq!(two.dependencies.values().next().unwrap().len(), 2);
        let one = compile(&[a]).unwrap();
        assert_eq!(one.issuance.credentials.len(), 1);
        assert_eq!(one.dependencies.values().next().unwrap().len(), 1);
        let empty = compile::<3>(&[]).unwrap();
        assert!(empty.issuance.credentials.is_empty());
    }
    fn common_snapshot_portfolio() -> [JointCircuit<3>; 2] {
        let mut wide = fixture::fixed::<3>(1, 9, 3, 3, 4);
        let mut narrow = fixture::fixed::<3>(2, 9, 3, 3, 4);
        let leaves = vec![
            leaf_hash(Domain::GrantLeaf, &[grant_digest(&wide.grants[0].grant)]),
            leaf_hash(Domain::GrantLeaf, &[grant_digest(&narrow.grants[0].grant)]),
        ];
        let (grant_root, levels) = build_tree(leaves, 3, Domain::TreeNode).unwrap();
        wide.grants[0].grant_path = path_for(&levels, 0).unwrap();
        narrow.grants[0].grant_path = path_for(&levels, 1).unwrap();
        for c in [&mut wide, &mut narrow] {
            c.state.grant_root = grant_root;
            let s = &c.state;
            let pos = s.position;
            let leaf = hash(
                Domain::StateLeaf,
                &[
                    s.owner_commitment,
                    s.grant_root,
                    Fr::from(s.state_version),
                    Fr::from(s.state_epoch),
                    Fr::from(s.state_expiry),
                    Fr::from(s.active as u64),
                    s.salt,
                    Fr::from(pos),
                ],
            );
            let mut state_leaves = vec![Fr::from(0u64); 8];
            state_leaves[pos as usize] = leaf;
            let (root, levels) = build_tree(state_leaves, 3, Domain::TreeNode).unwrap();
            c.snapshot.root_state = root;
            c.state.path = path_for(&levels, pos as usize).unwrap();
        }
        assert_eq!(wide.snapshot.root_state, narrow.snapshot.root_state);
        [wide, narrow]
    }
    #[test]
    fn contained_interval_is_dominated_not_unionized() {
        let [wide, narrow] = common_snapshot_portfolio();
        let c = compile(&[wide, narrow]).unwrap();
        assert_eq!(c.issuance.credentials.len(), 1);
        assert_eq!(c.dominated, 1);
        assert_eq!(c.issuance.credentials[0].not_before, 100);
        assert_eq!(c.issuance.credentials[0].upper(), 300);
        assert_eq!(c.dependencies.values().next().unwrap().len(), 2);
    }
    #[test]
    fn same_terminal_but_mixed_snapshot_rejects() {
        let wide = fixture::fixed::<3>(1, 9, 3, 3, 4);
        let mut narrow = wide.clone();
        narrow.snapshot.tuple_version += 1;
        assert!(matches!(
            compile(&[wide, narrow]),
            Err(CompileError::MixedSnapshot)
        ));
    }
    #[test]
    fn two_distinct_sources_share_snapshot_and_survive_one_source_revocation() {
        let [a, b] = crate::fixtures::two_source_same_terminal();
        let both = compile(&[a.clone(), b.clone()]).unwrap();
        assert_eq!(both.issuance.credentials.len(), 1);
        assert_eq!(both.dependencies.values().next().unwrap().len(), 2);
        let successor = crate::fixtures::revoke_source_b(a, b);
        let after = compile(&successor).unwrap();
        assert_eq!(after.valid_paths, 1);
        assert_eq!(after.invalid_paths, 1);
        assert_eq!(after.issuance.credentials.len(), 1);
        assert_eq!(after.dependencies.values().next().unwrap().len(), 1);
    }
    #[test]
    fn offline_child_requires_new_compiled_terminal_atom() {
        let (initial, child) = crate::fixtures::offline_child_to_new_terminal();
        let old = compile(&[initial]).unwrap();
        let recovered = compile(&[child]).unwrap();
        assert_eq!(old.issuance.credentials.len(), 1);
        assert_eq!(recovered.issuance.credentials.len(), 1);
        assert_ne!(
            old.issuance.credentials[0].key.terminal,
            recovered.issuance.credentials[0].key.terminal
        );
    }
    #[test]
    fn sorted_linear_maxima_matches_exhaustive_naive_oracle() {
        let universe = (0u64..=3)
            .flat_map(|lo| (lo..=3).map(move |hi| (lo, hi)))
            .collect::<Vec<_>>();
        for mask in 0usize..(1usize << universe.len()) {
            let distinct = universe
                .iter()
                .enumerate()
                .filter_map(|(i, x)| (mask & (1usize << i) != 0).then_some(*x))
                .collect::<BTreeSet<_>>();
            let expected = distinct
                .iter()
                .copied()
                .filter(|candidate| {
                    !distinct.iter().any(|other| {
                        other != candidate && other.0 <= candidate.0 && candidate.1 <= other.1
                    })
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(
                maximal_intervals(&distinct)
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                expected,
                "mask={mask}"
            );
        }
    }
}
