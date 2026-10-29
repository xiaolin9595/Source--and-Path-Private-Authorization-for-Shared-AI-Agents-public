//! Deterministic, genuinely distinct Joint portfolios for SR scale experiments.
//!
//! Every row has a different admitted owner and a separately signed root path,
//! while all rows share the exact authenticated snapshot, terminal, resource,
//! and one-hot action.  The successor revokes one real grant serial by its
//! capability; signed grant bytes are never rewritten during refresh.
use ark_ed_on_bls12_381::Fr as Scalar;
use plan_a_joint_circuit::{
    fixture,
    indexed_revocation::{derive_serial, revoke_by_capability, IndexedRevocationTree},
    joint::{grant_digest, JointCircuit},
    merkle::{build_tree, leaf_hash, path_for},
    poseidon::{hash, Domain},
    signature::{public_key, sign, SecretKey},
    Fr,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_PORTFOLIO: usize = 32;
pub const TREE_DEPTH: usize = 6;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntervalShape {
    Duplicate,
    Contained,
    Noncontained,
}

impl IntervalShape {
    pub fn label(self) -> &'static str {
        match self {
            Self::Duplicate => "duplicate",
            Self::Contained => "contained",
            Self::Noncontained => "noncontained",
        }
    }
}

#[derive(Clone)]
pub struct Portfolio {
    pub shape: IntervalShape,
    pub sources: Vec<JointCircuit<3>>,
    pub revocation_keys: Vec<[u8; 32]>,
    pub revocation_counters: Vec<u32>,
}

fn interval(shape: IntervalShape, index: usize) -> (u64, u64) {
    match shape {
        IntervalShape::Duplicate => (100, 300),
        IntervalShape::Contained => (100 + index as u64, 300 - index as u64),
        // Equal-width, shifted intervals overlap but none contains another.
        IntervalShape::Noncontained => (100 + 3 * index as u64, 207 + 3 * index as u64),
    }
}

fn entitlement_leaf(c: &JointCircuit<3>) -> Fr {
    let e = &c.entitlement;
    hash(
        Domain::RaLeaf,
        &[
            e.owner_commitment,
            e.resource,
            Fr::from(e.action_mask as u64),
            Fr::from(e.interval_lo),
            Fr::from(e.interval_hi),
            Fr::from(e.permit_expiry),
            e.admission_id,
        ],
    )
}

fn state_leaf(c: &JointCircuit<3>) -> Fr {
    let s = &c.state;
    hash(
        Domain::StateLeaf,
        &[
            s.owner_commitment,
            s.grant_root,
            Fr::from(s.state_version),
            Fr::from(s.state_epoch),
            Fr::from(s.state_expiry),
            Fr::from(s.active as u64),
            s.salt,
            Fr::from(s.position),
        ],
    )
}

pub fn build(size: usize, shape: IntervalShape) -> Portfolio {
    assert!(matches!(size, 2 | 8 | 32));
    let terminal_key = SecretKey(Scalar::from(0x5445_524du64));
    let terminal = public_key(&terminal_key).unwrap();
    let empty_revocation = IndexedRevocationTree::new(TREE_DEPTH).unwrap();
    let mut sources = Vec::with_capacity(size);
    let mut revocation_keys = Vec::with_capacity(size);
    let mut revocation_counters = Vec::with_capacity(size);

    for index in 0..size {
        let mut c = fixture::fixed::<3>(1, 77, TREE_DEPTH, TREE_DEPTH, TREE_DEPTH);
        let owner_key = SecretKey(Scalar::from(10_000u64 + index as u64));
        c.registration_salt = Fr::from(20_000u64 + index as u64);
        let owner_pk = public_key(&owner_key).unwrap();
        let owner = hash(
            Domain::Owner,
            &[owner_pk.0.x, owner_pk.0.y, c.registration_salt],
        );
        let (lo, hi) = interval(shape, index);
        c.entitlement.owner_commitment = owner;
        c.entitlement.admission_id = Fr::from(30_000u64 + index as u64);
        c.state.owner_commitment = owner;
        c.state.position = index as u32;
        c.state.salt = Fr::from(40_000u64 + index as u64);
        c.request.terminal = terminal.clone();
        c.request.interval_lo = lo;
        c.request.interval_hi = hi;
        c.request.time = lo;

        let rk = [0x40u8.wrapping_add(index as u8); 32];
        let counter = 100 + index as u32;
        let serial = derive_serial(rk, counter).unwrap();
        let g = &mut c.grants[0].grant;
        g.issuer = owner_pk;
        g.subject = terminal.clone();
        g.interval_lo = lo;
        g.interval_hi = hi;
        g.not_before = lo;
        g.expiry = hi;
        g.serial = serial;
        g.parent_digest = Fr::from(0u64);
        g.signature = sign(&owner_key, grant_digest(g), [index as u8 + 1; 32]).unwrap();
        c.grants[0].revocation = empty_revocation.prove_nonmember(serial).unwrap();
        let grant_leaf = leaf_hash(Domain::GrantLeaf, &[grant_digest(g)]);
        let (grant_root, grant_levels) = build_tree(vec![grant_leaf], 3, Domain::TreeNode).unwrap();
        c.state.grant_root = grant_root;
        c.grants[0].grant_path = path_for(&grant_levels, 0).unwrap();
        sources.push(c);
        revocation_keys.push(rk);
        revocation_counters.push(counter);
    }

    let ra_leaves = sources.iter().map(entitlement_leaf).collect::<Vec<_>>();
    let (ra_root, ra_levels) = build_tree(ra_leaves, TREE_DEPTH, Domain::TreeNode).unwrap();
    for (index, c) in sources.iter_mut().enumerate() {
        c.entitlement.path = path_for(&ra_levels, index).unwrap();
    }
    let mut state_leaves = vec![Fr::from(0u64); 1 << TREE_DEPTH];
    for c in &sources {
        state_leaves[c.state.position as usize] = state_leaf(c);
    }
    let (state_root, state_levels) =
        build_tree(state_leaves, TREE_DEPTH, Domain::TreeNode).unwrap();
    for c in &mut sources {
        c.state.path = path_for(&state_levels, c.state.position as usize).unwrap();
        c.snapshot.root_ra = ra_root;
        c.snapshot.root_state = state_root;
        c.snapshot.root_rev = empty_revocation.root();
    }
    Portfolio {
        shape,
        sources,
        revocation_keys,
        revocation_counters,
    }
}

pub fn revoke_support(portfolio: &Portfolio, source_index: usize) -> Vec<JointCircuit<3>> {
    assert!(source_index < portfolio.sources.len());
    let mut successor = portfolio.sources.clone();
    let serial = successor[source_index].grants[0].grant.serial;
    let mut revocation = IndexedRevocationTree::new(TREE_DEPTH).unwrap();
    revoke_by_capability(
        &mut revocation,
        portfolio.revocation_keys[source_index],
        portfolio.revocation_counters[source_index],
        serial,
    )
    .unwrap();
    for (index, c) in successor.iter_mut().enumerate() {
        if index != source_index {
            c.grants[0].revocation = revocation
                .prove_nonmember(c.grants[0].grant.serial)
                .unwrap();
        }
        c.snapshot.root_rev = revocation.root();
        c.snapshot.tuple_version += 1;
        c.snapshot.revocation_epoch += 1;
    }
    successor
}

pub fn unique_owner_count(sources: &[JointCircuit<3>]) -> usize {
    sources
        .iter()
        .map(|c| format!("{:?}", c.entitlement.owner_commitment))
        .collect::<BTreeSet<_>>()
        .len()
}

pub fn unique_signed_path_count(sources: &[JointCircuit<3>]) -> usize {
    sources
        .iter()
        .map(|c| format!("{:?}", grant_digest(&c.grants[0].grant)))
        .collect::<BTreeSet<_>>()
        .len()
}

/// The support whose removal exercises the defining refresh behavior.
pub fn revocation_target(shape: IntervalShape) -> usize {
    match shape {
        IntervalShape::Duplicate => 0,
        IntervalShape::Contained => 0,
        IntervalShape::Noncontained => 0,
    }
}
