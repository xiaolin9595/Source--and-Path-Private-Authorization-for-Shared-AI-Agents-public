//! Fixed-shape fixtures. Deep trees are constructed sparsely in O(depth).
use crate::{
    contract::*,
    indexed_revocation::{
        derive_serial, revoke_by_capability, IndexedRevocationTree, NonMembershipWitness,
    },
    joint::{grant_digest, request_digest, snapshot_digest, JointCircuit},
    merkle::{build_tree, leaf_hash, node_hash, path_for, MerklePath},
    poseidon::{hash, Domain},
    signature::{public_key, sign, PublicKey, SecretKey, Signature},
    Fr,
};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as Scalar};
use ark_ff::Zero;
use sha2::{Digest, Sha256};

fn zeros(depth: usize) -> MerklePath {
    MerklePath {
        siblings: vec![Fr::zero(); depth],
        directions: vec![false; depth],
    }
}

/// Root and path for one nonzero leaf in an otherwise raw-zero leaf array.
fn sparse_singleton(leaf: Fr, mut index: u32, depth: usize, domain: Domain) -> (Fr, MerklePath) {
    assert!(depth <= 32 && (index as u64) < (1u64 << depth));
    let mut defaults = vec![Fr::zero()];
    for i in 0..depth {
        defaults.push(node_hash(domain, defaults[i], defaults[i]));
    }
    let mut current = leaf;
    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    for level in 0..depth {
        let right = index & 1 == 1;
        siblings.push(defaults[level]);
        directions.push(right);
        current = if right {
            node_hash(domain, defaults[level], current)
        } else {
            node_hash(domain, current, defaults[level])
        };
        index >>= 1;
    }
    (
        current,
        MerklePath {
            siblings,
            directions,
        },
    )
}

fn disabled(grant_depth: usize, rev_depth: usize) -> Slot {
    Slot {
        enabled: false,
        grant: Grant {
            issuer: PublicKey(EdwardsAffine::zero()),
            subject: PublicKey(EdwardsAffine::zero()),
            resource: Fr::zero(),
            action_mask: 0,
            interval_lo: 0,
            interval_hi: 0,
            not_before: 0,
            expiry: 0,
            depth_remaining: 0,
            serial: Fr::zero(),
            parent_digest: Fr::zero(),
            signature: Signature {
                r: EdwardsAffine::zero(),
                s: Scalar::zero(),
            },
        },
        grant_path: zeros(grant_depth),
        revocation: NonMembershipWitness {
            predecessor_slot: 0,
            predecessor: Fr::zero(),
            successor_slot: 0,
            successor: Fr::zero(),
            path: zeros(rev_depth),
        },
    }
}

pub fn fixed<const L: usize>(
    active: usize,
    nonce: u64,
    state_depth: usize,
    ra_depth: usize,
    rev_depth: usize,
) -> JointCircuit<L> {
    assert!((1..=5).contains(&L) && (1..=L).contains(&active));
    assert!(
        (2..=32).contains(&state_depth)
            && (1..=32).contains(&ra_depth)
            && (1..=32).contains(&rev_depth)
    );
    let keys = (0..=L)
        .map(|i| SecretKey(Scalar::from(11u64 + i as u64)))
        .collect::<Vec<_>>();
    let pks = keys
        .iter()
        .map(|k| public_key(k).unwrap())
        .collect::<Vec<_>>();
    let registration_salt = Fr::from(91u64);
    let owner = hash(Domain::Owner, &[pks[0].0.x, pks[0].0.y, registration_salt]);

    let mut entitlement = Entitlement {
        owner_commitment: owner,
        resource: Fr::from(700u64),
        action_mask: 0b1_1111,
        interval_lo: 100,
        interval_hi: 300,
        permit_expiry: 300,
        admission_id: Fr::from(44u64),
        path: zeros(ra_depth),
    };
    let ent_leaf = hash(
        Domain::RaLeaf,
        &[
            owner,
            entitlement.resource,
            Fr::from(entitlement.action_mask as u64),
            Fr::from(entitlement.interval_lo),
            Fr::from(entitlement.interval_hi),
            Fr::from(entitlement.permit_expiry),
            entitlement.admission_id,
        ],
    );
    let (ra_root, ent_path) = sparse_singleton(ent_leaf, 0, ra_depth, Domain::TreeNode);
    entitlement.path = ent_path;

    let rev = IndexedRevocationTree::new(rev_depth).unwrap();
    let mut slots = Vec::with_capacity(L);
    let mut parent = Fr::zero();
    for i in 0..active {
        let mut grant = Grant {
            issuer: if i == 0 {
                pks[0].clone()
            } else {
                pks[L].clone()
            },
            subject: pks[L].clone(),
            resource: entitlement.resource,
            action_mask: 0b1_1111 >> i,
            interval_lo: 100 + i as u64,
            interval_hi: 300 - i as u64,
            not_before: 100 + i as u64,
            expiry: 300 - i as u64,
            depth_remaining: (L - i) as u8,
            serial: Fr::from(1000u64 + i as u64),
            parent_digest: parent,
            signature: Signature {
                r: EdwardsAffine::zero(),
                s: Scalar::zero(),
            },
        };
        let digest = grant_digest(&grant);
        grant.signature = sign(
            if i == 0 { &keys[0] } else { &keys[L] },
            digest,
            [31 + i as u8; 32],
        )
        .unwrap();
        parent = digest;
        slots.push(Slot {
            enabled: true,
            grant,
            grant_path: zeros(3),
            revocation: rev.prove_nonmember(Fr::from(1000u64 + i as u64)).unwrap(),
        });
    }
    while slots.len() < L {
        slots.push(disabled(3, rev_depth));
    }
    let grant_leaf = hash(Domain::GrantLeaf, &[grant_digest(&slots[0].grant)]);
    let (grant_root, grant_path) = sparse_singleton(grant_leaf, 0, 3, Domain::TreeNode);
    slots[0].grant_path = grant_path;

    let position = 2u32;
    let mut state = UserState {
        owner_commitment: owner,
        grant_root,
        state_version: 0,
        state_epoch: 55,
        state_expiry: 310,
        active: true,
        salt: Fr::from(82u64),
        position,
        path: zeros(state_depth),
    };
    let state_leaf = hash(
        Domain::StateLeaf,
        &[
            state.owner_commitment,
            state.grant_root,
            Fr::from(state.state_version),
            Fr::from(state.state_epoch),
            Fr::from(state.state_expiry),
            Fr::from(1u64),
            state.salt,
            Fr::from(position),
        ],
    );
    let (state_root, state_path) =
        sparse_singleton(state_leaf, position, state_depth, Domain::TreeNode);
    state.path = state_path;
    let snapshot = Snapshot {
        tuple_version: 1,
        root_ra: ra_root,
        root_state: state_root,
        root_rev: rev.root(),
        state_epoch: 55,
        revocation_epoch: 9,
        issued_at: 90,
    };
    let descriptor: [u8; 32] = Sha256::digest(crate::poseidon::descriptor().as_bytes()).into();
    let dlo = Fr::from(u128::from_be_bytes(descriptor[..16].try_into().unwrap()));
    let dhi = Fr::from(u128::from_be_bytes(descriptor[16..].try_into().unwrap()));
    let config_id = hash(
        Domain::Request,
        &[
            Fr::from(1u64),
            Fr::from(L as u64),
            Fr::from(state_depth as u64),
            Fr::from(ra_depth as u64),
            Fr::from(rev_depth as u64),
            Fr::from(3u64),
            dlo,
            dhi,
            Fr::from(1u64),
        ],
    );
    let request = Request {
        canonical_request_lo: Fr::from(123u64 + nonce),
        canonical_request_hi: Fr::from(456u64),
        circuit_id: config_id,
        verifier_id: Fr::from(78u64),
        pep_id: Fr::from(79u64),
        resource: entitlement.resource,
        action_onehot: 1,
        interval_lo: 120,
        interval_hi: 200,
        time: 150,
        nonce: Fr::from(nonce),
        context: Fr::from(80u64),
        terminal: pks[L].clone(),
    };
    JointCircuit {
        snapshot,
        request,
        entitlement,
        state,
        registration_salt,
        grants: slots.try_into().ok().unwrap(),
    }
}

pub fn l3(active: usize, nonce: u64) -> JointCircuit<3> {
    fixed::<3>(active, nonce, 3, 3, 4)
}

/// An admitted holder uses the unchanged root grant to delegate offline to a
/// terminal that had no credential when the snapshot was published.
pub fn offline_child_to_new_terminal() -> (JointCircuit<3>, JointCircuit<3>) {
    let initial = fixed::<3>(1, 88, 3, 3, 4);
    let mut child = initial.clone();
    let holder = SecretKey(Scalar::from(14u64));
    let terminal = SecretKey(Scalar::from(99u64));
    let root = &initial.grants[0].grant;
    let mut grant = root.clone();
    grant.issuer = public_key(&holder).unwrap();
    grant.subject = public_key(&terminal).unwrap();
    grant.action_mask >>= 1;
    grant.interval_lo += 1;
    grant.interval_hi -= 1;
    grant.not_before += 1;
    grant.expiry -= 1;
    grant.depth_remaining -= 1;
    grant.serial = Fr::from(9001u64);
    grant.parent_digest = grant_digest(root);
    grant.signature = sign(&holder, grant_digest(&grant), [99; 32]).unwrap();
    child.grants[1].enabled = true;
    child.grants[1].grant = grant;
    child.grants[1].revocation = IndexedRevocationTree::new(4)
        .unwrap()
        .prove_nonmember(Fr::from(9001u64))
        .unwrap();
    child.request.terminal = public_key(&terminal).unwrap();
    child.request.canonical_request_lo += Fr::from(1u64);
    child.request.nonce += Fr::from(1u64);
    assert_eq!(
        snapshot_digest(&child.snapshot),
        snapshot_digest(&initial.snapshot)
    );
    assert_eq!(
        grant_digest(&child.grants[0].grant),
        grant_digest(&initial.grants[0].grant)
    );
    (initial, child)
}

/// Benchmark H0 shared by the native Joint HTTP path and the SR compiler.
/// Both sources carry three real grants and share one complete snapshot,
/// terminal, resource, action and request interval.
pub fn two_source_same_terminal() -> [JointCircuit<3>; 2] {
    fn rebuild(c: &mut JointCircuit<3>, keys: &[SecretKey; 3], serial_base: u64) {
        let terminal = c.request.terminal.clone();
        let subjects = [
            public_key(&keys[1]).unwrap(),
            public_key(&keys[2]).unwrap(),
            terminal,
        ];
        let rev = IndexedRevocationTree::new(4).unwrap();
        let mut parent = Fr::zero();
        for i in 0..3 {
            let serial = {
                let g = &mut c.grants[i].grant;
                g.issuer = public_key(&keys[i]).unwrap();
                g.subject = subjects[i].clone();
                g.serial = Fr::from(serial_base + i as u64);
                g.parent_digest = parent;
                let d = grant_digest(g);
                g.signature = sign(&keys[i], d, [70 + i as u8; 32]).unwrap();
                parent = d;
                g.serial
            };
            c.grants[i].revocation = rev.prove_nonmember(serial).unwrap();
        }
        let leaf = leaf_hash(Domain::GrantLeaf, &[grant_digest(&c.grants[0].grant)]);
        let (root, levels) = build_tree(vec![leaf], 3, Domain::TreeNode).unwrap();
        c.state.grant_root = root;
        c.grants[0].grant_path = path_for(&levels, 0).unwrap();
    }
    fn ent(c: &JointCircuit<3>) -> Fr {
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
    fn state(c: &JointCircuit<3>) -> Fr {
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
    let mut a = fixed::<3>(3, 77, 3, 3, 4);
    let mut b = fixed::<3>(3, 77, 3, 3, 4);
    let ak = [
        SecretKey(Scalar::from(11u64)),
        SecretKey(Scalar::from(12u64)),
        SecretKey(Scalar::from(13u64)),
    ];
    let bk = [
        SecretKey(Scalar::from(21u64)),
        SecretKey(Scalar::from(22u64)),
        SecretKey(Scalar::from(23u64)),
    ];
    b.registration_salt = Fr::from(92u64);
    let ao = hash(
        Domain::Owner,
        &[
            public_key(&ak[0]).unwrap().0.x,
            public_key(&ak[0]).unwrap().0.y,
            a.registration_salt,
        ],
    );
    let bo = hash(
        Domain::Owner,
        &[
            public_key(&bk[0]).unwrap().0.x,
            public_key(&bk[0]).unwrap().0.y,
            b.registration_salt,
        ],
    );
    a.entitlement.owner_commitment = ao;
    a.state.owner_commitment = ao;
    b.entitlement.owner_commitment = bo;
    b.state.owner_commitment = bo;
    b.entitlement.admission_id = Fr::from(45u64);
    rebuild(&mut a, &ak, 1000);
    rebuild(&mut b, &bk, 2000);
    let (_, _, cap) = source_b_revocation_capability();
    b.grants[1].grant.serial = cap;
    let d1 = grant_digest(&b.grants[1].grant);
    b.grants[1].grant.signature = sign(&bk[1], d1, [88; 32]).unwrap();
    b.grants[2].grant.parent_digest = d1;
    let d2 = grant_digest(&b.grants[2].grant);
    b.grants[2].grant.signature = sign(&bk[2], d2, [89; 32]).unwrap();
    let rev = IndexedRevocationTree::new(4).unwrap();
    for s in b.grants.iter_mut() {
        s.revocation = rev.prove_nonmember(s.grant.serial).unwrap();
    }
    let (rr, rl) = build_tree(vec![ent(&a), ent(&b)], 3, Domain::TreeNode).unwrap();
    a.entitlement.path = path_for(&rl, 0).unwrap();
    b.entitlement.path = path_for(&rl, 1).unwrap();
    a.state.position = 2;
    b.state.position = 3;
    b.state.salt = Fr::from(83u64);
    let mut leaves = vec![Fr::zero(); 8];
    leaves[2] = state(&a);
    leaves[3] = state(&b);
    let (sr, sl) = build_tree(leaves, 3, Domain::TreeNode).unwrap();
    a.state.path = path_for(&sl, 2).unwrap();
    b.state.path = path_for(&sl, 3).unwrap();
    for c in [&mut a, &mut b] {
        c.snapshot.root_ra = rr;
        c.snapshot.root_state = sr;
    }
    [a, b]
}

/// Three distinct admitted owners under one snapshot and terminal.  This is
/// used only by the synthetic multi-owner MCP correctness gate.
pub fn three_source_same_terminal() -> [JointCircuit<3>; 3] {
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
    fn rebuild(c: &mut JointCircuit<3>, keys: &[SecretKey; 3], serial_base: u64) {
        let terminal = c.request.terminal.clone();
        let subjects = [
            public_key(&keys[1]).unwrap(),
            public_key(&keys[2]).unwrap(),
            terminal,
        ];
        let rev = IndexedRevocationTree::new(4).unwrap();
        let mut parent = Fr::zero();
        for i in 0..3 {
            let grant = &mut c.grants[i].grant;
            grant.issuer = public_key(&keys[i]).unwrap();
            grant.subject = subjects[i].clone();
            grant.serial = Fr::from(serial_base + i as u64);
            grant.parent_digest = parent;
            let digest = grant_digest(grant);
            grant.signature = sign(&keys[i], digest, [100 + i as u8; 32]).unwrap();
            parent = digest;
            c.grants[i].revocation = rev.prove_nonmember(grant.serial).unwrap();
        }
        let leaf = leaf_hash(Domain::GrantLeaf, &[grant_digest(&c.grants[0].grant)]);
        let (root, levels) = build_tree(vec![leaf], 3, Domain::TreeNode).unwrap();
        c.state.grant_root = root;
        c.grants[0].grant_path = path_for(&levels, 0).unwrap();
    }
    let [mut a, mut b] = two_source_same_terminal();
    let mut c = fixed::<3>(3, 77, 3, 3, 4);
    let ck = [
        SecretKey(Scalar::from(31u64)),
        SecretKey(Scalar::from(32u64)),
        SecretKey(Scalar::from(33u64)),
    ];
    c.registration_salt = Fr::from(93u64);
    let owner = hash(
        Domain::Owner,
        &[
            public_key(&ck[0]).unwrap().0.x,
            public_key(&ck[0]).unwrap().0.y,
            c.registration_salt,
        ],
    );
    c.entitlement.owner_commitment = owner;
    c.entitlement.admission_id = Fr::from(46u64);
    c.state.owner_commitment = owner;
    c.state.position = 4;
    c.state.salt = Fr::from(84u64);
    rebuild(&mut c, &ck, 3000);
    let (ra_root, ra_levels) = build_tree(
        vec![
            entitlement_leaf(&a),
            entitlement_leaf(&b),
            entitlement_leaf(&c),
        ],
        3,
        Domain::TreeNode,
    )
    .unwrap();
    a.entitlement.path = path_for(&ra_levels, 0).unwrap();
    b.entitlement.path = path_for(&ra_levels, 1).unwrap();
    c.entitlement.path = path_for(&ra_levels, 2).unwrap();
    let mut state_leaves = vec![Fr::zero(); 8];
    state_leaves[2] = state_leaf(&a);
    state_leaves[3] = state_leaf(&b);
    state_leaves[4] = state_leaf(&c);
    let (state_root, state_levels) = build_tree(state_leaves, 3, Domain::TreeNode).unwrap();
    a.state.path = path_for(&state_levels, 2).unwrap();
    b.state.path = path_for(&state_levels, 3).unwrap();
    c.state.path = path_for(&state_levels, 4).unwrap();
    for source in [&mut a, &mut b, &mut c] {
        source.snapshot.root_ra = ra_root;
        source.snapshot.root_state = state_root;
    }
    [a, b, c]
}

pub fn source_b_revocation_capability() -> ([u8; 32], u32, Fr) {
    let rk = [0x44; 32];
    let counter = 7;
    let sn = derive_serial(rk, counter).unwrap();
    (rk, counter, sn)
}

pub fn revoke_two_source_b(mut a: JointCircuit<3>, mut b: JointCircuit<3>) -> [JointCircuit<3>; 2] {
    let (rk, counter, serial) = source_b_revocation_capability();
    let mut rev = IndexedRevocationTree::new(4).unwrap();
    revoke_by_capability(&mut rev, rk, counter, serial).unwrap();
    for s in a.grants.iter_mut() {
        s.revocation = rev.prove_nonmember(s.grant.serial).unwrap();
    }
    for (i, s) in b.grants.iter_mut().enumerate() {
        if i != 1 {
            s.revocation = rev.prove_nonmember(s.grant.serial).unwrap();
        }
    }
    a.snapshot.root_rev = rev.root();
    b.snapshot.root_rev = rev.root();
    a.snapshot.tuple_version += 1;
    b.snapshot.tuple_version += 1;
    a.snapshot.revocation_epoch += 1;
    b.snapshot.revocation_epoch += 1;
    [a, b]
}

pub fn public_inputs<const L: usize>(c: &JointCircuit<L>) -> Vec<Fr> {
    let s = &c.snapshot;
    let r = &c.request;
    let sd = snapshot_digest(s);
    vec![
        Fr::from(s.tuple_version),
        s.root_ra,
        s.root_state,
        s.root_rev,
        Fr::from(s.state_epoch),
        Fr::from(s.revocation_epoch),
        Fr::from(s.issued_at),
        sd,
        r.canonical_request_lo,
        r.canonical_request_hi,
        r.circuit_id,
        r.verifier_id,
        r.pep_id,
        r.resource,
        Fr::from(r.action_onehot as u64),
        Fr::from(r.interval_lo),
        Fr::from(r.interval_hi),
        Fr::from(r.time),
        r.nonce,
        r.context,
        r.terminal.0.x,
        r.terminal.0.y,
        request_digest(r, sd),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381;
    use ark_groth16::Groth16;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
    use ark_std::rand::{rngs::StdRng, SeedableRng};
    #[test]
    fn l3_shapes_and_one_crs_multiple_requests_and_lengths() {
        let a = l3(1, 1);
        let b = l3(2, 2);
        let c = l3(3, 3);
        let mut shape = None;
        for x in [a.clone(), b.clone(), c.clone()] {
            let cs = ConstraintSystem::new_ref();
            x.generate_constraints(cs.clone()).unwrap();
            assert!(cs.is_satisfied().unwrap());
            let s = (
                cs.num_constraints(),
                cs.num_instance_variables(),
                cs.num_witness_variables(),
            );
            assert_eq!(shape.get_or_insert(s), &s);
        }
        let mut rng = StdRng::seed_from_u64(0x4c33);
        let (pk, vk) = Groth16::<Bls12_381>::setup(a.clone(), &mut rng).unwrap();
        for x in [a, b, c] {
            let proof = Groth16::<Bls12_381>::prove(&pk, x.clone(), &mut rng).unwrap();
            assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs(&x), &proof).unwrap());
        }
    }
}
