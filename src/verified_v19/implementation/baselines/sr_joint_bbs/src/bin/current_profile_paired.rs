#![recursion_limit = "256"]

use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_ff::{PrimeField, Zero};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, seq::SliceRandom, SeedableRng};
use base64::{engine::general_purpose::STANDARD, Engine};
use hrada_sr_full_f_bbs::{
    encode_complete_q, present, verify, AtomicCredential, Issuer, PublicCredentialFields,
    RequestContext, Showing,
};
use plan_a_joint_circuit::{
    contract::{Entitlement, Grant, Request, Snapshot, UserState},
    fixture,
    indexed_revocation::IndexedRevocationTree,
    joint::{grant_digest, snapshot_digest, JointCircuit},
    merkle::{build_tree, leaf_hash, path_for, MerklePath},
    plain::verify_plain,
    poseidon::{canonical_le_bytes, hash, Domain},
    signature::{
        encode_signature, public_key, sign, verify as verify_signature, SecretKey, Signature,
    },
    state_registry::{update_digest, StateLeafOpening},
    Fr,
};
use plan_a_sr_joint_bbs::{compile_timed, CompileTimings, Compiled};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    time::Instant,
};

const LMAX: usize = 3;
const ACTUAL: usize = 2;
const STATE_DEPTH: usize = 10;
const RA_DEPTH: usize = 10;
const REV_DEPTH: usize = 32;
const GRANT_DEPTH: usize = 3;
const POPULATION: usize = 16;
const ISSUER_SEED: u64 = 0x5352_4355_5252_454e;
const SCHEDULE_SEED: u64 = 20_261_024;

fn fh(x: Fr) -> String {
    let mut b = canonical_le_bytes(x);
    b.reverse();
    hex::encode(b)
}

fn compressed<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut out = Vec::new();
    x.serialize_compressed(&mut out).unwrap();
    out
}

fn path_json(path: &MerklePath) -> Value {
    json!({
        "siblings": path.siblings.iter().copied().map(fh).collect::<Vec<_>>(),
        "directions": path.directions,
    })
}

fn entitlement_leaf(e: &Entitlement) -> Fr {
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

fn state_leaf(s: &UserState) -> Fr {
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

fn rekey_two_grants(
    c: &mut JointCircuit<LMAX>,
    owner: &SecretKey,
    delegate: &SecretKey,
    terminal: &SecretKey,
    serial_base: u64,
    seed: u64,
) {
    let owner_pk = public_key(owner).unwrap();
    let delegate_pk = public_key(delegate).unwrap();
    let terminal_pk = public_key(terminal).unwrap();
    let keys = [owner, delegate];
    let issuers = [owner_pk.clone(), delegate_pk.clone()];
    let subjects = [delegate_pk, terminal_pk.clone()];
    let mut parent = Fr::zero();
    for i in 0..ACTUAL {
        let grant = &mut c.grants[i].grant;
        grant.issuer = issuers[i].clone();
        grant.subject = subjects[i].clone();
        grant.serial = Fr::from(serial_base + i as u64);
        grant.parent_digest = parent;
        let digest = grant_digest(grant);
        grant.signature = sign(keys[i], digest, [seed as u8 ^ (0x31 + i as u8); 32]).unwrap();
        parent = digest;
    }
    let root_leaf = leaf_hash(Domain::GrantLeaf, &[grant_digest(&c.grants[0].grant)]);
    let (grant_root, levels) = build_tree(vec![root_leaf], GRANT_DEPTH, Domain::TreeNode).unwrap();
    c.state.grant_root = grant_root;
    c.grants[0].grant_path = path_for(&levels, 0).unwrap();
    c.request.terminal = terminal_pk;
}

#[derive(Clone)]
struct TrialFixture {
    sources: [JointCircuit<LMAX>; 2],
    secrets: [SecretKey; 5],
    registry_secret: SecretKey,
    database_rows: Vec<DatabaseRow>,
    public_ra_leaves: Vec<Fr>,
    public_state_leaves: Vec<Fr>,
    public_rev_leaf_count: usize,
    rev_tree: IndexedRevocationTree,
}

#[derive(Clone)]
struct DatabaseRow {
    ra_position: usize,
    state_position: usize,
    owner_secret: SecretKey,
    registration_salt: Fr,
    entitlement: Entitlement,
    state: UserState,
    admission_message: Fr,
    admission_signature: Signature,
    ra_signature: Signature,
    owner_update_expected_version: Option<u64>,
    owner_update_message: Option<Fr>,
    owner_update_signature: Option<Signature>,
}

fn admission_message(row: &DatabaseRow) -> Fr {
    hash(
        Domain::StateUpdate,
        &[
            Fr::from(0u64),
            Fr::from(9u64),
            row.state.owner_commitment,
            Fr::from(row.state.position),
            Fr::from(row.state.state_expiry),
            Fr::from(row.state.state_version),
            Fr::from(row.state.state_epoch),
            row.state.grant_root,
            Fr::from(row.state.state_expiry),
            Fr::from(row.state.active as u64),
            row.state.salt,
        ],
    )
}

fn sign_database_row(row: &mut DatabaseRow, registry_secret: &SecretKey, aux: u8) {
    row.admission_message = admission_message(row);
    row.admission_signature = sign(registry_secret, row.admission_message, [aux; 32]).unwrap();
    row.ra_signature = sign(
        registry_secret,
        entitlement_leaf(&row.entitlement),
        [aux ^ 0x55; 32],
    )
    .unwrap();
}

fn recompute_public_roots(fixture: &mut TrialFixture) {
    let mut ra_leaves = vec![Fr::zero(); 1usize << RA_DEPTH];
    let mut state_leaves = vec![Fr::zero(); 1usize << STATE_DEPTH];
    for row in &fixture.database_rows {
        ra_leaves[row.ra_position] = entitlement_leaf(&row.entitlement);
        state_leaves[row.state_position] = state_leaf(&row.state);
    }
    let (root_ra, ra_levels) = build_tree(ra_leaves.clone(), RA_DEPTH, Domain::TreeNode).unwrap();
    let (root_state, state_levels) =
        build_tree(state_leaves.clone(), STATE_DEPTH, Domain::TreeNode).unwrap();
    for (index, source) in fixture.sources.iter_mut().enumerate() {
        let row = &fixture.database_rows[index];
        source.entitlement.path = path_for(&ra_levels, row.ra_position).unwrap();
        source.state.path = path_for(&state_levels, row.state_position).unwrap();
        source.snapshot.root_ra = root_ra;
        source.snapshot.root_state = root_state;
        source.snapshot.root_rev = fixture.rev_tree.root();
    }
    fixture.public_ra_leaves = ra_leaves.into_iter().filter(|x| !x.is_zero()).collect();
    fixture.public_state_leaves = state_leaves.into_iter().filter(|x| !x.is_zero()).collect();
    fixture.public_rev_leaf_count = fixture.rev_tree.public_leaves().len();
}

fn build_fixture(seed: u64) -> TrialFixture {
    let scalars = [
        10_000 + seed * 100,
        10_001 + seed * 100,
        10_002 + seed * 100,
        10_003 + seed * 100,
        10_004 + seed * 100,
    ];
    let secrets = scalars.map(|x| SecretKey(Scalar::from(x)));
    let mut a = fixture::fixed::<LMAX>(ACTUAL, 70 + seed, STATE_DEPTH, RA_DEPTH, REV_DEPTH);
    let mut b = fixture::fixed::<LMAX>(ACTUAL, 70 + seed, STATE_DEPTH, RA_DEPTH, REV_DEPTH);
    a.registration_salt = Fr::from(91_000 + seed);
    b.registration_salt = Fr::from(92_000 + seed);
    rekey_two_grants(
        &mut a,
        &secrets[0],
        &secrets[1],
        &secrets[4],
        100_000 + seed * 100,
        seed,
    );
    rekey_two_grants(
        &mut b,
        &secrets[2],
        &secrets[3],
        &secrets[4],
        200_000 + seed * 100,
        seed + 17,
    );

    for (c, owner, admission, position, salt) in [
        (&mut a, &secrets[0], 44_000 + seed, 2u32, 82_000 + seed),
        (&mut b, &secrets[2], 45_000 + seed, 3u32, 83_000 + seed),
    ] {
        let pk = public_key(owner).unwrap();
        let owner_commitment = hash(Domain::Owner, &[pk.0.x, pk.0.y, c.registration_salt]);
        c.entitlement.owner_commitment = owner_commitment;
        c.entitlement.admission_id = Fr::from(admission);
        c.state.owner_commitment = owner_commitment;
        c.state.position = position;
        c.state.salt = Fr::from(salt);
        c.state.state_version = 1;
        c.state.state_epoch = 55 + seed;
        c.snapshot.state_epoch = 55 + seed;
        c.snapshot.tuple_version = 2;
        c.snapshot.issued_at = 90 + seed;
        c.request.canonical_request_lo = Fr::from(10_000 + seed);
        c.request.canonical_request_hi = Fr::from(20_000 + seed);
        c.request.nonce = Fr::from(70 + seed);
    }

    let background_positions = (0..(1usize << STATE_DEPTH))
        .filter(|x| *x != 2 && *x != 3)
        .take(POPULATION - 2)
        .collect::<Vec<_>>();
    let registry_secret = SecretKey(Scalar::from(900u64));
    let zero_signature = sign(&registry_secret, Fr::from(1u64), [1; 32]).unwrap();
    let mut database_rows = Vec::with_capacity(POPULATION);
    for (index, source) in [&a, &b].into_iter().enumerate() {
        database_rows.push(DatabaseRow {
            ra_position: index,
            state_position: source.state.position as usize,
            owner_secret: secrets[index * 2].clone(),
            registration_salt: source.registration_salt,
            entitlement: source.entitlement.clone(),
            state: source.state.clone(),
            admission_message: Fr::zero(),
            admission_signature: zero_signature.clone(),
            ra_signature: zero_signature.clone(),
            owner_update_expected_version: None,
            owner_update_message: None,
            owner_update_signature: None,
        });
    }
    for (offset, state_position) in background_positions.into_iter().enumerate() {
        let row_index = offset + 2;
        let owner_secret = SecretKey(Scalar::from(30_000 + seed * 1_000 + row_index as u64));
        let owner_pk = public_key(&owner_secret).unwrap();
        let registration_salt = Fr::from(130_000 + seed * 1_000 + row_index as u64);
        let owner_commitment = hash(
            Domain::Owner,
            &[owner_pk.0.x, owner_pk.0.y, registration_salt],
        );
        let entitlement = Entitlement {
            owner_commitment,
            resource: Fr::from(700u64),
            action_mask: 0b1_1111,
            interval_lo: 100,
            interval_hi: 300,
            permit_expiry: 300,
            admission_id: Fr::from(240_000 + seed * 1_000 + row_index as u64),
            path: MerklePath {
                siblings: vec![Fr::zero(); RA_DEPTH],
                directions: vec![false; RA_DEPTH],
            },
        };
        let state = UserState {
            owner_commitment,
            grant_root: hash(
                Domain::GrantLeaf,
                &[Fr::from(seed), Fr::from(row_index as u64)],
            ),
            state_version: 0,
            state_epoch: 55 + seed,
            state_expiry: 310,
            active: true,
            salt: Fr::from(340_000 + seed * 1_000 + row_index as u64),
            position: state_position as u32,
            path: MerklePath {
                siblings: vec![Fr::zero(); STATE_DEPTH],
                directions: vec![false; STATE_DEPTH],
            },
        };
        database_rows.push(DatabaseRow {
            ra_position: row_index,
            state_position,
            owner_secret,
            registration_salt,
            entitlement,
            state,
            admission_message: Fr::zero(),
            admission_signature: zero_signature.clone(),
            ra_signature: zero_signature.clone(),
            owner_update_expected_version: None,
            owner_update_message: None,
            owner_update_signature: None,
        });
    }
    for (index, row) in database_rows.iter_mut().enumerate() {
        sign_database_row(row, &registry_secret, 0x20 + index as u8);
    }
    let rev_tree = IndexedRevocationTree::new(REV_DEPTH).unwrap();
    for c in [&mut a, &mut b] {
        for slot in c.grants.iter_mut().take(ACTUAL) {
            slot.revocation = rev_tree.prove_nonmember(slot.grant.serial).unwrap();
        }
        c.snapshot.root_rev = rev_tree.root();
        c.snapshot.revocation_epoch = 9;
    }
    let mut fixture = TrialFixture {
        sources: [a, b],
        secrets,
        registry_secret,
        database_rows,
        public_ra_leaves: vec![],
        public_state_leaves: vec![],
        public_rev_leaf_count: 0,
        rev_tree,
    };
    recompute_public_roots(&mut fixture);
    let [a, b] = &fixture.sources;
    assert_eq!(
        verify_plain(
            &a.snapshot,
            &a.request,
            &a.entitlement,
            &a.state,
            a.registration_salt,
            &a.grants
        ),
        Ok(())
    );
    assert_eq!(
        verify_plain(
            &b.snapshot,
            &b.request,
            &b.entitlement,
            &b.state,
            b.registration_salt,
            &b.grants
        ),
        Ok(())
    );
    fixture
}

fn snapshot_json(s: &Snapshot) -> Value {
    json!({
        "tuple_version": s.tuple_version,
        "root_ra": fh(s.root_ra),
        "root_state": fh(s.root_state),
        "root_rev": fh(s.root_rev),
        "state_epoch": s.state_epoch,
        "revocation_epoch": s.revocation_epoch,
        "issued_at": s.issued_at,
        "snapshot_digest": fh(snapshot_digest(s)),
    })
}

fn request_json(r: &Request) -> Value {
    json!({
        "canonical_request_lo": fh(r.canonical_request_lo),
        "canonical_request_hi": fh(r.canonical_request_hi),
        "circuit_id": fh(r.circuit_id),
        "verifier_id": fh(r.verifier_id),
        "pep_id": fh(r.pep_id),
        "resource": fh(r.resource),
        "action_onehot": r.action_onehot,
        "interval_lo": r.interval_lo,
        "interval_hi": r.interval_hi,
        "time": r.time,
        "nonce": fh(r.nonce),
        "context": fh(r.context),
        "terminal": STANDARD.encode(compressed(&r.terminal.0)),
    })
}

fn grant_json(g: &Grant) -> Value {
    json!({
        "issuer": STANDARD.encode(compressed(&g.issuer.0)),
        "subject": STANDARD.encode(compressed(&g.subject.0)),
        "resource": fh(g.resource),
        "action_mask": g.action_mask,
        "interval_lo": g.interval_lo,
        "interval_hi": g.interval_hi,
        "not_before": g.not_before,
        "expiry": g.expiry,
        "depth_remaining": g.depth_remaining,
        "serial": fh(g.serial),
        "parent_digest": fh(g.parent_digest),
        "signature": STANDARD.encode(encode_signature(&g.signature)),
    })
}

fn source_json(c: &JointCircuit<LMAX>) -> Value {
    json!({
        "snapshot": snapshot_json(&c.snapshot),
        "request": request_json(&c.request),
        "registration_salt": fh(c.registration_salt),
        "entitlement": {
            "owner_commitment": fh(c.entitlement.owner_commitment),
            "resource": fh(c.entitlement.resource),
            "action_mask": c.entitlement.action_mask,
            "interval_lo": c.entitlement.interval_lo,
            "interval_hi": c.entitlement.interval_hi,
            "permit_expiry": c.entitlement.permit_expiry,
            "admission_id": fh(c.entitlement.admission_id),
            "path": path_json(&c.entitlement.path),
        },
        "state": {
            "owner_commitment": fh(c.state.owner_commitment),
            "grant_root": fh(c.state.grant_root),
            "state_version": c.state.state_version,
            "state_epoch": c.state.state_epoch,
            "state_expiry": c.state.state_expiry,
            "active": c.state.active,
            "salt": fh(c.state.salt),
            "position": c.state.position,
            "path": path_json(&c.state.path),
        },
        "grants": c.grants.iter().map(|slot| json!({
            "enabled": slot.enabled,
            "grant": grant_json(&slot.grant),
            "grant_path": path_json(&slot.grant_path),
            "revocation": {
                "predecessor_slot": slot.revocation.predecessor_slot,
                "predecessor": fh(slot.revocation.predecessor),
                "successor_slot": slot.revocation.successor_slot,
                "successor": fh(slot.revocation.successor),
                "path": path_json(&slot.revocation.path),
            }
        })).collect::<Vec<_>>(),
    })
}

fn secret_json(name: &str, sk: &SecretKey) -> Value {
    json!({"role": name, "scalar_b64": STANDARD.encode(compressed(&sk.0))})
}

fn database_row_json(row: &DatabaseRow) -> Value {
    json!({
        "ra_position": row.ra_position,
        "state_position": row.state_position,
        "owner_public_key_b64": STANDARD.encode(compressed(&public_key(&row.owner_secret).unwrap().0)),
        "registration_salt": fh(row.registration_salt),
        "entitlement": {
            "owner_commitment": fh(row.entitlement.owner_commitment),
            "resource": fh(row.entitlement.resource),
            "action_mask": row.entitlement.action_mask,
            "interval_lo": row.entitlement.interval_lo,
            "interval_hi": row.entitlement.interval_hi,
            "permit_expiry": row.entitlement.permit_expiry,
            "admission_id": fh(row.entitlement.admission_id),
        },
        "state_opening": {
            "owner_commitment": fh(row.state.owner_commitment),
            "grant_root": fh(row.state.grant_root),
            "state_version": row.state.state_version,
            "state_epoch": row.state.state_epoch,
            "state_expiry": row.state.state_expiry,
            "active": row.state.active,
            "salt": fh(row.state.salt),
            "position": row.state.position,
        },
        "registry_admission_message": fh(row.admission_message),
        "registry_admission_signature_b64": STANDARD.encode(encode_signature(&row.admission_signature)),
        "registry_ra_signature_b64": STANDARD.encode(encode_signature(&row.ra_signature)),
        "owner_update_expected_version": row.owner_update_expected_version,
        "owner_update_message": row.owner_update_message.map(fh),
        "owner_update_signature_b64": row.owner_update_signature.as_ref().map(|signature| STANDARD.encode(encode_signature(signature))),
    })
}

fn database_json(fixture: &TrialFixture, seed: u64, phase: &str, updates: usize) -> Value {
    json!({
        "format": "PLAN-A-SR-MATERIALIZED-DATABASE-V1",
        "synthetic_nonproduction_fixture": true,
        "seed": seed,
        "phase": phase,
        "background_update_batch": updates,
        "registry_public_key_b64": STANDARD.encode(compressed(&public_key(&fixture.registry_secret).unwrap().0)),
        "ra_count": fixture.database_rows.len(),
        "state_count": fixture.database_rows.len(),
        "revocation_count": fixture.rev_tree.public_leaves().len() - 2,
        "rows": fixture.database_rows.iter().map(database_row_json).collect::<Vec<_>>(),
        "revoked_serials": fixture.rev_tree.public_leaves().iter().skip(2).map(|leaf| fh(leaf.value)).collect::<Vec<_>>(),
    })
}

fn public_version_json(fixture: &TrialFixture) -> Value {
    let snapshot = &fixture.sources[0].snapshot;
    let message = hash(Domain::Terminal, &[snapshot_digest(snapshot)]);
    let signature = sign(&fixture.registry_secret, message, [0x72; 32]).unwrap();
    let registry_public = public_key(&fixture.registry_secret).unwrap();
    assert!(verify_signature(&registry_public, message, &signature));
    json!({
        "schema": "plan-a-sr-paired-public-version-v1",
        "snapshot": snapshot_json(snapshot),
        "header_signature_b64": STANDARD.encode(encode_signature(&signature)),
        "ra": fixture.database_rows.iter().map(|row| json!({
            "position": row.ra_position,
            "leaf": fh(entitlement_leaf(&row.entitlement)),
        })).collect::<Vec<_>>(),
        "state": fixture.database_rows.iter().map(|row| json!({
            "position": row.state_position,
            "leaf": fh(state_leaf(&row.state)),
        })).collect::<Vec<_>>(),
        "revocation": fixture.rev_tree.public_leaves().iter().map(|leaf| json!({
            "slot": leaf.slot,
            "value": fh(leaf.value),
            "next_slot": leaf.next_slot,
            "next": fh(leaf.next),
            "leaf": fh(leaf.leaf),
        })).collect::<Vec<_>>(),
    })
}

fn database_signatures_valid(fixture: &TrialFixture) -> bool {
    let registry_public = public_key(&fixture.registry_secret).unwrap();
    fixture.database_rows.iter().all(|row| {
        verify_signature(
            &registry_public,
            row.admission_message,
            &row.admission_signature,
        ) && verify_signature(
            &registry_public,
            entitlement_leaf(&row.entitlement),
            &row.ra_signature,
        ) && match (
            row.owner_update_expected_version,
            row.owner_update_message,
            row.owner_update_signature.as_ref(),
        ) {
            (None, None, None) => true,
            (Some(expected_version), Some(message), Some(signature)) => {
                let opening = StateLeafOpening {
                    grant_root: row.state.grant_root,
                    state_expiry: row.state.state_expiry,
                    active: row.state.active,
                    salt: row.state.salt,
                };
                let recomputed = update_digest(
                    Fr::from(9u64),
                    row.state.owner_commitment,
                    row.state.position,
                    expected_version,
                    row.state.state_epoch,
                    &opening,
                );
                message == recomputed
                    && row.state.state_version == expected_version + 1
                    && verify_signature(
                        &public_key(&row.owner_secret).unwrap(),
                        recomputed,
                        signature,
                    )
            }
            _ => false,
        }
    })
}

fn support_json(fixture: &TrialFixture, seed: u64, updates: usize) -> Value {
    json!({
        "format": "PLAN-A-SR-PAIRED-TWO-SOURCE-PRIVATE-BUNDLE-V1",
        "synthetic_nonproduction_fixture": true,
        "seed": seed,
        "updates": updates,
        "configuration": {
            "population": POPULATION,
            "lmax": LMAX,
            "actual_enabled_length": ACTUAL,
            "state_depth": STATE_DEPTH,
            "ra_depth": RA_DEPTH,
            "revocation_depth": REV_DEPTH,
            "grant_depth": GRANT_DEPTH,
        },
        "keys": [
            secret_json("owner_a", &fixture.secrets[0]),
            secret_json("delegate_a", &fixture.secrets[1]),
            secret_json("owner_b", &fixture.secrets[2]),
            secret_json("delegate_b", &fixture.secrets[3]),
            secret_json("shared_terminal", &fixture.secrets[4]),
        ],
        "sources": fixture.sources.iter().map(source_json).collect::<Vec<_>>(),
        "public_materialization_summary": {
            "ra_populated_rows": fixture.public_ra_leaves.len(),
            "state_populated_rows": fixture.public_state_leaves.len(),
            "revocation_public_leaf_count": fixture.public_rev_leaf_count,
        },
    })
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn limbs_le(bytes: [u8; 32]) -> (Fr, Fr) {
    (
        Fr::from_le_bytes_mod_order(&bytes[..16]),
        Fr::from_le_bytes_mod_order(&bytes[16..]),
    )
}

fn request_context(
    issuer: &Issuer,
    c: &JointCircuit<LMAX>,
    seed: u64,
    phase: &str,
    expected_public: &PublicCredentialFields,
) -> (RequestContext, String, String) {
    let header_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&snapshot_json(&c.snapshot)).unwrap()).into();
    let request_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&request_json(&c.request)).unwrap()).into();
    let deployment_digest: [u8; 32] = Sha256::digest(b"plan-a-paired-sr-deployment-v1").into();
    let (h0, h1) = limbs_le(header_digest);
    let (q5, q6) = limbs_le(request_digest);
    let (q12, q13) = limbs_le(deployment_digest);
    let verifier_nonce = seed * 100 + c.snapshot.tuple_version + u64::from(phase == "successor");
    let terminal_bytes = compressed(&c.request.terminal.0);
    let fields = [
        h0,
        h1,
        Fr::from(c.snapshot.tuple_version),
        Fr::from(expected_public.system),
        Fr::from(expected_public.circuit_version),
        q5,
        q6,
        Fr::from(expected_public.resource),
        Fr::from(expected_public.action_one_hot as u64),
        Fr::from(c.request.interval_lo),
        Fr::from(verifier_nonce),
        Fr::from(c.request.interval_hi),
        q12,
        q13,
        c.request.terminal.0.x,
        c.request.terminal.0.y,
    ];
    let complete_q = encode_complete_q(&fields).unwrap();
    let (mapped, mapped_public) = RequestContext::from_q16(
        complete_q,
        header_digest,
        issuer.params_digest().unwrap(),
        &terminal_bytes,
        verifier_nonce,
    )
    .unwrap();
    assert_eq!(&mapped_public, expected_public);
    assert_eq!(
        (mapped.tq, mapped.te),
        (c.request.interval_lo, c.request.interval_hi)
    );
    (
        mapped,
        hex::encode(header_digest),
        hex::encode(request_digest),
    )
}

fn measure_joint(
    joint_pk: &ProvingKey<Bls12_381>,
    joint_vk: &VerifyingKey<Bls12_381>,
    circuit: &JointCircuit<LMAX>,
    rng: &mut StdRng,
) -> (bool, u128, u128, Vec<u8>) {
    let inputs = fixture::public_inputs(circuit);
    let prove_started = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(joint_pk, circuit.clone(), rng).unwrap();
    let prove_ns = prove_started.elapsed().as_nanos();
    let verify_started = Instant::now();
    let accepted = Groth16::<Bls12_381>::verify(joint_vk, &inputs, &proof).unwrap();
    let verify_ns = verify_started.elapsed().as_nanos();
    (accepted, prove_ns, verify_ns, compressed(&proof))
}

struct InitialSrMeasurement {
    compiled: Compiled,
    stages: CompileTimings,
    credential: AtomicCredential,
    credential_bytes: Vec<u8>,
    showing: Showing,
    showing_bytes: Vec<u8>,
    issuance_ns: u128,
    show_ns: u128,
    verify_ns: u128,
    accepted: bool,
    header_digest: String,
    request_digest: String,
}

struct RefreshSrMeasurement {
    compiled: Compiled,
    stages: CompileTimings,
    credential_bytes: Vec<u8>,
    showing_bytes: Vec<u8>,
    fresh_old_credential_showing_bytes: Vec<u8>,
    reissuance_ns: u128,
    show_ns: u128,
    verify_ns: u128,
    accepted: bool,
    old_showing_rejected: bool,
    old_credential_fresh_showing_rejected: bool,
    header_digest: String,
    request_digest: String,
}

fn measure_initial_sr(
    issuer: &Issuer,
    prover: &hrada_sr_full_f_bbs::ProverParams,
    verifier: &hrada_sr_full_f_bbs::VerifierParams,
    sources: &[JointCircuit<LMAX>; 2],
    seed: u64,
    rng: &mut StdRng,
) -> InitialSrMeasurement {
    let (compiled, stages) = compile_timed(sources).unwrap();
    compiled.issuance.validate().unwrap();
    assert_eq!(
        (
            compiled.scanned_paths,
            compiled.valid_paths,
            compiled.invalid_paths
        ),
        (2, 2, 0)
    );
    assert_eq!(compiled.issuance.credentials.len(), 1);
    let input = &compiled.issuance.credentials[0];
    let public = input.public_fields().unwrap();
    let issue_started = Instant::now();
    let credential = issuer
        .issue(rng, public.clone(), input.not_before, input.upper())
        .unwrap();
    let issuance_ns = issue_started.elapsed().as_nanos();
    let credential_bytes = credential.canonical_bytes().unwrap();
    let (request, header_digest, request_digest) =
        request_context(issuer, &sources[0], seed, "initial", &public);
    let show_started = Instant::now();
    let showing = present(rng, prover, &credential, &request).unwrap();
    let show_ns = show_started.elapsed().as_nanos();
    let showing_bytes = showing.canonical_bytes().unwrap();
    let verify_started = Instant::now();
    let accepted = verify(rng, verifier, &public, &request, &showing).is_ok();
    let verify_ns = verify_started.elapsed().as_nanos();
    InitialSrMeasurement {
        compiled,
        stages,
        credential,
        credential_bytes,
        showing,
        showing_bytes,
        issuance_ns,
        show_ns,
        verify_ns,
        accepted,
        header_digest,
        request_digest,
    }
}

fn measure_refresh_sr(
    issuer: &Issuer,
    prover: &hrada_sr_full_f_bbs::ProverParams,
    verifier: &hrada_sr_full_f_bbs::VerifierParams,
    sources: &[JointCircuit<LMAX>; 2],
    seed: u64,
    old_credential: &AtomicCredential,
    old_showing: &Showing,
    rng: &mut StdRng,
) -> RefreshSrMeasurement {
    let (compiled, stages) = compile_timed(sources).unwrap();
    compiled.issuance.validate().unwrap();
    assert_eq!((compiled.valid_paths, compiled.invalid_paths), (1, 1));
    assert_eq!(compiled.issuance.credentials.len(), 1);
    let input = &compiled.issuance.credentials[0];
    let public = input.public_fields().unwrap();
    let issue_started = Instant::now();
    let credential = issuer
        .issue(rng, public.clone(), input.not_before, input.upper())
        .unwrap();
    let reissuance_ns = issue_started.elapsed().as_nanos();
    let credential_bytes = credential.canonical_bytes().unwrap();
    let (request, header_digest, request_digest) =
        request_context(issuer, &sources[0], seed, "successor", &public);
    let show_started = Instant::now();
    let showing = present(rng, prover, &credential, &request).unwrap();
    let show_ns = show_started.elapsed().as_nanos();
    let showing_bytes = showing.canonical_bytes().unwrap();
    let verify_started = Instant::now();
    let accepted = verify(rng, verifier, &public, &request, &showing).is_ok();
    let verify_ns = verify_started.elapsed().as_nanos();
    let old_showing_rejected = verify(rng, verifier, &public, &request, old_showing).is_err();
    let fresh_old = present(rng, prover, old_credential, &request).unwrap();
    let fresh_old_credential_showing_bytes = fresh_old.canonical_bytes().unwrap();
    let old_credential_fresh_showing_rejected =
        verify(rng, verifier, &public, &request, &fresh_old).is_err();
    RefreshSrMeasurement {
        compiled,
        stages,
        credential_bytes,
        showing_bytes,
        fresh_old_credential_showing_bytes,
        reissuance_ns,
        show_ns,
        verify_ns,
        accepted,
        old_showing_rejected,
        old_credential_fresh_showing_rejected,
        header_digest,
        request_digest,
    }
}

fn successor(mut fixture: TrialFixture, seed: u64, updates: usize) -> TrialFixture {
    for offset in 0..updates {
        let row_index = 2 + offset;
        let row = &mut fixture.database_rows[row_index];
        row.entitlement.admission_id += Fr::from(1_000_000u64 + offset as u64);
        row.ra_signature = sign(
            &fixture.registry_secret,
            entitlement_leaf(&row.entitlement),
            [0x80 + offset as u8; 32],
        )
        .unwrap();
        let expected_version = row.state.state_version;
        row.state.state_version += 1;
        row.state.state_epoch = 64 + seed;
        row.state.salt += Fr::from(2_000_000u64 + offset as u64);
        let opening = StateLeafOpening {
            grant_root: row.state.grant_root,
            state_expiry: row.state.state_expiry,
            active: row.state.active,
            salt: row.state.salt,
        };
        let owner_update_message = update_digest(
            Fr::from(9u64),
            row.state.owner_commitment,
            row.state.position,
            expected_version,
            row.state.state_epoch,
            &opening,
        );
        row.owner_update_message = Some(owner_update_message);
        row.owner_update_expected_version = Some(expected_version);
        row.owner_update_signature = Some(
            sign(
                &row.owner_secret,
                owner_update_message,
                [0xa0 + offset as u8; 32],
            )
            .unwrap(),
        );
        fixture
            .rev_tree
            .insert(Fr::from(500_000 + seed * 100 + offset as u64))
            .unwrap();
    }
    let revoked = fixture.sources[1].grants[1].grant.serial;
    fixture.rev_tree.insert(revoked).unwrap();
    for (source_index, c) in fixture.sources.iter_mut().enumerate() {
        for (grant_index, slot) in c.grants.iter_mut().take(ACTUAL).enumerate() {
            if source_index != 1 || grant_index != 1 {
                slot.revocation = fixture.rev_tree.prove_nonmember(slot.grant.serial).unwrap();
            }
        }
        c.snapshot.revocation_epoch += updates as u64 + 1;
        c.snapshot.tuple_version += 1;
        c.snapshot.issued_at += 1;
        c.snapshot.state_epoch = 64 + seed;
    }
    recompute_public_roots(&mut fixture);
    fixture
}

fn signed_grant_hash(g: &Grant) -> String {
    sha256(&serde_json::to_vec(&grant_json(g)).unwrap())
}

fn run_trial(
    issuer: &Issuer,
    prover: &hrada_sr_full_f_bbs::ProverParams,
    verifier: &hrada_sr_full_f_bbs::VerifierParams,
    joint_pk: &ProvingKey<Bls12_381>,
    joint_vk: &VerifyingKey<Bls12_381>,
    out: &Path,
    seed: u64,
    updates: usize,
    trial_order: usize,
) -> Value {
    let trial_seed = 0x5352_5452_4941_4c00u64 ^ (seed << 8) ^ updates as u64;
    let mut rng = StdRng::seed_from_u64(trial_seed);
    let build_started = Instant::now();
    let fixture = build_fixture(seed);
    let synthetic_fixture_and_private_records_build_ns = build_started.elapsed().as_nanos();
    let before_hashes = fixture
        .sources
        .iter()
        .flat_map(|c| c.grants.iter().take(ACTUAL))
        .map(|s| signed_grant_hash(&s.grant))
        .collect::<Vec<_>>();

    let support = support_json(&fixture, seed, updates);
    let support_bytes = serde_json::to_vec(&support).unwrap();
    let support_name = format!("PAIRED_PRIVATE_SOURCE_BUNDLE_N16_U{updates}_SEED{seed}.json");
    fs::write(out.join(&support_name), &support_bytes).unwrap();
    let initial_database_bytes =
        serde_json::to_vec(&database_json(&fixture, seed, "initial", 0)).unwrap();
    let initial_database_name = format!("MATERIALIZED_DB_INITIAL_N16_U{updates}_SEED{seed}.json");
    fs::write(out.join(&initial_database_name), &initial_database_bytes).unwrap();
    let initial_public_version_bytes = serde_json::to_vec(&public_version_json(&fixture)).unwrap();
    let initial_public_version_name =
        format!("PUBLIC_VERSION_INITIAL_N16_U{updates}_SEED{seed}.json");
    fs::write(
        out.join(&initial_public_version_name),
        &initial_public_version_bytes,
    )
    .unwrap();

    let scheme_order = if (seed + updates as u64) % 2 == 0 {
        "joint_then_sr"
    } else {
        "sr_then_joint"
    };
    let (joint_initial, initial_sr) = if scheme_order == "joint_then_sr" {
        let joint = measure_joint(joint_pk, joint_vk, &fixture.sources[0], &mut rng);
        let sr = measure_initial_sr(issuer, prover, verifier, &fixture.sources, seed, &mut rng);
        (joint, sr)
    } else {
        let sr = measure_initial_sr(issuer, prover, verifier, &fixture.sources, seed, &mut rng);
        let joint = measure_joint(joint_pk, joint_vk, &fixture.sources[0], &mut rng);
        (joint, sr)
    };
    let (
        joint_initial_accepted,
        joint_initial_prove_ns,
        joint_initial_verify_ns,
        joint_initial_proof_bytes,
    ) = joint_initial;
    let InitialSrMeasurement {
        compiled,
        stages: compile_stages,
        credential,
        credential_bytes,
        showing,
        showing_bytes,
        issuance_ns,
        show_ns,
        verify_ns,
        accepted: initial_accepted,
        header_digest: initial_header_digest,
        request_digest: exact_request_digest,
    } = initial_sr;
    let ledger_bytes = serde_json::to_vec(&compiled.dependencies).unwrap();

    let successor_started = Instant::now();
    let successor_fixture = successor(fixture.clone(), seed, updates);
    let registry_batch_root_rebuild_and_two_source_witness_refresh_ns =
        successor_started.elapsed().as_nanos();
    let successor_publish_started = Instant::now();
    let successor_public_version_bytes =
        serde_json::to_vec(&public_version_json(&successor_fixture)).unwrap();
    let header_signature_and_public_json_serialization_ns =
        successor_publish_started.elapsed().as_nanos();
    let successor_public_version_name =
        format!("PUBLIC_VERSION_SUCCESSOR_N16_U{updates}_SEED{seed}.json");
    fs::write(
        out.join(&successor_public_version_name),
        &successor_public_version_bytes,
    )
    .unwrap();
    let successor_database_bytes = serde_json::to_vec(&database_json(
        &successor_fixture,
        seed,
        "successor",
        updates,
    ))
    .unwrap();
    let successor_database_name =
        format!("MATERIALIZED_DB_SUCCESSOR_N16_U{updates}_SEED{seed}.json");
    fs::write(
        out.join(&successor_database_name),
        &successor_database_bytes,
    )
    .unwrap();
    let materialized_database_signatures_valid = database_signatures_valid(&successor_fixture);
    let successor_support = support_json(&successor_fixture, seed, updates);
    let successor_support_bytes = serde_json::to_vec(&successor_support).unwrap();
    let successor_support_name =
        format!("PAIRED_PRIVATE_SOURCE_BUNDLE_SUCCESSOR_N16_U{updates}_SEED{seed}.json");
    fs::write(out.join(&successor_support_name), &successor_support_bytes).unwrap();
    let after_hashes = successor_fixture
        .sources
        .iter()
        .flat_map(|c| c.grants.iter().take(ACTUAL))
        .map(|s| signed_grant_hash(&s.grant))
        .collect::<Vec<_>>();
    let a_valid = verify_plain(
        &successor_fixture.sources[0].snapshot,
        &successor_fixture.sources[0].request,
        &successor_fixture.sources[0].entitlement,
        &successor_fixture.sources[0].state,
        successor_fixture.sources[0].registration_salt,
        &successor_fixture.sources[0].grants,
    )
    .is_ok();
    let b_rejected = verify_plain(
        &successor_fixture.sources[1].snapshot,
        &successor_fixture.sources[1].request,
        &successor_fixture.sources[1].entitlement,
        &successor_fixture.sources[1].state,
        successor_fixture.sources[1].registration_salt,
        &successor_fixture.sources[1].grants,
    )
    .is_err();
    let (joint_successor, refresh_sr) = if scheme_order == "joint_then_sr" {
        let joint = measure_joint(joint_pk, joint_vk, &successor_fixture.sources[0], &mut rng);
        let sr = measure_refresh_sr(
            issuer,
            prover,
            verifier,
            &successor_fixture.sources,
            seed,
            &credential,
            &showing,
            &mut rng,
        );
        (joint, sr)
    } else {
        let sr = measure_refresh_sr(
            issuer,
            prover,
            verifier,
            &successor_fixture.sources,
            seed,
            &credential,
            &showing,
            &mut rng,
        );
        let joint = measure_joint(joint_pk, joint_vk, &successor_fixture.sources[0], &mut rng);
        (joint, sr)
    };
    let (
        joint_successor_accepted,
        joint_successor_prove_ns,
        joint_successor_verify_ns,
        joint_successor_proof_bytes,
    ) = joint_successor;
    let RefreshSrMeasurement {
        compiled: refreshed,
        stages: refresh_stages,
        credential_bytes: next_credential_bytes,
        showing_bytes: next_showing_bytes,
        fresh_old_credential_showing_bytes,
        reissuance_ns,
        show_ns: refresh_show_ns,
        verify_ns: refresh_verify_ns,
        accepted: fresh_successor_accepted,
        old_showing_rejected: old_showing_rejected_under_successor_context,
        old_credential_fresh_showing_rejected:
            old_credential_fresh_showing_rejected_by_successor_public,
        header_digest: successor_header_digest,
        request_digest: successor_request_digest,
    } = refresh_sr;
    let refresh_ledger_bytes = serde_json::to_vec(&refreshed.dependencies).unwrap();
    assert_eq!(exact_request_digest, successor_request_digest);

    let wallet = json!({
        "format": "PLAN-A-SR-PAIRED-EXPERIMENT-AUDIT-BUNDLE-V1",
        "synthetic_nonproduction_fixture": true,
        "paired_private_source_bundle_file": support_name,
        "paired_private_source_bundle_sha256": sha256(&support_bytes),
        "successor_paired_private_source_bundle_file": successor_support_name,
        "successor_paired_private_source_bundle_sha256": sha256(&successor_support_bytes),
        "materialized_database_file": successor_database_name,
        "materialized_database_sha256": sha256(&successor_database_bytes),
        "successor_public_version_file": successor_public_version_name,
        "successor_public_version_sha256": sha256(&successor_public_version_bytes),
        "compiler_private_dependency_ledger": compiled.dependencies,
        "joint_initial_proof_b64": STANDARD.encode(&joint_initial_proof_bytes),
        "credential_b64": STANDARD.encode(&credential_bytes),
        "showing_b64": STANDARD.encode(&showing_bytes),
        "old_credential_fresh_successor_showing_b64": STANDARD.encode(&fresh_old_credential_showing_bytes),
        "successor_private_dependency_ledger": refreshed.dependencies,
        "joint_successor_proof_b64": STANDARD.encode(&joint_successor_proof_bytes),
        "successor_credential_b64": STANDARD.encode(&next_credential_bytes),
        "successor_showing_b64": STANDARD.encode(&next_showing_bytes),
    });
    let wallet_bytes = serde_json::to_vec(&wallet).unwrap();
    let wallet_name = format!("EXPERIMENT_AUDIT_BUNDLE_N16_U{updates}_SEED{seed}.json");
    fs::write(out.join(&wallet_name), &wallet_bytes).unwrap();

    assert!(
        joint_initial_accepted
            && joint_successor_accepted
            && initial_accepted
            && a_valid
            && b_rejected
            && fresh_successor_accepted
            && materialized_database_signatures_valid
    );
    assert!(old_showing_rejected_under_successor_context);
    assert!(old_credential_fresh_showing_rejected_by_successor_public);
    assert_eq!(before_hashes, after_hashes);
    json!({
        "trial_order_index": trial_order,
        "seed": seed,
        "population": POPULATION,
        "updates": updates,
        "configuration": {
            "lmax": LMAX,
            "actual_enabled_length": ACTUAL,
            "state_depth": STATE_DEPTH,
            "ra_depth": RA_DEPTH,
            "revocation_depth": REV_DEPTH,
            "grant_depth": GRANT_DEPTH,
            "fixed_sr_parameter_set": true,
            "workload_seed_changes": ["owner_keys", "delegate_keys", "terminal_key", "records", "paths", "background_leaves", "revocation_witnesses", "issuance_and_showing_randomness"],
            "fresh_setup_per_trial": false,
            "scheme_order": scheme_order,
            "background_update_batch": updates,
            "target_support_revocations": 1,
            "materialized_database_signatures_valid": materialized_database_signatures_valid,
        },
        "correctness": {
            "initial_two_sources_native_valid": compiled.valid_paths == 2,
            "joint_initial_proof_accepted": joint_initial_accepted,
            "joint_successor_proof_accepted": joint_successor_accepted,
            "initial_sr_show_verify_accepted": initial_accepted,
            "successor_source_a_native_valid": a_valid,
            "successor_revoked_source_b_rejected": b_rejected,
            "fresh_successor_show_verify_accepted": fresh_successor_accepted,
            "old_showing_rejected_under_successor_context": old_showing_rejected_under_successor_context,
            "old_credential_fresh_showing_rejected_by_successor_public": old_credential_fresh_showing_rejected_by_successor_public,
            "canonical_q16_typed_mapping_valid": true,
            "exact_external_request_digest_unchanged": exact_request_digest == successor_request_digest,
            "signed_grant_bytes_unchanged": before_hashes == after_hashes,
            "initial_compiler_valid_paths": compiled.valid_paths,
            "initial_compiler_invalid_paths": compiled.invalid_paths,
            "successor_compiler_valid_paths": refreshed.valid_paths,
            "successor_compiler_invalid_paths": refreshed.invalid_paths,
            "materialized_ra_rows": successor_fixture.database_rows.len(),
            "materialized_state_rows": successor_fixture.database_rows.len(),
            "background_ra_updates": updates,
            "background_state_updates": updates,
            "background_revocations": updates,
            "target_support_revocations": 1,
            "materialized_database_signatures_valid": materialized_database_signatures_valid,
            "initial_header_digest": initial_header_digest,
            "successor_header_digest": successor_header_digest,
            "exact_external_request_digest": exact_request_digest,
        },
        "timings_ns": {
            "synthetic_fixture_and_private_records_build": synthetic_fixture_and_private_records_build_ns,
            "joint_initial_prove": joint_initial_prove_ns,
            "joint_initial_verify": joint_initial_verify_ns,
            "native_path_validation": compile_stages.native_path_validation_ns,
            "support_derivation": compile_stages.support_derivation_ns,
            "maximal_containment_dedup": compile_stages.maximal_containment_dedup_ns,
            "issuance": issuance_ns,
            "client_show": show_ns,
            "service_verify": verify_ns,
            "registry_batch_root_rebuild_and_two_source_witness_refresh": registry_batch_root_rebuild_and_two_source_witness_refresh_ns,
            "header_signature_and_public_json_serialization": header_signature_and_public_json_serialization_ns,
            "joint_successor_prove": joint_successor_prove_ns,
            "joint_successor_verify": joint_successor_verify_ns,
            "refresh_native_path_validation": refresh_stages.native_path_validation_ns,
            "refresh_support_derivation": refresh_stages.support_derivation_ns,
            "refresh_maximal_containment_dedup": refresh_stages.maximal_containment_dedup_ns,
            "reissuance": reissuance_ns,
            "refresh_client_show": refresh_show_ns,
            "refresh_service_verify": refresh_verify_ns,
        },
        "storage_bytes": {
            "paired_two_source_private_bundle": support_bytes.len(),
            "successor_paired_two_source_private_bundle": successor_support_bytes.len(),
            "initial_materialized_database": initial_database_bytes.len(),
            "successor_materialized_database": successor_database_bytes.len(),
            "initial_public_version": initial_public_version_bytes.len(),
            "successor_public_version": successor_public_version_bytes.len(),
            "joint_initial_proof": joint_initial_proof_bytes.len(),
            "joint_successor_proof": joint_successor_proof_bytes.len(),
            "compiler_private_dependency_ledger": ledger_bytes.len(),
            "credential_delivery": credential_bytes.len(),
            "showing": showing_bytes.len(),
            "old_credential_fresh_successor_showing": fresh_old_credential_showing_bytes.len(),
            "successor_private_dependency_ledger": refresh_ledger_bytes.len(),
            "successor_credential_delivery": next_credential_bytes.len(),
            "successor_showing": next_showing_bytes.len(),
            "experiment_audit_bundle": wallet_bytes.len(),
        },
        "files": {
            "paired_private_source_bundle": support_name,
            "successor_paired_private_source_bundle": successor_support_name,
            "initial_materialized_database": initial_database_name,
            "successor_materialized_database": successor_database_name,
            "initial_public_version": initial_public_version_name,
            "successor_public_version": successor_public_version_name,
            "experiment_audit_bundle": wallet_name,
        },
        "access_and_cost_accounting": {
            "compiler_access": "trusted compiler reads complete private source records and authenticated paths",
            "joint_holder_access": "exact paired signed public version retained; transport/download time is not measured here",
            "registry_materialize_publish": "measured in this exact paired workload; shared once and never charged per holder",
            "timing_boundaries": "fixture build includes synthetic keys, grants, signatures, dense trees and initial witnesses; successor rebuild includes registry batch, dense roots and both source witnesses; publication includes only header signature and public JSON serialization, excluding durable install, transaction and HTTP",
            "production_network_time": Value::Null,
        }
    })
}

fn args() -> (PathBuf, PathBuf, PathBuf) {
    let mut args = std::env::args().skip(1);
    let mut out = None;
    let mut joint_pk = None;
    let mut joint_vk = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => {
                out = Some(PathBuf::from(
                    args.next().expect("--out requires a directory"),
                ))
            }
            "--joint-pk" => {
                joint_pk = Some(PathBuf::from(
                    args.next().expect("--joint-pk requires a file"),
                ))
            }
            "--joint-vk" => {
                joint_vk = Some(PathBuf::from(
                    args.next().expect("--joint-vk requires a file"),
                ))
            }
            _ => panic!("unknown argument {arg}"),
        }
    }
    (
        out.expect("--out is required"),
        joint_pk.expect("--joint-pk is required"),
        joint_vk.expect("--joint-vk is required"),
    )
}

fn main() {
    let (out, joint_pk_path, joint_vk_path) = args();
    fs::create_dir_all(&out).unwrap();
    let joint_pk_raw = fs::read(&joint_pk_path).unwrap();
    let mut joint_pk_cursor = Cursor::new(&joint_pk_raw);
    let joint_pk = ProvingKey::<Bls12_381>::deserialize_compressed(&mut joint_pk_cursor).unwrap();
    assert_eq!(joint_pk_cursor.position(), joint_pk_raw.len() as u64);
    let joint_vk_raw = fs::read(&joint_vk_path).unwrap();
    let mut joint_vk_cursor = Cursor::new(&joint_vk_raw);
    let joint_vk = VerifyingKey::<Bls12_381>::deserialize_compressed(&mut joint_vk_cursor).unwrap();
    assert_eq!(joint_vk_cursor.position(), joint_vk_raw.len() as u64);
    let mut setup_rng = StdRng::seed_from_u64(ISSUER_SEED);
    let setup_started = Instant::now();
    let issuer = Issuer::generate(&mut setup_rng);
    let fixed_parameter_setup_ns = setup_started.elapsed().as_nanos();
    let prover = issuer.prover_params();
    let verifier = issuer.verifier_params();
    let prover_bytes = prover.canonical_bytes().unwrap();
    let verifier_bytes = verifier.canonical_bytes().unwrap();
    fs::write(out.join("SR_PROVER_PARAMS.bin"), &prover_bytes).unwrap();
    fs::write(out.join("SR_VERIFIER_PARAMS.bin"), &verifier_bytes).unwrap();

    let mut schedule = [1usize, 8]
        .into_iter()
        .flat_map(|updates| (1u64..=10).map(move |seed| (updates, seed)))
        .collect::<Vec<_>>();
    let mut schedule_rng = StdRng::seed_from_u64(SCHEDULE_SEED);
    schedule.shuffle(&mut schedule_rng);
    let trials = schedule
        .into_iter()
        .enumerate()
        .map(|(order, (updates, seed))| {
            run_trial(
                &issuer, &prover, &verifier, &joint_pk, &joint_vk, &out, seed, updates, order,
            )
        })
        .collect::<Vec<_>>();
    let result = json!({
        "schema": "plan-a-sr-current-profile-paired-v1",
        "status": "measured only when this binary runs on benchmark-host",
        "fixed_parameter_setup_ns": fixed_parameter_setup_ns,
        "fixed_parameter_setup_count": 1,
        "prover_parameter_bytes": prover_bytes.len(),
        "verifier_parameter_bytes": verifier_bytes.len(),
        "prover_parameter_sha256": sha256(&prover_bytes),
        "verifier_parameter_sha256": sha256(&verifier_bytes),
        "joint_proving_key_bytes": joint_pk_raw.len(),
        "joint_verifying_key_bytes": joint_vk_raw.len(),
        "joint_proving_key_sha256": sha256(&joint_pk_raw),
        "joint_verifying_key_sha256": sha256(&joint_vk_raw),
        "issuer_seed": ISSUER_SEED,
        "schedule_seed": SCHEDULE_SEED,
        "trial_count": trials.len(),
        "selected_configurations": [
            {"population": POPULATION, "updates": 1, "trials": 10},
            {"population": POPULATION, "updates": 8, "trials": 10},
        ],
        "trial_independence": "distinct deterministic workload keys, records, Merkle paths, revocation witnesses and proof randomness; one shared fixed SR parameter set; not fresh setups and not deployment-generalization",
        "trials": trials,
    });
    let bytes = serde_json::to_vec_pretty(&result).unwrap();
    fs::write(out.join("RESULT.json"), &bytes).unwrap();
    println!("{}", String::from_utf8(bytes).unwrap());
}
