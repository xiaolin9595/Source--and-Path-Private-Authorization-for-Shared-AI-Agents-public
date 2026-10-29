#![forbid(unsafe_code)]
//! Joint Lmax=2 fixtures constructed only from the shared typed manifest.

use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as Scalar};
use ark_ff::{PrimeField, Zero};
use plan_a_dac_fixed_wrapper::semantic_schema::{
    canonical_http_digest_limbs, manifest_sha256, CanonicalHttpRequest, RawGrant, SemanticManifest,
};
use plan_a_joint_circuit::{
    contract::{Entitlement, Grant, Request, Slot, Snapshot, UserState},
    indexed_revocation::{IndexedRevocationTree, NonMembershipWitness},
    joint::{grant_digest, JointCircuit},
    merkle::{build_tree, leaf_hash, path_for, MerklePath},
    poseidon::{hash, Domain},
    signature::{public_key, sign, PublicKey, SecretKey, Signature},
};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("matched Joint profile requires l_max=2")]
    Lmax,
    #[error("semantic update index is out of range")]
    UpdateIndex,
    #[error("invalid semantic manifest: {0}")]
    Manifest(&'static str),
    #[error("Joint fixture construction failed: {0}")]
    Joint(&'static str),
}

#[derive(Clone)]
pub struct JointActuals {
    pub semantic_input_sha256: String,
    pub actual1: JointCircuit<2>,
    pub actual2: JointCircuit<2>,
}

fn scalar(limbs: [u64; 2]) -> Fr {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&limbs[0].to_le_bytes());
    bytes[8..].copy_from_slice(&limbs[1].to_le_bytes());
    Fr::from_le_bytes_mod_order(&bytes)
}

fn zero_path(depth: usize) -> MerklePath {
    MerklePath {
        siblings: vec![Fr::zero(); depth],
        directions: vec![false; depth],
    }
}

fn disabled(grant_depth: usize, revocation_depth: usize) -> Slot {
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
        grant_path: zero_path(grant_depth),
        revocation: NonMembershipWitness {
            predecessor_slot: 0,
            predecessor: Fr::zero(),
            successor_slot: 0,
            successor: Fr::zero(),
            path: zero_path(revocation_depth),
        },
    }
}

fn keys(manifest: &SemanticManifest) -> Result<BTreeMap<u64, (SecretKey, PublicKey)>, BuildError> {
    let ids = [
        manifest.logical_ids.owner,
        manifest.logical_ids.delegate_a,
        manifest.logical_ids.delegate_b,
        manifest.logical_ids.terminal,
    ];
    if ids.into_iter().collect::<BTreeSet<_>>().len() != ids.len() {
        return Err(BuildError::Manifest("logical IDs are not distinct"));
    }
    ids.into_iter()
        .map(|id| {
            let secret = SecretKey(Scalar::from(id));
            let public = public_key(&secret).map_err(|_| BuildError::Joint("logical key"))?;
            Ok((id, (secret, public)))
        })
        .collect()
}

fn native_grant(
    raw: &RawGrant,
    parent_digest: Fr,
    keys: &BTreeMap<u64, (SecretKey, PublicKey)>,
) -> Result<Grant, BuildError> {
    let (issuer_secret, issuer) = keys
        .get(&raw.issuer)
        .ok_or(BuildError::Manifest("issuer ID"))?;
    let subject = &keys
        .get(&raw.subject)
        .ok_or(BuildError::Manifest("subject ID"))?
        .1;
    let mut grant = Grant {
        issuer: issuer.clone(),
        subject: subject.clone(),
        resource: Fr::from(raw.resource),
        action_mask: u16::try_from(raw.actions).map_err(|_| BuildError::Manifest("action mask"))?,
        interval_lo: raw.lo,
        interval_hi: raw.hi,
        not_before: raw.not_before,
        expiry: raw.expiry,
        depth_remaining: u8::try_from(raw.remaining_depth)
            .map_err(|_| BuildError::Manifest("depth"))?,
        serial: scalar(raw.serial),
        parent_digest,
        signature: Signature {
            r: EdwardsAffine::zero(),
            s: Scalar::zero(),
        },
    };
    grant.signature = sign(
        issuer_secret,
        grant_digest(&grant),
        [raw.serial[0] as u8; 32],
    )
    .map_err(|_| BuildError::Joint("grant signature"))?;
    Ok(grant)
}

/// Build the actual-depth 1 and 2 Joint witnesses for one installed update.
/// This function has no fallback to `fixture::fixed` or any L3 fixture.
pub fn build_joint_actuals(
    manifest: &SemanticManifest,
    update_index: usize,
    canonical_http: &CanonicalHttpRequest,
) -> Result<JointActuals, BuildError> {
    build_joint_actuals_bound(
        manifest,
        update_index,
        canonical_http_digest_limbs(canonical_http).map_err(BuildError::Manifest)?,
    )
}

/// Service-bound variant. `canonical_request_limbs` is the four little-endian
/// u64 limbs of SHA-256("plan-a-matched-http-v1\0" || canonical HTTP JSON).
pub fn build_joint_actuals_bound(
    manifest: &SemanticManifest,
    update_index: usize,
    canonical_request_limbs: [u64; 4],
) -> Result<JointActuals, BuildError> {
    build_joint_actuals_bound_nonce(
        manifest,
        update_index,
        canonical_request_limbs,
        manifest.request.nonce_u64,
    )
}
pub fn build_joint_actuals_bound_nonce(
    manifest: &SemanticManifest,
    update_index: usize,
    canonical_request_limbs: [u64; 4],
    nonce_u64: u64,
) -> Result<JointActuals, BuildError> {
    build_impl(
        manifest,
        update_index,
        canonical_request_limbs,
        nonce_u64,
        true,
    )
}

/// Build only the valid actual-depth-1 C path. This remains usable at t2 when
/// B is revoked and therefore cannot have a non-membership witness.
pub fn build_joint_actual1_bound(
    manifest: &SemanticManifest,
    update_index: usize,
    canonical_request_limbs: [u64; 4],
) -> Result<(String, JointCircuit<2>), BuildError> {
    build_joint_actual1_bound_nonce(
        manifest,
        update_index,
        canonical_request_limbs,
        manifest.request.nonce_u64,
    )
}
pub fn build_joint_actual1_bound_nonce(
    manifest: &SemanticManifest,
    update_index: usize,
    canonical_request_limbs: [u64; 4],
    nonce_u64: u64,
) -> Result<(String, JointCircuit<2>), BuildError> {
    let built = build_impl(
        manifest,
        update_index,
        canonical_request_limbs,
        nonce_u64,
        false,
    )?;
    Ok((built.semantic_input_sha256, built.actual1))
}

/// Build the A two-hop witness without exposing the selected chain on the
/// resident wire. The relabeling is internal and bijective: it reuses the same
/// typed manifest records, update ordering and public statement as the B/C
/// builders while selecting root-a -> child-a as the private witness.
pub fn build_joint_a_actual2_bound_nonce(
    manifest: &SemanticManifest,
    update_index: usize,
    canonical_request_limbs: [u64; 4],
    nonce_u64: u64,
) -> Result<JointCircuit<2>, BuildError> {
    let mut selected = manifest.clone();
    for grant in &mut selected.grants {
        grant.id = match grant.id.as_str() {
            "root-a" => "root-b",
            "root-b" => "root-a",
            "child-a" => "child-b",
            "child-b" => "child-a",
            other => other,
        }
        .to_owned();
        if let Some(parent) = &mut grant.parent {
            *parent = match parent.as_str() {
                "root-a" => "root-b",
                "root-b" => "root-a",
                other => other,
            }
            .to_owned();
        }
    }
    for update in &mut selected.updates {
        for id in &mut update.active_root_grants {
            *id = match id.as_str() {
                "root-a" => "root-b",
                "root-b" => "root-a",
                other => other,
            }
            .to_owned();
        }
        for id in &mut update.revoked_serials {
            *id = match id.as_str() {
                "child-a" => "child-b",
                "child-b" => "child-a",
                other => other,
            }
            .to_owned();
        }
    }
    Ok(build_impl(
        &selected,
        update_index,
        canonical_request_limbs,
        nonce_u64,
        true,
    )?
    .actual2)
}

fn build_impl(
    manifest: &SemanticManifest,
    update_index: usize,
    canonical_request_limbs: [u64; 4],
    nonce_u64: u64,
    require_actual2: bool,
) -> Result<JointActuals, BuildError> {
    if manifest.profile.l_max != 2 {
        return Err(BuildError::Lmax);
    }
    let update = manifest
        .updates
        .get(update_index)
        .ok_or(BuildError::UpdateIndex)?;
    let by_id = manifest
        .grants
        .iter()
        .map(|grant| (grant.id.as_str(), grant))
        .collect::<BTreeMap<_, _>>();
    let find = |id: &'static str| {
        by_id
            .get(id)
            .copied()
            .ok_or(BuildError::Manifest("grant ID"))
    };
    let raw_root_b = find("root-b")?;
    let raw_child_b = find("child-b")?;
    let raw_root_c = find("root-c")?;
    if raw_child_b.parent.as_deref() != Some("root-b")
        || raw_root_b.parent.is_some()
        || raw_root_c.parent.is_some()
    {
        return Err(BuildError::Manifest("parent chain"));
    }
    let key_map = keys(manifest)?;
    let root_b = native_grant(raw_root_b, Fr::zero(), &key_map)?;
    let child_b = native_grant(raw_child_b, grant_digest(&root_b), &key_map)?;
    let root_c = native_grant(raw_root_c, Fr::zero(), &key_map)?;

    let root_ids = manifest
        .grants
        .iter()
        .filter(|grant| grant.parent.is_none())
        .map(|grant| grant.id.as_str())
        .collect::<Vec<_>>();
    let active = update
        .active_root_grants
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let root_native = root_ids
        .iter()
        .map(|id| {
            let raw = by_id
                .get(id)
                .copied()
                .ok_or(BuildError::Manifest("root grant"))?;
            native_grant(raw, Fr::zero(), &key_map)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaves = root_ids
        .iter()
        .zip(&root_native)
        .map(|(id, grant)| {
            if active.contains(id) {
                leaf_hash(Domain::GrantLeaf, &[grant_digest(grant)])
            } else {
                Fr::zero()
            }
        })
        .collect::<Vec<_>>();
    let (grant_root, grant_levels) =
        build_tree(leaves, manifest.profile.grant_depth, Domain::TreeNode)
            .map_err(BuildError::Joint)?;
    let root_path = |id: &str| -> Result<MerklePath, BuildError> {
        let index = root_ids
            .iter()
            .position(|candidate| *candidate == id)
            .ok_or(BuildError::Manifest("root position"))?;
        path_for(&grant_levels, index).map_err(BuildError::Joint)
    };

    let owner_pk = &key_map
        .get(&manifest.entitlement.owner)
        .ok_or(BuildError::Manifest("owner ID"))?
        .1;
    let registration_salt = scalar(manifest.entitlement.registration_salt_u128_le_limbs);
    let owner = hash(
        Domain::Owner,
        &[owner_pk.0.x, owner_pk.0.y, registration_salt],
    );
    let entitlement_leaf = hash(
        Domain::RaLeaf,
        &[
            owner,
            Fr::from(manifest.entitlement.resource),
            Fr::from(manifest.entitlement.action_mask_u16),
            Fr::from(manifest.entitlement.interval_lo),
            Fr::from(manifest.entitlement.interval_hi),
            Fr::from(manifest.entitlement.permit_expiry),
            scalar(manifest.entitlement.admission_id_u128_le_limbs),
        ],
    );
    let mut ra_leaves = vec![Fr::zero(); manifest.entitlement.position + 1];
    ra_leaves[manifest.entitlement.position] = entitlement_leaf;
    let (ra_root, ra_levels) = build_tree(ra_leaves, manifest.profile.ra_depth, Domain::TreeNode)
        .map_err(BuildError::Joint)?;
    let entitlement = Entitlement {
        owner_commitment: owner,
        resource: Fr::from(manifest.entitlement.resource),
        action_mask: u16::try_from(manifest.entitlement.action_mask_u16)
            .map_err(|_| BuildError::Manifest("entitlement action"))?,
        interval_lo: manifest.entitlement.interval_lo,
        interval_hi: manifest.entitlement.interval_hi,
        permit_expiry: manifest.entitlement.permit_expiry,
        admission_id: scalar(manifest.entitlement.admission_id_u128_le_limbs),
        path: path_for(&ra_levels, manifest.entitlement.position).map_err(BuildError::Joint)?,
    };

    let state_version = manifest.updates[..=update_index]
        .windows(2)
        .filter(|pair| pair[0].active_root_grants != pair[1].active_root_grants)
        .count() as u64;
    let state_leaf = hash(
        Domain::StateLeaf,
        &[
            owner,
            grant_root,
            Fr::from(state_version),
            Fr::from(update.state_epoch),
            Fr::from(manifest.state.state_expiry),
            Fr::from(1u64),
            scalar(manifest.state.state_salt_u128_le_limbs),
            Fr::from(manifest.state.state_position as u64),
        ],
    );
    let mut state_leaves = vec![Fr::zero(); manifest.state.state_position + 1];
    state_leaves[manifest.state.state_position] = state_leaf;
    let (state_root, state_levels) =
        build_tree(state_leaves, manifest.profile.state_depth, Domain::TreeNode)
            .map_err(BuildError::Joint)?;
    let state = UserState {
        owner_commitment: owner,
        grant_root,
        state_version,
        state_epoch: update.state_epoch,
        state_expiry: manifest.state.state_expiry,
        active: true,
        salt: scalar(manifest.state.state_salt_u128_le_limbs),
        position: manifest.state.state_position as u32,
        path: path_for(&state_levels, manifest.state.state_position).map_err(BuildError::Joint)?,
    };

    let mut revocation = IndexedRevocationTree::new(manifest.profile.revocation_depth)
        .map_err(|_| BuildError::Joint("revocation tree"))?;
    let mut inserted = BTreeSet::new();
    for phase in &manifest.updates[..=update_index] {
        for id in &phase.revoked_serials {
            if inserted.insert(id) {
                revocation
                    .insert(scalar(
                        by_id
                            .get(id.as_str())
                            .ok_or(BuildError::Manifest("revoked grant"))?
                            .serial,
                    ))
                    .map_err(|_| BuildError::Joint("revocation insert"))?;
            }
        }
    }
    let metadata_limbs = plan_a_dac_fixed_wrapper::semantic_schema::metadata_digest_limbs(
        &plan_a_dac_fixed_wrapper::semantic_schema::bound_metadata(manifest),
    );
    let request = Request {
        canonical_request_lo: scalar([canonical_request_limbs[0], canonical_request_limbs[1]]),
        canonical_request_hi: scalar([canonical_request_limbs[2], canonical_request_limbs[3]]),
        circuit_id: Fr::from(metadata_limbs[0]),
        verifier_id: Fr::from(metadata_limbs[1]),
        pep_id: Fr::from(metadata_limbs[2]),
        resource: Fr::from(manifest.request.resource),
        action_onehot: u16::try_from(manifest.request.one_hot_action_u16)
            .map_err(|_| BuildError::Manifest("request action"))?,
        interval_lo: manifest.request.interval_lo,
        interval_hi: manifest.request.interval_hi,
        time: manifest.request.now,
        nonce: Fr::from(nonce_u64),
        context: Fr::from(metadata_limbs[3]),
        terminal: key_map
            .get(&manifest.request.terminal)
            .ok_or(BuildError::Manifest("terminal ID"))?
            .1
            .clone(),
    };
    let snapshot = Snapshot {
        tuple_version: update.tuple_version,
        root_ra: ra_root,
        root_state: state_root,
        root_rev: revocation.root(),
        state_epoch: update.state_epoch,
        revocation_epoch: update.revocation_epoch,
        issued_at: update.issued_at,
    };
    let base = |slots: [Slot; 2]| JointCircuit {
        snapshot: snapshot.clone(),
        request: request.clone(),
        entitlement: entitlement.clone(),
        state: state.clone(),
        registration_salt,
        grants: slots,
    };
    let actual1 = base([
        Slot {
            enabled: true,
            grant: root_c.clone(),
            grant_path: root_path("root-c")?,
            revocation: revocation
                .prove_nonmember(root_c.serial)
                .map_err(|_| BuildError::Joint("root-c revocation witness"))?,
        },
        disabled(
            manifest.profile.grant_depth,
            manifest.profile.revocation_depth,
        ),
    ]);
    let actual2_result = (|| {
        Ok::<_, BuildError>(base([
            Slot {
                enabled: true,
                grant: root_b.clone(),
                grant_path: root_path("root-b")?,
                revocation: revocation
                    .prove_nonmember(root_b.serial)
                    .map_err(|_| BuildError::Joint("root-b revocation witness"))?,
            },
            Slot {
                enabled: true,
                grant: child_b.clone(),
                grant_path: zero_path(manifest.profile.grant_depth),
                revocation: revocation
                    .prove_nonmember(child_b.serial)
                    .map_err(|_| BuildError::Joint("child-b revocation witness"))?,
            },
        ]))
    })();
    let actual2 = if require_actual2 {
        actual2_result?
    } else {
        actual2_result.unwrap_or_else(|_| actual1.clone())
    };
    Ok(JointActuals {
        semantic_input_sha256: manifest_sha256(manifest),
        actual1,
        actual2,
    })
}
