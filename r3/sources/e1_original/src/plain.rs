//! Native plaintext verifier for the same signed-chain authorization contract.
//! This is a protocol-independent component baseline; it is not OAuth or UCAN.
use crate::{
    contract::{Entitlement, Grant, Request, Slot, Snapshot, UserState, SERIAL_BITS},
    merkle::root_from_path,
    poseidon::{hash, Domain},
    signature::verify,
    Fr,
};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as Scalar};
use ark_ff::{BigInteger, PrimeField, Zero};
use thiserror::Error;

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum PlainError {
    #[error("invalid request or snapshot range")]
    Request,
    #[error("RA entitlement is not admitted")]
    Admission,
    #[error("state leaf is invalid or inactive")]
    State,
    #[error("enabled slots are not a nonempty prefix")]
    Prefix,
    #[error("disabled slot is not canonical padding")]
    Padding,
    #[error("grant signature or key chain is invalid")]
    SignatureChain,
    #[error("grant policy does not attenuate")]
    Policy,
    #[error("grant is revoked or serial proof is invalid")]
    Revocation,
    #[error("terminal does not equal final subject")]
    Terminal,
}

fn point_valid(p: EdwardsAffine) -> bool {
    !p.is_zero() && p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()
}
fn low_bits(x: Fr, n: usize) -> bool {
    !x.into_bigint().to_bits_le()[n..].iter().any(|b| *b)
}
fn grant_digest(g: &Grant) -> Fr {
    hash(
        Domain::Grant,
        &[
            g.issuer.0.x,
            g.issuer.0.y,
            g.subject.0.x,
            g.subject.0.y,
            g.resource,
            Fr::from(g.action_mask as u64),
            Fr::from(g.interval_lo),
            Fr::from(g.interval_hi),
            Fr::from(g.not_before),
            Fr::from(g.expiry),
            Fr::from(g.depth_remaining as u64),
            g.serial,
            g.parent_digest,
        ],
    )
}
fn directions_match(index: u32, directions: &[bool]) -> bool {
    directions
        .iter()
        .enumerate()
        .all(|(i, bit)| *bit == ((index >> i) & 1 == 1))
        && (directions.len() >= 32 || (index as u64) < (1u64 << directions.len()))
}
fn nonmember(slot: &Slot, root: Fr) -> bool {
    let w = &slot.revocation;
    if slot.grant.serial.is_zero()
        || !low_bits(slot.grant.serial, SERIAL_BITS)
        || !low_bits(w.predecessor, SERIAL_BITS)
        || !low_bits(w.successor, SERIAL_BITS)
        || w.predecessor.into_bigint() >= slot.grant.serial.into_bigint()
        || slot.grant.serial.into_bigint() >= w.successor.into_bigint()
        || !directions_match(w.predecessor_slot, &w.path.directions)
    {
        return false;
    }
    let leaf = hash(
        Domain::RevLeaf,
        &[
            Fr::from(w.predecessor_slot),
            w.predecessor,
            Fr::from(w.successor_slot),
            w.successor,
        ],
    );
    root_from_path(leaf, &w.path, Domain::RevNode) == Some(root)
}
fn zero_path(path: &crate::merkle::MerklePath) -> bool {
    path.siblings.iter().all(Zero::is_zero) && path.directions.iter().all(|x| !*x)
}
fn canonical_disabled(slot: &Slot) -> bool {
    let g = &slot.grant;
    let w = &slot.revocation;
    !slot.enabled
        && g.issuer.0 == EdwardsAffine::zero()
        && g.subject.0 == EdwardsAffine::zero()
        && g.resource.is_zero()
        && g.action_mask == 0
        && g.interval_lo == 0
        && g.interval_hi == 0
        && g.not_before == 0
        && g.expiry == 0
        && g.depth_remaining == 0
        && g.serial.is_zero()
        && g.parent_digest.is_zero()
        && g.signature.r == EdwardsAffine::zero()
        && g.signature.s == Scalar::zero()
        && zero_path(&slot.grant_path)
        && w.predecessor_slot == 0
        && w.predecessor.is_zero()
        && w.successor_slot == 0
        && w.successor.is_zero()
        && zero_path(&w.path)
}

/// Verify authorization using ordinary native cryptography and comparisons.
/// This function never synthesizes or queries an R1CS.
pub fn verify_plain<const L: usize>(
    snapshot: &Snapshot,
    request: &Request,
    entitlement: &Entitlement,
    state: &UserState,
    registration_salt: Fr,
    grants: &[Slot; L],
) -> Result<(), PlainError> {
    if L == 0
        || L > 5
        || !low_bits(request.canonical_request_lo, 128)
        || !low_bits(request.canonical_request_hi, 128)
        || request.action_onehot == 0
        || request.action_onehot.count_ones() != 1
        || request.interval_lo > request.time
        || request.time > request.interval_hi
    {
        return Err(PlainError::Request);
    }
    let ent_leaf = hash(
        Domain::RaLeaf,
        &[
            entitlement.owner_commitment,
            entitlement.resource,
            Fr::from(entitlement.action_mask as u64),
            Fr::from(entitlement.interval_lo),
            Fr::from(entitlement.interval_hi),
            Fr::from(entitlement.permit_expiry),
            entitlement.admission_id,
        ],
    );
    if root_from_path(ent_leaf, &entitlement.path, Domain::TreeNode) != Some(snapshot.root_ra)
        || entitlement.resource != request.resource
        || request.interval_lo < entitlement.interval_lo
        || request.interval_hi > entitlement.interval_hi
        || request.interval_hi > entitlement.permit_expiry
        || request.action_onehot & !entitlement.action_mask != 0
    {
        return Err(PlainError::Admission);
    }
    let state_leaf = hash(
        Domain::StateLeaf,
        &[
            state.owner_commitment,
            state.grant_root,
            Fr::from(state.state_version),
            Fr::from(state.state_epoch),
            Fr::from(state.state_expiry),
            Fr::from(state.active as u64),
            state.salt,
            Fr::from(state.position),
        ],
    );
    if !state.active
        || state.owner_commitment != entitlement.owner_commitment
        || state.state_epoch > snapshot.state_epoch
        || request.interval_hi > state.state_expiry
        || !directions_match(state.position, &state.path.directions)
        || root_from_path(state_leaf, &state.path, Domain::TreeNode) != Some(snapshot.root_state)
    {
        return Err(PlainError::State);
    }
    let active = grants.iter().take_while(|s| s.enabled).count();
    if active == 0 || grants[active..].iter().any(|s| s.enabled) {
        return Err(PlainError::Prefix);
    }
    if grants[active..].iter().any(|s| !canonical_disabled(s)) {
        return Err(PlainError::Padding);
    }
    let mut previous_digest = Fr::zero();
    let mut previous_subject = None;
    let mut parent_mask = entitlement.action_mask;
    let mut parent_lo = entitlement.interval_lo;
    let mut parent_hi = entitlement.interval_hi;
    let mut parent_nbf = entitlement.interval_lo;
    let mut parent_expiry = entitlement.permit_expiry;
    let mut parent_depth = None;
    for (i, slot) in grants[..active].iter().enumerate() {
        let g = &slot.grant;
        let digest = grant_digest(g);
        if !point_valid(g.issuer.0)
            || !point_valid(g.subject.0)
            || !verify(&g.issuer, digest, &g.signature)
            || (i == 0
                && hash(
                    Domain::Owner,
                    &[g.issuer.0.x, g.issuer.0.y, registration_salt],
                ) != entitlement.owner_commitment)
            || (i > 0
                && (Some(&g.issuer) != previous_subject.as_ref()
                    || g.parent_digest != previous_digest))
        {
            return Err(PlainError::SignatureChain);
        }
        if i == 0 {
            let leaf = hash(Domain::GrantLeaf, &[digest]);
            if g.parent_digest != Fr::zero()
                || root_from_path(leaf, &slot.grant_path, Domain::TreeNode)
                    != Some(state.grant_root)
            {
                return Err(PlainError::State);
            }
        } else if !zero_path(&slot.grant_path) {
            return Err(PlainError::Padding);
        }
        if g.resource != request.resource
            || g.action_mask & !parent_mask != 0
            || request.action_onehot & !g.action_mask != 0
            || g.interval_lo < parent_lo
            || g.interval_hi > parent_hi
            || g.interval_lo > request.interval_lo
            || request.interval_hi > g.interval_hi
            || g.not_before < parent_nbf
            || g.not_before > request.interval_lo
            || request.interval_hi > g.expiry
            || g.expiry > parent_expiry
            || parent_depth.is_some_and(|d: u8| g.depth_remaining.checked_add(1) != Some(d))
        {
            return Err(PlainError::Policy);
        }
        if !nonmember(slot, snapshot.root_rev) {
            return Err(PlainError::Revocation);
        }
        previous_digest = digest;
        previous_subject = Some(g.subject.clone());
        parent_mask = g.action_mask;
        parent_lo = g.interval_lo;
        parent_hi = g.interval_hi;
        parent_nbf = g.not_before;
        parent_expiry = g.expiry;
        parent_depth = Some(g.depth_remaining);
    }
    if previous_subject.as_ref() != Some(&request.terminal) {
        return Err(PlainError::Terminal);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture;
    use crate::signature::{public_key, SecretKey};

    fn check(c: &crate::joint::JointCircuit<3>) -> Result<(), PlainError> {
        verify_plain(
            &c.snapshot,
            &c.request,
            &c.entitlement,
            &c.state,
            c.registration_salt,
            &c.grants,
        )
    }
    #[test]
    fn valid_lengths_and_native_negative_cross_checks() {
        for active in 1..=3 {
            assert_eq!(check(&fixture::l3(active, active as u64)), Ok(()));
        }

        let mut c = fixture::l3(2, 10);
        c.snapshot.root_ra += Fr::from(1u64);
        assert_eq!(check(&c), Err(PlainError::Admission));
        let mut c = fixture::l3(2, 11);
        c.snapshot.state_epoch -= 1;
        assert_eq!(check(&c), Err(PlainError::State));
        let mut c = fixture::l3(2, 12);
        c.snapshot.root_rev += Fr::from(1u64);
        assert_eq!(check(&c), Err(PlainError::Revocation));
        let mut c = fixture::l3(2, 13);
        c.grants[1].grant.signature.s = Scalar::zero();
        assert_eq!(check(&c), Err(PlainError::SignatureChain));
        let mut c = fixture::l3(2, 14);
        c.grants[1].grant.parent_digest += Fr::from(1u64);
        assert_eq!(check(&c), Err(PlainError::SignatureChain));
        let mut c = fixture::l3(2, 15);
        c.request.action_onehot = 0b1_0000;
        assert_eq!(check(&c), Err(PlainError::Policy));
        let mut c = fixture::l3(2, 16);
        c.request.terminal = public_key(&SecretKey(Scalar::from(999u64))).unwrap();
        assert_eq!(check(&c), Err(PlainError::Terminal));
        let mut c = fixture::l3(2, 17);
        c.grants[2].grant.resource = Fr::from(1u64);
        assert_eq!(check(&c), Err(PlainError::Padding));
        let mut c = fixture::l3(2, 18);
        c.request.time = c.request.interval_lo - 1;
        assert_eq!(check(&c), Err(PlainError::Request));
    }
}
