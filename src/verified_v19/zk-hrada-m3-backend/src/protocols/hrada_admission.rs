//! Trusted SR boundary for admitting business-authorized root grants.
//!
//! The proof circuit establishes authorization relative to a signed root. The
//! SR must call this gate on the complete prospective grant tree before it
//! publishes that tree. The synthetic fixture signs its candidate internally
//! before this gate; it does not model a production signing-service API.
//! Entitlements are an authoritative business input, not a witness or a claim
//! supplied by the presenter.

use crate::protocols::hrada_auth::{AuthCircuit, Grant, Hash, Scheme, TREE_DEPTH};
use ark_bls12_381::Fr;
use ark_crypto_primitives::{signature::schnorr::Parameters, SignatureScheme};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective};
use ark_ff::PrimeField;
use blake2::{Blake2s, Digest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BusinessEntitlement {
    pub user_commitment: Hash,
    pub system: u64,
    pub resource: u64,
    pub action_mask: u16,
    pub not_before: u64,
    pub not_after: u64,
    pub active: bool,
    /// Maximum delegation edges a root grant may authorize.
    pub max_delegation_depth: u8,
}

/// An SR-owned, authoritative source. Implementations must use trusted business
/// records, not fields offered by the Agent or a proof presenter.
pub trait EntitlementSource {
    fn for_user_resource(
        &self,
        user_commitment: &Hash,
        system: u64,
        resource: u64,
    ) -> Vec<BusinessEntitlement>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryEntitlementLedger {
    pub records: Vec<BusinessEntitlement>,
}

/// Configured independently of the candidate state by the trusted SR.
/// A candidate cannot choose its own RA/SR key, signature parameters, system,
/// or circuit version and thereby satisfy admission with self-signed records.
#[derive(Clone)]
pub struct AdmissionAuthority {
    params: Parameters<EdwardsProjective, Blake2s>,
    ra_pk: EdwardsAffine,
    sr_pk: EdwardsAffine,
    system: u64,
    circuit_version: u64,
}

impl AdmissionAuthority {
    pub fn new(
        trusted_params: Parameters<EdwardsProjective, Blake2s>,
        trusted_ra_pk: EdwardsAffine,
        trusted_sr_pk: EdwardsAffine,
        system: u64,
        circuit_version: u64,
    ) -> Self {
        Self {
            params: trusted_params,
            ra_pk: trusted_ra_pk,
            sr_pk: trusted_sr_pk,
            system,
            circuit_version,
        }
    }

    fn accepts(&self, state: &AuthCircuit) -> bool {
        state.params.generator == self.params.generator
            && state.params.salt == self.params.salt
            && state.ra_pk == self.ra_pk
            && state.sr_pk == self.sr_pk
            && state.request.fields[3] == Fr::from(self.system)
            && state.request.fields[4] == Fr::from(self.circuit_version)
    }
}

impl EntitlementSource for InMemoryEntitlementLedger {
    fn for_user_resource(
        &self,
        user_commitment: &Hash,
        system: u64,
        resource: u64,
    ) -> Vec<BusinessEntitlement> {
        self.records
            .iter()
            .filter(|item| {
                &item.user_commitment == user_commitment
                    && item.system == system
                    && item.resource == resource
            })
            .cloned()
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmissionError {
    UntrustedAuthority,
    InvalidStateTree,
    InvalidRegistration,
    InvalidRootGrant,
    NoCoveringEntitlement,
}

/// A successful decision is tied to the exact prospective state root and
/// signed grant record. It is not a substitute for an SR signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmissionReceipt {
    pub auth_root: Hash,
    pub root_grant_id: Hash,
    pub user_commitment: Hash,
    pub system: u64,
    pub resource: u64,
}

fn as_u64(value: Fr) -> Option<u64> {
    let repr = value.into_repr();
    let limbs = repr.as_ref();
    if limbs.iter().skip(1).any(|limb| *limb != 0) {
        None
    } else {
        Some(limbs[0])
    }
}

fn blake2s_domain(domain: u8, body: &[u8]) -> Hash {
    let mut hasher = Blake2s::new();
    hasher.update(&[domain]);
    hasher.update(body);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Reconstruct the exact eight-leaf grant tree used by `hrada_auth`, rejecting
/// duplicate or out-of-range leaf indices before any admission decision.
fn checked_tree_root(grants: &[Grant]) -> Result<Hash, AdmissionError> {
    let mut leaves = vec![[0u8; 32]; 1 << TREE_DEPTH];
    let mut occupied = vec![false; leaves.len()];
    for grant in grants {
        let index = as_u64(grant.fields[14]).ok_or(AdmissionError::InvalidStateTree)? as usize;
        if index >= leaves.len() || occupied[index] {
            return Err(AdmissionError::InvalidStateTree);
        }
        occupied[index] = true;
        leaves[index] = grant.leaf();
    }
    for _ in 0..TREE_DEPTH {
        leaves = leaves
            .chunks_exact(2)
            .map(|pair| {
                let mut input = [0u8; 64];
                input[..32].copy_from_slice(&pair[0]);
                input[32..].copy_from_slice(&pair[1]);
                blake2s_domain(7, &input)
            })
            .collect();
    }
    Ok(leaves[0])
}

fn admit_root<S: EntitlementSource>(
    source: &S,
    state: &AuthCircuit,
    root: &Grant,
    now: Option<u64>,
) -> Result<AdmissionReceipt, AdmissionError> {
    let commitment = state.user_commitment();
    let system = as_u64(state.request.fields[3]).ok_or(AdmissionError::InvalidRegistration)?;
    if state.reg_serial == 0 || now.map(|value| value > state.reg_expiry).unwrap_or(false) {
        return Err(AdmissionError::InvalidRegistration);
    }
    let ra_ok = Scheme::verify(
        &state.params,
        &state.ra_pk,
        &state.reg_hash(),
        &state.ra_sig,
    )
    .map_err(|_| AdmissionError::InvalidRegistration)?;
    if !ra_ok {
        return Err(AdmissionError::InvalidRegistration);
    }
    if !root.active
        || root.fields[0] != Fr::from(0u64)
        || root.fields[1] != Fr::from_le_bytes_mod_order(&commitment[..16])
        || root.fields[2] != Fr::from_le_bytes_mod_order(&commitment[16..])
        || root.fields[3] != state.user_pk.x
        || root.fields[4] != state.user_pk.y
        || root.parent != state.reg_hash()
    {
        return Err(AdmissionError::InvalidRootGrant);
    }
    let resource = as_u64(root.fields[7]).ok_or(AdmissionError::InvalidRootGrant)?;
    let action = as_u64(root.fields[8]).ok_or(AdmissionError::InvalidRootGrant)?;
    let not_before = as_u64(root.fields[9]).ok_or(AdmissionError::InvalidRootGrant)?;
    let not_after = as_u64(root.fields[10]).ok_or(AdmissionError::InvalidRootGrant)?;
    let delegable = as_u64(root.fields[11]).ok_or(AdmissionError::InvalidRootGrant)?;
    let depth = as_u64(root.fields[12]).ok_or(AdmissionError::InvalidRootGrant)?;
    let serial = as_u64(root.fields[13]).ok_or(AdmissionError::InvalidRootGrant)?;
    let record_version = as_u64(root.fields[16]).ok_or(AdmissionError::InvalidRootGrant)?;
    if action == 0
        || action > u16::MAX as u64
        || now.map(|value| not_before > value || value > not_after).unwrap_or(false)
        || not_after > state.reg_expiry
        || delegable > 1
        || depth > 2
        || (depth > 0 && delegable != 1)
        || serial == 0
        || record_version != 1
    {
        return Err(AdmissionError::InvalidRootGrant);
    }
    let signature_ok = Scheme::verify(&state.params, &state.user_pk, &root.core(), &root.signature)
        .map_err(|_| AdmissionError::InvalidRootGrant)?;
    if !signature_ok {
        return Err(AdmissionError::InvalidRootGrant);
    }
    let covered = source
        .for_user_resource(&commitment, system, resource)
        .iter()
        .any(|entitlement| {
            entitlement.active
                && entitlement.user_commitment == commitment
                && entitlement.system == system
                && entitlement.resource == resource
                && entitlement.action_mask != 0
                && (action as u16 & !entitlement.action_mask) == 0
                && entitlement.not_before <= not_before
                && entitlement.not_after >= not_after
                && now.map(|value| value >= entitlement.not_before && value <= entitlement.not_after).unwrap_or(true)
                && depth <= entitlement.max_delegation_depth as u64
        });
    if !covered {
        return Err(AdmissionError::NoCoveringEntitlement);
    }
    Ok(AdmissionReceipt {
        auth_root: state.auth_root,
        root_grant_id: root.id(),
        user_commitment: commitment,
        system,
        resource,
    })
}

/// Fail-closed prepublication gate for every active root grant in the complete
/// prospective tree. The SR must reject the state if this returns an error.
pub fn admit_state_roots<S: EntitlementSource>(
    authority: &AdmissionAuthority,
    source: &S,
    prospective_state: &AuthCircuit,
    full_grant_tree: &[Grant],
    now: u64,
) -> Result<Vec<AdmissionReceipt>, AdmissionError> {
    if !authority.accepts(prospective_state) {
        return Err(AdmissionError::UntrustedAuthority);
    }
    if checked_tree_root(full_grant_tree)? != prospective_state.auth_root {
        return Err(AdmissionError::InvalidStateTree);
    }
    let mut receipts = Vec::new();
    for grant in full_grant_tree {
        let kind = as_u64(grant.fields[0]).ok_or(AdmissionError::InvalidRootGrant)?;
        if kind > 1 {
            return Err(AdmissionError::InvalidRootGrant);
        }
        if kind == 0 && grant.active {
            receipts.push(admit_root(source, prospective_state, grant, Some(now))?);
        }
    }
    Ok(receipts)
}

/// Revalidate the immutable publication admission of active roots without
/// requiring every unrelated root interval to contain the current request
/// time. Request-time validity is checked on each candidate path separately.
pub fn validate_published_state_roots<S: EntitlementSource>(
    authority: &AdmissionAuthority,
    source: &S,
    prospective_state: &AuthCircuit,
    full_grant_tree: &[Grant],
) -> Result<Vec<AdmissionReceipt>, AdmissionError> {
    if !authority.accepts(prospective_state) {
        return Err(AdmissionError::UntrustedAuthority);
    }
    if checked_tree_root(full_grant_tree)? != prospective_state.auth_root {
        return Err(AdmissionError::InvalidStateTree);
    }
    let mut receipts = Vec::new();
    for grant in full_grant_tree {
        let kind = as_u64(grant.fields[0]).ok_or(AdmissionError::InvalidRootGrant)?;
        if kind > 1 {
            return Err(AdmissionError::InvalidRootGrant);
        }
        if kind == 0 && grant.active {
            receipts.push(admit_root(source, prospective_state, grant, None)?);
        }
    }
    Ok(receipts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::hrada_auth::AuthFixture;

    fn ledger(fixture: &AuthFixture) -> InMemoryEntitlementLedger {
        InMemoryEntitlementLedger {
            records: vec![BusinessEntitlement {
                user_commitment: fixture.base.user_commitment(),
                system: 1,
                resource: 42,
                action_mask: 3,
                not_before: 0,
                not_after: 2000,
                active: true,
                max_delegation_depth: 2,
            }],
        }
    }

    fn authority(fixture: &AuthFixture) -> AdmissionAuthority {
        AdmissionAuthority::new(
            fixture.base.params.clone(),
            fixture.base.ra_pk,
            fixture.base.sr_pk,
            1,
            1,
        )
    }

    #[test]
    fn admits_all_signed_roots_against_authoritative_entitlement() {
        let fixture = AuthFixture::new(41);
        let receipts = admit_state_roots(
            &authority(&fixture),
            &ledger(&fixture),
            &fixture.base,
            &fixture.all_grants,
            500,
        )
        .unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].auth_root, fixture.base.auth_root);
        assert_eq!(receipts[0].root_grant_id, fixture.all_grants[0].id());
        assert_eq!(receipts[1].root_grant_id, fixture.all_grants[4].id());
    }

    #[test]
    fn rejects_business_permission_gaps_and_revocation() {
        let fixture = AuthFixture::new(42);
        let mut policies = ledger(&fixture);
        policies.records[0].resource = 43;
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::NoCoveringEntitlement)
        );
        policies.records[0].resource = 42;
        policies.records[0].action_mask = 1;
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::NoCoveringEntitlement)
        );
        policies.records[0].action_mask = 3;
        policies.records[0].max_delegation_depth = 1;
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::NoCoveringEntitlement)
        );
        policies.records[0].max_delegation_depth = 2;
        policies.records[0].active = false;
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::NoCoveringEntitlement)
        );
    }

    #[test]
    fn rejects_incomplete_or_modified_prospective_tree() {
        let fixture = AuthFixture::new(43);
        let policies = ledger(&fixture);
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants[..7],
                500
            ),
            Err(AdmissionError::InvalidStateTree)
        );
        let mut tampered = fixture.all_grants.clone();
        tampered[4].fields[8] = Fr::from(7u64);
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &tampered,
                500
            ),
            Err(AdmissionError::InvalidStateTree)
        );
        tampered = fixture.all_grants.clone();
        tampered[4].fields[14] = tampered[0].fields[14];
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &tampered,
                500
            ),
            Err(AdmissionError::InvalidStateTree)
        );
    }

    #[test]
    fn rejects_expired_or_wrong_user_entitlement() {
        let fixture = AuthFixture::new(44);
        let mut policies = ledger(&fixture);
        policies.records[0].not_after = 900;
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::NoCoveringEntitlement)
        );
        policies.records[0].not_after = 2000;
        policies.records[0].user_commitment = [0; 32];
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::NoCoveringEntitlement)
        );
    }

    #[test]
    fn checks_each_active_root_before_publication() {
        let mut fixture = AuthFixture::new(45);
        let policies = ledger(&fixture);
        fixture.all_grants[4].fields[7] = Fr::from(43u64);
        let modified_core = fixture.all_grants[4].core();
        fixture.all_grants[4].signature = fixture.issuer_sign(0, modified_core).unwrap();
        // Build an unsigned prospective state: SR must run admission before signing it.
        fixture.base.auth_root = checked_tree_root(&fixture.all_grants).unwrap();
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &policies,
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::NoCoveringEntitlement)
        );
    }

    #[test]
    fn rejects_a_forged_root_signature_even_with_a_matching_tree() {
        let mut fixture = AuthFixture::new(46);
        fixture.all_grants[0].signature = Default::default();
        fixture.base.auth_root = checked_tree_root(&fixture.all_grants).unwrap();
        assert_eq!(
            admit_state_roots(
                &authority(&fixture),
                &ledger(&fixture),
                &fixture.base,
                &fixture.all_grants,
                500
            ),
            Err(AdmissionError::InvalidRootGrant)
        );
    }

    #[test]
    fn rejects_candidate_selected_authority() {
        let trusted = AuthFixture::new(47);
        let candidate = AuthFixture::new(48);
        assert_eq!(
            admit_state_roots(
                &authority(&trusted),
                &ledger(&candidate),
                &candidate.base,
                &candidate.all_grants,
                500,
            ),
            Err(AdmissionError::UntrustedAuthority)
        );
    }
}
