//! Native validation bridge for the isolated SR/P23 comparison.
//!
//! This module uses the production experiment's exact deterministic fixture,
//! encodings, signatures, private tree and admission gate.  It exposes only
//! source-neutral receipts to the arkworks 0.4 P23 adapter.

use crate::protocols::{
    hrada_admission::{
        admit_state_roots, AdmissionAuthority, BusinessEntitlement,
        InMemoryEntitlementLedger,
    },
    hrada_auth::{AuthCircuit, AuthFixture, Grant, Hash, Scheme, Sig, TREE_DEPTH},
};
use ark_bls12_381::Fr;
use ark_crypto_primitives::SignatureScheme;
use ark_ff::{One, PrimeField, ToBytes, Zero};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use rand::{rngs::StdRng, SeedableRng};

#[derive(Clone, Debug)]
pub struct NativeReceipt {
    /// SR-internal audit data. The adapter never serializes these fields into a show.
    pub path: String,
    pub grant_ids: Vec<Hash>,
    pub terminal_bytes: Vec<u8>,
    pub request_bytes: Vec<u8>,
    pub resource: u64,
    pub action: u16,
    pub window_start: u64,
    pub window_end: u64,
}

#[derive(Clone)]
pub struct TrustedNativeContext {
    authority: AdmissionAuthority,
    ledger: InMemoryEntitlementLedger,
}

impl TrustedNativeContext {
    /// Freeze trust anchors and business records before validating a candidate.
    pub fn from_fixtures(fixtures: &[&AuthFixture]) -> Result<Self, String> {
        let first = fixtures.first().ok_or("empty_trusted_fixture_set")?;
        let authority = authority(first);
        let mut records = Vec::with_capacity(fixtures.len());
        for fixture in fixtures {
            if fixture.base.params.generator != first.base.params.generator
                || fixture.base.params.salt != first.base.params.salt
                || fixture.base.ra_pk != first.base.ra_pk
                || fixture.base.sr_pk != first.base.sr_pk
            {
                return Err("fixture_trust_anchor_mismatch".into());
            }
            records.push(BusinessEntitlement {
                user_commitment: fixture.base.user_commitment(),
                system: as_u64(fixture.base.request.fields[3])?,
                resource: 42,
                action_mask: 3,
                not_before: 100,
                not_after: fixture.base.reg_expiry,
                active: true,
                max_delegation_depth: 2,
            });
        }
        Ok(Self {
            authority,
            ledger: InMemoryEntitlementLedger { records },
        })
    }

    pub fn without_entitlements(&self) -> Self {
        Self {
            authority: self.authority.clone(),
            ledger: InMemoryEntitlementLedger::default(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NativeMutation {
    NoEntitlement,
    BadRaSignature,
    BadGrantSignature,
    BadParent,
    PermissionExpansion,
    ExpiredGrant,
    BadDepth,
    InactiveAncestor,
    WrongTerminal,
}

fn as_u64(value: Fr) -> Result<u64, String> {
    let repr = value.into_repr();
    let limbs = repr.as_ref();
    if limbs.iter().skip(1).any(|limb| *limb != 0) {
        Err("field_not_u64".into())
    } else {
        Ok(limbs[0])
    }
}

fn as_u16(value: Fr) -> Result<u16, String> {
    let value = as_u64(value)?;
    u16::try_from(value).map_err(|_| "field_not_u16".into())
}

fn enc<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut out = Vec::new();
    value.serialize(&mut out).expect("vec serialization");
    out
}

fn hash(domain: u8, bytes: &[u8]) -> Hash {
    let mut h = Blake2s::new();
    h.update(&[domain]);
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn authority(fixture: &AuthFixture) -> AdmissionAuthority {
    AdmissionAuthority::new(
        fixture.base.params.clone(),
        fixture.base.ra_pk,
        fixture.base.sr_pk,
        as_u64(fixture.base.request.fields[3]).unwrap(),
        as_u64(fixture.base.request.fields[4]).unwrap(),
    )
}

fn verify_merkle_path(fixture: &AuthFixture, grant: &Grant) -> Result<(), String> {
    let index = as_u64(grant.fields[14])? as usize;
    if index >= (1usize << TREE_DEPTH) {
        return Err("leaf_index_out_of_range".into());
    }
    let tree = fixture.tree();
    if tree[0][index] != grant.leaf() || tree[TREE_DEPTH][0] != fixture.base.auth_root {
        return Err("grant_tree_membership_failed".into());
    }
    Ok(())
}

fn validate_chain(
    fixture: &AuthFixture,
    path: &str,
    circuit: AuthCircuit,
    window: (u64, u64),
) -> Result<NativeReceipt, String> {
    if circuit.prime != fixture.base.prime
        || circuit.auth_root != fixture.base.auth_root
        || circuit.state_version != fixture.base.state_version
        || circuit.state_status != fixture.base.state_status
        || circuit.state_expiry != fixture.base.state_expiry
        || circuit.transition != fixture.base.transition
        || circuit.sr_sig != fixture.base.sr_sig
    {
        return Err("candidate_state_mismatch".into());
    }
    let active = circuit
        .enabled
        .iter()
        .take_while(|enabled| **enabled)
        .count();
    if active == 0 || circuit.enabled.iter().skip(active).any(|enabled| *enabled) {
        return Err("enabled_prefix_invalid".into());
    }
    let grants = &circuit.grants[..active];
    let user_commitment = circuit.user_commitment();
    let commitment_limbs = [
        Fr::from_le_bytes_mod_order(&user_commitment[..16]),
        Fr::from_le_bytes_mod_order(&user_commitment[16..]),
    ];
    let mut previous: Option<&Grant> = None;
    for (position, grant) in grants.iter().enumerate() {
        verify_merkle_path(fixture, grant)?;
        let _record_version = as_u64(grant.fields[16])?;
        if !grant.active || as_u64(grant.fields[13])? == 0 {
            return Err("inactive_or_malformed_grant".into());
        }
        if grant.fields[1] != commitment_limbs[0] || grant.fields[2] != commitment_limbs[1] {
            return Err("user_commitment_mismatch".into());
        }
        let issuer = ark_ed_on_bls12_381::EdwardsAffine::new(grant.fields[3], grant.fields[4]);
        let subject = ark_ed_on_bls12_381::EdwardsAffine::new(grant.fields[5], grant.fields[6]);
        if issuer.is_zero() || !issuer.is_on_curve() || !issuer.is_in_correct_subgroup_assuming_on_curve() {
            return Err("issuer_point_invalid".into());
        }
        if subject.is_zero() || !subject.is_on_curve() || !subject.is_in_correct_subgroup_assuming_on_curve() {
            return Err("subject_point_invalid".into());
        }
        let delegable = as_u64(grant.fields[11])?;
        let remaining_depth = as_u64(grant.fields[12])?;
        if delegable > 1 || remaining_depth > 15 {
            return Err("grant_range_invalid".into());
        }
        if !Scheme::verify(&circuit.params, &issuer, &grant.core(), &grant.signature)
            .map_err(|_| "grant_signature_error")?
        {
            return Err("grant_signature_invalid".into());
        }
        let kind = as_u64(grant.fields[0])?;
        if position == 0 {
            if kind != 0
                || issuer != circuit.user_pk
                || grant.parent != circuit.reg_hash()
                || remaining_depth > 2
            {
                return Err("root_binding_invalid".into());
            }
        } else {
            let parent = previous.unwrap();
            if kind != 1
                || grant.parent != parent.id()
                || grant.fields[3] != parent.fields[5]
                || grant.fields[4] != parent.fields[6]
                || grant.fields[7] != parent.fields[7]
                || grant.fields[15] != parent.fields[15]
            {
                return Err("parent_or_subject_link_invalid".into());
            }
            let parent_actions = as_u16(parent.fields[8])?;
            let child_actions = as_u16(grant.fields[8])?;
            if child_actions == 0 || (child_actions & !parent_actions) != 0 {
                return Err("permission_expansion".into());
            }
            if as_u64(parent.fields[11])? != 1
                || as_u64(parent.fields[12])? != as_u64(grant.fields[12])? + 1
                || as_u64(parent.fields[9])? > as_u64(grant.fields[9])?
                || as_u64(grant.fields[10])? > as_u64(parent.fields[10])?
            {
                return Err("delegation_attenuation_invalid".into());
            }
        }
        if as_u64(grant.fields[7])? != 42
            || as_u64(grant.fields[9])? > window.0
            || as_u64(grant.fields[10])? < window.1
        {
            return Err("batch_window_not_covered".into());
        }
        previous = Some(grant);
    }
    let last = grants.last().unwrap();
    let q = &circuit.request.fields;
    let resource = as_u64(q[7])?;
    let action = as_u16(q[8])?;
    if action == 0 || action.count_ones() != 1 || resource != as_u64(last.fields[7])? {
        return Err("request_permission_invalid".into());
    }
    if (action & !as_u16(last.fields[8])?) != 0 {
        return Err("request_not_authorized".into());
    }
    if as_u64(q[9])? < window.0
        || as_u64(q[11])? > window.1
        || as_u64(q[9])? > as_u64(q[11])?
        || q[14] != last.fields[5]
        || q[15] != last.fields[6]
    {
        return Err("request_window_or_terminal_invalid".into());
    }
    let sr_ok = Scheme::verify(
        &circuit.params,
        &circuit.sr_pk,
        &circuit.state_hash(),
        &circuit.sr_sig,
    )
    .map_err(|_| "sr_signature_error")?;
    if !sr_ok
        || circuit.state_status != 1
        || circuit.state_version > u32::MAX as u64
        || circuit.state_expiry < window.1
    {
        return Err("sr_state_invalid".into());
    }
    let mut terminal_bytes = enc(&last.fields[5]);
    terminal_bytes.extend(enc(&last.fields[6]));
    let request_bytes = encode_request(&circuit);
    Ok(NativeReceipt {
        path: path.to_string(),
        grant_ids: grants.iter().map(Grant::id).collect(),
        terminal_bytes,
        request_bytes,
        resource,
        action,
        window_start: window.0,
        window_end: window.1,
    })
}

pub fn validate_for_issuance(
    trusted: &TrustedNativeContext,
    fixture: &AuthFixture,
    path: &str,
    window: (u64, u64),
) -> Result<NativeReceipt, String> {
    admit_state_roots(
        &trusted.authority,
        &trusted.ledger,
        &fixture.base,
        &fixture.all_grants,
        window.0,
    )
    .map_err(|error| format!("admission:{:?}", error))?;
    validate_chain(fixture, path, fixture.circuit_for(path), window)
}

pub fn relation_satisfied(
    fixture: &AuthFixture,
    path: &str,
) -> Result<bool, String> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    fixture
        .circuit_for(path)
        .generate_constraints(cs.clone())
        .map_err(|error| format!("constraint_generation:{:?}", error))?;
    cs.is_satisfied()
        .map_err(|error| format!("constraint_check:{:?}", error))
}

pub fn install_header(fixture: &mut AuthFixture, digest: &[u8; 32], epoch: u64) {
    fixture.base.request.fields[0] = Fr::from_le_bytes_mod_order(&digest[..16]);
    fixture.base.request.fields[1] = Fr::from_le_bytes_mod_order(&digest[16..]);
    fixture.base.request.fields[2] = Fr::from(epoch);
}

pub fn encode_request(circuit: &AuthCircuit) -> Vec<u8> {
    let mut out = b"HRADA-Q16-V1".to_vec();
    for field in circuit.request.fields.iter() {
        let bytes = enc(field);
        out.extend((bytes.len() as u32).to_le_bytes());
        out.extend(bytes);
    }
    out
}

pub fn terminal_public_bytes(fixture: &AuthFixture) -> Vec<u8> {
    let mut out = enc(&fixture.keys[5].0.x);
    out.extend(enc(&fixture.keys[5].0.y));
    out
}

pub fn terminal_sign(fixture: &AuthFixture, message: &[u8]) -> Result<Sig, String> {
    let mut rng = StdRng::from_rng(rand::rngs::OsRng).map_err(|error| error.to_string())?;
    Scheme::sign(
        &fixture.base.params,
        &fixture.keys[5].1,
        &hash(31, message),
        &mut rng,
    )
    .map_err(|error| format!("terminal_sign:{:?}", error))
}

pub fn terminal_verify(
    fixture: &AuthFixture,
    message: &[u8],
    signature: &Sig,
) -> Result<bool, String> {
    Scheme::verify(
        &fixture.base.params,
        &fixture.keys[5].0,
        &hash(31, message),
        signature,
    )
    .map_err(|error| format!("terminal_verify:{:?}", error))
}

pub fn terminal_signature_bytes(signature: &Sig) -> Vec<u8> {
    let mut out = Vec::new();
    signature
        .prover_response
        .write(&mut out)
        .expect("vec write");
    signature
        .verifier_challenge
        .write(&mut out)
        .expect("vec write");
    out
}

fn resign_grant(fixture: &mut AuthFixture, grant_index: usize, issuer_index: usize) {
    let core = fixture.all_grants[grant_index].core();
    fixture.all_grants[grant_index].signature = fixture.issuer_sign(issuer_index, core).unwrap();
}

pub fn mutation_rejected(
    seed: u64,
    path: &str,
    window: (u64, u64),
    mutation: NativeMutation,
) -> Result<bool, String> {
    let mut fixture = AuthFixture::new_with_expiry(seed, 1000);
    let trusted = TrustedNativeContext::from_fixtures(&[&fixture])?;
    let mut trusted_for_case = trusted.clone();
    let mut wrong_terminal = false;
    match mutation {
        NativeMutation::NoEntitlement => trusted_for_case = trusted.without_entitlements(),
        NativeMutation::BadRaSignature => fixture.base.ra_sig = Sig::default(),
        NativeMutation::BadGrantSignature => fixture.all_grants[5].signature = Sig::default(),
        NativeMutation::BadParent => {
            fixture.all_grants[5].parent = [9u8; 32];
            resign_grant(&mut fixture, 5, 3);
        }
        NativeMutation::PermissionExpansion => {
            fixture.all_grants[5].fields[8] = Fr::from(7u64);
            resign_grant(&mut fixture, 5, 3);
        }
        NativeMutation::ExpiredGrant => {
            fixture.all_grants[5].fields[10] = Fr::from(window.1 - 1);
            resign_grant(&mut fixture, 5, 3);
        }
        NativeMutation::BadDepth => {
            fixture.all_grants[5].fields[12] = Fr::from(2u64);
            resign_grant(&mut fixture, 5, 3);
        }
        NativeMutation::InactiveAncestor => fixture.all_grants[5].active = false,
        NativeMutation::WrongTerminal => wrong_terminal = true,
    }
    fixture.refresh_state(fixture.base.prime + Fr::one());
    let result = if wrong_terminal {
        let mut circuit = fixture.circuit_for(path);
        circuit.request.fields[14] += Fr::one();
        admit_state_roots(
            &trusted_for_case.authority,
            &trusted_for_case.ledger,
            &fixture.base,
            &fixture.all_grants,
            window.0,
        )
        .map_err(|error| format!("admission:{:?}", error))
        .and_then(|_| validate_chain(&fixture, path, circuit, window))
    } else {
        validate_for_issuance(&trusted_for_case, &fixture, path, window)
    };
    Ok(result.is_err())
}

/// Digest of the signed grant archive. Active bits are state, not signed grant data.
pub fn grant_signed_archive_digest(fixture: &AuthFixture) -> Hash {
    let mut bytes = Vec::new();
    for grant in fixture.all_grants.iter() {
        bytes.extend(grant.id());
    }
    hash(30, &bytes)
}
