//! Fixed-length typed-policy relation for the Mir-DAC wrapper.
//!
//! This module is the next circuit layer after the stage-1 singleton gate. It
//! verifies one fixed-size SPSEQ-UC signature, proves that every typed field is
//! a member of its signed set commitment, enforces delegation attenuation and
//! checks per-enabled-slot VB accumulator non-membership, authenticates private
//! source and root-grant membership under RA/state roots, and binds the typed
//! public header and request. The external terminal signature and atomic
//! Delta=0 commit are implemented by `service_adapter`; runner evidence and
//! the paired raw-record/service experiment remain completion obligations.

use crate::{
    enforce_non_identity, enforce_pairing_product_is_one, new_g1_subgroup_witness,
    new_g2_subgroup_witness, DacEngine,
};
use ark_bls12_377::{constraints::G1Var, Fq, Fr, G1Affine, G2Affine};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    },
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveConfig};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBitsGadget,
    fields::{fp::FpVar, FieldVar},
    groups::CurveVar,
    pairing::PairingVar as PairingVarTrait,
    prelude::{Boolean, CondSelectGadget, EqGadget, R1CSVar},
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use blake2::{Blake2s256, Digest};
use core::cmp::Ordering;
use delegatable_credentials::{
    msbm::{keys::RootIssuerPublicKey, sps_eq_uc_sig::Signature},
    set_commitment::SetCommitment,
};
use std::sync::OnceLock;
use vb_accumulator::{setup::PublicKey as AccumulatorPublicKey, witness::NonMembershipWitness};

const FIELD_COUNT: usize = 16;
const VALUE_BITS: usize = 192;
const POSEIDON_FULL_ROUNDS: usize = 8;
const POSEIDON_PARTIAL_ROUNDS: usize = 57;
const POSEIDON_ALPHA: u64 = 5;
const POSEIDON_RATE: usize = 2;
const POSEIDON_CAPACITY: usize = 1;
const RECORD_DOMAIN: u64 = 0x4441_4352;

// This permutation is instantiated over BLS12-377 Fq because Fq is the
// BW6-761 Groth16 constraint scalar field.  Do not silently move it to the
// BLS12-377 scalar field Fr: 5 divides Fr::MODULUS - 1, so x^5 is not a
// permutation there.  The round schedule is the Poseidon reference
// calculator's M=128, t=3, alpha=5 schedule with its prescribed margin.  The
// field-specific derivation and primary-source links are recorded in
// POSEIDON_PARAMETERS.md.

#[repr(u8)]
#[derive(Clone, Copy)]
enum GrantField {
    Enabled = 1,
    Padding = 2,
    Issuer = 3,
    Subject = 4,
    Resource = 5,
    Actions = 6,
    Lo = 7,
    Hi = 8,
    NotBefore = 9,
    Expiry = 10,
    RemainingDepth = 11,
    Serial = 12,
    ParentDigestLo = 13,
    ParentDigestHi = 14,
    Schema = 15,
    Policy = 16,
}

#[repr(u64)]
#[derive(Clone, Copy)]
enum BridgeDomain {
    IssuerKey = 0x4441_0101,
    RaLeaf = 0x4441_0102,
    StateLeaf = 0x4441_0103,
    TreeNode = 0x4441_0104,
    RootCommitment = 0x4441_0105,
    Header = 0x4441_0106,
    Request = 0x4441_0107,
    RootGrantLeaf = 0x4441_0108,
    OwnerCommitment = 0x4441_0109,
}

fn poseidon_config() -> &'static PoseidonConfig<Fq> {
    static CONFIG: OnceLock<PoseidonConfig<Fq>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fq>(
            Fq::MODULUS_BIT_SIZE as u64,
            POSEIDON_RATE,
            POSEIDON_FULL_ROUNDS as u64,
            POSEIDON_PARTIAL_ROUNDS as u64,
            0,
        );
        PoseidonConfig::new(
            POSEIDON_FULL_ROUNDS,
            POSEIDON_PARTIAL_ROUNDS,
            POSEIDON_ALPHA,
            mds,
            ark,
            POSEIDON_RATE,
            POSEIDON_CAPACITY,
        )
    })
}

pub fn poseidon_parameter_descriptor() -> &'static str {
    "plan-a-dac-record-poseidon-v1|BLS12-377-Fq-377bit|M=128|t=3|rate=2|capacity=1|alpha=5|RF=8|RP=57|arkworks-0.4-grain-lfsr|skip-matrices=0"
}

fn modulus_mod_five<F: PrimeField>() -> u64 {
    // 2^64 == 1 (mod 5), so summing the little-endian u64 limbs gives the
    // prime modulus modulo 5 without introducing a bigint dependency.
    F::MODULUS
        .as_ref()
        .iter()
        .fold(0u64, |acc, limb| (acc + (limb % 5)) % 5)
}

/// `true` exactly when the configured x^5 S-box is a permutation over the
/// native record-hash field.  Since 5 is prime this is equivalent to
/// `gcd(5, Fq::MODULUS - 1) = 1`.
pub fn poseidon_alpha_is_permutation_over_hash_fq() -> bool {
    modulus_mod_five::<Fq>() != 1
}

/// This deliberately returns false for BLS12-377 Fr.  It is exposed as a
/// regression guard against accidentally moving the Fq Poseidon instance into
/// the set-commitment scalar field merely because typed members live in Fr.
pub fn poseidon_alpha_is_permutation_over_commitment_fr() -> bool {
    modulus_mod_five::<Fr>() != 1
}

pub fn poseidon_parameter_fingerprint() -> String {
    let mut bytes = Vec::new();
    for row in &poseidon_config().ark {
        for value in row {
            value.serialize_compressed(&mut bytes).expect("vec writer");
        }
    }
    for row in &poseidon_config().mds {
        for value in row {
            value.serialize_compressed(&mut bytes).expect("vec writer");
        }
    }
    Blake2s256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bridge_hash(domain: BridgeDomain, fields: &[Fq]) -> Fq {
    let header = [
        Fq::from(RELATION_VERSION_FOR_RECORD_HASH),
        Fq::from(domain as u64),
        Fq::from(fields.len() as u64),
    ];
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&header.as_slice());
    sponge.absorb(&fields);
    sponge.squeeze_native_field_elements(1)[0]
}

fn bridge_hash_var(
    domain: BridgeDomain,
    fields: &[FpVar<Fq>],
) -> Result<FpVar<Fq>, SynthesisError> {
    let cs = fields
        .first()
        .map(|field| field.cs())
        .unwrap_or(ConstraintSystemRef::None);
    let header = vec![
        FpVar::constant(Fq::from(RELATION_VERSION_FOR_RECORD_HASH)),
        FpVar::constant(Fq::from(domain as u64)),
        FpVar::constant(Fq::from(fields.len() as u64)),
    ];
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&header)?;
    sponge.absorb(&fields.to_vec())?;
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}

fn issuer_key_fields(issuer_pk: &RootIssuerPublicKey<DacEngine>) -> Vec<Fq> {
    let mut fields = vec![
        Fq::from(issuer_pk.X.0.len() as u64),
        issuer_pk.X_0.x,
        issuer_pk.X_0.y,
        issuer_pk.X_0_hat.x.c0,
        issuer_pk.X_0_hat.x.c1,
        issuer_pk.X_0_hat.y.c0,
        issuer_pk.X_0_hat.y.c1,
    ];
    for point in &issuer_pk.X.0 {
        fields.extend([point.x.c0, point.x.c1, point.y.c0, point.y.c1]);
    }
    fields
}

pub fn issuer_key_digest(issuer_pk: &RootIssuerPublicKey<DacEngine>) -> Fq {
    bridge_hash(BridgeDomain::IssuerKey, &issuer_key_fields(issuer_pk))
}

pub fn owner_commitment(
    logical_owner: u64,
    mapping_version: u64,
    registration_salt_lo: u64,
    registration_salt_hi: u64,
    issuer_pk: &RootIssuerPublicKey<DacEngine>,
) -> Fq {
    bridge_hash(
        BridgeDomain::OwnerCommitment,
        &[
            Fq::from(logical_owner),
            Fq::from(mapping_version),
            issuer_key_digest(issuer_pk),
            Fq::from(registration_salt_lo),
            Fq::from(registration_salt_hi),
        ],
    )
}

pub fn root_commitment_digest(commitment: &SetCommitment<DacEngine>) -> Fq {
    bridge_hash(
        BridgeDomain::RootCommitment,
        &[commitment.0.x, commitment.0.y],
    )
}

pub fn root_grant_leaf(record: &GrantRecord, commitment: &SetCommitment<DacEngine>) -> Fq {
    bridge_hash(
        BridgeDomain::RootGrantLeaf,
        &[
            Fq::from(1u64),
            root_commitment_digest(commitment),
            record_digest(record, 0),
        ],
    )
}

pub fn entitlement_leaf(
    deployment_id: Fq,
    mapping_version: u64,
    schema_version: u64,
    policy_version: u64,
    issuer_pk: &RootIssuerPublicKey<DacEngine>,
    entitlement: &DacEntitlementWitness,
) -> Fq {
    bridge_hash(
        BridgeDomain::RaLeaf,
        &[
            deployment_id,
            Fq::from(mapping_version),
            Fq::from(schema_version),
            Fq::from(policy_version),
            Fq::from(entitlement.logical_owner),
            owner_commitment(
                entitlement.logical_owner,
                mapping_version,
                entitlement.registration_salt_lo,
                entitlement.registration_salt_hi,
                issuer_pk,
            ),
            Fq::from(entitlement.resource),
            Fq::from(entitlement.action_mask),
            Fq::from(entitlement.interval_lo),
            Fq::from(entitlement.interval_hi),
            Fq::from(entitlement.permit_expiry),
            Fq::from(entitlement.admission_id_lo),
            Fq::from(entitlement.admission_id_hi),
        ],
    )
}

pub fn state_leaf(
    deployment_id: Fq,
    mapping_version: u64,
    schema_version: u64,
    policy_version: u64,
    state: &DacStateWitness,
) -> Fq {
    bridge_hash(
        BridgeDomain::StateLeaf,
        &[
            deployment_id,
            Fq::from(mapping_version),
            Fq::from(schema_version),
            Fq::from(policy_version),
            Fq::from(state.logical_owner),
            state.owner_commitment,
            state.grant_root,
            Fq::from(state.state_version),
            Fq::from(state.state_epoch),
            Fq::from(state.state_expiry),
            Fq::from(state.active as u64),
            Fq::from(state.salt_lo),
            Fq::from(state.salt_hi),
            Fq::from(state.position),
        ],
    )
}

pub fn merkle_root(leaf: Fq, path: &DacMerklePath) -> Option<Fq> {
    if path.siblings.len() != path.directions.len() {
        return None;
    }
    Some(path.siblings.iter().zip(path.directions.iter()).fold(
        leaf,
        |current, (sibling, right)| {
            if *right {
                bridge_hash(BridgeDomain::TreeNode, &[*sibling, current])
            } else {
                bridge_hash(BridgeDomain::TreeNode, &[current, *sibling])
            }
        },
    ))
}

pub fn tree_node_hash(left: Fq, right: Fq) -> Fq {
    bridge_hash(BridgeDomain::TreeNode, &[left, right])
}

/// Constants fixed into one wrapper proving/verifying key.
#[derive(Clone)]
pub struct FixedPolicyDeployment {
    pub relation_version: u64,
    pub l_max: usize,
    pub ra_depth: usize,
    pub state_depth: usize,
    pub grant_depth: usize,
    pub p1: G1Affine,
    pub p2: G2Affine,
    pub s_p2: G2Affine,
    pub accumulator_p: G1Affine,
    pub accumulator_p_tilde: G2Affine,
    pub accumulator_pk: AccumulatorPublicKey<DacEngine>,
}

/// Verifier-visible values. The logical IDs are deployment registry IDs whose
/// mapping to backend keys is authenticated by the later RA/state bridge.
#[derive(Clone)]
pub struct FixedPolicyStatement {
    pub deployment_id: Fq,
    pub tuple_version: u64,
    pub ra_root: Fq,
    pub state_root: Fq,
    pub state_epoch: u64,
    pub revocation_epoch: u64,
    pub issued_at: u64,
    pub mapping_version: u64,
    pub header_digest: Fq,
    pub canonical_request_lo: [u64; 2],
    pub canonical_request_hi: [u64; 2],
    pub circuit_id: Fq,
    pub verifier_id: Fq,
    pub pep_id: Fq,
    pub nonce: Fq,
    pub context: Fq,
    pub request_digest: Fq,
    pub terminal: u64,
    pub terminal_key: G1Affine,
    pub resource: u64,
    pub one_hot_action: u64,
    pub request_lo: u64,
    pub request_hi: u64,
    pub now: u64,
    pub policy_version: u64,
    pub schema_version: u64,
    pub accumulator_value: G1Affine,
}

#[derive(Clone, Debug)]
pub struct DacMerklePath {
    pub siblings: Vec<Fq>,
    pub directions: Vec<bool>,
}

/// DAC-native opening of the paired semantic RA entitlement.  The source's
/// SPSEQ issuer key is private and authenticated by this leaf; it is not fixed
/// in the wrapper VK, which would reveal the source by key selection.
#[derive(Clone)]
pub struct DacEntitlementWitness {
    pub logical_owner: u64,
    pub registration_salt_lo: u64,
    pub registration_salt_hi: u64,
    pub resource: u64,
    pub action_mask: u64,
    pub interval_lo: u64,
    pub interval_hi: u64,
    pub permit_expiry: u64,
    pub admission_id_lo: u64,
    pub admission_id_hi: u64,
    pub position: u64,
    pub path: DacMerklePath,
}

#[derive(Clone)]
pub struct DacStateWitness {
    pub logical_owner: u64,
    pub owner_commitment: Fq,
    pub grant_root: Fq,
    pub root_grant_position: u64,
    pub root_grant_path: DacMerklePath,
    pub state_version: u64,
    pub state_epoch: u64,
    pub state_expiry: u64,
    pub active: bool,
    pub salt_lo: u64,
    pub salt_hi: u64,
    pub position: u64,
    pub path: DacMerklePath,
}

/// Canonical typed values in one real or padding delegation slot.
#[derive(Clone, Debug)]
pub struct GrantRecord {
    pub enabled: bool,
    pub issuer: u64,
    pub subject: u64,
    pub resource: u64,
    pub actions: u64,
    pub lo: u64,
    pub hi: u64,
    pub not_before: u64,
    pub expiry: u64,
    pub remaining_depth: u64,
    pub serial_lo: u64,
    pub serial_hi: u64,
    /// Exact 384-bit little-endian container for the previous record's
    /// native-Fq Poseidon digest.  Each half is three u64 limbs (192 bits);
    /// the top seven bits of the high half are constrained to zero because Fq
    /// is 377 bits.  Nothing from the Fq digest is truncated.
    pub parent_digest_lo: [u64; 3],
    pub parent_digest_hi: [u64; 3],
    pub schema_version: u64,
    pub policy_version: u64,
}

/// A quotient is supplied after removing each required typed field. Chaining
/// all 16 quotient equations and ending at `opening_randomness * P1` proves an
/// exact opening to the canonical record, so duplicate tags and extra members
/// are rejected rather than delegated to an honest-issuer premise.
#[derive(Clone)]
pub struct FixedPolicySlotWitness {
    pub record: GrantRecord,
    pub commitment: SetCommitment<DacEngine>,
    /// Quotient chain after removing the first 1, 2, ..., 16 canonical
    /// members. The final point must equal `opening_randomness * P1`, proving
    /// that no extra or duplicate-tag member remains.
    pub exact_opening_quotients: Vec<G1Affine>,
    pub opening_randomness: Fr,
    pub non_membership_witness: NonMembershipWitness<G1Affine>,
}

#[derive(Clone)]
pub struct FixedPolicyWitness {
    pub issuer_pk: RootIssuerPublicKey<DacEngine>,
    pub entitlement: DacEntitlementWitness,
    pub state: DacStateWitness,
    pub slots: Vec<FixedPolicySlotWitness>,
    pub signature: Signature<DacEngine>,
}

#[derive(Clone)]
pub struct FixedPolicyCircuit {
    pub deployment: FixedPolicyDeployment,
    pub statement: FixedPolicyStatement,
    pub witness: FixedPolicyWitness,
}

fn pack_u128_native(limbs: [u64; 2]) -> Fq {
    Fq::from(limbs[0]) + Fq::from(limbs[1]) * Fq::from(2u64).pow([64])
}

pub fn compute_header_digest(statement: &FixedPolicyStatement) -> Fq {
    bridge_hash(
        BridgeDomain::Header,
        &[
            statement.deployment_id,
            Fq::from(statement.tuple_version),
            statement.ra_root,
            statement.state_root,
            statement.accumulator_value.x,
            statement.accumulator_value.y,
            Fq::from(statement.state_epoch),
            Fq::from(statement.revocation_epoch),
            Fq::from(statement.issued_at),
            Fq::from(statement.mapping_version),
            Fq::from(statement.policy_version),
            Fq::from(statement.schema_version),
        ],
    )
}

pub fn compute_request_digest(statement: &FixedPolicyStatement) -> Fq {
    bridge_hash(
        BridgeDomain::Request,
        &[
            pack_u128_native(statement.canonical_request_lo),
            pack_u128_native(statement.canonical_request_hi),
            statement.circuit_id,
            statement.verifier_id,
            statement.pep_id,
            Fq::from(statement.resource),
            Fq::from(statement.one_hot_action),
            Fq::from(statement.request_lo),
            Fq::from(statement.request_hi),
            Fq::from(statement.now),
            statement.nonce,
            statement.context,
            Fq::from(statement.terminal),
            statement.terminal_key.x,
            statement.terminal_key.y,
            statement.header_digest,
        ],
    )
}

#[derive(Clone)]
struct U64Var {
    value: FpVar<Fq>,
    bits: Vec<Boolean<Fq>>,
}

#[derive(Clone)]
struct RecordVar {
    enabled: Boolean<Fq>,
    issuer: U64Var,
    subject: U64Var,
    resource: U64Var,
    actions: U64Var,
    lo: U64Var,
    hi: U64Var,
    not_before: U64Var,
    expiry: U64Var,
    remaining_depth: U64Var,
    serial_lo: U64Var,
    serial_hi: U64Var,
    parent_digest_lo: Vec<U64Var>,
    parent_digest_hi: Vec<U64Var>,
    schema_version: U64Var,
    policy_version: U64Var,
}

fn alloc_u64(
    cs: ConstraintSystemRef<Fq>,
    value: u64,
    mode: AllocationMode,
) -> Result<U64Var, SynthesisError> {
    let var = FpVar::<Fq>::new_variable(cs, || Ok(Fq::from(value)), mode)?;
    let all_bits = var.to_bits_le()?;
    for bit in all_bits.iter().skip(64) {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(U64Var {
        value: var,
        bits: all_bits[..64].to_vec(),
    })
}

fn pack_u128_var(limbs: &[U64Var; 2]) -> FpVar<Fq> {
    &limbs[0].value + &limbs[1].value * Fq::from(2u64).pow([64])
}

fn const_bits(value: u64, width: usize) -> Vec<Boolean<Fq>> {
    (0..width)
        .map(|i| Boolean::constant(((value >> i) & 1) == 1))
        .collect()
}

fn typed_member_bits(
    field: GrantField,
    slot: usize,
    value_bits: &[Boolean<Fq>],
) -> Result<Vec<Boolean<Fq>>, SynthesisError> {
    if value_bits.len() > VALUE_BITS || slot > u16::MAX as usize {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut bits = value_bits.to_vec();
    bits.resize(VALUE_BITS, Boolean::FALSE);
    bits.extend(const_bits(field as u64, 8));
    bits.extend(const_bits(slot as u64, 16));
    Ok(bits)
}

fn encode_typed_native(field: GrantField, slot: usize, value: [u64; 3]) -> Fr {
    assert!(slot <= u16::MAX as usize);
    let mut bytes = [0u8; 32];
    for (i, limb) in value.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb.to_le_bytes());
    }
    bytes[24] = field as u8;
    bytes[25..27].copy_from_slice(&(slot as u16).to_le_bytes());
    Fr::from_le_bytes_mod_order(&bytes)
}

fn value_u64(value: u64) -> [u64; 3] {
    [value, 0, 0]
}

fn value_u128(lo: u64, hi: u64) -> [u64; 3] {
    [lo, hi, 0]
}

pub fn record_digest(record: &GrantRecord, slot: usize) -> Fq {
    let mut fields = vec![
        Fq::from(record.enabled as u64),
        Fq::from(record.issuer),
        Fq::from(record.subject),
        Fq::from(record.resource),
        Fq::from(record.actions),
        Fq::from(record.lo),
        Fq::from(record.hi),
        Fq::from(record.not_before),
        Fq::from(record.expiry),
        Fq::from(record.remaining_depth),
        Fq::from(record.serial_lo),
        Fq::from(record.serial_hi),
    ];
    fields.extend(record.parent_digest_lo.iter().copied().map(Fq::from));
    fields.extend(record.parent_digest_hi.iter().copied().map(Fq::from));
    fields.push(Fq::from(record.schema_version));
    fields.push(Fq::from(record.policy_version));
    let header = [
        Fq::from(RELATION_VERSION_FOR_RECORD_HASH),
        Fq::from(RECORD_DOMAIN),
        Fq::from(fields.len() as u64),
        Fq::from(slot as u64),
    ];
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&header.as_slice());
    sponge.absorb(&fields.as_slice());
    sponge.squeeze_native_field_elements(1)[0]
}

const RELATION_VERSION_FOR_RECORD_HASH: u64 = 2;

pub fn split_record_digest(digest: Fq) -> ([u64; 3], [u64; 3]) {
    let mut bits = digest.into_bigint().to_bits_le();
    bits.resize(384, false);
    let limb = |offset: usize| -> u64 {
        (0..64).fold(0u64, |acc, i| acc | ((bits[offset + i] as u64) << i))
    };
    (
        [limb(0), limb(64), limb(128)],
        [limb(192), limb(256), limb(320)],
    )
}

/// Native canonical set in the exact field order expected by the circuit.
/// This is used only to issue/open the Dock commitment; authorization reads
/// the separately constrained typed variables rather than trusting this helper.
pub fn encode_record(record: &GrantRecord, slot: usize) -> Vec<Fr> {
    vec![
        encode_typed_native(GrantField::Enabled, slot, value_u64(record.enabled as u64)),
        encode_typed_native(
            GrantField::Padding,
            slot,
            value_u64((!record.enabled) as u64),
        ),
        encode_typed_native(GrantField::Issuer, slot, value_u64(record.issuer)),
        encode_typed_native(GrantField::Subject, slot, value_u64(record.subject)),
        encode_typed_native(GrantField::Resource, slot, value_u64(record.resource)),
        encode_typed_native(GrantField::Actions, slot, value_u64(record.actions)),
        encode_typed_native(GrantField::Lo, slot, value_u64(record.lo)),
        encode_typed_native(GrantField::Hi, slot, value_u64(record.hi)),
        encode_typed_native(GrantField::NotBefore, slot, value_u64(record.not_before)),
        encode_typed_native(GrantField::Expiry, slot, value_u64(record.expiry)),
        encode_typed_native(
            GrantField::RemainingDepth,
            slot,
            value_u64(record.remaining_depth),
        ),
        encode_typed_native(
            GrantField::Serial,
            slot,
            value_u128(record.serial_lo, record.serial_hi),
        ),
        encode_typed_native(GrantField::ParentDigestLo, slot, record.parent_digest_lo),
        encode_typed_native(GrantField::ParentDigestHi, slot, record.parent_digest_hi),
        encode_typed_native(GrantField::Schema, slot, value_u64(record.schema_version)),
        encode_typed_native(GrantField::Policy, slot, value_u64(record.policy_version)),
    ]
}

fn enforce_if(condition: &Boolean<Fq>, predicate: &Boolean<Fq>) -> Result<(), SynthesisError> {
    predicate.conditional_enforce_equal(&Boolean::TRUE, condition)
}

fn enforce_less_than_constant_bits(
    value_bits_le: &[Boolean<Fq>],
    bound_bits_le: &[bool],
) -> Result<(), SynthesisError> {
    if value_bits_le.len() != bound_bits_le.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut equal_prefix = Boolean::TRUE;
    let mut is_less = Boolean::FALSE;
    for (value, bound) in value_bits_le.iter().zip(bound_bits_le.iter()).rev() {
        if *bound {
            is_less = is_less.or(&equal_prefix.and(&value.not())?)?;
            equal_prefix = equal_prefix.and(value)?;
        } else {
            equal_prefix = equal_prefix.and(&value.not())?;
        }
    }
    is_less.enforce_equal(&Boolean::TRUE)
}

fn enforce_le_if(
    left: &FpVar<Fq>,
    right: &FpVar<Fq>,
    condition: &Boolean<Fq>,
) -> Result<(), SynthesisError> {
    let ok = left.is_cmp(right, Ordering::Less, true)?;
    enforce_if(condition, &ok)
}

fn enforce_g1_subgroup_image(
    cs: ConstraintSystemRef<Fq>,
    claimed: &G1Var,
    value: G1Affine,
) -> Result<(), SynthesisError> {
    let preimage = value.mul_by_cofactor_inv();
    let raw = G1Var::new_variable_omit_prime_order_check(
        cs,
        || Ok(preimage.into_group()),
        AllocationMode::Witness,
    )?;
    let cofactor_bits = <ark_bls12_377::g1::Config as CurveConfig>::COFACTOR
        .iter()
        .flat_map(|limb| (0..64).map(move |i| Boolean::constant(((limb >> i) & 1) == 1)))
        .collect::<Vec<_>>();
    raw.scalar_mul_le(cofactor_bits.iter())?
        .enforce_equal(claimed)
}

fn issuer_key_fields_var(
    issuer_x0: &G1Var,
    issuer_x0_hat: &ark_bls12_377::constraints::G2Var,
    issuer_x: &[ark_bls12_377::constraints::G2Var],
) -> Result<Vec<FpVar<Fq>>, SynthesisError> {
    let x0 = issuer_x0.to_affine()?;
    let x0_hat = issuer_x0_hat.to_affine()?;
    let mut fields = vec![
        FpVar::constant(Fq::from(issuer_x.len() as u64)),
        x0.x,
        x0.y,
        x0_hat.x.c0,
        x0_hat.x.c1,
        x0_hat.y.c0,
        x0_hat.y.c1,
    ];
    for point in issuer_x {
        let affine = point.to_affine()?;
        fields.extend([affine.x.c0, affine.x.c1, affine.y.c0, affine.y.c1]);
    }
    Ok(fields)
}

fn path_root_var(
    cs: ConstraintSystemRef<Fq>,
    leaf: FpVar<Fq>,
    path: &DacMerklePath,
    position: &U64Var,
    expected_depth: usize,
) -> Result<FpVar<Fq>, SynthesisError> {
    if path.siblings.len() != expected_depth
        || path.directions.len() != expected_depth
        || expected_depth > 64
    {
        return Err(SynthesisError::Unsatisfiable);
    }
    for bit in position.bits.iter().skip(expected_depth) {
        bit.enforce_equal(&Boolean::FALSE)?;
    }
    let mut current = leaf;
    for (level, (sibling, right)) in path.siblings.iter().zip(path.directions.iter()).enumerate() {
        let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
        let right = Boolean::new_witness(cs.clone(), || Ok(*right))?;
        right.enforce_equal(&position.bits[level])?;
        let left = FpVar::conditionally_select(&right, &sibling, &current)?;
        let right_value = FpVar::conditionally_select(&right, &current, &sibling)?;
        current = bridge_hash_var(BridgeDomain::TreeNode, &[left, right_value])?;
    }
    Ok(current)
}

fn enforce_typed_membership(
    current_commitment: &G1Var,
    quotient: &G1Var,
    member_bits: &[Boolean<Fq>],
    p2: &ark_bls12_377::constraints::G2Var,
    s_p2: &ark_bls12_377::constraints::G2Var,
) -> Result<(), SynthesisError> {
    // e(Q_i, (s-m_i)P2) = e(Q_{i-1}, P2).
    let divisor = s_p2 - &p2.scalar_mul_le(member_bits.iter())?;
    enforce_pairing_product_is_one(
        &[quotient.clone(), current_commitment.negate()?],
        &[divisor, p2.clone()],
    )
}

fn alloc_record(
    cs: ConstraintSystemRef<Fq>,
    record: &GrantRecord,
) -> Result<RecordVar, SynthesisError> {
    let parent_digest_lo = record
        .parent_digest_lo
        .iter()
        .map(|value| alloc_u64(cs.clone(), *value, AllocationMode::Witness))
        .collect::<Result<Vec<_>, _>>()?;
    let parent_digest_hi = record
        .parent_digest_hi
        .iter()
        .map(|value| alloc_u64(cs.clone(), *value, AllocationMode::Witness))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RecordVar {
        enabled: Boolean::new_witness(cs.clone(), || Ok(record.enabled))?,
        issuer: alloc_u64(cs.clone(), record.issuer, AllocationMode::Witness)?,
        subject: alloc_u64(cs.clone(), record.subject, AllocationMode::Witness)?,
        resource: alloc_u64(cs.clone(), record.resource, AllocationMode::Witness)?,
        actions: alloc_u64(cs.clone(), record.actions, AllocationMode::Witness)?,
        lo: alloc_u64(cs.clone(), record.lo, AllocationMode::Witness)?,
        hi: alloc_u64(cs.clone(), record.hi, AllocationMode::Witness)?,
        not_before: alloc_u64(cs.clone(), record.not_before, AllocationMode::Witness)?,
        expiry: alloc_u64(cs.clone(), record.expiry, AllocationMode::Witness)?,
        remaining_depth: alloc_u64(cs.clone(), record.remaining_depth, AllocationMode::Witness)?,
        serial_lo: alloc_u64(cs.clone(), record.serial_lo, AllocationMode::Witness)?,
        serial_hi: alloc_u64(cs.clone(), record.serial_hi, AllocationMode::Witness)?,
        parent_digest_lo,
        parent_digest_hi,
        schema_version: alloc_u64(cs.clone(), record.schema_version, AllocationMode::Witness)?,
        policy_version: alloc_u64(cs, record.policy_version, AllocationMode::Witness)?,
    })
}

fn record_members(
    record: &RecordVar,
    slot: usize,
) -> Result<Vec<Vec<Boolean<Fq>>>, SynthesisError> {
    let mut serial = record.serial_lo.bits.clone();
    serial.extend(record.serial_hi.bits.clone());
    let parent_digest_lo = record
        .parent_digest_lo
        .iter()
        .flat_map(|limb| limb.bits.clone())
        .collect::<Vec<_>>();
    let parent_digest_hi = record
        .parent_digest_hi
        .iter()
        .flat_map(|limb| limb.bits.clone())
        .collect::<Vec<_>>();
    Ok(vec![
        typed_member_bits(GrantField::Enabled, slot, &[record.enabled.clone()])?,
        typed_member_bits(GrantField::Padding, slot, &[record.enabled.not()])?,
        typed_member_bits(GrantField::Issuer, slot, &record.issuer.bits)?,
        typed_member_bits(GrantField::Subject, slot, &record.subject.bits)?,
        typed_member_bits(GrantField::Resource, slot, &record.resource.bits)?,
        typed_member_bits(GrantField::Actions, slot, &record.actions.bits)?,
        typed_member_bits(GrantField::Lo, slot, &record.lo.bits)?,
        typed_member_bits(GrantField::Hi, slot, &record.hi.bits)?,
        typed_member_bits(GrantField::NotBefore, slot, &record.not_before.bits)?,
        typed_member_bits(GrantField::Expiry, slot, &record.expiry.bits)?,
        typed_member_bits(
            GrantField::RemainingDepth,
            slot,
            &record.remaining_depth.bits,
        )?,
        typed_member_bits(GrantField::Serial, slot, &serial)?,
        typed_member_bits(GrantField::ParentDigestLo, slot, &parent_digest_lo)?,
        typed_member_bits(GrantField::ParentDigestHi, slot, &parent_digest_hi)?,
        typed_member_bits(GrantField::Schema, slot, &record.schema_version.bits)?,
        typed_member_bits(GrantField::Policy, slot, &record.policy_version.bits)?,
    ])
}

fn record_digest_var(
    cs: ConstraintSystemRef<Fq>,
    record: &RecordVar,
    slot: usize,
) -> Result<FpVar<Fq>, SynthesisError> {
    let mut fields = vec![
        FpVar::from(record.enabled.clone()),
        record.issuer.value.clone(),
        record.subject.value.clone(),
        record.resource.value.clone(),
        record.actions.value.clone(),
        record.lo.value.clone(),
        record.hi.value.clone(),
        record.not_before.value.clone(),
        record.expiry.value.clone(),
        record.remaining_depth.value.clone(),
        record.serial_lo.value.clone(),
        record.serial_hi.value.clone(),
    ];
    fields.extend(
        record
            .parent_digest_lo
            .iter()
            .map(|limb| limb.value.clone()),
    );
    fields.extend(
        record
            .parent_digest_hi
            .iter()
            .map(|limb| limb.value.clone()),
    );
    fields.push(record.schema_version.value.clone());
    fields.push(record.policy_version.value.clone());
    let header = vec![
        FpVar::constant(Fq::from(RELATION_VERSION_FOR_RECORD_HASH)),
        FpVar::constant(Fq::from(RECORD_DOMAIN)),
        FpVar::constant(Fq::from(fields.len() as u64)),
        FpVar::constant(Fq::from(slot as u64)),
    ];
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&header)?;
    sponge.absorb(&fields)?;
    Ok(sponge.squeeze_field_elements(1)?.remove(0))
}

impl ConstraintSynthesizer<Fq> for FixedPolicyCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fq>) -> Result<(), SynthesisError> {
        let l_max = self.deployment.l_max;
        if l_max == 0
            || self.deployment.relation_version != RELATION_VERSION_FOR_RECORD_HASH
            || self.witness.slots.len() != l_max
            || self.witness.issuer_pk.X.0.len() != l_max
            || self
                .witness
                .slots
                .iter()
                .any(|slot| slot.exact_opening_quotients.len() != FIELD_COUNT)
        {
            return Err(SynthesisError::Unsatisfiable);
        }

        let deployment_id = FpVar::new_input(cs.clone(), || Ok(self.statement.deployment_id))?;
        let tuple_version = alloc_u64(
            cs.clone(),
            self.statement.tuple_version,
            AllocationMode::Input,
        )?;
        let ra_root = FpVar::new_input(cs.clone(), || Ok(self.statement.ra_root))?;
        let state_root = FpVar::new_input(cs.clone(), || Ok(self.statement.state_root))?;
        let state_epoch = alloc_u64(
            cs.clone(),
            self.statement.state_epoch,
            AllocationMode::Input,
        )?;
        let revocation_epoch = alloc_u64(
            cs.clone(),
            self.statement.revocation_epoch,
            AllocationMode::Input,
        )?;
        let issued_at = alloc_u64(cs.clone(), self.statement.issued_at, AllocationMode::Input)?;
        let mapping_version = alloc_u64(
            cs.clone(),
            self.statement.mapping_version,
            AllocationMode::Input,
        )?;
        let header_digest = FpVar::new_input(cs.clone(), || Ok(self.statement.header_digest))?;
        let canonical_request_lo = [
            alloc_u64(
                cs.clone(),
                self.statement.canonical_request_lo[0],
                AllocationMode::Input,
            )?,
            alloc_u64(
                cs.clone(),
                self.statement.canonical_request_lo[1],
                AllocationMode::Input,
            )?,
        ];
        let canonical_request_hi = [
            alloc_u64(
                cs.clone(),
                self.statement.canonical_request_hi[0],
                AllocationMode::Input,
            )?,
            alloc_u64(
                cs.clone(),
                self.statement.canonical_request_hi[1],
                AllocationMode::Input,
            )?,
        ];
        let circuit_id = FpVar::new_input(cs.clone(), || Ok(self.statement.circuit_id))?;
        let verifier_id = FpVar::new_input(cs.clone(), || Ok(self.statement.verifier_id))?;
        let pep_id = FpVar::new_input(cs.clone(), || Ok(self.statement.pep_id))?;
        let nonce = FpVar::new_input(cs.clone(), || Ok(self.statement.nonce))?;
        let context = FpVar::new_input(cs.clone(), || Ok(self.statement.context))?;
        let request_digest = FpVar::new_input(cs.clone(), || Ok(self.statement.request_digest))?;
        let terminal = alloc_u64(cs.clone(), self.statement.terminal, AllocationMode::Input)?;
        let resource = alloc_u64(cs.clone(), self.statement.resource, AllocationMode::Input)?;
        let one_hot_action = alloc_u64(
            cs.clone(),
            self.statement.one_hot_action,
            AllocationMode::Input,
        )?;
        let request_lo = alloc_u64(cs.clone(), self.statement.request_lo, AllocationMode::Input)?;
        let request_hi = alloc_u64(cs.clone(), self.statement.request_hi, AllocationMode::Input)?;
        let now = alloc_u64(cs.clone(), self.statement.now, AllocationMode::Input)?;
        let policy_version = alloc_u64(
            cs.clone(),
            self.statement.policy_version,
            AllocationMode::Input,
        )?;
        let schema_version = alloc_u64(
            cs.clone(),
            self.statement.schema_version,
            AllocationMode::Input,
        )?;

        // The explicit public relation version prevents reusing a proof across
        // circuit/profile revisions and is fixed by the wrapper key.
        let relation_version = FpVar::new_input(cs.clone(), || {
            Ok(Fq::from(self.deployment.relation_version))
        })?;
        relation_version
            .enforce_equal(&FpVar::constant(Fq::from(self.deployment.relation_version)))?;

        let terminal_key = G1Var::new_input(cs.clone(), || Ok(self.statement.terminal_key))?;
        enforce_g1_subgroup_image(cs.clone(), &terminal_key, self.statement.terminal_key)?;
        enforce_non_identity(&terminal_key)?;
        let accumulator_value =
            G1Var::new_input(cs.clone(), || Ok(self.statement.accumulator_value))?;
        enforce_g1_subgroup_image(
            cs.clone(),
            &accumulator_value,
            self.statement.accumulator_value,
        )?;
        enforce_non_identity(&accumulator_value)?;

        let accumulator_affine = accumulator_value.to_affine()?;
        let expected_header_digest = bridge_hash_var(
            BridgeDomain::Header,
            &[
                deployment_id.clone(),
                tuple_version.value.clone(),
                ra_root.clone(),
                state_root.clone(),
                accumulator_affine.x,
                accumulator_affine.y,
                state_epoch.value.clone(),
                revocation_epoch.value,
                issued_at.value,
                mapping_version.value.clone(),
                policy_version.value.clone(),
                schema_version.value.clone(),
            ],
        )?;
        header_digest.enforce_equal(&expected_header_digest)?;
        let terminal_key_affine = terminal_key.to_affine()?;
        let expected_request_digest = bridge_hash_var(
            BridgeDomain::Request,
            &[
                pack_u128_var(&canonical_request_lo),
                pack_u128_var(&canonical_request_hi),
                circuit_id,
                verifier_id,
                pep_id,
                resource.value.clone(),
                one_hot_action.value.clone(),
                request_lo.value.clone(),
                request_hi.value.clone(),
                now.value.clone(),
                nonce,
                context,
                terminal.value.clone(),
                terminal_key_affine.x,
                terminal_key_affine.y,
                header_digest.clone(),
            ],
        )?;
        request_digest.enforce_equal(&expected_request_digest)?;

        let p1 = G1Var::new_constant(cs.clone(), self.deployment.p1)?;
        let p2 = ark_bls12_377::constraints::G2Var::new_constant(cs.clone(), self.deployment.p2)?;
        let s_p2 =
            ark_bls12_377::constraints::G2Var::new_constant(cs.clone(), self.deployment.s_p2)?;
        let accum_p = G1Var::new_constant(cs.clone(), self.deployment.accumulator_p)?;
        let accum_p_tilde = ark_bls12_377::constraints::G2Var::new_constant(
            cs.clone(),
            self.deployment.accumulator_p_tilde,
        )?;
        let accum_pk = ark_bls12_377::constraints::G2Var::new_constant(
            cs.clone(),
            self.deployment.accumulator_pk.0,
        )?;

        // The per-source issuer key remains private.  Its complete affine
        // encoding is authenticated by both the RA and state leaves below,
        // and every adversary-chosen pairing point gets a subgroup and
        // non-identity check.  X_0 and X_0_hat must encode the same scalar.
        let issuer_x0 = new_g1_subgroup_witness(cs.clone(), self.witness.issuer_pk.X_0)?;
        enforce_non_identity(&issuer_x0)?;
        let issuer_x0_hat = new_g2_subgroup_witness(cs.clone(), self.witness.issuer_pk.X_0_hat)?;
        enforce_non_identity(&issuer_x0_hat)?;
        let issuer_x = self
            .witness
            .issuer_pk
            .X
            .0
            .iter()
            .map(|point| {
                let var = new_g2_subgroup_witness(cs.clone(), *point)?;
                enforce_non_identity(&var)?;
                Ok(var)
            })
            .collect::<Result<Vec<_>, SynthesisError>>()?;
        enforce_pairing_product_is_one(
            &[issuer_x0.clone(), p1.negate()?],
            &[p2.clone(), issuer_x0_hat.clone()],
        )?;
        let issuer_key_digest_var = bridge_hash_var(
            BridgeDomain::IssuerKey,
            &issuer_key_fields_var(&issuer_x0, &issuer_x0_hat, &issuer_x)?,
        )?;

        let mut commitments = Vec::with_capacity(l_max);
        let mut records = Vec::with_capacity(l_max);

        for (slot_index, slot) in self.witness.slots.iter().enumerate() {
            let commitment = new_g1_subgroup_witness(cs.clone(), slot.commitment.0)?;
            enforce_non_identity(&commitment)?;
            let record = alloc_record(cs.clone(), &slot.record)?;
            let member_bits = record_members(&record, slot_index)?;

            let mut quotient_base = commitment.clone();
            for (native_quotient, bits) in
                slot.exact_opening_quotients.iter().zip(member_bits.iter())
            {
                let quotient = new_g1_subgroup_witness(cs.clone(), *native_quotient)?;
                enforce_non_identity(&quotient)?;
                enforce_typed_membership(&quotient_base, &quotient, bits, &p2, &s_p2)?;
                quotient_base = quotient;
            }
            let opening_native = slot.opening_randomness.into_bigint().to_bits_le();
            let opening_bits = opening_native
                .into_iter()
                .map(|bit| Boolean::new_witness(cs.clone(), || Ok(bit)))
                .collect::<Result<Vec<_>, _>>()?;
            let expected_final_quotient = p1.scalar_mul_le(opening_bits.iter())?;
            quotient_base.enforce_equal(&expected_final_quotient)?;

            // The serial used by the signed set membership and the accumulator
            // equation is literally the same 128-bit circuit variable.
            let mut serial_bits = record.serial_lo.bits.clone();
            serial_bits.extend(record.serial_hi.bits.clone());
            let nm_c = new_g1_subgroup_witness(cs.clone(), slot.non_membership_witness.C)?;
            enforce_non_identity(&nm_c)?;
            let d_native = slot.non_membership_witness.d.into_bigint().to_bits_le();
            let d_all_bits = d_native
                .into_iter()
                .map(|bit| Boolean::new_witness(cs.clone(), || Ok(bit)))
                .collect::<Result<Vec<_>, _>>()?;
            let d_width =
                <<DacEngine as Pairing>::ScalarField as PrimeField>::MODULUS_BIT_SIZE as usize;
            for bit in d_all_bits.iter().skip(d_width) {
                bit.enforce_equal(&Boolean::FALSE)?;
            }
            let d_bits = d_all_bits[..d_width].to_vec();
            let modulus_bits =
                <<DacEngine as Pairing>::ScalarField as PrimeField>::MODULUS.to_bits_le();
            enforce_less_than_constant_bits(&d_bits, &modulus_bits[..d_width])?;
            let d_nonzero = Boolean::kary_or(&d_bits)?;
            enforce_if(&record.enabled, &d_nonzero)?;
            let serial_p_tilde = &accum_p_tilde.scalar_mul_le(serial_bits.iter())? + &accum_pk;
            let d_p_minus_v = &accum_p.scalar_mul_le(d_bits.iter())? - &accumulator_value;
            let prepared_g1 = [nm_c, d_p_minus_v]
                .iter()
                .map(ark_bls12_377::constraints::PairingVar::prepare_g1)
                .collect::<Result<Vec<_>, _>>()?;
            let prepared_g2 = [serial_p_tilde, accum_p_tilde.clone()]
                .iter()
                .map(ark_bls12_377::constraints::PairingVar::prepare_g2)
                .collect::<Result<Vec<_>, _>>()?;
            let nm_product = ark_bls12_377::constraints::PairingVar::product_of_pairings(
                &prepared_g1,
                &prepared_g2,
            )?;
            nm_product.conditional_enforce_equal(
                &<ark_bls12_377::constraints::PairingVar as ark_r1cs_std::pairing::PairingVar<
                    DacEngine,
                >>::GTVar::one(),
                &record.enabled,
            )?;

            record
                .serial_lo
                .value
                .conditional_enforce_equal(&FpVar::zero(), &record.enabled.not())?;
            record
                .serial_hi
                .value
                .conditional_enforce_equal(&FpVar::zero(), &record.enabled.not())?;
            record.resource.value.enforce_equal(&resource.value)?;
            record
                .schema_version
                .value
                .enforce_equal(&schema_version.value)?;
            record
                .policy_version
                .value
                .enforce_equal(&policy_version.value)?;
            for bit in record.actions.bits.iter().skip(16) {
                bit.enforce_equal(&Boolean::FALSE)?;
            }
            for bit in record.remaining_depth.bits.iter().skip(8) {
                bit.enforce_equal(&Boolean::FALSE)?;
            }
            enforce_le_if(&record.lo.value, &record.hi.value, &Boolean::TRUE)?;
            enforce_le_if(
                &record.not_before.value,
                &record.expiry.value,
                &Boolean::TRUE,
            )?;

            commitments.push(commitment);
            records.push(record);
        }

        // Authenticate the same hidden logical source and source-specific DAC
        // issuer key under both paired-semantic native roots.  The roots are
        // public header values, while leaf contents and paths remain witness.
        let entitlement_owner = alloc_u64(
            cs.clone(),
            self.witness.entitlement.logical_owner,
            AllocationMode::Witness,
        )?;
        let entitlement_resource = alloc_u64(
            cs.clone(),
            self.witness.entitlement.resource,
            AllocationMode::Witness,
        )?;
        let registration_salt_lo = alloc_u64(
            cs.clone(),
            self.witness.entitlement.registration_salt_lo,
            AllocationMode::Witness,
        )?;
        let registration_salt_hi = alloc_u64(
            cs.clone(),
            self.witness.entitlement.registration_salt_hi,
            AllocationMode::Witness,
        )?;
        let owner_commitment_var = bridge_hash_var(
            BridgeDomain::OwnerCommitment,
            &[
                entitlement_owner.value.clone(),
                mapping_version.value.clone(),
                issuer_key_digest_var.clone(),
                registration_salt_lo.value,
                registration_salt_hi.value,
            ],
        )?;
        let entitlement_actions = alloc_u64(
            cs.clone(),
            self.witness.entitlement.action_mask,
            AllocationMode::Witness,
        )?;
        for bit in entitlement_actions.bits.iter().skip(16) {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        let entitlement_lo = alloc_u64(
            cs.clone(),
            self.witness.entitlement.interval_lo,
            AllocationMode::Witness,
        )?;
        let entitlement_hi = alloc_u64(
            cs.clone(),
            self.witness.entitlement.interval_hi,
            AllocationMode::Witness,
        )?;
        let permit_expiry = alloc_u64(
            cs.clone(),
            self.witness.entitlement.permit_expiry,
            AllocationMode::Witness,
        )?;
        let admission_id_lo = alloc_u64(
            cs.clone(),
            self.witness.entitlement.admission_id_lo,
            AllocationMode::Witness,
        )?;
        let admission_id_hi = alloc_u64(
            cs.clone(),
            self.witness.entitlement.admission_id_hi,
            AllocationMode::Witness,
        )?;
        let entitlement_position = alloc_u64(
            cs.clone(),
            self.witness.entitlement.position,
            AllocationMode::Witness,
        )?;
        enforce_le_if(&entitlement_lo.value, &entitlement_hi.value, &Boolean::TRUE)?;
        enforce_le_if(&entitlement_hi.value, &permit_expiry.value, &Boolean::TRUE)?;
        let ra_leaf_var = bridge_hash_var(
            BridgeDomain::RaLeaf,
            &[
                deployment_id.clone(),
                mapping_version.value.clone(),
                schema_version.value.clone(),
                policy_version.value.clone(),
                entitlement_owner.value.clone(),
                owner_commitment_var.clone(),
                entitlement_resource.value.clone(),
                entitlement_actions.value.clone(),
                entitlement_lo.value.clone(),
                entitlement_hi.value.clone(),
                permit_expiry.value.clone(),
                admission_id_lo.value,
                admission_id_hi.value,
            ],
        )?;
        path_root_var(
            cs.clone(),
            ra_leaf_var,
            &self.witness.entitlement.path,
            &entitlement_position,
            self.deployment.ra_depth,
        )?
        .enforce_equal(&ra_root)?;

        let state_owner = alloc_u64(
            cs.clone(),
            self.witness.state.logical_owner,
            AllocationMode::Witness,
        )?;
        let state_owner_commitment =
            FpVar::new_witness(cs.clone(), || Ok(self.witness.state.owner_commitment))?;
        let state_grant_root =
            FpVar::new_witness(cs.clone(), || Ok(self.witness.state.grant_root))?;
        let root_grant_position = alloc_u64(
            cs.clone(),
            self.witness.state.root_grant_position,
            AllocationMode::Witness,
        )?;
        let state_version = alloc_u64(
            cs.clone(),
            self.witness.state.state_version,
            AllocationMode::Witness,
        )?;
        let witness_state_epoch = alloc_u64(
            cs.clone(),
            self.witness.state.state_epoch,
            AllocationMode::Witness,
        )?;
        let state_expiry = alloc_u64(
            cs.clone(),
            self.witness.state.state_expiry,
            AllocationMode::Witness,
        )?;
        let state_active = Boolean::new_witness(cs.clone(), || Ok(self.witness.state.active))?;
        let state_salt_lo = alloc_u64(
            cs.clone(),
            self.witness.state.salt_lo,
            AllocationMode::Witness,
        )?;
        let state_salt_hi = alloc_u64(
            cs.clone(),
            self.witness.state.salt_hi,
            AllocationMode::Witness,
        )?;
        let state_position = alloc_u64(
            cs.clone(),
            self.witness.state.position,
            AllocationMode::Witness,
        )?;
        let root_commitment_affine = commitments[0].to_affine()?;
        let root_commitment_digest_var = bridge_hash_var(
            BridgeDomain::RootCommitment,
            &[root_commitment_affine.x, root_commitment_affine.y],
        )?;
        let root_record_digest_var = record_digest_var(cs.clone(), &records[0], 0)?;
        let root_grant_leaf_var = bridge_hash_var(
            BridgeDomain::RootGrantLeaf,
            &[
                FpVar::one(),
                root_commitment_digest_var,
                root_record_digest_var,
            ],
        )?;
        path_root_var(
            cs.clone(),
            root_grant_leaf_var,
            &self.witness.state.root_grant_path,
            &root_grant_position,
            self.deployment.grant_depth,
        )?
        .enforce_equal(&state_grant_root)?;
        let state_leaf_var = bridge_hash_var(
            BridgeDomain::StateLeaf,
            &[
                deployment_id,
                mapping_version.value,
                schema_version.value.clone(),
                policy_version.value.clone(),
                state_owner.value.clone(),
                state_owner_commitment.clone(),
                state_grant_root,
                state_version.value,
                witness_state_epoch.value.clone(),
                state_expiry.value.clone(),
                FpVar::from(state_active.clone()),
                state_salt_lo.value,
                state_salt_hi.value,
                state_position.value.clone(),
            ],
        )?;
        path_root_var(
            cs.clone(),
            state_leaf_var,
            &self.witness.state.path,
            &state_position,
            self.deployment.state_depth,
        )?
        .enforce_equal(&state_root)?;
        state_owner.value.enforce_equal(&entitlement_owner.value)?;
        state_owner_commitment.enforce_equal(&owner_commitment_var)?;
        state_active.enforce_equal(&Boolean::TRUE)?;
        enforce_le_if(
            &witness_state_epoch.value,
            &state_epoch.value,
            &Boolean::TRUE,
        )?;
        enforce_le_if(&request_hi.value, &state_expiry.value, &Boolean::TRUE)?;

        records[0].enabled.enforce_equal(&Boolean::TRUE)?;
        records[0]
            .issuer
            .value
            .enforce_equal(&entitlement_owner.value)?;
        entitlement_resource.value.enforce_equal(&resource.value)?;
        for (root_action, entitled_action) in records[0]
            .actions
            .bits
            .iter()
            .zip(entitlement_actions.bits.iter())
        {
            let unauthorized = root_action.and(&entitled_action.not())?;
            unauthorized.enforce_equal(&Boolean::FALSE)?;
        }
        enforce_le_if(&entitlement_lo.value, &records[0].lo.value, &Boolean::TRUE)?;
        enforce_le_if(&records[0].hi.value, &entitlement_hi.value, &Boolean::TRUE)?;
        enforce_le_if(
            &entitlement_lo.value,
            &records[0].not_before.value,
            &Boolean::TRUE,
        )?;
        enforce_le_if(
            &records[0].expiry.value,
            &permit_expiry.value,
            &Boolean::TRUE,
        )?;
        enforce_le_if(&request_hi.value, &permit_expiry.value, &Boolean::TRUE)?;
        for limb in records[0]
            .parent_digest_lo
            .iter()
            .chain(records[0].parent_digest_hi.iter())
        {
            limb.value.enforce_equal(&FpVar::zero())?;
        }

        for i in 1..l_max {
            let current = &records[i];
            let previous = &records[i - 1];
            enforce_if(&current.enabled, &previous.enabled)?;
            current
                .issuer
                .value
                .enforce_equal(&previous.subject.value)?;
            let previous_digest = record_digest_var(cs.clone(), previous, i - 1)?;
            let mut expected_parent_bits = previous_digest.to_bits_le()?;
            expected_parent_bits.resize(384, Boolean::FALSE);
            let actual_parent_bits = current
                .parent_digest_lo
                .iter()
                .chain(current.parent_digest_hi.iter())
                .flat_map(|limb| limb.bits.clone())
                .collect::<Vec<_>>();
            actual_parent_bits.enforce_equal(&expected_parent_bits)?;

            for (child, parent) in current
                .actions
                .bits
                .iter()
                .zip(previous.actions.bits.iter())
            {
                let unauthorized = child.and(&parent.not())?;
                unauthorized.enforce_equal(&Boolean::FALSE)?;
            }

            enforce_le_if(&previous.lo.value, &current.lo.value, &current.enabled)?;
            enforce_le_if(&current.hi.value, &previous.hi.value, &current.enabled)?;
            enforce_le_if(
                &previous.not_before.value,
                &current.not_before.value,
                &current.enabled,
            )?;
            enforce_le_if(
                &current.expiry.value,
                &previous.expiry.value,
                &current.enabled,
            )?;
            (&current.remaining_depth.value + Fq::from(1u64))
                .conditional_enforce_equal(&previous.remaining_depth.value, &current.enabled)?;

            let padding = current.enabled.not();
            current
                .subject
                .value
                .conditional_enforce_equal(&previous.subject.value, &padding)?;
            current
                .actions
                .value
                .conditional_enforce_equal(&previous.actions.value, &padding)?;
            current
                .lo
                .value
                .conditional_enforce_equal(&previous.lo.value, &padding)?;
            current
                .hi
                .value
                .conditional_enforce_equal(&previous.hi.value, &padding)?;
            current
                .not_before
                .value
                .conditional_enforce_equal(&previous.not_before.value, &padding)?;
            current
                .expiry
                .value
                .conditional_enforce_equal(&previous.expiry.value, &padding)?;
            current
                .remaining_depth
                .value
                .conditional_enforce_equal(&previous.remaining_depth.value, &padding)?;
        }

        let final_record = records.last().ok_or(SynthesisError::Unsatisfiable)?;
        final_record.subject.value.enforce_equal(&terminal.value)?;
        for bit in one_hot_action.bits.iter().skip(16) {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        let action_count = one_hot_action
            .bits
            .iter()
            .fold(FpVar::zero(), |sum, bit| sum + FpVar::from(bit.clone()));
        action_count.enforce_equal(&FpVar::one())?;
        for (requested, allowed) in one_hot_action
            .bits
            .iter()
            .zip(final_record.actions.bits.iter())
        {
            enforce_if(requested, allowed)?;
        }
        enforce_le_if(&request_lo.value, &request_hi.value, &Boolean::TRUE)?;
        enforce_le_if(&request_lo.value, &now.value, &Boolean::TRUE)?;
        enforce_le_if(&now.value, &request_hi.value, &Boolean::TRUE)?;
        enforce_le_if(&final_record.lo.value, &request_lo.value, &Boolean::TRUE)?;
        enforce_le_if(&request_hi.value, &final_record.hi.value, &Boolean::TRUE)?;
        enforce_le_if(
            &final_record.not_before.value,
            &request_lo.value,
            &Boolean::TRUE,
        )?;
        enforce_le_if(
            &request_hi.value,
            &final_record.expiry.value,
            &Boolean::TRUE,
        )?;

        let z = new_g1_subgroup_witness(cs.clone(), self.witness.signature.comm_sig.Z)?;
        let y = new_g1_subgroup_witness(cs.clone(), self.witness.signature.comm_sig.Y)?;
        let y_tilde = new_g2_subgroup_witness(cs.clone(), self.witness.signature.comm_sig.Y_tilde)?;
        let tag = new_g1_subgroup_witness(cs.clone(), self.witness.signature.T)?;
        enforce_non_identity(&z)?;
        enforce_non_identity(&y)?;
        enforce_non_identity(&y_tilde)?;
        enforce_non_identity(&tag)?;

        let mut eq1_g1 = commitments;
        let mut eq1_g2 = issuer_x.clone();
        eq1_g1.push(z.negate()?);
        eq1_g2.push(y_tilde.clone());
        enforce_pairing_product_is_one(&eq1_g1, &eq1_g2)?;
        enforce_pairing_product_is_one(&[y.clone(), p1.negate()?], &[p2.clone(), y_tilde])?;

        enforce_pairing_product_is_one(
            &[y, terminal_key, tag.negate()?],
            &[issuer_x[0].clone(), issuer_x0_hat, p2],
        )?;

        Ok(())
    }
}

/// Public input order for Groth16 verification. `G1Var::new_input` allocates
/// the short-Weierstrass projective `(x, y, z)` coordinates even when its
/// source value is affine. Both public points are required to be non-identity,
/// so their canonical projective encoding has `z = 1`.
pub fn public_inputs(statement: &FixedPolicyStatement, relation_version: u64) -> Vec<Fq> {
    let mut inputs = vec![
        statement.deployment_id,
        Fq::from(statement.tuple_version),
        statement.ra_root,
        statement.state_root,
        Fq::from(statement.state_epoch),
        Fq::from(statement.revocation_epoch),
        Fq::from(statement.issued_at),
        Fq::from(statement.mapping_version),
        statement.header_digest,
        Fq::from(statement.canonical_request_lo[0]),
        Fq::from(statement.canonical_request_lo[1]),
        Fq::from(statement.canonical_request_hi[0]),
        Fq::from(statement.canonical_request_hi[1]),
        statement.circuit_id,
        statement.verifier_id,
        statement.pep_id,
        statement.nonce,
        statement.context,
        statement.request_digest,
        Fq::from(statement.terminal),
        Fq::from(statement.resource),
        Fq::from(statement.one_hot_action),
        Fq::from(statement.request_lo),
        Fq::from(statement.request_hi),
        Fq::from(statement.now),
        Fq::from(statement.policy_version),
        Fq::from(statement.schema_version),
        Fq::from(relation_version),
    ];
    inputs.extend([
        statement.terminal_key.x,
        statement.terminal_key.y,
        Fq::from(1u64),
    ]);
    inputs.extend([
        statement.accumulator_value.x,
        statement.accumulator_value.y,
        Fq::from(1u64),
    ]);
    inputs
}
