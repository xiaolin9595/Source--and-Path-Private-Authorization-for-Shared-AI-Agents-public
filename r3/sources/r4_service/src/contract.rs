use crate::{
    merkle::MerklePath,
    signature::{PublicKey, Signature},
    Fr,
};
use ark_ff::PrimeField;
use sha2::{Digest, Sha256};

pub const ACTION_BITS: usize = 16;
pub const SERIAL_BITS: usize = 252;

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub tuple_version: u64,
    pub root_ra: Fr,
    pub root_state: Fr,
    pub root_rev: Fr,
    pub state_epoch: u64,
    pub revocation_epoch: u64,
    pub issued_at: u64,
}

#[derive(Clone, Debug)]
pub struct Request {
    /// Two 128-bit limbs of SHA-256("plan-a-request-v1\0" || canonical JSON).
    pub canonical_request_lo: Fr,
    pub canonical_request_hi: Fr,
    pub circuit_id: Fr,
    pub verifier_id: Fr,
    pub pep_id: Fr,
    pub resource: Fr,
    pub action_onehot: u16,
    pub interval_lo: u64,
    pub interval_hi: u64,
    pub time: u64,
    pub nonce: Fr,
    pub context: Fr,
    pub terminal: PublicKey,
}

#[derive(Clone, Debug)]
pub struct Entitlement {
    pub owner_commitment: Fr,
    pub resource: Fr,
    pub action_mask: u16,
    pub interval_lo: u64,
    pub interval_hi: u64,
    pub permit_expiry: u64,
    pub admission_id: Fr,
    pub path: MerklePath,
}

#[derive(Clone, Debug)]
pub struct UserState {
    pub owner_commitment: Fr,
    pub grant_root: Fr,
    pub state_version: u64,
    pub state_epoch: u64,
    pub state_expiry: u64,
    pub active: bool,
    pub salt: Fr,
    pub position: u32,
    pub path: MerklePath,
}

#[derive(Clone, Debug)]
pub struct Grant {
    pub issuer: PublicKey,
    pub subject: PublicKey,
    pub resource: Fr,
    pub action_mask: u16,
    pub interval_lo: u64,
    pub interval_hi: u64,
    pub not_before: u64,
    pub expiry: u64,
    pub depth_remaining: u8,
    pub serial: Fr,
    /// Zero for the admitted root; otherwise the preceding grant digest.
    pub parent_digest: Fr,
    pub signature: Signature,
}

#[derive(Clone, Debug)]
pub struct Slot {
    pub enabled: bool,
    pub grant: Grant,
    pub grant_path: MerklePath,
    pub revocation: crate::indexed_revocation::NonMembershipWitness,
}

/// Canonical Agent/service terminal signature message. The signature covers
/// the exact serialized proof bytes; the service verifies it before its atomic
/// clock/header/nonce commit recheck.
pub fn terminal_transcript(
    request_sha256: [u8; 32],
    snapshot_sha256: [u8; 32],
    circuit_id: &str,
    proof_bytes: &[u8],
) -> Fr {
    fn limbs(x: [u8; 32]) -> [Fr; 2] {
        [
            Fr::from(u128::from_be_bytes(
                x[..16].try_into().expect("fixed slice"),
            )),
            Fr::from(u128::from_be_bytes(
                x[16..].try_into().expect("fixed slice"),
            )),
        ]
    }
    let request = limbs(request_sha256);
    let snapshot = limbs(snapshot_sha256);
    let circuit = limbs(Sha256::digest(circuit_id.as_bytes()).into());
    let mut fields = vec![
        request[0],
        request[1],
        snapshot[0],
        snapshot[1],
        circuit[0],
        circuit[1],
        Fr::from(proof_bytes.len() as u64),
    ];
    fields.extend(proof_bytes.chunks(31).map(Fr::from_le_bytes_mod_order));
    crate::poseidon::hash(crate::poseidon::Domain::Terminal, &fields)
}
