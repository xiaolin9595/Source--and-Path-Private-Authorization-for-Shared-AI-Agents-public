//! Admission-bound SR verification and atomic compare-and-swap for blind updates.
use crate::{
    blind_update::{authorization_digest, public_inputs, BlindUpdateStatement},
    signature::{verify, PublicKey, Signature},
    Fr,
};
use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, Proof, VerifyingKey};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct Admission {
    pub deployment: Fr,
    pub owner: Fr,
    pub position: u32,
    pub owner_public_key: PublicKey,
    pub expiry_cap: u64,
    pub admission_version: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindStateRecord {
    pub leaf: Fr,
    pub version: u64,
    pub epoch: u64,
    pub active_hint: Option<bool>,
}

#[derive(Clone)]
pub struct BlindUpdateRequest {
    pub statement: BlindUpdateStatement,
    pub proof: Proof<Bls12_381>,
    pub owner_signature: Signature,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlindUpdateError {
    #[error("trusted config, deployment, or circuit mismatch")]
    Identity,
    #[error("admission mismatch or invalid registered public key")]
    Admission,
    #[error("proof verification failed")]
    Proof,
    #[error("owner signature verification failed")]
    Signature,
    #[error("current state changed before commit")]
    CompareAndSwap,
    #[error("proof encoding failed")]
    Encoding,
}

#[derive(Default)]
struct RegistryData {
    admissions: BTreeMap<(Fr, u32), Admission>,
    records: BTreeMap<(Fr, u32), BlindStateRecord>,
}

pub struct BlindStateRegistry {
    config_digest: Fr,
    deployment: Fr,
    circuit_id: Fr,
    vk: VerifyingKey<Bls12_381>,
    data: Mutex<RegistryData>,
}

pub fn proof_sha256_limbs(proof: &Proof<Bls12_381>) -> Result<[Fr; 2], BlindUpdateError> {
    let mut encoded = Vec::new();
    proof
        .serialize_compressed(&mut encoded)
        .map_err(|_| BlindUpdateError::Encoding)?;
    let digest: [u8; 32] = Sha256::digest(encoded).into();
    Ok([
        Fr::from(u128::from_be_bytes(
            digest[..16].try_into().expect("fixed digest"),
        )),
        Fr::from(u128::from_be_bytes(
            digest[16..].try_into().expect("fixed digest"),
        )),
    ])
}

impl BlindStateRegistry {
    pub fn new(
        config_digest: Fr,
        deployment: Fr,
        circuit_id: Fr,
        vk: VerifyingKey<Bls12_381>,
    ) -> Self {
        Self {
            config_digest,
            deployment,
            circuit_id,
            vk,
            data: Mutex::new(RegistryData::default()),
        }
    }

    /// Trusted RA enrollment. Initial opening remains a baseline/history concern;
    /// this API stores only the resulting public leaf and metadata.
    pub fn enroll(
        &self,
        admission: Admission,
        initial: BlindStateRecord,
    ) -> Result<(), BlindUpdateError> {
        if admission.deployment != self.deployment
            || admission.owner_public_key.0.is_zero()
            || !admission.owner_public_key.0.is_on_curve()
            || !admission
                .owner_public_key
                .0
                .is_in_correct_subgroup_assuming_on_curve()
        {
            return Err(BlindUpdateError::Admission);
        }
        let key = (admission.owner, admission.position);
        let mut data = self.data.lock().expect("registry lock poisoned");
        if data.admissions.contains_key(&key) || data.records.contains_key(&key) {
            return Err(BlindUpdateError::Admission);
        }
        data.admissions.insert(key, admission);
        data.records.insert(key, initial);
        Ok(())
    }

    pub fn record(&self, owner: Fr, position: u32) -> Option<BlindStateRecord> {
        self.data
            .lock()
            .expect("registry lock poisoned")
            .records
            .get(&(owner, position))
            .cloned()
    }

    /// Verify expensive cryptography before the write lock, then re-read every
    /// admission/current-state field under the lock before one atomic replacement.
    pub fn apply(
        &self,
        request: &BlindUpdateRequest,
    ) -> Result<BlindStateRecord, BlindUpdateError> {
        let s = &request.statement;
        if s.config_digest != self.config_digest
            || s.deployment != self.deployment
            || s.circuit_id != self.circuit_id
        {
            return Err(BlindUpdateError::Identity);
        }
        let admission = {
            let data = self.data.lock().expect("registry lock poisoned");
            data.admissions
                .get(&(s.owner, s.position))
                .cloned()
                .ok_or(BlindUpdateError::Admission)?
        };
        if admission.deployment != s.deployment
            || admission.owner != s.owner
            || admission.position != s.position
            || admission.expiry_cap != s.expiry_cap
            || admission.admission_version != s.admission_version
        {
            return Err(BlindUpdateError::Admission);
        }
        if !Groth16::<Bls12_381>::verify(&self.vk, &public_inputs(s), &request.proof)
            .map_err(|_| BlindUpdateError::Proof)?
        {
            return Err(BlindUpdateError::Proof);
        }
        let auth_digest = authorization_digest(s, proof_sha256_limbs(&request.proof)?);
        if !verify(
            &admission.owner_public_key,
            auth_digest,
            &request.owner_signature,
        ) {
            return Err(BlindUpdateError::Signature);
        }

        let mut data = self.data.lock().expect("registry lock poisoned");
        let current_admission = data
            .admissions
            .get(&(s.owner, s.position))
            .ok_or(BlindUpdateError::Admission)?;
        if current_admission.deployment != s.deployment
            || current_admission.owner != s.owner
            || current_admission.position != s.position
            || current_admission.expiry_cap != s.expiry_cap
            || current_admission.admission_version != s.admission_version
        {
            return Err(BlindUpdateError::Admission);
        }
        let current = data
            .records
            .get(&(s.owner, s.position))
            .ok_or(BlindUpdateError::CompareAndSwap)?;
        if current.leaf != s.old_leaf
            || current.version != s.old_version
            || current.epoch != s.old_epoch
        {
            return Err(BlindUpdateError::CompareAndSwap);
        }
        let next = BlindStateRecord {
            leaf: s.new_leaf,
            version: s.new_version,
            epoch: s.new_epoch,
            // Hidden update requests never reveal active; the hint is deliberately erased.
            active_hint: None,
        };
        data.records.insert((s.owner, s.position), next.clone());
        Ok(next)
    }
}
