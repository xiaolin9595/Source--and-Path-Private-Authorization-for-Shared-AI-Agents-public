//! Visible-opening SR state transitions with signed, deployment-bound CAS.
use crate::{
    poseidon::{hash, Domain},
    signature::{verify, PublicKey, Signature},
    Fr,
};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct StateRecord {
    pub owner_commitment: Fr,
    pub leaf: Fr,
    pub version: u64,
    pub epoch: u64,
    pub position: u32,
    pub active: bool,
}
#[derive(Clone, Debug)]
pub struct StateLeafOpening {
    pub grant_root: Fr,
    pub state_expiry: u64,
    pub active: bool,
    pub salt: Fr,
}
#[derive(Clone, Debug)]
pub struct OwnerAuthentication {
    pub signature: Signature,
}
#[derive(Clone, Debug)]
struct Admission {
    pk: PublicKey,
    max_expiry: u64,
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpdateError {
    #[error("owner authentication failed")]
    Authentication,
    #[error("position or owner mismatch")]
    Ownership,
    #[error("compare-and-swap version mismatch")]
    Version,
    #[error("epoch must increase")]
    Epoch,
    #[error("expiry exceeds admitted permit")]
    Expiry,
    #[error("inactive state requires authority-mediated recovery")]
    Reactivation,
}
#[derive(Clone, Debug)]
pub struct StateRegistry {
    deployment: Fr,
    records: BTreeMap<u32, StateRecord>,
    admissions: BTreeMap<u32, Admission>,
}
pub fn owner_commitment(x: Fr, y: Fr, salt: Fr) -> Fr {
    hash(Domain::Owner, &[x, y, salt])
}
pub fn update_digest(
    deployment: Fr,
    owner: Fr,
    position: u32,
    expected_version: u64,
    new_epoch: u64,
    o: &StateLeafOpening,
) -> Fr {
    hash(
        Domain::StateUpdate,
        &[
            deployment,
            owner,
            Fr::from(position),
            Fr::from(expected_version),
            Fr::from(new_epoch),
            o.grant_root,
            Fr::from(o.state_expiry),
            Fr::from(o.active as u64),
            o.salt,
        ],
    )
}
fn state_leaf(owner: Fr, version: u64, epoch: u64, position: u32, o: &StateLeafOpening) -> Fr {
    hash(
        Domain::StateLeaf,
        &[
            owner,
            o.grant_root,
            Fr::from(version),
            Fr::from(epoch),
            Fr::from(o.state_expiry),
            Fr::from(o.active as u64),
            o.salt,
            Fr::from(position),
        ],
    )
}
impl StateRegistry {
    pub fn new(deployment: Fr) -> Self {
        Self {
            deployment,
            records: BTreeMap::new(),
            admissions: BTreeMap::new(),
        }
    }
    /// Trusted RA admission: verifies the owner commitment from the admitted key
    /// and salt, fixes its unique position, and caps every owner update expiry.
    pub fn enroll(
        &mut self,
        pk: PublicKey,
        registration_salt: Fr,
        claimed_owner: Fr,
        position: u32,
        max_expiry: u64,
        epoch: u64,
        opening: StateLeafOpening,
    ) -> Result<StateRecord, UpdateError> {
        if claimed_owner != owner_commitment(pk.0.x, pk.0.y, registration_salt)
            || opening.state_expiry > max_expiry
            || self.records.contains_key(&position)
            || self
                .records
                .values()
                .any(|r| r.owner_commitment == claimed_owner)
        {
            return Err(UpdateError::Ownership);
        }
        let record = StateRecord {
            owner_commitment: claimed_owner,
            leaf: state_leaf(claimed_owner, 0, epoch, position, &opening),
            version: 0,
            epoch,
            position,
            active: opening.active,
        };
        self.admissions
            .insert(position, Admission { pk, max_expiry });
        self.records.insert(position, record.clone());
        Ok(record)
    }
    pub fn update(
        &mut self,
        auth: &OwnerAuthentication,
        owner: Fr,
        position: u32,
        expected_version: u64,
        new_epoch: u64,
        opening: StateLeafOpening,
    ) -> Result<StateRecord, UpdateError> {
        let old = self.records.get(&position).ok_or(UpdateError::Ownership)?;
        if old.owner_commitment != owner {
            return Err(UpdateError::Ownership);
        }
        if old.version != expected_version {
            return Err(UpdateError::Version);
        }
        if new_epoch <= old.epoch {
            return Err(UpdateError::Epoch);
        }
        if !old.active && opening.active {
            return Err(UpdateError::Reactivation);
        }
        let admission = self
            .admissions
            .get(&position)
            .ok_or(UpdateError::Ownership)?;
        if opening.state_expiry > admission.max_expiry {
            return Err(UpdateError::Expiry);
        }
        if !verify(
            &admission.pk,
            update_digest(
                self.deployment,
                owner,
                position,
                expected_version,
                new_epoch,
                &opening,
            ),
            &auth.signature,
        ) {
            return Err(UpdateError::Authentication);
        }
        let version = expected_version
            .checked_add(1)
            .ok_or(UpdateError::Version)?;
        let next = StateRecord {
            owner_commitment: owner,
            leaf: state_leaf(owner, version, new_epoch, position, &opening),
            version,
            epoch: new_epoch,
            position,
            active: opening.active,
        };
        self.records.insert(position, next.clone());
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signature::{public_key, sign, SecretKey};
    use ark_ed_on_bls12_381::Fr as Scalar;
    #[test]
    fn deployment_owner_cas_expiry_and_reactivation() {
        let deployment = Fr::from(9u64);
        let sk = SecretKey(Scalar::from(7u64));
        let pk = public_key(&sk).unwrap();
        let salt = Fr::from(8u64);
        let owner = owner_commitment(pk.0.x, pk.0.y, salt);
        let mut r = StateRegistry::new(deployment);
        let initial = StateLeafOpening {
            grant_root: Fr::from(1u64),
            state_expiry: 90,
            active: true,
            salt: Fr::from(2u64),
        };
        r.enroll(pk, salt, owner, 3, 100, 1, initial).unwrap();
        let stop = StateLeafOpening {
            grant_root: Fr::from(1u64),
            state_expiry: 100,
            active: false,
            salt: Fr::from(3u64),
        };
        let sig = sign(
            &sk,
            update_digest(deployment, owner, 3, 0, 2, &stop),
            [4; 32],
        )
        .unwrap();
        r.update(
            &OwnerAuthentication { signature: sig },
            owner,
            3,
            0,
            2,
            stop,
        )
        .unwrap();
        let reopen = StateLeafOpening {
            grant_root: Fr::from(1u64),
            state_expiry: 100,
            active: true,
            salt: Fr::from(4u64),
        };
        let sig = sign(
            &sk,
            update_digest(deployment, owner, 3, 1, 3, &reopen),
            [5; 32],
        )
        .unwrap();
        assert_eq!(
            r.update(
                &OwnerAuthentication { signature: sig },
                owner,
                3,
                1,
                3,
                reopen
            )
            .unwrap_err(),
            UpdateError::Reactivation
        )
    }
}
