//! Joint CP/Lego verification against a trusted current header.
//! Exclusive mutable access serializes nonce consumption and header updates in
//! this local experimental verifier; no distributed transaction is claimed.
use super::{
    hrada_link::{self, LinkParameters},
    hrada_membership::{CpProof, CpStatement, RsaElem, StateMembership},
};
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use std::collections::HashSet;

pub struct Header {
    pub accumulator: RsaElem,
    pub epoch: u64,
    pub digest: [u8; 32],
}
impl Header {
    pub fn new(accumulator: RsaElem, epoch: u64, parameters: &[u8; 32]) -> Self {
        let mut bytes = b"HRADA-TRUSTED-HEADER-V1".to_vec();
        bytes.extend_from_slice(parameters);
        bytes.extend_from_slice(&epoch.to_le_bytes());
        bytes.extend_from_slice(&Rsa2048::elem_to_bytes(&accumulator));
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Blake2s::digest(&bytes));
        Self {
            accumulator,
            epoch,
            digest,
        }
    }
    pub fn digest_fields(&self) -> [Fr; 2] {
        use ark_ff::PrimeField;
        [
            Fr::from_le_bytes_mod_order(&self.digest[..16]),
            Fr::from_le_bytes_mod_order(&self.digest[16..]),
        ]
    }
}

pub fn context(parameters: &[u8; 32], fields: &[Fr]) -> Result<Vec<u8>, String> {
    let mut bytes = b"HRADA-JOINT-REQUEST-V1".to_vec();
    bytes.extend_from_slice(parameters);
    bytes.extend_from_slice(&(fields.len() as u64).to_le_bytes());
    for field in fields {
        field
            .serialize(&mut bytes)
            .map_err(|e| format!("{:?}", e))?;
    }
    Ok(bytes)
}

pub struct JointVerifier {
    pub header: Header,
    pub parameters_digest: [u8; 32],
    consumed: HashSet<Vec<u8>>,
}
impl JointVerifier {
    pub fn new(header: Header, parameters_digest: [u8; 32]) -> Self {
        Self {
            header,
            parameters_digest,
            consumed: HashSet::new(),
        }
    }
    // A trusted SR supplies the next authenticated header after a legal state
    // transition. This method does not itself authenticate a remote SR message.
    pub fn replace_header(&mut self, header: Header) -> Result<(), String> {
        if header.epoch != self.header.epoch.checked_add(1).ok_or("epoch_overflow")? {
            return Err("nonconsecutive_epoch".into());
        }
        let correct = Header::new(
            header.accumulator.clone(),
            header.epoch,
            &self.parameters_digest,
        );
        if correct.digest != header.digest {
            return Err("header_digest_mismatch".into());
        }
        self.header = header;
        Ok(())
    }
    pub fn authorize<F>(
        &mut self,
        cp: &StateMembership,
        link: &LinkParameters,
        statement: &CpStatement,
        membership_proof: &CpProof,
        authorization_proof: &legogro16::Proof<Bls12_381>,
        fields: &[Fr],
        expected_fields: &[Fr],
        request_time: u64,
        permit_until: u64,
        mut trusted_clock: F,
    ) -> Result<(), String>
    where
        F: FnMut() -> u64,
    {
        if fields.len() != 16 || fields != expected_fields {
            return Err("request_mismatch".into());
        }
        let hd = self.header.digest_fields();
        if statement.c_p != self.header.accumulator
            || fields[0] != hd[0]
            || fields[1] != hd[1]
            || fields[2] != Fr::from(self.header.epoch)
        {
            return Err("stale_header".into());
        }
        if fields[9] != Fr::from(request_time)
            || fields[11] != Fr::from(permit_until)
            || request_time > permit_until
        {
            return Err("invalid_request_interval".into());
        }
        let before = trusted_clock();
        if before < request_time || before > permit_until {
            return Err("request_outside_validity".into());
        }
        let mut nonce_key = Vec::new();
        for i in [3usize, 5, 6, 10].iter() {
            fields[*i]
                .serialize(&mut nonce_key)
                .map_err(|e| format!("{:?}", e))?;
        }
        if self.consumed.contains(&nonce_key) {
            return Err("nonce_already_consumed".into());
        }
        let cp_bytes = cp.canonical_parameters()?;
        let ctx = context(&self.parameters_digest, fields)?;
        cp.verify(statement, membership_proof, &ctx)
            .map_err(|_| "cp_proof_rejected")?;
        let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
        if !hrada_link::verify(
            link,
            ck,
            &cp_bytes,
            &self.parameters_digest,
            authorization_proof,
            fields,
            &statement.c_e_q,
        )
        .map_err(|e| format!("{:?}", e))?
        {
            return Err("authorization_link_rejected".into());
        }
        // Real proof verification may take time. Check the trusted clock again
        // before atomically consuming the nonce and issuing this local permit.
        let commit_time = trusted_clock();
        if commit_time < before || commit_time > permit_until {
            return Err("expired_before_commit".into());
        }
        self.consumed.insert(nonce_key);
        Ok(())
    }
}
