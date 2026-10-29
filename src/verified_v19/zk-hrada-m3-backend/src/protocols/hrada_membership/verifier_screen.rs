//! Experimental CP-only range PVK reuse. Borrow binds cache to immutable parameters.
use super::*;
use crate::protocols::{
    hash_to_prime::{channel::HashToPrimeProverChannel, HashToPrimeProtocol},
    membership::channel::MembershipProverChannel,
    modeq, root,
};
use ark_ec::AffineCurve;
use serde::Serialize;
use std::time::Instant;
#[derive(Default, Serialize)]
pub struct Profile {
    pub transcript_ms: f64,
    pub root_ms: f64,
    pub modeq_ms: f64,
    pub range_clone_ms: f64,
    pub prepare_ms: f64,
    pub range_verify_ms: f64,
    pub commitment_ms: f64,
    pub total_ms: f64,
}
fn elapsed(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
pub struct PreparedCpVerifier<'a> {
    owner: &'a StateMembership,
    pvk: legogro16::PreparedVerifyingKey<Bls12_381>,
}
impl<'a> PreparedCpVerifier<'a> {
    pub fn new(owner: &'a StateMembership) -> Self {
        Self {
            owner,
            pvk: legogro16::prepare_verifying_key(
                &owner
                    .protocol
                    .crs
                    .crs_hash_to_prime
                    .hash_to_prime_parameters
                    .vk,
            ),
        }
    }
    pub fn verify(&self, s: &CpStatement, p: &CpProof, ctx: &[u8]) -> Result<Profile, String> {
        profile_inner(self.owner, s, p, ctx, Some(&self.pvk))
    }
    pub fn stack_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
    }
}
fn profile_inner(
    owner: &StateMembership,
    s: &CpStatement,
    p: &CpProof,
    ctx: &[u8],
    pvk: Option<&legogro16::PreparedVerifyingKey<Bls12_381>>,
) -> Result<Profile, String> {
    let all = Instant::now();
    let mut out = Profile::default();
    let t = Instant::now();
    let transcript = RefCell::new(owner.transcript(s, ctx)?);
    let mut ch =
        membership::transcript::TranscriptProverChannel::new(&owner.protocol.crs, &transcript, p);
    out.transcript_ms = elapsed(t);
    let t = Instant::now();
    let c_e = ch.receive_c_e().map_err(|e| format!("{:?}", e))?;
    let r = root::Protocol::from_crs(&owner.protocol.crs.crs_root);
    r.verify(
        &mut ch,
        &root::Statement {
            c_e: c_e.clone(),
            acc: s.c_p.clone(),
        },
    )
    .map_err(|e| format!("{:?}", e))?;
    out.root_ms = elapsed(t);
    let t = Instant::now();
    let m = modeq::Protocol::from_crs(&owner.protocol.crs.crs_modeq);
    m.verify(
        &mut ch,
        &modeq::Statement {
            c_e,
            c_e_q: s.c_e_q.clone(),
        },
    )
    .map_err(|e| format!("{:?}", e))?;
    out.modeq_ms = elapsed(t);
    let t = Instant::now();
    let hp = snark_range::Protocol::<Bls12_381>::from_crs(&owner.protocol.crs.crs_hash_to_prime);
    let proof = ch.receive_proof().map_err(|e| format!("{:?}", e))?;
    out.range_clone_ms = elapsed(t);
    let t = Instant::now();
    let local;
    let key = match pvk {
        Some(k) => k,
        None => {
            local = legogro16::prepare_verifying_key(&hp.crs.hash_to_prime_parameters.vk);
            &local
        }
    };
    out.prepare_ms = elapsed(t);
    let t = Instant::now();
    if !legogro16::verify_proof(key, &proof).map_err(|e| format!("{:?}", e))? {
        return Err("range verification failed".into());
    }
    out.range_verify_ms = elapsed(t);
    let t = Instant::now();
    if s.c_e_q
        != proof.link_d.into_projective()
            - hp.crs.hash_to_prime_parameters.vk.link_bases[0].into_projective()
    {
        return Err("commitment mismatch".into());
    }
    out.commitment_ms = elapsed(t);
    drop(hp);
    drop(ch);
    drop(transcript);
    out.total_ms = elapsed(all);
    Ok(out)
}

pub fn profile_uncached(
    owner: &StateMembership,
    s: &CpStatement,
    p: &CpProof,
    ctx: &[u8],
) -> Result<Profile, String> {
    profile_inner(owner, s, p, ctx, None)
}
