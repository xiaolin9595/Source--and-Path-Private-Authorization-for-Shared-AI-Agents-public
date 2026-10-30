//! In-process, one-use offline masks for the five Groth16 prover MSMs.
//!
//! The variable-time arkworks MSM sees only a uniformly masked scalar vector.
//! Scalar masking and all witness-dependent group operations after that MSM use
//! zkcrypto's fixed-width scalar arithmetic and complete group formulas. The
//! ark/zkcrypto encoding bridges remain part of online latency and are not
//! claimed constant-time. The final bridge depends only on the public proof.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bls12_381_ct::{G1Affine as CtG1Affine, G1Projective as CtG1, G2Affine as CtG2Affine, G2Projective as CtG2, Scalar as CtScalar};
use ff_ct::Field;
use group_ct::Group;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, sync::{Arc, Mutex}, time::Instant};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum QueryId { H, L, A, B1, B2 }

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum QueryGroup { G1, G2 }

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Binding {
    pub key_sha256: [u8; 32],
    pub query_sha256: [u8; 32],
    pub query: QueryId,
    pub group: QueryGroup,
    pub scalar_len: usize,
    pub order: u8,
}

pub struct G1MaskToken { binding: Binding, rho: Vec<CtScalar>, correction: CtG1 }
pub struct G2MaskToken { binding: Binding, rho: Vec<CtScalar>, correction: CtG2 }

pub struct MaskSet {
    pub token_id: u64,
    h: G1MaskToken,
    l: G1MaskToken,
    a: G1MaskToken,
    b1: G1MaskToken,
    b2: G2MaskToken,
}

#[derive(Clone)]
pub struct TokenPool {
    inner: Arc<Mutex<TokenPoolInner>>,
}

struct TokenPoolInner {
    /// The pool retains one Arc for every allocation until the pool/process is
    /// dropped. Claiming clones only the Arc pointer and never moves, frees, or
    /// replaces the mask allocation.
    tokens: Vec<Arc<MaskSet>>,
    claimed: Vec<bool>,
    next: usize,
}

impl TokenPool {
    pub fn new(tokens: Vec<MaskSet>) -> Result<Self, MaskError> {
        let ids = tokens.iter().map(|token| token.token_id).collect::<HashSet<_>>();
        if ids.len() != tokens.len() { return Err(MaskError::DuplicateTokenId); }
        let tokens = tokens.into_iter().map(Arc::new).collect::<Vec<_>>();
        let claimed = vec![false; tokens.len()];
        Ok(Self { inner: Arc::new(Mutex::new(TokenPoolInner { tokens, claimed, next: 0 })) })
    }
    pub fn remaining(&self) -> usize {
        let inner = self.inner.lock().expect("token mutex poisoned");
        inner.claimed.iter().filter(|claimed| !**claimed).count()
    }
    pub fn consumed(&self) -> usize {
        let inner = self.inner.lock().expect("token mutex poisoned");
        inner.claimed.iter().filter(|claimed| **claimed).count()
    }
    pub fn resident(&self) -> usize {
        self.inner.lock().expect("token mutex poisoned").tokens.len()
    }
    /// Marks the allocation consumed before returning shared read access to it.
    /// Validation, cancellation, proof failure, and unwinding never restore it;
    /// the pool retains the original Arc and allocation until process exit.
    pub fn claim_next(&self) -> Result<Arc<MaskSet>, MaskError> {
        let mut inner = self.inner.lock().map_err(|_| MaskError::PoolPoisoned)?;
        while inner.next < inner.tokens.len() && inner.claimed[inner.next] {
            inner.next += 1;
        }
        if inner.next == inner.tokens.len() { return Err(MaskError::Exhausted); }
        let index = inner.next;
        inner.claimed[index] = true;
        inner.next += 1;
        Ok(Arc::clone(&inner.tokens[index]))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MaskError {
    #[error("mask pool exhausted")]
    Exhausted,
    #[error("mask pool poisoned")]
    PoolPoisoned,
    #[error("token binding mismatch")]
    Binding,
    #[error("strict scalar/query length mismatch")]
    Length,
    #[error("strict scalar/query length mismatch for {0:?}: scalars={1}, bases={2}, bound={3}")]
    LengthAt(QueryId, usize, usize, usize),
    #[error("non-canonical scalar bridge")]
    ScalarBridge,
    #[error("invalid group bridge")]
    GroupBridge,
    #[error("proof output decode failed")]
    OutputDecode,
    #[error("native H truncation would discard a nonzero coefficient")]
    NonzeroHTail,
    #[error("duplicate token id in one process-local pool")]
    DuplicateTokenId,
    #[error("query {0:?} has no non-identity base; uniform masked-output argument does not apply")]
    AllIdentityQuery(QueryId),
}

pub struct MaskContext {
    key_sha256: [u8; 32],
    bindings: [Binding; 5],
}

fn sha(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }

fn query_hash<G: CanonicalSerialize>(query: &[G]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update((query.len() as u64).to_le_bytes());
    let mut bytes = Vec::new();
    for point in query {
        bytes.clear();
        point.serialize_compressed(&mut bytes).expect("Vec serialization cannot fail");
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    h.finalize().into()
}

impl MaskContext {
    pub fn new(
        key_bytes: &[u8], h: &[G1Affine], l: &[G1Affine], a: &[G1Affine],
        b1: &[G1Affine], b2: &[G2Affine],
    ) -> Result<Self, MaskError> {
        for (id, any_nonidentity) in [
            (QueryId::H, h.iter().any(|p| !p.is_zero())),
            (QueryId::L, l.iter().any(|p| !p.is_zero())),
            (QueryId::A, a.iter().any(|p| !p.is_zero())),
            (QueryId::B1, b1.iter().any(|p| !p.is_zero())),
            (QueryId::B2, b2.iter().any(|p| !p.is_zero())),
        ] {
            if !any_nonidentity { return Err(MaskError::AllIdentityQuery(id)); }
        }
        let key_sha256 = sha(key_bytes);
        let specs = [
            (QueryId::H, QueryGroup::G1, h.len(), 0, query_hash(h)),
            (QueryId::L, QueryGroup::G1, l.len(), 1, query_hash(l)),
            (QueryId::A, QueryGroup::G1, a.len(), 2, query_hash(a)),
            (QueryId::B1, QueryGroup::G1, b1.len(), 3, query_hash(b1)),
            (QueryId::B2, QueryGroup::G2, b2.len(), 4, query_hash(b2)),
        ];
        Ok(Self { key_sha256, bindings: specs.map(|(query, group, scalar_len, order, query_sha256)| Binding { key_sha256, query_sha256, query, group, scalar_len, order }) })
    }
    pub fn bindings(&self) -> &[Binding; 5] { &self.bindings }

    pub fn generate_set(
        &self, token_id: u64, h: &[G1Affine], l: &[G1Affine], a: &[G1Affine],
        b1: &[G1Affine], b2: &[G2Affine],
    ) -> Result<MaskSet, MaskError> {
        self.validate_queries(h,l,a,b1,b2)?;
        Ok(MaskSet {
            token_id,
            h: generate_g1(self.bindings[0].clone(), h),
            l: generate_g1(self.bindings[1].clone(), l),
            a: generate_g1(self.bindings[2].clone(), a),
            b1: generate_g1(self.bindings[3].clone(), b1),
            b2: generate_g2(self.bindings[4].clone(), b2),
        })
    }

    pub fn validate_queries(&self, h:&[G1Affine],l:&[G1Affine],a:&[G1Affine],b1:&[G1Affine],b2:&[G2Affine]) -> Result<(),MaskError> {
        let got=[query_hash(h),query_hash(l),query_hash(a),query_hash(b1),query_hash(b2)];
        let lens=[h.len(),l.len(),a.len(),b1.len(),b2.len()];
        for i in 0..5 { if got[i]!=self.bindings[i].query_sha256 {return Err(MaskError::Binding)} if lens[i]!=self.bindings[i].scalar_len{return Err(MaskError::Length)} }
        Ok(())
    }
}

fn scalar_bigint(s: &CtScalar) -> BigInt<4> {
    let b=s.to_bytes();
    BigInt([u64::from_le_bytes(b[0..8].try_into().unwrap()),u64::from_le_bytes(b[8..16].try_into().unwrap()),u64::from_le_bytes(b[16..24].try_into().unwrap()),u64::from_le_bytes(b[24..32].try_into().unwrap())])
}

fn ark_scalar_to_ct(s: &Fr) -> Result<CtScalar,MaskError> {
    let limbs=s.into_bigint().0;
    let mut bytes=[0u8;32]; for (i,limb) in limbs.into_iter().enumerate(){bytes[i*8..i*8+8].copy_from_slice(&limb.to_le_bytes())}
    let candidate=CtScalar::from_bytes(&bytes); let valid=bool::from(candidate.is_some());
    let value=candidate.unwrap_or(CtScalar::zero());
    if valid {Ok(value)} else {Err(MaskError::ScalarBridge)}
}

fn generate_g1(binding:Binding,bases:&[G1Affine])->G1MaskToken {
    let rho=(0..bases.len()).map(|_|CtScalar::random(&mut OsRng)).collect::<Vec<_>>();
    let bigints=rho.iter().map(scalar_bigint).collect::<Vec<_>>();
    let correction=ark_g1_to_ct(G1Projective::msm_bigint(bases,&bigints)).expect("valid offline G1");
    G1MaskToken{binding,rho,correction}
}
fn generate_g2(binding:Binding,bases:&[G2Affine])->G2MaskToken {
    let rho=(0..bases.len()).map(|_|CtScalar::random(&mut OsRng)).collect::<Vec<_>>();
    let bigints=rho.iter().map(scalar_bigint).collect::<Vec<_>>();
    let correction=ark_g2_to_ct(G2Projective::msm_bigint(bases,&bigints)).expect("valid offline G2");
    G2MaskToken{binding,rho,correction}
}

fn validate_binding(got:&Binding,expected:&Binding,scalar_len:usize,base_len:usize)->Result<(),MaskError>{
    if got!=expected{return Err(MaskError::Binding)}
    if scalar_len!=got.scalar_len || base_len!=got.scalar_len {
        return Err(MaskError::LengthAt(got.query, scalar_len, base_len, got.scalar_len));
    }
    Ok(())
}

fn masked_bigints(scalars:&[Fr],rho:&[CtScalar])->Result<Vec<BigInt<4>>,MaskError>{
    if scalars.len()!=rho.len(){return Err(MaskError::Length)}
    scalars.iter().zip(rho).map(|(a,r)|Ok(scalar_bigint(&(ark_scalar_to_ct(a)?+r)))).collect()
}

fn apply_g1(token:&G1MaskToken,expected:&Binding,bases:&[G1Affine],scalars:&[Fr])->Result<CtG1,MaskError>{
    validate_binding(&token.binding,expected,scalars.len(),bases.len())?;
    let masked=G1Projective::msm_bigint(bases,&masked_bigints(scalars,&token.rho)?);
    Ok(ark_g1_to_ct(masked)?-token.correction)
}
fn apply_g2(token:&G2MaskToken,expected:&Binding,bases:&[G2Affine],scalars:&[Fr])->Result<CtG2,MaskError>{
    validate_binding(&token.binding,expected,scalars.len(),bases.len())?;
    let masked=G2Projective::msm_bigint(bases,&masked_bigints(scalars,&token.rho)?);
    Ok(ark_g2_to_ct(masked)?-token.correction)
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct QueryMaskTimes {
    pub masking_ms: f64,
    pub masked_msm_ms: f64,
    pub masked_bridge_ms: f64,
    pub correction_ms: f64,
}

fn apply_g1_timed(token:&G1MaskToken,expected:&Binding,bases:&[G1Affine],scalars:&[Fr])->Result<(CtG1,QueryMaskTimes),MaskError>{
    validate_binding(&token.binding,expected,scalars.len(),bases.len())?;
    let t=Instant::now(); let bigints=masked_bigints(scalars,&token.rho)?; let masking_ms=t.elapsed().as_secs_f64()*1000.0;
    let t=Instant::now(); let masked=G1Projective::msm_bigint(bases,&bigints); let masked_msm_ms=t.elapsed().as_secs_f64()*1000.0;
    let t=Instant::now(); let bridged=ark_g1_to_ct(masked)?; let masked_bridge_ms=t.elapsed().as_secs_f64()*1000.0;
    let t=Instant::now(); let corrected=bridged-token.correction; let correction_ms=t.elapsed().as_secs_f64()*1000.0;
    Ok((corrected,QueryMaskTimes{masking_ms,masked_msm_ms,masked_bridge_ms,correction_ms}))
}
fn apply_g2_timed(token:&G2MaskToken,expected:&Binding,bases:&[G2Affine],scalars:&[Fr])->Result<(CtG2,QueryMaskTimes),MaskError>{
    validate_binding(&token.binding,expected,scalars.len(),bases.len())?;
    let t=Instant::now(); let bigints=masked_bigints(scalars,&token.rho)?; let masking_ms=t.elapsed().as_secs_f64()*1000.0;
    let t=Instant::now(); let masked=G2Projective::msm_bigint(bases,&bigints); let masked_msm_ms=t.elapsed().as_secs_f64()*1000.0;
    let t=Instant::now(); let bridged=ark_g2_to_ct(masked)?; let masked_bridge_ms=t.elapsed().as_secs_f64()*1000.0;
    let t=Instant::now(); let corrected=bridged-token.correction; let correction_ms=t.elapsed().as_secs_f64()*1000.0;
    Ok((corrected,QueryMaskTimes{masking_ms,masked_msm_ms,masked_bridge_ms,correction_ms}))
}

fn ark_g1_to_ct(point:G1Projective)->Result<CtG1,MaskError>{
    let mut bytes=Vec::new();point.into_affine().serialize_compressed(&mut bytes).unwrap();
    let repr: [u8; 48] = bytes.try_into().map_err(|_|MaskError::GroupBridge)?;
    Option::<CtG1Affine>::from(CtG1Affine::from_compressed(&repr)).map(CtG1::from).ok_or(MaskError::GroupBridge)
}
fn ark_g2_to_ct(point:G2Projective)->Result<CtG2,MaskError>{
    let mut bytes=Vec::new();point.into_affine().serialize_compressed(&mut bytes).unwrap();
    let repr: [u8; 96] = bytes.try_into().map_err(|_|MaskError::GroupBridge)?;
    Option::<CtG2Affine>::from(CtG2Affine::from_compressed(&repr)).map(CtG2::from).ok_or(MaskError::GroupBridge)
}
pub fn ct_g1_to_ark(point:CtG1)->Result<G1Projective,MaskError>{
    let bytes=CtG1Affine::from(point).to_compressed();
    G1Affine::deserialize_compressed(&bytes[..]).map(|p|p.into_group()).map_err(|_|MaskError::OutputDecode)
}
pub fn ct_g2_to_ark(point:CtG2)->Result<G2Projective,MaskError>{
    let bytes=CtG2Affine::from(point).to_compressed();
    G2Affine::deserialize_compressed(&bytes[..]).map(|p|p.into_group()).map_err(|_|MaskError::OutputDecode)
}

pub struct CorrectedMsms { pub h:CtG1,pub l:CtG1,pub a:CtG1,pub b1:CtG1,pub b2:CtG2 }
#[derive(Clone, Debug, Serialize)]
pub struct FiveQueryTimes { pub h:QueryMaskTimes,pub l:QueryMaskTimes,pub a:QueryMaskTimes,pub b1:QueryMaskTimes,pub b2:QueryMaskTimes }

impl MaskSet {
    pub fn validate(&self, context: &MaskContext) -> Result<(), MaskError> {
        let got = [&self.h.binding, &self.l.binding, &self.a.binding, &self.b1.binding, &self.b2.binding];
        for (actual, expected) in got.into_iter().zip(context.bindings.iter()) {
            if actual != expected { return Err(MaskError::Binding); }
        }
        Ok(())
    }

    pub fn apply(
        &self, context:&MaskContext,
        h_bases:&[G1Affine],h:&[Fr],l_bases:&[G1Affine],l:&[Fr],
        a_bases:&[G1Affine],a:&[Fr],b1_bases:&[G1Affine],b1:&[Fr],b2_bases:&[G2Affine],b2:&[Fr],
    )->Result<CorrectedMsms,MaskError>{
        Ok(CorrectedMsms{
            h:apply_g1(&self.h,&context.bindings[0],h_bases,h)?,
            l:apply_g1(&self.l,&context.bindings[1],l_bases,l)?,
            a:apply_g1(&self.a,&context.bindings[2],a_bases,a)?,
            b1:apply_g1(&self.b1,&context.bindings[3],b1_bases,b1)?,
            b2:apply_g2(&self.b2,&context.bindings[4],b2_bases,b2)?,
        })
    }

    pub fn apply_timed(
        &self, context:&MaskContext,
        h_bases:&[G1Affine],h:&[Fr],l_bases:&[G1Affine],l:&[Fr],
        a_bases:&[G1Affine],a:&[Fr],b1_bases:&[G1Affine],b1:&[Fr],b2_bases:&[G2Affine],b2:&[Fr],
    )->Result<(CorrectedMsms,FiveQueryTimes),MaskError>{
        let (h,h_t)=apply_g1_timed(&self.h,&context.bindings[0],h_bases,h)?;
        let (l,l_t)=apply_g1_timed(&self.l,&context.bindings[1],l_bases,l)?;
        let (a,a_t)=apply_g1_timed(&self.a,&context.bindings[2],a_bases,a)?;
        let (b1,b1_t)=apply_g1_timed(&self.b1,&context.bindings[3],b1_bases,b1)?;
        let (b2,b2_t)=apply_g2_timed(&self.b2,&context.bindings[4],b2_bases,b2)?;
        Ok((CorrectedMsms{h,l,a,b1,b2},FiveQueryTimes{h:h_t,l:l_t,a:a_t,b1:b1_t,b2:b2_t}))
    }
}

pub fn ark_fr_to_ct_public(s:&Fr)->Result<CtScalar,MaskError>{ark_scalar_to_ct(s)}
pub fn ark_g1_to_ct_public(p:G1Projective)->Result<CtG1,MaskError>{ark_g1_to_ct(p)}
pub fn ark_g2_to_ct_public(p:G2Projective)->Result<CtG2,MaskError>{ark_g2_to_ct(p)}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::Group as ArkGroup;
    use ark_ff::{One, Zero};
    use std::sync::{Arc, Barrier};

    fn small() -> (Vec<G1Affine>, Vec<G2Affine>, MaskContext) {
        let g1=G1Projective::generator(); let g2=G2Projective::generator();
        let q1=vec![g1.into_affine(),G1Projective::zero().into_affine(),(-g1).into_affine()];
        let q2=vec![g2.into_affine(),G2Projective::zero().into_affine(),(-g2).into_affine()];
        let c=MaskContext::new(b"test-key",&q1,&q1,&q1,&q1,&q2).unwrap(); (q1,q2,c)
    }

    #[test]
    fn scalar_and_group_extremes_match_native_for_all_queries() {
        let (q1,q2,c)=small();
        let cases=[
            vec![Fr::zero(),Fr::zero(),Fr::zero()],
            vec![Fr::one(),Fr::one(),Fr::one()],
            vec![-Fr::one(),Fr::one(),Fr::zero()],
            vec![Fr::from(7u64),-Fr::from(7u64),Fr::from(11u64)],
        ];
        for (i,s) in cases.into_iter().enumerate() {
            let out=c.generate_set(i as u64,&q1,&q1,&q1,&q1,&q2).unwrap()
                .apply(&c,&q1,&s,&q1,&s,&q1,&s,&q1,&s,&q2,&s).unwrap();
            let big=s.iter().map(|x|x.into_bigint()).collect::<Vec<_>>();
            let n1=G1Projective::msm_bigint(&q1,&big); let n2=G2Projective::msm_bigint(&q2,&big);
            assert_eq!(ct_g1_to_ark(out.h).unwrap(),n1); assert_eq!(ct_g1_to_ark(out.l).unwrap(),n1);
            assert_eq!(ct_g1_to_ark(out.a).unwrap(),n1); assert_eq!(ct_g1_to_ark(out.b1).unwrap(),n1);
            assert_eq!(ct_g2_to_ark(out.b2).unwrap(),n2);
        }
    }

    #[test]
    fn metadata_length_identity_and_duplicate_ids_fail_closed() {
        let (q1,q2,c)=small(); let s=vec![Fr::one();3];
        let mut wrong=c.generate_set(1,&q1,&q1,&q1,&q1,&q2).unwrap(); wrong.h.binding.order=9;
        assert!(matches!(wrong.apply(&c,&q1,&s,&q1,&s,&q1,&s,&q1,&s,&q2,&s),Err(MaskError::Binding)));
        for field in 0..4 {
            let mut wrong=c.generate_set(10+field,&q1,&q1,&q1,&q1,&q2).unwrap();
            match field {0=>wrong.h.binding.key_sha256[0]^=1,1=>wrong.h.binding.query_sha256[0]^=1,2=>wrong.h.binding.query=QueryId::L,_=>wrong.h.binding.group=QueryGroup::G2}
            let pool=TokenPool::new(vec![wrong]).unwrap(); let burned=pool.claim_next().unwrap();
            assert!(matches!(burned.validate(&c),Err(MaskError::Binding))); assert_eq!(pool.remaining(),0);
        }
        let short=vec![Fr::one();2];
        let token=c.generate_set(2,&q1,&q1,&q1,&q1,&q2).unwrap();
        assert!(matches!(token.apply(&c,&q1,&short,&q1,&s,&q1,&s,&q1,&s,&q2,&s),Err(MaskError::LengthAt(QueryId::H,2,3,3))));
        let all_zero1=vec![G1Projective::zero().into_affine()]; let all_zero2=vec![G2Projective::zero().into_affine()];
        assert!(matches!(MaskContext::new(b"k",&all_zero1,&q1,&q1,&q1,&q2),Err(MaskError::AllIdentityQuery(QueryId::H))));
        assert!(matches!(MaskContext::new(b"k",&q1,&q1,&q1,&q1,&all_zero2),Err(MaskError::AllIdentityQuery(QueryId::B2))));
        let a=c.generate_set(7,&q1,&q1,&q1,&q1,&q2).unwrap(); let b=c.generate_set(7,&q1,&q1,&q1,&q1,&q2).unwrap();
        assert!(matches!(TokenPool::new(vec![a,b]),Err(MaskError::DuplicateTokenId)));
    }

    #[test]
    fn concurrent_claim_and_cancel_burn_exactly_once() {
        let (q1,q2,c)=small(); let pool=TokenPool::new(vec![c.generate_set(1,&q1,&q1,&q1,&q1,&q2).unwrap()]).unwrap();
        let barrier=Arc::new(Barrier::new(3)); let mut joins=Vec::new();
        for _ in 0..2 { let p=pool.clone(); let b=barrier.clone(); joins.push(std::thread::spawn(move||{b.wait();p.claim_next().is_ok()})); }
        barrier.wait(); let wins=joins.into_iter().map(|j|j.join().unwrap()).filter(|won|*won).count();
        assert_eq!(wins,1); assert_eq!(pool.remaining(),0); assert_eq!(pool.consumed(),1); assert_eq!(pool.resident(),1);
        let cancel=TokenPool::new(vec![c.generate_set(2,&q1,&q1,&q1,&q1,&q2).unwrap()]).unwrap();
        let claimed=cancel.claim_next().unwrap();
        assert_eq!(Arc::strong_count(&claimed),2); // returned handle + pool-retained allocation
        drop(claimed);
        assert_eq!(cancel.remaining(),0); assert_eq!(cancel.consumed(),1); assert_eq!(cancel.resident(),1);
        assert!(cancel.claim_next().is_err());
    }
}
