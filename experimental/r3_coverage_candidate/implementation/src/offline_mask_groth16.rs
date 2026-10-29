//! BLS12-381 Groth16 prover using one-use offline masks for all five MSMs.
//!
//! This is intentionally concrete rather than generic: the correction and all
//! subsequent witness-dependent group arithmetic remain in zkcrypto's
//! BLS12-381 implementation until the final, public proof is encoded.

use crate::offline_mask::{
    ark_fr_to_ct_public, ark_g1_to_ct_public, ark_g2_to_ct_public, ct_g1_to_ark,
    ct_g2_to_ark, FiveQueryTimes, MaskContext, MaskError, MaskSet, TokenPool,
};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::{AffineRepr, CurveGroup};
use ark_groth16::{r1cs_to_qap::{LibsnarkReduction, R1CSToQAP}, Proof, ProvingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_r1cs_std::synthesis_patch::{enter, Mode};
use bls12_381_ct::{G1Projective as CtG1, G2Projective as CtG2};
use serde::Serialize;
use std::{sync::Arc, time::Instant};

type Domain = GeneralEvaluationDomain<Fr>;

#[derive(Debug, thiserror::Error)]
pub enum MaskedProverError {
    #[error(transparent)]
    Synthesis(#[from] SynthesisError),
    #[error(transparent)]
    Mask(#[from] MaskError),
}

#[derive(Clone, Debug, Serialize)]
pub struct MaskedProverTimes {
    pub token_claim_and_binding_ms: f64,
    pub synthesis_ms: f64,
    pub finalize_ms: f64,
    pub qap_witness_map_ms: f64,
    pub queries: FiveQueryTimes,
    pub correction_to_proof_assembly_ms: f64,
    pub public_output_bridge_ms: f64,
}

/// Public, key-only material. Construct outside the online proof timer.
pub struct PublicAssemblyContext {
    /// Immutable PK ownership prevents a caller from pairing cached bindings
    /// with a different key. All query hashing/serialization happens in `new`.
    pub pk: Arc<ProvingKey<Bls12_381>>,
    pub masks: MaskContext,
    delta_g1: CtG1,
    delta_g2: CtG2,
    alpha_g1: CtG1,
    beta_g1: CtG1,
    beta_g2: CtG2,
    a_zero: CtG1,
    b1_zero: CtG1,
    b2_zero: CtG2,
}

impl PublicAssemblyContext {
    pub fn new(pk: Arc<ProvingKey<Bls12_381>>) -> Result<Self, MaskError> {
        let mut key_bytes = Vec::new();
        pk.serialize_compressed(&mut key_bytes).expect("Vec serialization cannot fail");
        let masks = MaskContext::new(
            &key_bytes,
            &pk.h_query,
            &pk.l_query,
            &pk.a_query[1..],
            &pk.b_g1_query[1..],
            &pk.b_g2_query[1..],
        )?;
        Ok(Self {
            masks,
            delta_g1: ark_g1_to_ct_public(pk.delta_g1.into_group())?,
            delta_g2: ark_g2_to_ct_public(pk.vk.delta_g2.into_group())?,
            alpha_g1: ark_g1_to_ct_public(pk.vk.alpha_g1.into_group())?,
            beta_g1: ark_g1_to_ct_public(pk.beta_g1.into_group())?,
            beta_g2: ark_g2_to_ct_public(pk.vk.beta_g2.into_group())?,
            a_zero: ark_g1_to_ct_public(pk.a_query[0].into_group())?,
            b1_zero: ark_g1_to_ct_public(pk.b_g1_query[0].into_group())?,
            b2_zero: ark_g2_to_ct_public(pk.b_g2_query[0].into_group())?,
            pk,
        })
    }

    pub fn generate_set(&self, token_id: u64) -> Result<MaskSet, MaskError> {
        let pk=&self.pk;
        self.masks.generate_set(
            token_id,
            &pk.h_query,
            &pk.l_query,
            &pk.a_query[1..],
            &pk.b_g1_query[1..],
            &pk.b_g2_query[1..],
        )
    }
}

/// Atomically burns a whole token before binding validation, synthesis, or any
/// other witness-dependent work. Errors and unwinding cannot return it.
pub fn prove_from_pool<C: ConstraintSynthesizer<Fr>>(
    pool: &TokenPool,
    public: &PublicAssemblyContext,
    circuit: C,
    r: Fr,
    s: Fr,
    synthesis_mode: Mode,
) -> Result<(Proof<Bls12_381>, MaskedProverTimes), MaskedProverError> {
    let claim_started = Instant::now();
    let token = pool.claim_next()?;
    token.validate(&public.masks)?;
    let token_claim_and_binding_ms=claim_started.elapsed().as_secs_f64()*1000.0;
    prove_with_burned_token(&public.pk, public, token, circuit, r, s, synthesis_mode, token_claim_and_binding_ms)
}

fn prove_with_burned_token<C: ConstraintSynthesizer<Fr>>(
    pk: &ProvingKey<Bls12_381>, public: &PublicAssemblyContext, token: Arc<MaskSet>,
    circuit: C, r: Fr, s: Fr, synthesis_mode: Mode, token_claim_and_binding_ms:f64,
) -> Result<(Proof<Bls12_381>, MaskedProverTimes), MaskedProverError> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    // The !Send TLS guard is created and consumed on the exact thread that
    // runs synthesis; no Rayon task owns or changes this public mode.
    let t=Instant::now(); let synthesis_guard = enter(synthesis_mode);
    circuit.generate_constraints(cs.clone())?;
    drop(synthesis_guard);
    let synthesis_ms=t.elapsed().as_secs_f64()*1000.0;
    let t=Instant::now(); cs.finalize(); let finalize_ms=t.elapsed().as_secs_f64()*1000.0;

    let t=Instant::now(); let h = LibsnarkReduction::witness_map::<Fr, Domain>(cs.clone())?;
    let qap_witness_map_ms=t.elapsed().as_secs_f64()*1000.0;
    // arkworks' native prover passes the full domain vector (one element longer)
    // to `msm_bigint`, whose implementation truncates to the query length. Make
    // that effective scalar sequence explicit, then enforce exact mask lengths.
    if h.len() != pk.h_query.len() + 1 {
        return Err(MaskError::LengthAt(crate::offline_mask::QueryId::H, h.len(), pk.h_query.len(), pk.h_query.len() + 1).into());
    }
    let h_effective = &h[..pk.h_query.len()];
    let borrowed = cs.borrow().ok_or(SynthesisError::AssignmentMissing)?;
    let input_assignment = &borrowed.instance_assignment[1..];
    let aux_assignment = &borrowed.witness_assignment;
    let assignment = [input_assignment, aux_assignment].concat();

    let (corrected,queries) = token.apply_timed(
        &public.masks,
        &pk.h_query,
        h_effective,
        &pk.l_query,
        aux_assignment,
        &pk.a_query[1..],
        &assignment,
        &pk.b_g1_query[1..],
        &assignment,
        &pk.b_g2_query[1..],
        &assignment,
    )?;
    drop(borrowed);

    let t=Instant::now();
    let r_ct = ark_fr_to_ct_public(&r)?;
    let s_ct = ark_fr_to_ct_public(&s)?;
    let g_a = (&public.delta_g1 * &r_ct) + public.a_zero + corrected.a + public.alpha_g1;
    let g1_b = (&public.delta_g1 * &s_ct) + public.b1_zero + corrected.b1 + public.beta_g1;
    let g2_b = (&public.delta_g2 * &s_ct) + public.b2_zero + corrected.b2 + public.beta_g2;
    let rs = r_ct * s_ct;
    let g_c = (&g_a * &s_ct) + (&g1_b * &r_ct) - (&public.delta_g1 * &rs)
        + corrected.l + corrected.h;
    let correction_to_proof_assembly_ms=t.elapsed().as_secs_f64()*1000.0;

    let t=Instant::now(); let proof=Proof {
        a: ct_g1_to_ark(g_a)?.into_affine(),
        b: ct_g2_to_ark(g2_b)?.into_affine(),
        c: ct_g1_to_ark(g_c)?.into_affine(),
    }; let public_output_bridge_ms=t.elapsed().as_secs_f64()*1000.0;
    Ok((proof,MaskedProverTimes{token_claim_and_binding_ms,synthesis_ms,finalize_ms,qap_witness_map_ms,queries,correction_to_proof_assembly_ms,public_output_bridge_ms}))
}
