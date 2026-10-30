//! Timestamp-only copy of the ark-groth16 0.4.0 prover path used by R11.
//! No counters, hashes, serialization, verification, or output occur here.

use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_groth16::{r1cs_to_qap::{LibsnarkReduction, R1CSToQAP}, Proof, ProvingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, Result as R1CSResult};
use serde::Serialize;
use ark_r1cs_std::synthesis_patch::{enter, Mode};
use std::{ops::{AddAssign, Mul}, time::Instant};

type Domain<F> = GeneralEvaluationDomain<F>;

#[derive(Clone, Serialize)]
pub struct PhaseTimes {
    pub synthesis_ms: f64,
    pub finalize_ms: f64,
    pub qap_witness_map_ms: f64,
    pub h_scalar_conversion_ms: f64,
    pub h_msm_ms: f64,
    pub l_scalar_conversion_ms: f64,
    pub l_msm_ms: f64,
    pub rs_delta_randomizer_ms: f64,
    pub assignment_conversion_ms: f64,
    pub a_randomizer_pre_ms: f64,
    pub a_msm_ms: f64,
    pub a_coeff_fixed_ms: f64,
    pub a_randomizer_post_ms: f64,
    pub b_g1_randomizer_pre_ms: f64,
    pub b_g1_msm_ms: f64,
    pub b_g1_coeff_fixed_ms: f64,
    pub b_g2_randomizer_pre_ms: f64,
    pub b_g2_msm_ms: f64,
    pub b_g2_coeff_fixed_ms: f64,
    pub b_g1_randomizer_post_ms: f64,
    pub final_c_assembly_ms: f64,
    pub affine_normalization_ms: f64,
}

fn timed_coeff<G: AffineRepr>(
    initial: G::Group,
    query: &[G],
    vk_param: G,
    assignment: &[<G::ScalarField as PrimeField>::BigInt],
) -> (G::Group, f64, f64)
where
    G::Group: VariableBaseMSM<MulBase = G>,
{
    let t = Instant::now();
    let mut result = initial;
    result.add_assign(&query[0]);
    let fixed_pre_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let msm = G::Group::msm_bigint(&query[1..], assignment);
    let msm_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    result += &msm;
    result.add_assign(&vk_param);
    let fixed_post_ms = t.elapsed().as_secs_f64() * 1000.0;
    (result, msm_ms, fixed_pre_ms + fixed_post_ms)
}

pub fn prove_with_randomness<E, C>(
    pk: &ProvingKey<E>,
    circuit: C,
    r: E::ScalarField,
    s: E::ScalarField,
) -> R1CSResult<(Proof<E>, PhaseTimes)>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    prove_with_randomness_mode(pk, circuit, r, s, Mode::Native)
}

pub fn prove_with_randomness_mode<E, C>(
    pk: &ProvingKey<E>,
    circuit: C,
    r: E::ScalarField,
    s: E::ScalarField,
    synthesis_mode: Mode,
) -> R1CSResult<(Proof<E>, PhaseTimes)>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);

    let t = Instant::now();
    let synthesis_guard = enter(synthesis_mode);
    circuit.generate_constraints(cs.clone())?;
    drop(synthesis_guard);
    debug_assert!(cs.is_satisfied().unwrap());
    let synthesis_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    cs.finalize();
    let finalize_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    let h = LibsnarkReduction::witness_map::<E::ScalarField, Domain<E::ScalarField>>(cs.clone())?;
    let qap_witness_map_ms = t.elapsed().as_secs_f64() * 1000.0;
    let borrowed = cs.borrow().unwrap();
    let input_assignment = &borrowed.instance_assignment[1..];
    let aux_assignment = &borrowed.witness_assignment;

    let t = Instant::now();
    let h_assignment = h.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
    let h_scalar_conversion_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let h_acc = E::G1::msm_bigint(&pk.h_query, &h_assignment);
    let h_msm_ms = t.elapsed().as_secs_f64() * 1000.0;
    drop(h_assignment);

    let t = Instant::now();
    let aux_bigints = aux_assignment.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
    let l_scalar_conversion_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let l_aux_acc = E::G1::msm_bigint(&pk.l_query, &aux_bigints);
    let l_msm_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    let r_s_delta_g1 = pk.delta_g1.into_group().mul_bigint(r.into_bigint()).mul_bigint(s.into_bigint());
    let rs_delta_randomizer_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    let input_bigints = input_assignment.iter().map(|x| x.into_bigint()).collect::<Vec<_>>();
    let assignment = [&input_bigints[..], &aux_bigints[..]].concat();
    let assignment_conversion_ms = t.elapsed().as_secs_f64() * 1000.0;
    drop(aux_bigints);

    let t = Instant::now();
    let r_g1 = pk.delta_g1.mul(r);
    let a_randomizer_pre_ms = t.elapsed().as_secs_f64() * 1000.0;
    let (g_a, a_msm_ms, a_coeff_fixed_ms) = timed_coeff(r_g1, &pk.a_query, pk.vk.alpha_g1, &assignment);
    let t = Instant::now();
    let s_g_a = g_a.mul_bigint(s.into_bigint());
    let a_randomizer_post_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    let (g1_b, b_g1_randomizer_pre_ms, b_g1_msm_ms, b_g1_coeff_fixed_ms) = if !r.is_zero() {
        let s_g1 = pk.delta_g1.mul(s);
        let pre_ms = t.elapsed().as_secs_f64() * 1000.0;
        let (value, msm_ms, fixed_ms) = timed_coeff(s_g1, &pk.b_g1_query, pk.beta_g1, &assignment);
        (value, pre_ms, msm_ms, fixed_ms)
    } else {
        (E::G1::zero(), t.elapsed().as_secs_f64() * 1000.0, 0.0, 0.0)
    };

    let t = Instant::now();
    let s_g2 = pk.vk.delta_g2.mul(s);
    let b_g2_randomizer_pre_ms = t.elapsed().as_secs_f64() * 1000.0;
    let (g2_b, b_g2_msm_ms, b_g2_coeff_fixed_ms) = timed_coeff(s_g2, &pk.b_g2_query, pk.vk.beta_g2, &assignment);
    let t = Instant::now();
    let r_g1_b = g1_b.mul_bigint(r.into_bigint());
    let b_g1_randomizer_post_ms = t.elapsed().as_secs_f64() * 1000.0;
    drop(assignment);

    let t = Instant::now();
    let mut g_c = s_g_a;
    g_c += &r_g1_b;
    g_c -= &r_s_delta_g1;
    g_c += &l_aux_acc;
    g_c += &h_acc;
    let final_c_assembly_ms = t.elapsed().as_secs_f64() * 1000.0;

    let t = Instant::now();
    let proof = Proof { a: g_a.into_affine(), b: g2_b.into_affine(), c: g_c.into_affine() };
    let affine_normalization_ms = t.elapsed().as_secs_f64() * 1000.0;

    Ok((proof, PhaseTimes {
        synthesis_ms, finalize_ms, qap_witness_map_ms, h_scalar_conversion_ms, h_msm_ms,
        l_scalar_conversion_ms, l_msm_ms, rs_delta_randomizer_ms, assignment_conversion_ms,
        a_randomizer_pre_ms, a_msm_ms, a_coeff_fixed_ms, a_randomizer_post_ms,
        b_g1_randomizer_pre_ms, b_g1_msm_ms, b_g1_coeff_fixed_ms,
        b_g2_randomizer_pre_ms, b_g2_msm_ms, b_g2_coeff_fixed_ms,
        b_g1_randomizer_post_ms, final_c_assembly_ms, affine_normalization_ms,
    }))
}
