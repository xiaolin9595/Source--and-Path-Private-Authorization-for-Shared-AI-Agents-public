use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{BigInteger, PrimeField, UniformRand, Zero};
use std::time::Instant;
use serde_json::{json, Value};
use rayon::prelude::*;
use ark_groth16::{
    r1cs_to_qap::{LibsnarkReduction, R1CSToQAP},
    Proof, ProvingKey,
};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, Result as R1CSResult,
};
use ark_std::rand::Rng;
use std::ops::{AddAssign, Mul};

type Domain<F> = GeneralEvaluationDomain<F>;

fn measured_msm<G: AffineRepr>(bases: &[G], scalars: &[G::ScalarField], dense: bool, label: &str, phases: &mut Vec<Value>) -> G::Group
where G::Group: VariableBaseMSM<MulBase=G> {
 let n=bases.len().min(scalars.len());
 let values:Vec<_>=scalars[..n].iter().map(|s|s.into_bigint()).collect();
 if dense {dense_wnaf::<G::Group>(bases,&values)} else {G::Group::msm_bigint(bases,&values)}
}

fn coeff<G:AffineRepr>(initial:G::Group,query:&[G],vk:G,assignment:&[G::ScalarField],dense:bool,label:&str,phases:&mut Vec<Value>)->G::Group where G::Group:VariableBaseMSM<MulBase=G> {
 let mut r=initial;r+=&query[0];r+=&measured_msm(&query[1..],assignment,dense,label,phases);r+=&vk;r
}
/// Produce a standard Groth16 proof with density-blinded prover MSMs.
pub fn prove_pilot<E, C>(
    pk: &ProvingKey<E>,
    circuit: C,
    rng: &mut impl Rng,
    dense: bool,
    phases: &mut Vec<Value>,
) -> R1CSResult<Proof<E>>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField>,
{
    let r = E::ScalarField::rand(rng);
    let s = E::ScalarField::rand(rng);
    let t=Instant::now();
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone())?;
    debug_assert!(cs.is_satisfied().unwrap());
    cs.finalize();

    let t=Instant::now();
    let h = LibsnarkReduction::witness_map::<E::ScalarField, Domain<E::ScalarField>>(cs.clone())?;
    let borrowed = cs.borrow().unwrap();
    let input_assignment = &borrowed.instance_assignment[1..];
    let aux_assignment = &borrowed.witness_assignment;

    let h_acc = measured_msm(&pk.h_query, &h, dense,"h_msm",phases);
    let l_aux_acc = measured_msm(&pk.l_query, aux_assignment,dense,"l_msm",phases);
    let assignment = [input_assignment, aux_assignment].concat();

    let r_g1 = pk.delta_g1.mul(r);
    let g_a = coeff(r_g1,&pk.a_query,pk.vk.alpha_g1,&assignment,dense,"a_msm",phases);
    let s_g1 = pk.delta_g1.mul(s);
    let g1_b = coeff(s_g1,&pk.b_g1_query,pk.beta_g1,&assignment,dense,"b_g1_msm",phases);
    let s_g2 = pk.vk.delta_g2.mul(s);
    let g2_b = coeff(s_g2,&pk.b_g2_query,pk.vk.beta_g2,&assignment,dense,"b_g2_msm",phases);

    let mut g_c = g_a.mul_bigint(s.into_bigint());
    g_c += &g1_b.mul_bigint(r.into_bigint());
    g_c -= &pk
        .delta_g1
        .into_group()
        .mul_bigint(r.into_bigint())
        .mul_bigint(s.into_bigint());
    g_c += &l_aux_acc;
    g_c += &h_acc;

    Ok(Proof {
        a: g_a.into_affine(),
        b: g2_b.into_affine(),
        c: g_c.into_affine(),
    })
}


fn dense_wnaf<V: VariableBaseMSM>(
    bases: &[V::MulBase],
    bigints: &[<V::ScalarField as PrimeField>::BigInt],
) -> V {
    let size = ark_std::cmp::min(bases.len(), bigints.len());
    let scalars = &bigints[..size];
    let bases = &bases[..size];

    let c = if size < 32 {
        3
    } else {
        ((ark_std::log2(size) as usize)*69/100) + 2
    };

    let num_bits = V::ScalarField::MODULUS_BIT_SIZE as usize;
    let digits_count = (num_bits + c - 1) / c;
    let scalar_digits = scalars
        .iter()
        .flat_map(|s| make_digits(s, c, num_bits))
        .collect::<Vec<_>>();
    let zero = V::zero();
    let window_sums: Vec<_> = (0..digits_count).into_par_iter()
        .map(|i| {
            let mut buckets = vec![zero; (1 << c)+1];
            for (digits, base) in scalar_digits.chunks(digits_count).zip(bases) {
                use ark_std::cmp::Ordering;
                // digits is the digits thing of the first scalar?
                let scalar = digits[i];
                match 0.cmp(&scalar) {
                    Ordering::Less => buckets[scalar as usize] += base,
                    Ordering::Greater => buckets[(-scalar) as usize] -= base,
                    Ordering::Equal => buckets[0] += base,
                }
            }

            std::hint::black_box(&buckets[0]);
            let mut running_sum = V::zero();
            let mut res = V::zero();
            buckets.into_iter().skip(1).rev().for_each(|b| {
                running_sum += &b;
                res += &running_sum;
            });
            res
        })
        .collect();

    // We store the sum for the lowest window.
    let lowest = *window_sums.first().unwrap();

    // We're traversing windows from high to low.
    lowest
        + &window_sums[1..]
            .iter()
            .rev()
            .fold(zero, |mut total, sum_i| {
                total += sum_i;
                for _ in 0..c {
                    total.double_in_place();
                }
                total
            })
}


fn make_digits(a: &impl BigInteger, w: usize, num_bits: usize) -> Vec<i64> {
    let scalar = a.as_ref();
    let radix: u64 = 1 << w;
    let window_mask: u64 = radix - 1;

    let mut carry = 0u64;
    let num_bits = if num_bits == 0 {
        a.num_bits() as usize
    } else {
        num_bits
    };
    let digits_count = (num_bits + w - 1) / w;
    let mut digits = vec![0i64; digits_count];
    for (i, digit) in digits.iter_mut().enumerate() {
        // Construct a buffer of bits of the scalar, starting at `bit_offset`.
        let bit_offset = i * w;
        let u64_idx = bit_offset / 64;
        let bit_idx = bit_offset % 64;
        // Read the bits from the scalar
        let bit_buf = if bit_idx < 64 - w || u64_idx == scalar.len() - 1 {
            // This window's bits are contained in a single u64,
            // or it's the last u64 anyway.
            scalar[u64_idx] >> bit_idx
        } else {
            // Combine the current u64's bits with the bits from the next u64
            (scalar[u64_idx] >> bit_idx) | (scalar[1 + u64_idx] << (64 - bit_idx))
        };

        // Read the actual coefficient value from the window
        let coef = carry + (bit_buf & window_mask); // coef = [0, 2^r)

        // Recenter coefficients from [0,2^w) to [-2^w/2, 2^w/2)
        carry = (coef + radix / 2) >> w;
        *digit = (coef as i64) - (carry << w) as i64;
    }

    digits[digits_count - 1] += (carry << w) as i64;

    digits
}
