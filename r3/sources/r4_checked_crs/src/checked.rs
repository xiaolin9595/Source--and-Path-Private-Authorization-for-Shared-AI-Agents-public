//! Exact, non-batched validation for the isolated R4 prototype.
use crate::{prepare_verifying_key, CheckingMaterial, Groth16, LibsnarkReduction, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{One, Zero};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::Rng;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, marker::PhantomData, time::Instant};
#[cfg(feature="parallel")]
use rayon::prelude::*;

/// Checker version included in every in-memory receipt.
pub const CHECKER_VERSION: &str = "r4-exact-ark-groth16-0.4.0-v5-g1-ifft";
/// Canonical checking-material format used by this isolated prototype.
pub const MATERIAL_FORMAT_VERSION: u64 = 1;
/// Exact R1CS-to-QAP reduction identifier.
pub const REDUCTION_ID: [u8; 32] = *b"ark-libsnark-reduction-v1.......";
/// Exact evaluation-domain construction identifier.
pub const DOMAIN_ID: [u8; 32] = *b"ark-radix2-domain-v1............";
/// Exact curve identifier for this prototype.
pub const CURVE_ID: [u8; 32] = *b"ark-bls12-381-v1................";

/// A validation failure. No witness callback has run when this is returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedError(pub String);
impl fmt::Display for CheckedError { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) } }
impl Error for CheckedError {}
fn fail<T>(message: impl Into<String>) -> Result<T, CheckedError> { Err(CheckedError(message.into())) }

/// An immutable proving key that can only be built by the exact checker.
pub struct CheckedProvingKey<E: Pairing, C> {
    pk: ProvingKey<E>,
    prepared_vk: PreparedVerifyingKey<E>,
    receipt: [u8; 32],
    relation_digest: [u8; 32],
    _relation: PhantomData<fn() -> C>,
}

impl<E: Pairing, C: ConstraintSynthesizer<E::ScalarField> + Clone> CheckedProvingKey<E, C> {
    /// Prove with the exact key object that passed validation.
    pub fn prove(
        &self,
        circuit: C,
        rng: &mut impl Rng,
    ) -> Result<Proof<E>, CheckedError> {
        let observed = relation_digest::<E, C>(circuit.clone())?;
        if observed != self.relation_digest { return fail("proof circuit differs from checked relation"); }
        Groth16::<E, LibsnarkReduction>::create_random_proof_with_reduction(circuit, &self.pk, rng)
            .map_err(|e| CheckedError(format!("proof synthesis: {e}")))
    }
    /// Prepared VK is always rebuilt from the checked embedded VK.
    pub fn prepared_vk(&self) -> &PreparedVerifyingKey<E> { &self.prepared_vk }
    /// Content-and-relation receipt for this in-memory object.
    pub fn receipt(&self) -> [u8; 32] { self.receipt }
}

fn digest_matrices<E: Pairing>(
    matrices: &ConstraintMatrices<E::ScalarField>, constraints: usize, instances: usize, witnesses: usize,
) -> Result<[u8; 32], CheckedError> {
    let mut hasher = Sha256::new();
    hasher.update((constraints as u64).to_le_bytes());
    hasher.update((instances as u64).to_le_bytes());
    hasher.update((witnesses as u64).to_le_bytes());
    for matrix in [&matrices.a, &matrices.b, &matrices.c] {
        hasher.update((matrix.len() as u64).to_le_bytes());
        for row in matrix {
            hasher.update((row.len() as u64).to_le_bytes());
            for (coeff, index) in row {
                let mut encoded=Vec::new();
                coeff.serialize_compressed(&mut encoded).map_err(|e| CheckedError(format!("relation serialize: {e}")))?;
                hasher.update(encoded); hasher.update((*index as u64).to_le_bytes());
            }
        }
    }
    Ok(hasher.finalize().into())
}

fn relation_digest<E: Pairing, C: ConstraintSynthesizer<E::ScalarField>>(circuit:C)->Result<[u8;32],CheckedError>{
    let cs=ConstraintSystem::new_ref();cs.set_optimization_goal(OptimizationGoal::Constraints);cs.set_mode(SynthesisMode::Setup);
    circuit.generate_constraints(cs.clone()).map_err(|e|CheckedError(format!("relation synthesis: {e}")))?;cs.finalize();
    let matrices=cs.to_matrices().ok_or_else(||CheckedError("missing relation matrices".into()))?;
    digest_matrices::<E>(&matrices,cs.num_constraints(),cs.num_instance_variables(),cs.num_witness_variables())
}

fn decode_exact<T: CanonicalDeserialize + CanonicalSerialize>(bytes: &[u8], label: &str) -> Result<T, CheckedError> {
    let mut cursor = bytes;
    let value = T::deserialize_compressed(&mut cursor)
        .map_err(|e| CheckedError(format!("{label} decode: {e}")))?;
    if !cursor.is_empty() { return fail(format!("trailing bytes in {label}")); }
    let mut canonical = Vec::new();
    value.serialize_compressed(&mut canonical)
        .map_err(|e| CheckedError(format!("{label} re-encode: {e}")))?;
    if canonical.as_slice() != bytes { return fail(format!("non-canonical {label} encoding")); }
    Ok(value)
}

fn mul<G: CurveGroup>(point: G, scalar: G::ScalarField) -> G {
    if scalar.is_zero() { G::zero() }
    else if scalar.is_one() { point }
    else if scalar == -G::ScalarField::one() { -point }
    else { point * scalar }
}

fn product_is_one<E: Pairing>(pairs: &[(E::G1Affine,E::G2Affine)]) -> bool {
    E::multi_pairing(pairs.iter().map(|p|p.0),pairs.iter().map(|p|p.1)).is_zero()
}
fn neg<G: AffineRepr>(point:G)->G { (-point.into_group()).into_affine() }

/// Non-overlapping checker stage durations for measurement drivers.
#[derive(Clone,Debug,Default)]
pub struct CheckMetrics {
    /// Canonical PK decode and re-encode.
    pub pk_decode_ns:u128,
    /// Canonical VK decode and re-encode.
    pub vk_decode_ns:u128,
    /// Canonical sidecar decode and re-encode.
    pub material_decode_ns:u128,
    /// Trusted relation synthesis, matrix extraction, domain and shape checks.
    pub relation_ns:u128,
    /// Power recurrence and cross-group consistency checks.
    pub powers_ns:u128,
    /// Group IFFT and sparse query reconstruction.
    pub reconstruction_ns:u128,
    /// Direct A/B1 query comparisons.
    pub direct_query_ns:u128,
    /// Per-index exact B1/B2 cross-group binding equations.
    pub b_cross_ns:u128,
    /// Public/private/H exact pairing equations.
    pub equation_ns:u128,
    /// Receipt digest and prepared-VK construction.
    pub binding_ns:u128,
    /// Entire in-memory checker call (file reads excluded).
    pub total_ns:u128,
}

/// Validate all fields consumed by the stock prover against a locally synthesized relation.
pub fn check<E, C>(
    pk_bytes: &[u8],
    vk_bytes: &[u8],
    material_bytes: &[u8],
    shape_circuit: C,
) -> Result<CheckedProvingKey<E, C>, CheckedError>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField> + Clone,
{
    check_profiled::<E,C>(pk_bytes,vk_bytes,material_bytes,shape_circuit).map(|x|x.0)
}

/// Exact check with non-overlapping stage timings.
pub fn check_profiled<E,C>(pk_bytes:&[u8],vk_bytes:&[u8],material_bytes:&[u8],shape_circuit:C)
    ->Result<(CheckedProvingKey<E,C>,CheckMetrics),CheckedError>
where E:Pairing,C:ConstraintSynthesizer<E::ScalarField>+Clone,
{
    check_profiled_with_progress::<E,C>(pk_bytes,vk_bytes,material_bytes,shape_circuit,|_,_|{})
}

/// Exact profiled check with a callback after every completed public stage.
pub fn check_profiled_with_progress<E,C>(pk_bytes:&[u8],vk_bytes:&[u8],material_bytes:&[u8],shape_circuit:C,mut progress:impl FnMut(&str,u128))
    ->Result<(CheckedProvingKey<E,C>,CheckMetrics),CheckedError>
where E:Pairing,C:ConstraintSynthesizer<E::ScalarField>+Clone,
{
    let total_started=Instant::now();let mut metrics=CheckMetrics::default();
    let t=Instant::now();
    let pk: ProvingKey<E> = decode_exact(pk_bytes, "pk")?;
    metrics.pk_decode_ns=t.elapsed().as_nanos();progress("pk_decode",metrics.pk_decode_ns);let t=Instant::now();
    let vk: VerifyingKey<E> = decode_exact(vk_bytes, "vk")?;
    metrics.vk_decode_ns=t.elapsed().as_nanos();progress("vk_decode",metrics.vk_decode_ns);let t=Instant::now();
    let material: CheckingMaterial<E> = decode_exact(material_bytes, "checking material")?;
    metrics.material_decode_ns=t.elapsed().as_nanos();progress("material_decode",metrics.material_decode_ns);
    if material.format_version != MATERIAL_FORMAT_VERSION
        || material.reduction_id != REDUCTION_ID
        || material.domain_id != DOMAIN_ID
        || material.curve_id != CURVE_ID {
        return fail("checking-material identity mismatch");
    }
    if pk.vk != vk { return fail("external VK differs from embedded VK"); }

    let t=Instant::now();let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(SynthesisMode::Setup);
    shape_circuit.generate_constraints(cs.clone()).map_err(|e| CheckedError(format!("shape synthesis: {e}")))?;
    cs.finalize();
    let constraints = cs.num_constraints();
    let instances = cs.num_instance_variables();
    let witnesses = cs.num_witness_variables();
    let matrices = cs.to_matrices().ok_or_else(|| CheckedError("missing matrices".into()))?;
    let requested = constraints.checked_add(instances).ok_or_else(|| CheckedError("shape overflow".into()))?;
    let general = GeneralEvaluationDomain::<E::ScalarField>::new(requested)
        .ok_or_else(|| CheckedError("unsupported domain".into()))?;
    let domain = match general {
        GeneralEvaluationDomain::Radix2(domain) => domain,
        GeneralEvaluationDomain::MixedRadix(_) => return fail("mixed-radix domain rejected"),
    };
    let d = domain.size();
    if d < 2 { return fail("domain size below two"); }
    if material.requested_domain_size != requested as u64 || material.domain_size != d as u64
        || material.num_constraints != constraints as u64
        || material.num_instance_variables != instances as u64
        || material.num_witness_variables != witnesses as u64 {
        return fail("checking-material shape mismatch");
    }
    let variables = instances + witnesses;
    if material.tau_powers_g1.len() != d || material.tau_powers_g2.len() != d
        || pk.a_query.len() != variables || pk.b_g1_query.len() != variables
        || pk.b_g2_query.len() != variables || pk.h_query.len() != d - 1
        || pk.l_query.len() != witnesses || vk.gamma_abc_g1.len() != instances {
        return fail("query dimension mismatch");
    }
    let g1 = material.tau_powers_g1[0];
    let g2 = material.tau_powers_g2[0];
    if g1.is_zero() || g2.is_zero() || vk.alpha_g1.is_zero() || pk.beta_g1.is_zero()
        || vk.gamma_g2.is_zero() || pk.delta_g1.is_zero() || pk.h_query[0].is_zero() {
        return fail("degenerate CRS element");
    }
    metrics.relation_ns=t.elapsed().as_nanos();progress("relation",metrics.relation_ns);let t=Instant::now();

    ark_std::cfg_into_iter!(1..d).try_for_each(|j| -> Result<(),CheckedError> {
        if !product_is_one::<E>(&[(material.tau_powers_g1[j],g2),(neg(material.tau_powers_g1[j-1]),material.tau_powers_g2[1])]) {
            return fail(format!("G1 power recurrence {j}"));
        }
        if !product_is_one::<E>(&[(g1,material.tau_powers_g2[j]),(neg(material.tau_powers_g1[j]),g2)]) {
            return fail(format!("cross-group power {j}"));
        }
        Ok(())
    })?;
    if !product_is_one::<E>(&[(pk.beta_g1,g2),(neg(g1),vk.beta_g2)]) { return fail("beta mismatch"); }
    if !product_is_one::<E>(&[(pk.delta_g1,g2),(neg(g1),vk.delta_g2)]) { return fail("delta mismatch"); }
    metrics.powers_ns=t.elapsed().as_nanos();progress("powers",metrics.powers_ns);let t=Instant::now();

    let powers_g1 = material.tau_powers_g1.iter().map(|x| x.into_group()).collect::<Vec<_>>();
    let lagrange_g1 = domain.ifft(&powers_g1);
    let mut a1 = vec![E::G1::zero(); variables];
    let mut b1 = vec![E::G1::zero(); variables];
    let mut c1 = vec![E::G1::zero(); variables];
    for i in 0..instances { a1[i] += lagrange_g1[constraints + i]; }
    for row in 0..constraints {
        for &(coeff, index) in &matrices.a[row] { a1[index] += mul(lagrange_g1[row], coeff); }
        for &(coeff, index) in &matrices.b[row] {
            b1[index] += mul(lagrange_g1[row], coeff);
        }
        for &(coeff, index) in &matrices.c[row] { c1[index] += mul(lagrange_g1[row], coeff); }
    }
    metrics.reconstruction_ns=t.elapsed().as_nanos();progress("reconstruction",metrics.reconstruction_ns);let t=Instant::now();
    for i in 0..variables {
        if a1[i].into_affine() != pk.a_query[i] { return fail(format!("a_query {i}")); }
        if b1[i].into_affine() != pk.b_g1_query[i] { return fail(format!("b_g1_query {i}")); }
    }
    metrics.direct_query_ns=t.elapsed().as_nanos();progress("direct_query",metrics.direct_query_ns);let t=Instant::now();
    ark_std::cfg_into_iter!(0..variables).try_for_each(|i| -> Result<(),CheckedError> {
        if !product_is_one::<E>(&[(pk.b_g1_query[i],g2),(neg(g1),pk.b_g2_query[i])]) { return fail(format!("b_query cross-group {i}")); }
        Ok(())
    })?;
    metrics.b_cross_ns=t.elapsed().as_nanos();progress("b_cross",metrics.b_cross_ns);let t=Instant::now();

    ark_std::cfg_into_iter!(0..instances).try_for_each(|i| -> Result<(),CheckedError> {
        if !product_is_one::<E>(&[(vk.gamma_abc_g1[i],vk.gamma_g2),(neg(a1[i].into_affine()),vk.beta_g2),(neg(vk.alpha_g1),pk.b_g2_query[i]),(neg(c1[i].into_affine()),g2)]) { return fail(format!("public query {i}")); }
        Ok(())
    })?;
    ark_std::cfg_into_iter!(instances..variables).try_for_each(|i| -> Result<(),CheckedError> {
        if !product_is_one::<E>(&[(pk.l_query[i-instances],vk.delta_g2),(neg(a1[i].into_affine()),vk.beta_g2),(neg(vk.alpha_g1),pk.b_g2_query[i]),(neg(c1[i].into_affine()),g2)]) { return fail(format!("private query {i}")); }
        Ok(())
    })?;
    ark_std::cfg_into_iter!(0..(d-1)).try_for_each(|i| -> Result<(),CheckedError> {
        if !product_is_one::<E>(&[(pk.h_query[i],vk.delta_g2),(g1,material.tau_powers_g2[i]),(neg(material.tau_powers_g1[d-1]),material.tau_powers_g2[i+1])]) { return fail(format!("h_query {i}")); }
        Ok(())
    })?;
    metrics.equation_ns=t.elapsed().as_nanos();progress("equations",metrics.equation_ns);let t=Instant::now();

    let relation_digest = digest_matrices::<E>(&matrices,constraints,instances,witnesses)?;
    let mut hasher = Sha256::new();
    hasher.update(CHECKER_VERSION.as_bytes());
    hasher.update(pk_bytes); hasher.update(vk_bytes); hasher.update(material_bytes);
    hasher.update((constraints as u64).to_le_bytes());
    hasher.update((instances as u64).to_le_bytes());
    hasher.update((witnesses as u64).to_le_bytes());
    hasher.update(relation_digest);
    let receipt: [u8; 32] = hasher.finalize().into();
    let prepared_vk = prepare_verifying_key(&vk);
    metrics.binding_ns=t.elapsed().as_nanos();progress("binding",metrics.binding_ns);metrics.total_ns=total_started.elapsed().as_nanos();progress("checker_total",metrics.total_ns);
    Ok((CheckedProvingKey { pk, prepared_vk, receipt, relation_digest, _relation:PhantomData },metrics))
}

/// Check before invoking a callback that can materialize a private witness.
pub fn check_then_prove<E, C>(
    pk_bytes: &[u8], vk_bytes: &[u8], material_bytes: &[u8], shape: C,
    witness_callback: impl FnOnce() -> C, rng: &mut impl Rng,
) -> Result<(Proof<E>, PreparedVerifyingKey<E>, [u8; 32]), CheckedError>
where
    E: Pairing,
    C: ConstraintSynthesizer<E::ScalarField> + Clone,
{
    let checked = check::<E, C>(pk_bytes, vk_bytes, material_bytes, shape)?;
    let proof = checked.prove(witness_callback(), rng)?;
    Ok((proof, checked.prepared_vk.clone(), checked.receipt))
}
