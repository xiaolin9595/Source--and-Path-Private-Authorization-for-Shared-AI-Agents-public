//! Pilot HRADA common authorization relation, BLS12-381 Fr / Jubjub.
//! Full 256-bit domain-separated Blake2s digests; three private prefix slots.
//! This module is the common authorization relation, not the CP membership proof.
use ark_bls12_381::Fr;
use ark_crypto_primitives::{
    prf::blake2s::constraints::evaluate_blake2s,
    signature::schnorr::{Parameters, Schnorr, SecretKey, Signature},
    SignatureScheme,
};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ed_on_bls12_381::{
    constraints::EdwardsVar, EdwardsAffine, EdwardsProjective, Fr as Scalar,
};
use ark_ff::{BigInteger, Field, FpParameters, One, PrimeField, ToBytes, Zero};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use blake2::{Blake2s, Digest};
use rand::{rngs::StdRng, SeedableRng};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::convert::TryInto;

/// Experiment-only authorization relation with parameterized private capacity.
pub mod scaling;

pub type Hash = [u8; 32];
pub type Sig = Signature<EdwardsProjective>;
pub type Scheme = Schnorr<EdwardsProjective, Blake2s>;
pub const TREE_DEPTH: usize = 3;
pub const REQUEST_FIELDS: usize = 16;
fn f(x: u64) -> Fr {
    Fr::from(x)
}
fn bytes(xs: &[Fr]) -> Vec<u8> {
    let mut b = vec![];
    for x in xs {
        x.write(&mut b).unwrap();
    }
    b
}
fn hash(domain: u8, data: &[u8]) -> Hash {
    let mut b = vec![domain];
    b.extend_from_slice(data);
    let d = Blake2s::digest(&b);
    let mut o = [0; 32];
    o.copy_from_slice(&d);
    o
}
fn fh(domain: u8, xs: &[Fr], tail: &[u8]) -> Hash {
    let mut b = bytes(xs);
    b.extend_from_slice(tail);
    hash(domain, &b)
}
fn limbs(h: Hash) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&h[..16]),
        Fr::from_le_bytes_mod_order(&h[16..]),
    ]
}
fn scalar_base(s: Scalar) -> Fr {
    Fr::from_le_bytes_mod_order(&bytes_scalar(s))
}
fn bytes_scalar(s: Scalar) -> Vec<u8> {
    let mut v = vec![];
    s.write(&mut v).unwrap();
    v
}
fn sig_bytes(s: &Sig) -> Vec<u8> {
    [
        bytes_scalar(s.prover_response),
        bytes_scalar(s.verifier_challenge),
    ]
    .concat()
}
fn sign(
    p: &Parameters<EdwardsProjective, Blake2s>,
    sk: &SecretKey<EdwardsProjective>,
    h: Hash,
    rng: &mut StdRng,
) -> Sig {
    Scheme::sign(p, sk, &h, rng).unwrap()
}

/// Public order after prime: header limbs, epoch, system, circuit version,
/// verifier, PEP, resource, action, time, nonce, permit expiry, context limbs, Agent x/y.
#[derive(Clone, Debug)]
pub struct AuthRequest {
    pub fields: [Fr; REQUEST_FIELDS],
}
impl AuthRequest {
    pub fn new(agent: EdwardsAffine) -> Self {
        Self {
            fields: [
                f(10),
                f(11),
                f(1),
                f(1),
                f(1),
                f(17),
                f(18),
                f(42),
                f(1),
                f(500),
                f(99),
                f(550),
                f(12),
                f(13),
                agent.x,
                agent.y,
            ],
        }
    }
}
#[derive(Clone)]
/// fields: type, C_U.lo, C_U.hi, issuer.x, issuer.y, subject.x, subject.y,
/// resource, actionMask, notBefore, notAfter, delegable, depth, serial,
/// leafIndex, private chainId (opaque Fr), recordVersion.
pub struct Grant {
    pub fields: [Fr; 17],
    pub parent: Hash,
    pub signature: Sig,
    pub active: bool,
}
impl Grant {
    pub fn core(&self) -> Hash {
        fh(3, &self.fields, &self.parent)
    }
    pub fn id(&self) -> Hash {
        let mut b = self.core().to_vec();
        b.extend(sig_bytes(&self.signature));
        hash(4, &b)
    }
    pub fn leaf(&self) -> Hash {
        let mut b = bytes(&[self.fields[14]]);
        b.extend(self.core());
        b.push(self.active as u8);
        hash(5, &b)
    }
}
#[derive(Clone)]
pub struct AuthCircuit {
    /// Nonempty private prefix; circuit shape is independent of these bits.
    pub enabled: [bool; 3],
    pub prime: Fr,
    pub request: AuthRequest,
    pub params: Parameters<EdwardsProjective, Blake2s>,
    pub ra_pk: EdwardsAffine,
    pub sr_pk: EdwardsAffine,
    pub user_pk: EdwardsAffine,
    pub rho: Fr,
    pub reg_serial: u64,
    pub reg_expiry: u64,
    pub ra_sig: Sig,
    pub auth_root: Hash,
    pub state_version: u64,
    pub state_status: u64,
    pub state_expiry: u64,
    pub transition: Hash,
    pub sr_sig: Sig,
    pub grants: Vec<Grant>,
    pub paths: Vec<Vec<Hash>>,
    pub holder: Scalar,
}

/// Explicit experiment-only relation that omits the final discarded domain-8
/// request hash. The ordinary [`AuthCircuit`] implementation remains unchanged.
#[derive(Clone)]
pub struct ExperimentalAuthWithoutRequestHash(pub AuthCircuit);

impl ConstraintSynthesizer<Fr> for ExperimentalAuthWithoutRequestHash {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.0
            .synthesize_with_constraint_observer(cs, false, None, false, None)
            .map(|_| ())
    }
}

/// One fixed-capacity parent row in the experiment-only private Merkle union.
#[derive(Clone, Debug, Default, Serialize)]
pub struct PrivateMerkleUnionRow {
    pub active: bool,
    pub address: usize,
    pub left: Hash,
    pub right: Hash,
}

/// Private 3/2/1-row witness. These values are only assignments: the circuit
/// constrains all routing, coverage, addresses, child sides and the final root.
#[derive(Clone, Debug, Serialize)]
pub struct PrivateMerkleUnionWitness {
    pub level0: [PrivateMerkleUnionRow; 3],
    pub level1: [PrivateMerkleUnionRow; 2],
    pub level2: [PrivateMerkleUnionRow; 1],
    pub query_routes: [[bool; 3]; 3],
    pub level0_routes: [[bool; 2]; 3],
    pub level1_routes: [[bool; 1]; 2],
}

/// Explicit experiment-only Auth relation. It omits the same discarded
/// domain-8 request hash as [`ExperimentalAuthWithoutRequestHash`] and replaces
/// only the three independent depth-3 paths with a private 3/2/1-row union.
#[derive(Clone)]
pub struct ExperimentalAuthWithPrivateMerkleUnion {
    pub circuit: AuthCircuit,
    /// `None` uses the deterministic witness builder. An explicit witness is
    /// exposed for adversarial synthesis tests; it receives no special trust.
    pub union_witness: Option<PrivateMerkleUnionWitness>,
}

impl ExperimentalAuthWithPrivateMerkleUnion {
    pub fn new(circuit: AuthCircuit) -> Self {
        Self {
            circuit,
            union_witness: None,
        }
    }

    pub fn with_witness(circuit: AuthCircuit, union_witness: PrivateMerkleUnionWitness) -> Self {
        Self {
            circuit,
            union_witness: Some(union_witness),
        }
    }
}

impl ConstraintSynthesizer<Fr> for ExperimentalAuthWithPrivateMerkleUnion {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let witness = match self.union_witness {
            Some(witness) => witness,
            None => build_private_merkle_union_witness(&self.circuit)?,
        };
        self.circuit
            .synthesize_with_constraint_observer(cs, false, None, false, Some(witness))
            .map(|_| ())
    }
}

/// Read-only synthesis checkpoint used by the constraint attribution audit.
/// Counts are cumulative and describe the constraint system before finalization.
#[derive(Clone, Debug, Serialize)]
pub struct AuthConstraintSnapshot {
    pub phase: String,
    pub constraints: usize,
    pub instance_variables: usize,
    pub witness_variables: usize,
}

fn auth_constraint_snapshot(cs: &ConstraintSystemRef<Fr>, phase: &str) -> AuthConstraintSnapshot {
    AuthConstraintSnapshot {
        phase: phase.to_owned(),
        constraints: cs.num_constraints(),
        instance_variables: cs.num_instance_variables(),
        witness_variables: cs.num_witness_variables(),
    }
}

/// Serializable prover view of [`AuthCircuit`].  It intentionally contains the
/// holder witness needed to prove, but no RA/SR/original-issuer signing key.
/// This is an experiment wire format, not a deployment credential container.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthCircuitWire {
    pub version: u64,
    pub enabled: Vec<bool>,
    pub prime: String,
    pub request_fields: Vec<String>,
    pub generator: String,
    pub salt: String,
    pub ra_pk: String,
    pub sr_pk: String,
    pub user_pk: String,
    pub rho: String,
    pub reg_serial: u64,
    pub reg_expiry: u64,
    pub ra_sig: Vec<String>,
    pub auth_root: String,
    pub state_version: u64,
    pub state_status: u64,
    pub state_expiry: u64,
    pub transition: String,
    pub sr_sig: Vec<String>,
    pub grants: Vec<GrantWire>,
    pub paths: Vec<Vec<String>>,
    pub holder: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GrantWire {
    pub fields: Vec<String>,
    pub parent: String,
    pub signature: Vec<String>,
    pub active: bool,
}

fn wire_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn wire_unhex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("auth_wire_hex_length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| "auth_wire_hex_digit".into()))
        .collect()
}

fn wire_encode<T: CanonicalSerialize>(value: &T) -> String {
    let mut bytes = vec![];
    value.serialize(&mut bytes).expect("canonical wire serialization");
    wire_hex(&bytes)
}

fn wire_decode<T: CanonicalDeserialize>(value: &str) -> Result<T, String> {
    let bytes = wire_unhex(value)?;
    let mut input = bytes.as_slice();
    let decoded = T::deserialize(&mut input).map_err(|_| "auth_wire_canonical_decode".to_string())?;
    if !input.is_empty() {
        return Err("auth_wire_trailing_bytes".into());
    }
    Ok(decoded)
}

fn sig_to_wire(sig: &Sig) -> Vec<String> {
    vec![wire_encode(&sig.prover_response), wire_encode(&sig.verifier_challenge)]
}

fn sig_from_wire(values: &[String]) -> Result<Sig, String> {
    if values.len() != 2 {
        return Err("auth_wire_signature_arity".into());
    }
    Ok(Sig {
        prover_response: wire_decode(&values[0])?,
        verifier_challenge: wire_decode(&values[1])?,
    })
}

impl AuthCircuitWire {
    pub fn from_circuit(circuit: &AuthCircuit) -> Self {
        Self {
            version: 1,
            enabled: circuit.enabled.to_vec(),
            prime: wire_encode(&circuit.prime),
            request_fields: circuit.request.fields.iter().map(wire_encode).collect(),
            generator: wire_encode(&circuit.params.generator),
            salt: wire_hex(&circuit.params.salt),
            ra_pk: wire_encode(&circuit.ra_pk),
            sr_pk: wire_encode(&circuit.sr_pk),
            user_pk: wire_encode(&circuit.user_pk),
            rho: wire_encode(&circuit.rho),
            reg_serial: circuit.reg_serial,
            reg_expiry: circuit.reg_expiry,
            ra_sig: sig_to_wire(&circuit.ra_sig),
            auth_root: wire_hex(&circuit.auth_root),
            state_version: circuit.state_version,
            state_status: circuit.state_status,
            state_expiry: circuit.state_expiry,
            transition: wire_hex(&circuit.transition),
            sr_sig: sig_to_wire(&circuit.sr_sig),
            grants: circuit.grants.iter().map(|grant| GrantWire {
                fields: grant.fields.iter().map(wire_encode).collect(),
                parent: wire_hex(&grant.parent),
                signature: sig_to_wire(&grant.signature),
                active: grant.active,
            }).collect(),
            paths: circuit.paths.iter().map(|path| path.iter().map(|node| wire_hex(node)).collect()).collect(),
            holder: wire_encode(&circuit.holder),
        }
    }

    pub fn into_circuit_with_params(
        self,
        params: &Parameters<EdwardsProjective, Blake2s>,
    ) -> Result<AuthCircuit, String> {
        if self.version != 1 || self.enabled.len() != 3 || self.request_fields.len() != REQUEST_FIELDS
            || self.grants.len() != 3 || self.paths.len() != 3
        {
            return Err("auth_wire_shape".into());
        }
        let enabled: [bool; 3] = [self.enabled[0], self.enabled[1], self.enabled[2]];
        let request_values = self.request_fields.iter().map(|v| wire_decode(v)).collect::<Result<Vec<Fr>, _>>()?;
        let request_fields: [Fr; REQUEST_FIELDS] = request_values.try_into().map_err(|_| "auth_wire_request_shape")?;
        let salt_vec = wire_unhex(&self.salt)?;
        let salt: [u8; 32] = salt_vec.try_into().map_err(|_| "auth_wire_salt_shape")?;
        let generator: EdwardsAffine = wire_decode(&self.generator)?;
        if generator != params.generator || salt != params.salt {
            return Err("auth_wire_parameter_mismatch".into());
        }
        let auth_root_vec = wire_unhex(&self.auth_root)?;
        let auth_root: Hash = auth_root_vec.try_into().map_err(|_| "auth_wire_root_shape")?;
        let transition_vec = wire_unhex(&self.transition)?;
        let transition: Hash = transition_vec.try_into().map_err(|_| "auth_wire_transition_shape")?;
        let grants = self.grants.into_iter().map(|grant| {
            if grant.fields.len() != 17 {
                return Err("auth_wire_grant_shape".into());
            }
            let values = grant.fields.iter().map(|v| wire_decode(v)).collect::<Result<Vec<Fr>, _>>()?;
            let fields: [Fr; 17] = values.try_into().map_err(|_| "auth_wire_grant_shape")?;
            let parent_vec = wire_unhex(&grant.parent)?;
            let parent: Hash = parent_vec.try_into().map_err(|_| "auth_wire_parent_shape")?;
            Ok(Grant { fields, parent, signature: sig_from_wire(&grant.signature)?, active: grant.active })
        }).collect::<Result<Vec<_>, String>>()?;
        let paths = self.paths.into_iter().map(|path| {
            if path.len() != TREE_DEPTH {
                return Err("auth_wire_path_shape".into());
            }
            path.into_iter().map(|node| {
                let bytes = wire_unhex(&node)?;
                bytes.try_into().map_err(|_| "auth_wire_path_node_shape".into())
            }).collect::<Result<Vec<Hash>, String>>()
        }).collect::<Result<Vec<_>, String>>()?;
        Ok(AuthCircuit {
            enabled,
            prime: wire_decode(&self.prime)?,
            request: AuthRequest { fields: request_fields },
            params: params.clone(),
            ra_pk: wire_decode(&self.ra_pk)?,
            sr_pk: wire_decode(&self.sr_pk)?,
            user_pk: wire_decode(&self.user_pk)?,
            rho: wire_decode(&self.rho)?,
            reg_serial: self.reg_serial,
            reg_expiry: self.reg_expiry,
            ra_sig: sig_from_wire(&self.ra_sig)?,
            auth_root,
            state_version: self.state_version,
            state_status: self.state_status,
            state_expiry: self.state_expiry,
            transition,
            sr_sig: sig_from_wire(&self.sr_sig)?,
            grants,
            paths,
            holder: wire_decode(&self.holder)?,
        })
    }
}

/// Reconstruct only the deterministic fixture's public Schnorr parameters.
/// Unlike [`AuthFixture::new`], this does not generate or return any RA/SR key.
pub fn fixture_public_parameters(seed: u64) -> Parameters<EdwardsProjective, Blake2s> {
    let mut rng = StdRng::seed_from_u64(seed);
    Scheme::setup(&mut rng).expect("fixture public parameters")
}

/// Constraint-shape template for trusted setup. It uses only public parameters
/// and dummy assignments, and therefore creates no RA/SR/issuer secret key.
/// Setup consumes the relation shape; real proving uses a server-delivered,
/// signed [`AuthCircuitWire`] snapshot instead.
pub fn fixture_setup_template(seed: u64, prime: Fr) -> AuthCircuit {
    let params = fixture_public_parameters(seed);
    let point = params.generator;
    let mut request = AuthRequest::new(point);
    request.fields[2] = f(1);
    let grant = Grant {
        fields: [
            f(0), f(1), f(1), point.x, point.y, point.x, point.y,
            f(42), f(3), f(100), f(1000), f(1), f(2), f(1), f(0), f(777), f(1),
        ],
        parent: [0; 32],
        signature: Sig::default(),
        active: true,
    };
    AuthCircuit {
        enabled: [true; 3], prime, request, params, ra_pk: point, sr_pk: point,
        user_pk: point, rho: f(1), reg_serial: 1, reg_expiry: 2000,
        ra_sig: Sig::default(), auth_root: [0; 32], state_version: 1,
        state_status: 1, state_expiry: 2000, transition: [0; 32],
        sr_sig: Sig::default(), grants: vec![grant.clone(), grant.clone(), grant],
        paths: vec![vec![[0; 32]; TREE_DEPTH]; 3], holder: Scalar::one(),
    }
}
impl AuthCircuit {
    pub fn public_fields(&self) -> Vec<Fr> {
        self.request.fields.to_vec()
    }
    pub fn instance(&self) -> Vec<Fr> {
        let mut r = vec![self.prime];
        r.extend(self.public_fields());
        r
    }
    pub fn user_commitment(&self) -> Hash {
        fh(1, &[self.user_pk.x, self.user_pk.y, self.rho], &[])
    }
    pub fn reg_hash(&self) -> Hash {
        let cu = limbs(self.user_commitment());
        fh(
            2,
            &[
                self.request.fields[3],
                cu[0],
                cu[1],
                f(self.reg_serial),
                f(self.reg_expiry),
            ],
            &[],
        )
    }
    pub fn state_hash(&self) -> Hash {
        let cu = limbs(self.user_commitment());
        let rt = limbs(self.auth_root);
        let tr = limbs(self.transition);
        fh(
            6,
            &[
                self.prime,
                self.request.fields[3],
                cu[0],
                cu[1],
                rt[0],
                rt[1],
                f(self.state_version),
                f(self.state_status),
                f(self.state_expiry),
                tr[0],
                tr[1],
                self.request.fields[4],
            ],
            &[],
        )
    }
}

// Full digest native/gadget encoding is little-endian canonical field bytes.
fn hv(domain: u8, data: &[UInt8<Fr>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut b = vec![UInt8::constant(domain)];
    b.extend_from_slice(data);
    let bits = b
        .iter()
        .map(|x| x.to_bits_le())
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    let hash_cs = bits
        .iter()
        .fold(ConstraintSystemRef::None, |acc, bit| acc.or(bit.cs()));
    let before = hash_cs.num_constraints();
    let output = evaluate_blake2s(&bits)?;
    let after = hash_cs.num_constraints();
    record_blake2s_call(format!("domain_{domain}"), bits.len(), before, after);
    Ok(output
        .iter()
        .flat_map(|x| x.to_bytes().unwrap())
        .collect())
}

/// Diagnostic-only atomic record around one `evaluate_blake2s` invocation.
/// Recording reads counters but adds no variables or constraints.
#[derive(Clone, Debug, Serialize)]
pub struct Blake2sConstraintRecord {
    pub call: String,
    pub input_bits: usize,
    pub compression_blocks: usize,
    pub constraints_before: usize,
    pub constraints_after: usize,
    pub constraints_delta: usize,
}

thread_local! {
    static BLAKE2S_CONSTRAINT_RECORDS: RefCell<Vec<Blake2sConstraintRecord>> = RefCell::new(Vec::new());
}

fn record_blake2s_call(call: String, input_bits: usize, before: usize, after: usize) {
    BLAKE2S_CONSTRAINT_RECORDS.with(|records| records.borrow_mut().push(Blake2sConstraintRecord {
        call,
        input_bits,
        compression_blocks: std::cmp::max(1, (input_bits + 511) / 512),
        constraints_before: before,
        constraints_after: after,
        constraints_delta: after - before,
    }));
}

pub fn reset_blake2s_constraint_records() {
    BLAKE2S_CONSTRAINT_RECORDS.with(|records| records.borrow_mut().clear());
}

pub fn take_blake2s_constraint_records() -> Vec<Blake2sConstraintRecord> {
    BLAKE2S_CONSTRAINT_RECORDS.with(|records| std::mem::take(&mut *records.borrow_mut()))
}

fn native_node_hash(left: &Hash, right: &Hash) -> Hash {
    hash(7, &[left.as_ref(), right.as_ref()].concat())
}

fn row_from_pair(address: usize, left: Hash, right: Hash) -> PrivateMerkleUnionRow {
    PrivateMerkleUnionRow {
        active: true,
        address,
        left,
        right,
    }
}

/// Build assignments from the ordinary Auth paths. For a shared address the
/// first row assignment is retained; the circuit checks every authenticated
/// query and active row link. Redundant, unused path fields are intentionally
/// not promised to be equivalent byte-for-byte after compression.
pub fn build_private_merkle_union_witness(
    circuit: &AuthCircuit,
) -> Result<PrivateMerkleUnionWitness, SynthesisError> {
    if circuit.grants.len() != 3 || circuit.paths.len() != 3 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut candidates: [Vec<(usize, Hash, Hash)>; TREE_DEPTH] = Default::default();
    for query in 0..3 {
        if circuit.paths[query].len() != TREE_DEPTH {
            return Err(SynthesisError::Unsatisfiable);
        }
        if !circuit.enabled[query] {
            continue;
        }
        let index = circuit.grants[query].fields[14].into_repr().as_ref()[0] as usize;
        let mut current = circuit.grants[query].leaf();
        for level in 0..TREE_DEPTH {
            let sibling = circuit.paths[query][level];
            let address = index >> (level + 1);
            let (left, right) = if ((index >> level) & 1) == 0 {
                (current, sibling)
            } else {
                (sibling, current)
            };
            if !candidates[level]
                .iter()
                .any(|(seen, _, _)| *seen == address)
            {
                candidates[level].push((address, left, right));
            }
            current = native_node_hash(&left, &right);
        }
    }
    if candidates[0].len() > 3 || candidates[1].len() > 2 || candidates[2].len() > 1 {
        return Err(SynthesisError::Unsatisfiable);
    }
    let mut level0: [PrivateMerkleUnionRow; 3] = Default::default();
    let mut level1: [PrivateMerkleUnionRow; 2] = Default::default();
    let mut level2: [PrivateMerkleUnionRow; 1] = Default::default();
    for (slot, (address, left, right)) in candidates[0].iter().enumerate() {
        level0[slot] = row_from_pair(*address, *left, *right);
    }
    for (slot, (address, left, right)) in candidates[1].iter().enumerate() {
        level1[slot] = row_from_pair(*address, *left, *right);
    }
    for (slot, (address, left, right)) in candidates[2].iter().enumerate() {
        level2[slot] = row_from_pair(*address, *left, *right);
    }
    let mut query_routes = [[false; 3]; 3];
    for query in 0..3 {
        if circuit.enabled[query] {
            let index = circuit.grants[query].fields[14].into_repr().as_ref()[0] as usize;
            if let Some(target) = candidates[0]
                .iter()
                .position(|(address, _, _)| *address == index >> 1)
            {
                query_routes[query][target] = true;
            }
        }
    }
    let mut level0_routes = [[false; 2]; 3];
    for child in 0..candidates[0].len() {
        if let Some(target) = candidates[1]
            .iter()
            .position(|(address, _, _)| *address == candidates[0][child].0 >> 1)
        {
            level0_routes[child][target] = true;
        }
    }
    let mut level1_routes = [[false; 1]; 2];
    for child in 0..candidates[1].len() {
        if !candidates[2].is_empty() {
            level1_routes[child][0] = true;
        }
    }
    Ok(PrivateMerkleUnionWitness {
        level0,
        level1,
        level2,
        query_routes,
        level0_routes,
        level1_routes,
    })
}

struct PrivateMerkleUnionRowVar {
    active: Boolean<Fr>,
    address: Vec<Boolean<Fr>>,
    left: Vec<UInt8<Fr>>,
    right: Vec<UInt8<Fr>>,
    parent: Vec<UInt8<Fr>>,
}

fn allocate_private_merkle_union_rows(
    cs: ConstraintSystemRef<Fr>,
    witnesses: &[PrivateMerkleUnionRow],
    address_bits: usize,
) -> Result<Vec<PrivateMerkleUnionRowVar>, SynthesisError> {
    let mut rows = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        let active = Boolean::new_witness(cs.clone(), || Ok(witness.active))?;
        let address_value = alloc(cs.clone(), f(witness.address as u64))?;
        let address = (0..address_bits)
            .map(|bit| {
                Boolean::new_witness(cs.clone(), || Ok(((witness.address >> bit) & 1) == 1))
            })
            .collect::<Result<Vec<_>, _>>()?;
        address_value.enforce_equal(&Boolean::le_bits_to_fp_var(&address)?)?;
        let left = UInt8::new_witness_vec(cs.clone(), &witness.left)?;
        let right = UInt8::new_witness_vec(cs.clone(), &witness.right)?;
        let inactive = active.not();
        for bit in &address {
            bit.conditional_enforce_equal(&Boolean::FALSE, &inactive)?;
        }
        for byte in left.iter().chain(right.iter()) {
            byte.conditional_enforce_equal(&UInt8::constant(0), &inactive)?;
        }
        let mut data = left.clone();
        data.extend(right.clone());
        let parent = hv(7, &data)?;
        rows.push(PrivateMerkleUnionRowVar {
            active,
            address,
            left,
            right,
            parent,
        });
    }
    for first in 0..rows.len() {
        for second in (first + 1)..rows.len() {
            let both = rows[first].active.and(&rows[second].active)?;
            let mut equal = Boolean::TRUE;
            for bit in 0..address_bits {
                equal = equal.and(
                    &rows[first].address[bit]
                        .xor(&rows[second].address[bit])?
                        .not(),
                )?;
            }
            both.and(&equal)?.enforce_equal(&Boolean::FALSE)?;
        }
    }
    Ok(rows)
}

fn private_merkle_union_sum_equals(
    bits: &[Boolean<Fr>],
    expected: &Boolean<Fr>,
) -> Result<(), SynthesisError> {
    let mut sum = FpVar::zero();
    for bit in bits {
        sum += Boolean::le_bits_to_fp_var(&[bit.clone()])?;
    }
    sum.enforce_equal(&Boolean::le_bits_to_fp_var(&[expected.clone()])?)
}

fn enforce_private_merkle_query_routes(
    cs: ConstraintSystemRef<Fr>,
    route_values: &[[bool; 3]; 3],
    enabled: &[Boolean<Fr>],
    indexes: &[Vec<Boolean<Fr>>],
    leaves: &[Vec<UInt8<Fr>>],
    parents: &[PrivateMerkleUnionRowVar],
) -> Result<(), SynthesisError> {
    let mut selectors = Vec::with_capacity(3);
    for query in 0..3 {
        let route = route_values[query]
            .iter()
            .map(|value| Boolean::new_witness(cs.clone(), || Ok(*value)))
            .collect::<Result<Vec<_>, _>>()?;
        private_merkle_union_sum_equals(&route, &enabled[query])?;
        for parent in 0..3 {
            parents[parent]
                .active
                .conditional_enforce_equal(&Boolean::TRUE, &route[parent])?;
            for bit in 0..2 {
                parents[parent].address[bit]
                    .conditional_enforce_equal(&indexes[query][bit + 1], &route[parent])?;
            }
            for byte in 0..32 {
                let child = UInt8::conditionally_select(
                    &indexes[query][0],
                    &parents[parent].right[byte],
                    &parents[parent].left[byte],
                )?;
                child.conditional_enforce_equal(&leaves[query][byte], &route[parent])?;
            }
        }
        selectors.push(route);
    }
    for parent in 0..3 {
        let mut covered = Boolean::FALSE;
        for query in 0..3 {
            covered = covered.or(&selectors[query][parent])?;
        }
        parents[parent].active.enforce_equal(&covered)?;
    }
    Ok(())
}

fn enforce_private_merkle_row_routes<const CHILDREN: usize, const PARENTS: usize>(
    cs: ConstraintSystemRef<Fr>,
    route_values: &[[bool; PARENTS]; CHILDREN],
    children: &[PrivateMerkleUnionRowVar],
    parents: &[PrivateMerkleUnionRowVar],
) -> Result<(), SynthesisError> {
    let mut selectors = Vec::with_capacity(CHILDREN);
    for child in 0..CHILDREN {
        let route = route_values[child]
            .iter()
            .map(|value| Boolean::new_witness(cs.clone(), || Ok(*value)))
            .collect::<Result<Vec<_>, _>>()?;
        private_merkle_union_sum_equals(&route, &children[child].active)?;
        for parent in 0..PARENTS {
            parents[parent]
                .active
                .conditional_enforce_equal(&Boolean::TRUE, &route[parent])?;
            for bit in 1..children[child].address.len() {
                parents[parent].address[bit - 1]
                    .conditional_enforce_equal(&children[child].address[bit], &route[parent])?;
            }
            for byte in 0..32 {
                let selected = UInt8::conditionally_select(
                    &children[child].address[0],
                    &parents[parent].right[byte],
                    &parents[parent].left[byte],
                )?;
                selected.conditional_enforce_equal(&children[child].parent[byte], &route[parent])?;
            }
        }
        selectors.push(route);
    }
    for parent in 0..PARENTS {
        let mut covered = Boolean::FALSE;
        for child in 0..CHILDREN {
            covered = covered.or(&selectors[child][parent])?;
        }
        parents[parent].active.enforce_equal(&covered)?;
    }
    Ok(())
}

fn enforce_private_merkle_union(
    cs: ConstraintSystemRef<Fr>,
    witness: &PrivateMerkleUnionWitness,
    enabled: &[Boolean<Fr>],
    indexes: &[Vec<Boolean<Fr>>],
    leaves: &[Vec<UInt8<Fr>>],
    root: &[UInt8<Fr>],
) -> Result<(), SynthesisError> {
    let level0 = allocate_private_merkle_union_rows(cs.clone(), &witness.level0, 2)?;
    let level1 = allocate_private_merkle_union_rows(cs.clone(), &witness.level1, 1)?;
    let level2 = allocate_private_merkle_union_rows(cs.clone(), &witness.level2, 0)?;
    enforce_private_merkle_query_routes(
        cs.clone(),
        &witness.query_routes,
        enabled,
        indexes,
        leaves,
        &level0,
    )?;
    enforce_private_merkle_row_routes::<3, 2>(
        cs.clone(),
        &witness.level0_routes,
        &level0,
        &level1,
    )?;
    enforce_private_merkle_row_routes::<2, 1>(
        cs,
        &witness.level1_routes,
        &level1,
        &level2,
    )?;
    level2[0].active.enforce_equal(&Boolean::TRUE)?;
    for byte in 0..32 {
        level2[0].parent[byte].enforce_equal(&root[byte])?;
    }
    Ok(())
}
fn fvhash(
    domain: u8,
    xs: &[FpVar<Fr>],
    tail: &[UInt8<Fr>],
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut b = vec![];
    for x in xs {
        b.extend(x.to_bytes()?);
    }
    b.extend_from_slice(tail);
    hv(domain, &b)
}
fn hlimbs(h: &[UInt8<Fr>]) -> Result<Vec<FpVar<Fr>>, SynthesisError> {
    h.chunks(16)
        .map(|part| {
            let bits = part
                .iter()
                .map(|x| x.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?
                .concat();
            Boolean::le_bits_to_fp_var(&bits)
        })
        .collect()
}
fn alloc(cs: ConstraintSystemRef<Fr>, x: Fr) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs, || Ok(x))
}
fn range(v: &FpVar<Fr>, n: usize) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let b = v.to_bits_le()?;
    for x in &b[n..] {
        x.enforce_equal(&Boolean::FALSE)?;
    }
    Ok(b[..n].to_vec())
}
fn le(a: &FpVar<Fr>, b: &FpVar<Fr>, n: usize) -> Result<(), SynthesisError> {
    range(a, n)?;
    range(b, n)?;
    range(&(b - a), n)?;
    Ok(())
}
/// Total witness assignment even for a forbidden zero. An enabled zero
/// synthesizes normally and violates value * multiplier == 1, rather than
/// disguising the negative case as AssignmentMissing from inverse().get().
fn nonzero_if(value: &FpVar<Fr>, enabled: &Boolean<Fr>) -> Result<(), SynthesisError> {
    let multiplier = FpVar::new_witness(value.cs(), || {
        Ok(if enabled.value()? {
            value.value()?.inverse().unwrap_or_else(Fr::zero)
        } else {
            Fr::zero()
        })
    })?;
    let target = Boolean::le_bits_to_fp_var(&[enabled.clone()])?;
    (value * multiplier).enforce_equal(&target)
}
// Select operands before comparison so disabled zero padding does not create
// an ungated negative difference. All allocation/constraints remain fixed.
fn le_if(a: &FpVar<Fr>, b: &FpVar<Fr>, n: usize, on: &Boolean<Fr>) -> Result<(), SynthesisError> {
    let aa = FpVar::conditionally_select(on, a, &FpVar::zero())?;
    let bb = FpVar::conditionally_select(on, b, &FpVar::zero())?;
    le(&aa, &bb, n)
}
fn scalar(cs: ConstraintSystemRef<Fr>, s: Scalar) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let v = alloc(cs, scalar_base(s))?;
    let b = range(&v, 252)?;
    let modulus = <Scalar as PrimeField>::Params::MODULUS.to_bits_le();
    let mut lt = Boolean::FALSE;
    let mut eq = Boolean::TRUE;
    for i in (0..252).rev() {
        if modulus[i] {
            lt = lt.or(&eq.and(&b[i].not())?)?;
            eq = eq.and(&b[i])?;
        } else {
            eq = eq.and(&b[i].not())?;
        }
    }
    lt.enforce_equal(&Boolean::TRUE)?;
    Ok(b)
}
fn point(cs: ConstraintSystemRef<Fr>, p: EdwardsAffine) -> Result<EdwardsVar, SynthesisError> {
    let q = EdwardsVar::new_witness(cs, || Ok(p))?;
    q.enforce_not_equal(&EdwardsVar::zero())?;
    Ok(q)
}
/// Exact arkworks 0.1 Schnorr verification, including from_random_bytes masking.
fn verify_sig(
    cs: ConstraintSystemRef<Fr>,
    params: &Parameters<EdwardsProjective, Blake2s>,
    pk: &EdwardsVar,
    h: &[UInt8<Fr>],
    s: &Sig,
) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let sb = scalar(cs.clone(), s.prover_response)?;
    let eb = scalar(cs.clone(), s.verifier_challenge)?;
    let gen = EdwardsVar::new_constant(cs, params.generator)?;
    let r = gen.scalar_mul_le(sb.iter())? + pk.scalar_mul_le(eb.iter())?;
    let mut b = UInt8::constant_vec(&params.salt);
    b.extend(r.x.to_bytes()?);
    b.extend(r.y.to_bytes()?);
    b.extend_from_slice(h);
    let bits = b
        .iter()
        .map(|x| x.to_bits_le())
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    let before = bits
        .iter()
        .fold(ConstraintSystemRef::None, |acc, bit| acc.or(bit.cs()))
        .num_constraints();
    let digest_words = evaluate_blake2s(&bits)?;
    let after = bits
        .iter()
        .fold(ConstraintSystemRef::None, |acc, bit| acc.or(bit.cs()))
        .num_constraints();
    record_blake2s_call("signature_challenge".to_owned(), bits.len(), before, after);
    let out = digest_words
        .iter()
        .flat_map(|x| x.to_bits_le())
        .collect::<Vec<_>>();
    for i in 0..252 {
        out[i].enforce_equal(&eb[i])?;
    }
    let mut encoding = vec![];
    for mut bits in [sb, eb].iter().cloned() {
        bits.resize(256, Boolean::FALSE);
        for chunk in bits.chunks(8) {
            encoding.push(UInt8::from_bits_le(chunk));
        }
    }
    Ok(encoding)
}
impl ConstraintSynthesizer<Fr> for AuthCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        self.synthesize_with_prime_visibility(cs, false).map(|_| ())
    }
}

impl AuthCircuit {
    /// Reuse the exact business relation, returning the allocated state variable.
    /// Ordinary Groth16 callers MUST choose private_prime=true and constrain this
    /// returned variable in their commitment gadget. Lego keeps its original
    /// committed-instance allocation and ordering through the trait above.
    pub fn synthesize_with_prime_visibility(
        self,
        cs: ConstraintSystemRef<Fr>,
        private_prime: bool,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        self.synthesize_with_constraint_observer(cs, private_prime, None, true, None)
    }

    /// Synthesize the unchanged authorization relation while collecting
    /// cumulative, pre-finalization counts at semantic boundaries.
    pub fn synthesize_with_constraint_audit(
        self,
        cs: ConstraintSystemRef<Fr>,
        private_prime: bool,
    ) -> Result<(FpVar<Fr>, Vec<AuthConstraintSnapshot>), SynthesisError> {
        let mut snapshots = Vec::new();
        let mut observer = |phase: &str, at: &ConstraintSystemRef<Fr>| {
            snapshots.push(auth_constraint_snapshot(at, phase));
        };
        let prime = self.synthesize_with_constraint_observer(
            cs,
            private_prime,
            Some(&mut observer),
            true,
            None,
        )?;
        Ok((prime, snapshots))
    }

    fn synthesize_with_constraint_observer(
        self,
        cs: ConstraintSystemRef<Fr>,
        private_prime: bool,
        mut observer: Option<&mut dyn FnMut(&str, &ConstraintSystemRef<Fr>)>,
        include_request_hash: bool,
        private_merkle_union: Option<PrivateMerkleUnionWitness>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let mut observe = |phase: &str, at: &ConstraintSystemRef<Fr>| {
            if let Some(callback) = observer.as_deref_mut() {
                callback(phase, at);
            }
        };
        observe("start", &cs);
        if self.grants.len() != 3 || self.paths.len() != 3 {
            return Err(SynthesisError::Unsatisfiable);
        }
        for pk in [self.params.generator, self.ra_pk, self.sr_pk].iter() {
            if pk.is_zero() || !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
                return Err(SynthesisError::Unsatisfiable);
            }
        }
        let p = if private_prime {
            FpVar::new_witness(cs.clone(), || Ok(self.prime))?
        } else {
            FpVar::new_input(cs.clone(), || Ok(self.prime))?
        };
        let pb = range(&p, 252)?;
        pb[251].enforce_equal(&Boolean::TRUE)?;
        let q = self
            .request
            .fields
            .iter()
            .map(|v| FpVar::new_input(cs.clone(), || Ok(*v)))
            .collect::<Result<Vec<_>, _>>()?;
        for i in [0, 1, 12, 13].iter() {
            range(&q[*i], 128)?;
        }
        for i in [2, 3, 4, 5, 6, 7, 9, 10, 11].iter() {
            range(&q[*i], 64)?;
        }
        let reqbits = range(&q[8], 16)?;
        let mut sum = FpVar::zero();
        for b in &reqbits {
            sum += Boolean::le_bits_to_fp_var(&[b.clone()])?;
        }
        sum.enforce_equal(&FpVar::one())?;
        le(&q[9], &q[11], 64)?;
        observe("request_inputs_and_ranges", &cs);
        let up = point(cs.clone(), self.user_pk)?;
        let rho = alloc(cs.clone(), self.rho)?;
        let cu = hlimbs(&fvhash(1, &[up.x.clone(), up.y.clone(), rho], &[])?)?;
        let serial = alloc(cs.clone(), f(self.reg_serial))?;
        range(&serial, 64)?;
        nonzero_if(&serial, &Boolean::TRUE)?;
        let re = alloc(cs.clone(), f(self.reg_expiry))?;
        le(&q[11], &re, 64)?;
        let reg = fvhash(
            2,
            &[q[3].clone(), cu[0].clone(), cu[1].clone(), serial, re],
            &[],
        )?;
        observe("registration_commitment_and_digest", &cs);
        let ra = EdwardsVar::new_constant(cs.clone(), self.ra_pk)?;
        verify_sig(cs.clone(), &self.params, &ra, &reg, &self.ra_sig)?;
        observe("registration_ra_signature", &cs);
        let root = UInt8::new_witness_vec(cs.clone(), &self.auth_root)?;
        let rt = hlimbs(&root)?;
        let ver = alloc(cs.clone(), f(self.state_version))?;
        range(&ver, 32)?;
        let status = alloc(cs.clone(), f(self.state_status))?;
        status.enforce_equal(&FpVar::one())?;
        let expiry = alloc(cs.clone(), f(self.state_expiry))?;
        le(&q[11], &expiry, 64)?;
        let tr = hlimbs(&UInt8::new_witness_vec(cs.clone(), &self.transition)?)?;
        let sh = fvhash(
            6,
            &[
                p.clone(),
                q[3].clone(),
                cu[0].clone(),
                cu[1].clone(),
                rt[0].clone(),
                rt[1].clone(),
                ver,
                status,
                expiry,
                tr[0].clone(),
                tr[1].clone(),
                q[4].clone(),
            ],
            &[],
        )?;
        observe("sr_state_and_digest", &cs);
        let sr = EdwardsVar::new_constant(cs.clone(), self.sr_pk)?;
        verify_sig(cs.clone(), &self.params, &sr, &sh, &self.sr_sig)?;
        observe("sr_signature", &cs);
        let enabled = self
            .enabled
            .iter()
            .map(|x| Boolean::new_witness(cs.clone(), || Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;
        enabled[0].enforce_equal(&Boolean::TRUE)?;
        for i in 1..3 {
            enabled[i]
                .and(&enabled[i - 1].not())?
                .enforce_equal(&Boolean::FALSE)?;
        }
        observe("private_prefix_enablement", &cs);
        let mut selected_pk = up.clone();
        let mut prevpk = up;
        let mut parent = reg;
        let mut prev: Option<Vec<FpVar<Fr>>> = None;
        let mut chain = None;
        let mut union_leaves = Vec::with_capacity(3);
        let mut union_indexes = Vec::with_capacity(3);
        for i in 0..3 {
            let g = &self.grants[i];
            let xs = g
                .fields
                .iter()
                .map(|v| alloc(cs.clone(), *v))
                .collect::<Result<Vec<_>, _>>()?;
            xs[0].enforce_equal(&FpVar::constant(f(if i == 0 { 0 } else { 1 })))?;
            xs[1].enforce_equal(&cu[0])?;
            xs[2].enforce_equal(&cu[1])?;
            xs[3].enforce_equal(&prevpk.x)?;
            xs[4].enforce_equal(&prevpk.y)?;
            let pk = point(cs.clone(), EdwardsAffine::new(g.fields[5], g.fields[6]))?;
            pk.x.enforce_equal(&xs[5])?;
            pk.y.enforce_equal(&xs[6])?;
            for j in [7, 9, 10, 13, 16].iter() {
                range(&xs[*j], 64)?;
            }
            range(&xs[12], 4)?;
            range(&xs[14], TREE_DEPTH)?;
            let db = range(&xs[11], 1)?;
            let _ = db;
            nonzero_if(&xs[13], &enabled[i])?;
            // Canonical disabled record: zero policy/serial/index, version 1,
            // no parent, and a self-loop at the previous terminal key.
            let disabled = enabled[i].not();
            for j in [7, 8, 9, 10, 11, 12, 13, 14].iter() {
                xs[*j].conditional_enforce_equal(&FpVar::zero(), &disabled)?;
            }
            xs[16].conditional_enforce_equal(&FpVar::one(), &disabled)?;
            pk.conditional_enforce_equal(&prevpk, &disabled)?;
            if let Some(ch) = &chain {
                xs[15].enforce_equal(ch)?;
            } else {
                chain = Some(xs[15].clone());
            }
            let ph = UInt8::new_witness_vec(cs.clone(), &g.parent)?;
            ph.conditional_enforce_equal(&parent, &enabled[i])?;
            ph.conditional_enforce_equal(&UInt8::constant_vec(&[0; 32]), &disabled)?;
            let core = fvhash(3, &xs, &ph)?;
            observe(&format!("grant_{}_allocation_and_core", i), &cs);
            let sigencoding = verify_sig(cs.clone(), &self.params, &prevpk, &core, &g.signature)?;
            observe(&format!("grant_{}_signature", i), &cs);
            let mut idbytes = core.clone();
            idbytes.extend(sigencoding);
            parent = hv(4, &idbytes)?;
            observe(&format!("grant_{}_id", i), &cs);
            let active = Boolean::new_witness(cs.clone(), || Ok(g.active))?;
            active.enforce_equal(&enabled[i])?;
            let mut leafbytes = xs[14].to_bytes()?;
            leafbytes.extend(core);
            leafbytes.push(UInt8::from_bits_le(&[
                active,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
                Boolean::FALSE,
            ]));
            let mut node = hv(5, &leafbytes)?;
            observe(&format!("grant_{}_active_leaf", i), &cs);
            let index = range(&xs[14], TREE_DEPTH)?;
            if self.paths[i].len() != TREE_DEPTH {
                return Err(SynthesisError::Unsatisfiable);
            }
            if private_merkle_union.is_some() {
                union_leaves.push(node.clone());
                union_indexes.push(index.clone());
            }
            for level in 0..TREE_DEPTH {
                let sibling = UInt8::new_witness_vec(cs.clone(), &self.paths[i][level])?;
                sibling.conditional_enforce_equal(&UInt8::constant_vec(&[0; 32]), &disabled)?;
                if private_merkle_union.is_none() {
                    let mut data = vec![];
                    for j in 0..32 {
                        data.push(UInt8::conditionally_select(
                            &index[level],
                            &sibling[j],
                            &node[j],
                        )?);
                    }
                    for j in 0..32 {
                        data.push(UInt8::conditionally_select(
                            &index[level],
                            &node[j],
                            &sibling[j],
                        )?);
                    }
                    node = hv(7, &data)?;
                }
            }
            if private_merkle_union.is_none() {
                node.conditional_enforce_equal(&root, &enabled[i])?;
            }
            observe(&format!("grant_{}_tree_path", i), &cs);
            let mask = range(&xs[8], 16)?;
            xs[7].conditional_enforce_equal(&q[7], &enabled[i])?;
            le_if(&xs[9], &q[9], 64, &enabled[i])?;
            le_if(&q[11], &xs[10], 64, &enabled[i])?;
            for k in 0..16 {
                reqbits[k]
                    .and(&mask[k].not())?
                    .conditional_enforce_equal(&Boolean::FALSE, &enabled[i])?;
            }
            observe(&format!("grant_{}_permission_and_scope", i), &cs);
            if let Some(old) = prev {
                old[11].conditional_enforce_equal(&FpVar::one(), &enabled[i])?;
                (&xs[12] + Fr::one()).conditional_enforce_equal(&old[12], &enabled[i])?;
                le_if(&old[9], &xs[9], 64, &enabled[i])?;
                le_if(&xs[10], &old[10], 64, &enabled[i])?;
                let bm = range(&old[8], 16)?;
                for k in 0..16 {
                    mask[k]
                        .and(&bm[k].not())?
                        .conditional_enforce_equal(&Boolean::FALSE, &enabled[i])?;
                }
            } else {
                le(&xs[12], &FpVar::constant(f(2)), 4)?;
            }
            observe(&format!("grant_{}_delegation", i), &cs);
            selected_pk = EdwardsVar::conditionally_select(&enabled[i], &pk, &selected_pk)?;
            prev = Some(xs);
            prevpk = pk;
        }
        if let Some(witness) = private_merkle_union.as_ref() {
            enforce_private_merkle_union(
                cs.clone(),
                witness,
                &enabled,
                &union_indexes,
                &union_leaves,
                &root,
            )?;
            observe("private_merkle_union_3_2_1", &cs);
        }
        selected_pk.x.enforce_equal(&q[14])?;
        selected_pk.y.enforce_equal(&q[15])?;
        let sk = scalar(cs.clone(), self.holder)?;
        let gen = EdwardsVar::new_constant(cs.clone(), self.params.generator)?;
        gen.scalar_mul_le(sk.iter())?.enforce_equal(&selected_pk)?;
        observe("terminal_holder_binding", &cs);
        if include_request_hash {
            // The default relation retains the original full-vector hash trace.
            let _request_hash = fvhash(8, &q, &[])?;
            observe("request_q_full_vector_serialization_hash", &cs);
        }
        Ok(p)
    }
}

/// Deterministic fixture is for tests only; do not use seeded keys in deployments.
/// Eight grants share one private tree: P=[0,1,2], P2=[0,1,3], Q=[4,5,6], short_Q=[4,7].
#[derive(Clone)]
pub struct AuthFixture {
    pub base: AuthCircuit,
    pub all_grants: Vec<Grant>,
    pub keys: Vec<(EdwardsAffine, SecretKey<EdwardsProjective>)>,
    pub sr_sk: SecretKey<EdwardsProjective>,
    ra_sk: SecretKey<EdwardsProjective>,
    pub issuers_closed: bool,
    pub sr_signatures: u64,
    pub grant_signatures: u64,
    pub padding_signatures: std::cell::Cell<u64>,
    rng: StdRng,
}
impl AuthFixture {
    pub fn new(seed: u64) -> Self {
        Self::with_expiries(seed, 2000, 1000)
    }
    /// Signs the complete registration, state and grant chain with a longer validity.
    pub fn new_with_expiry(seed: u64, expiry: u64) -> Self {
        assert!(expiry >= 1000 && expiry < u32::MAX as u64);
        Self::with_expiries(seed, expiry, expiry)
    }
    fn with_expiries(seed: u64, state_expiry: u64, grant_expiry: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let params = Scheme::setup(&mut rng).unwrap();
        let (ra_pk, ra_sk) = Scheme::keygen(&params, &mut rng).unwrap();
        let (sr_pk, sr_sk) = Scheme::keygen(&params, &mut rng).unwrap();
        let keys = (0..7)
            .map(|_| Scheme::keygen(&params, &mut rng).unwrap())
            .collect::<Vec<_>>();
        // root user=0, A=1, B=2, C=3, D=4, terminal=5, second terminal=6.
        let request = AuthRequest::new(keys[5].0);
        let mut prime_bytes = [0u8; 32];
        prime_bytes[31] = 8;
        prime_bytes[0] = 17;
        let prime = Fr::from_le_bytes_mod_order(&prime_bytes);
        let mut base = AuthCircuit {
            enabled: [true; 3],
            prime,
            request,
            params: params.clone(),
            ra_pk,
            sr_pk,
            user_pk: keys[0].0,
            rho: f(seed + 10),
            reg_serial: 1,
            reg_expiry: state_expiry,
            ra_sig: Sig::default(),
            auth_root: [0; 32],
            state_version: 1,
            state_status: 1,
            state_expiry,
            transition: [0; 32],
            sr_sig: Sig::default(),
            grants: vec![],
            paths: vec![],
            holder: keys[5].1 .0,
        };
        base.ra_sig = sign(&params, &ra_sk, base.reg_hash(), &mut rng);
        let cu = limbs(base.user_commitment());
        let mut gs: Vec<Grant> = vec![];
        for (index, (parent, issuer, subject, depth)) in [
            (None, 0, 1, 2),
            (Some(0), 1, 2, 1),
            (Some(1), 2, 5, 0),
            (Some(1), 2, 6, 0),
            (None, 0, 3, 2),
            (Some(4), 3, 4, 1),
            (Some(5), 4, 5, 0),
            (Some(4), 3, 5, 1),
        ]
        .iter()
        .enumerate()
        {
            let ph = match parent {
                Some(i) => gs[*i].id(),
                None => base.reg_hash(),
            };
            let ip = keys[*issuer].0;
            let sp = keys[*subject].0;
            let fields = [
                f(if parent.is_none() { 0 } else { 1 }),
                cu[0],
                cu[1],
                ip.x,
                ip.y,
                sp.x,
                sp.y,
                f(42),
                f(3),
                f(100),
                f(grant_expiry),
                f(1),
                f(*depth),
                f(index as u64 + 1),
                f(index as u64),
                f(777),
                f(1),
            ];
            let mut g = Grant {
                fields,
                parent: ph,
                signature: Sig::default(),
                active: true,
            };
            g.signature = sign(&params, &keys[*issuer].1, g.core(), &mut rng);
            gs.push(g);
        }
        let mut out = Self {
            base,
            all_grants: gs,
            keys,
            sr_sk,
            ra_sk,
            issuers_closed: false,
            sr_signatures: 0,
            grant_signatures: 8,
            padding_signatures: std::cell::Cell::new(0),
            rng,
        };
        out.refresh_state(prime);
        out
    }
    /// Distinct user under identical RA/SR/generator and public terminal (fixture only).
    pub fn second_user(&self, seed: u64) -> Self {
        let mut out = Self::new(seed);
        out.base.params = self.base.params.clone();
        out.base.ra_pk = self.base.ra_pk;
        out.base.sr_pk = self.base.sr_pk;
        out.ra_sk = self.ra_sk.clone();
        out.sr_sk = self.sr_sk.clone();
        for i in 0..5 {
            out.keys[i].0 = out
                .base
                .params
                .generator
                .mul(out.keys[i].1 .0)
                .into_affine();
        }
        out.keys[5] = self.keys[5].clone();
        out.keys[6] = self.keys[6].clone();
        out.base.user_pk = out.keys[0].0;
        out.base.reg_serial = seed + 1;
        out.base.holder = out.keys[5].1 .0;
        out.base.request = self.base.request.clone();
        out.base.ra_sig = sign(
            &out.base.params,
            &out.ra_sk,
            out.base.reg_hash(),
            &mut out.rng,
        );
        let cu = limbs(out.base.user_commitment());
        let map = [
            (None, 0, 1),
            (Some(0), 1, 2),
            (Some(1), 2, 5),
            (Some(1), 2, 6),
            (None, 0, 3),
            (Some(4), 3, 4),
            (Some(5), 4, 5),
            (Some(4), 3, 5),
        ];
        out.grant_signatures = 0;
        for (i, (parent, issuer, subject)) in map.iter().enumerate() {
            let ph = match parent {
                Some(j) => out.all_grants[*j].id(),
                None => out.base.reg_hash(),
            };
            let g = &mut out.all_grants[i];
            g.fields[1] = cu[0];
            g.fields[2] = cu[1];
            g.fields[3] = out.keys[*issuer].0.x;
            g.fields[4] = out.keys[*issuer].0.y;
            g.fields[5] = out.keys[*subject].0.x;
            g.fields[6] = out.keys[*subject].0.y;
            g.parent = ph;
            let h = g.core();
            let sig = out.issuer_sign(*issuer, h).unwrap();
            out.all_grants[i].signature = sig;
        }
        out.sr_signatures = 0;
        out.refresh_state(out.base.prime);
        out
    }
    pub fn tree(&self) -> Vec<Vec<Hash>> {
        let mut leaves = vec![[0; 32]; 1 << TREE_DEPTH];
        for g in &self.all_grants {
            let ix = g.fields[14].into_repr().as_ref()[0] as usize;
            leaves[ix] = g.leaf();
        }
        let mut t = vec![leaves];
        for level in 0..TREE_DEPTH {
            let next = t[level]
                .chunks(2)
                .map(|p| hash(7, &[p[0].to_vec(), p[1].to_vec()].concat()))
                .collect();
            t.push(next);
        }
        t
    }
    /// Only SR signs this update. Original grant signatures/records are untouched.
    pub fn refresh_state(&mut self, prime: Fr) {
        self.base.prime = prime;
        self.base.auth_root = self.tree()[TREE_DEPTH][0];
        self.base.sr_sig = sign(
            &self.base.params,
            &self.sr_sk,
            self.base.state_hash(),
            &mut self.rng,
        );
        self.sr_signatures += 1;
    }
    pub fn revoke_middle(&mut self, new_prime: Fr) {
        self.all_grants[1].active = false;
        self.base.state_version += 1;
        self.base.request.fields[2] += Fr::one();
        self.base.transition = hash(9, b"revoke-middle-grant-2");
        self.refresh_state(new_prime);
    }
    pub fn close_issuers(&mut self) {
        self.issuers_closed = true;
        for i in 0..5 {
            self.keys[i].1 .0 = Scalar::zero();
        }
    }
    pub fn issuer_sign(&mut self, issuer: usize, message: Hash) -> Result<Sig, &'static str> {
        if self.issuers_closed {
            return Err("issuer signing interface closed");
        }
        if issuer >= 5 {
            return Err("not an original issuer");
        }
        self.grant_signatures += 1;
        Ok(sign(
            &self.base.params,
            &self.keys[issuer].1,
            message,
            &mut self.rng,
        ))
    }
    /// Fixed-three-slot compatibility wrapper. Original grant signatures untouched.
    pub fn circuit_for_indices(&self, indices: [usize; 3]) -> AuthCircuit {
        self.circuit_for_prefix(&indices)
    }
    /// Assemble one, two, or three real grants with canonical terminal-self-signed
    /// dummy slots. Padding signatures are counted separately from authorization.
    pub fn circuit_for_prefix(&self, indices: &[usize]) -> AuthCircuit {
        assert!(!indices.is_empty() && indices.len() <= 3);
        let mut c = self.base.clone();
        let t = self.tree();
        c.enabled = [false; 3];
        for e in c.enabled.iter_mut().take(indices.len()) {
            *e = true;
        }
        c.grants = indices
            .iter()
            .map(|i| self.all_grants[*i].clone())
            .collect();
        c.paths = indices
            .iter()
            .map(|i| {
                let mut pos = *i;
                let mut path = vec![];
                for level in 0..TREE_DEPTH {
                    path.push(t[level][pos ^ 1]);
                    pos /= 2;
                }
                path
            })
            .collect();
        let last = c.grants.last().unwrap();
        let terminal = self
            .keys
            .iter()
            .position(|(pk, _)| pk.x == last.fields[5] && pk.y == last.fields[6])
            .expect("fixture terminal key");
        c.holder = self.keys[terminal].1 .0;
        c.request.fields[14] = self.keys[terminal].0.x;
        c.request.fields[15] = self.keys[terminal].0.y;
        let cu = limbs(c.user_commitment());
        let chain = last.fields[15];
        let pk = self.keys[terminal].0;
        // Never clone the SR signing RNG: Schnorr nonce reuse across keys leaks secrets.
        let mut padding_rng = StdRng::from_rng(rand::rngs::OsRng).expect("OS padding randomness");
        while c.grants.len() < 3 {
            assert!(
                !self.keys[terminal].1 .0.is_zero(),
                "terminal secret unavailable for padding"
            );
            let mut g = Grant {
                fields: [
                    f(1),
                    cu[0],
                    cu[1],
                    pk.x,
                    pk.y,
                    pk.x,
                    pk.y,
                    f(0),
                    f(0),
                    f(0),
                    f(0),
                    f(0),
                    f(0),
                    f(0),
                    f(0),
                    chain,
                    f(1),
                ],
                parent: [0; 32],
                signature: Sig::default(),
                active: false,
            };
            g.signature = sign(
                &self.base.params,
                &self.keys[terminal].1,
                g.core(),
                &mut padding_rng,
            );
            self.padding_signatures
                .set(self.padding_signatures.get() + 1);
            c.grants.push(g);
            c.paths.push(vec![[0; 32]; TREE_DEPTH]);
        }
        c
    }
    pub fn circuit(&self) -> AuthCircuit {
        self.circuit_for("Q")
    }
    pub fn circuit_for(&self, path: &str) -> AuthCircuit {
        match path {
            "P" => self.circuit_for_prefix(&[0, 1, 2]),
            "P2" => self.circuit_for_prefix(&[0, 1, 3]),
            "Q" => self.circuit_for_prefix(&[4, 5, 6]),
            "short_Q" => self.circuit_for_prefix(&[4, 7]),
            "prefix_P1" => self.circuit_for_prefix(&[0]),
            "prefix_P2" => self.circuit_for_prefix(&[0, 1]),
            _ => panic!("unknown fixture path"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    fn sat(c: AuthCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        cs.is_satisfied().unwrap()
    }
    #[test]
    fn extended_expiry_signed_fixture() {
        let old = AuthFixture::new(97);
        assert_eq!(old.base.reg_expiry, 2000);
        assert_eq!(old.all_grants[0].fields[10], f(1000));
        let fixture = AuthFixture::new_with_expiry(97, 86400);
        let mut c = fixture.circuit_for("Q");
        c.request.fields[9] = f(36000);
        c.request.fields[11] = f(36120);
        assert!(sat(c.clone()));
        c.request.fields[9] = f(86401);
        c.request.fields[11] = f(86521);
        assert!(!sat(c));
    }
    fn checked_shape(c: AuthCircuit) -> (usize, usize, usize) {
        let cs = ConstraintSystem::<Fr>::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        (
            cs.num_constraints(),
            cs.num_instance_variables(),
            cs.num_witness_variables(),
        )
    }
    #[test]
    fn private_prefix_shapes_and_padding() {
        let mut f = AuthFixture::new(910);
        let three = f.circuit_for("Q");
        let two = f.circuit_for("short_Q");
        assert_eq!(three.public_fields(), two.public_fields());
        let shape = checked_shape(three.clone());
        eprintln!(
            "private-prefix shape constraints/instances/witnesses: {:?}",
            shape
        );
        assert_eq!(shape, checked_shape(two.clone()));
        assert_eq!(shape, checked_shape(f.circuit_for("prefix_P1")));
        assert_eq!(shape, checked_shape(f.circuit_for("prefix_P2")));
        let mut bad = three.clone();
        bad.enabled = [true, false, true];
        assert!(!sat(bad));
        let mut bad = three.clone();
        bad.enabled = [false; 3];
        assert!(!sat(bad));
        let mut bad = two.clone();
        bad.holder = f.keys[1].1 .0;
        assert!(!sat(bad));
        let mut bad = two.clone();
        bad.grants[2].fields[8] = Fr::one();
        assert!(!sat(bad));
        f.close_issuers();
        let pc = f.padding_signatures.get();
        let gc = f.grant_signatures;
        let short = f.circuit_for("short_Q");
        assert!(sat(short));
        assert_eq!(f.padding_signatures.get(), pc + 1);
        assert_eq!(f.grant_signatures, gc);
        f.revoke_middle(f.base.prime + Fr::one());
        let mut bypass = f.circuit_for("P");
        bypass.enabled[1] = false;
        assert!(!sat(bypass));
        assert!(sat(f.circuit_for("short_Q")));
    }
    #[test]
    fn forbidden_zero_synthesizes_then_rejects() {
        let fixture = AuthFixture::new(911);
        let mut padding = fixture.circuit_for("short_Q");
        padding.enabled[2] = true;
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(
            padding.generate_constraints(cs.clone()).is_ok(),
            "padding-as-real must not be AssignmentMissing"
        );
        assert!(!cs.is_satisfied().unwrap());
        let mut zero_reg = fixture.circuit();
        zero_reg.reg_serial = 0;
        let cs = ConstraintSystem::<Fr>::new_ref();
        assert!(
            zero_reg.generate_constraints(cs.clone()).is_ok(),
            "zero reg serial must not be AssignmentMissing"
        );
        assert!(!cs.is_satisfied().unwrap());
    }
    #[test]
    fn native_schnorr_matches_gadget() {
        let f = AuthFixture::new(901);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pk = point(cs.clone(), f.base.ra_pk).unwrap();
        let msg = UInt8::new_witness_vec(cs.clone(), &f.base.reg_hash()).unwrap();
        verify_sig(cs.clone(), &f.base.params, &pk, &msg, &f.base.ra_sig).unwrap();
        assert!(cs.is_satisfied().unwrap());
        let mut bad = f.base.ra_sig.clone();
        bad.prover_response += Scalar::one();
        let cs = ConstraintSystem::<Fr>::new_ref();
        let pk = point(cs.clone(), f.base.ra_pk).unwrap();
        let msg = UInt8::new_witness_vec(cs.clone(), &f.base.reg_hash()).unwrap();
        verify_sig(cs.clone(), &f.base.params, &pk, &msg, &bad).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
    #[test]
    fn selective_revocation_relation() {
        let mut f = AuthFixture::new(902);
        assert!(sat(f.circuit_for("P")));
        assert!(sat(f.circuit_for("Q")));
        let original = f
            .all_grants
            .iter()
            .map(|g| sig_bytes(&g.signature))
            .collect::<Vec<_>>();
        f.close_issuers();
        for i in 0..5 {
            assert!(f.issuer_sign(i, [0; 32]).is_err());
        }
        let count = f.grant_signatures;
        let sr_count = f.sr_signatures;
        f.revoke_middle(f.base.prime + Fr::one());
        assert_eq!(f.grant_signatures, count);
        assert_eq!(f.sr_signatures, sr_count + 1);
        assert!(sat(f.circuit_for("Q")));
        assert!(!sat(f.circuit_for("P")));
        assert!(!sat(f.circuit_for("P2")));
        assert_eq!(
            original,
            f.all_grants
                .iter()
                .map(|g| sig_bytes(&g.signature))
                .collect::<Vec<_>>()
        );
    }
    #[test]
    fn second_user_shared_setup_valid() {
        let one = AuthFixture::new(904);
        let two = one.second_user(905);
        assert_ne!(one.base.user_commitment(), two.base.user_commitment());
        assert_eq!(one.circuit().public_fields(), two.circuit().public_fields());
        assert!(sat(two.circuit()));
    }
    #[test]
    fn rejects_wrong_holder_and_state_binding() {
        let f = AuthFixture::new(903);
        let mut bad = f.circuit();
        bad.holder = f.keys[1].1 .0;
        assert!(!sat(bad));
        let mut bad = f.circuit();
        bad.prime += Fr::one();
        assert!(!sat(bad));
        let mut bad = f.circuit();
        bad.grants[1].parent = [0; 32];
        assert!(!sat(bad));
    }
}
