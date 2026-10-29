//! Poseidon-Merkle hidden membership over the existing BLS12-381 scalar field.
//! Source-backed Poseidon permutation (t=3, alpha=5, RF=8, RP=57).
//! Registered slots are stable and bound in occupied leaves. Empty subtrees use
//! shared default nodes; replace performs O(depth) hashes. No primality circuit:
//! trusted SR checks probable primality before insertion, as in the old baseline.
use crate::protocols::hrada_membership::validate_prime;
use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField, ToBytes};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use rug::{integer::Order, Integer};
use std::{collections::BTreeMap, str::FromStr, sync::OnceLock};
#[path = "hrada_poseidon_parameters.rs"]
mod parameters;

pub type Hash = [u8; 32];
pub const DEPTH: usize = 4;
pub const ALLOWED_DEPTHS: [usize; 20] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
];
const LEAF: u64 = 0x91;
const EMPTY: u64 = 0x92;
const NODE: u64 = 0x93;
struct Parameters {
    ark: Vec<Fr>,
    mds: [[Fr; 3]; 3],
}
fn parameters() -> &'static Parameters {
    static PARAMS: OnceLock<Parameters> = OnceLock::new();
    PARAMS.get_or_init(|| Parameters {
        ark: parameters::ROUND_CONSTANTS
            .iter()
            .map(|v| Fr::from_str(v).unwrap())
            .collect(),
        mds: std::array::from_fn(|i| {
            std::array::from_fn(|j| Fr::from_str(parameters::MDS[i][j]).unwrap())
        }),
    })
}
/// Versioned descriptor to bind parameter provenance and exact hash relation.
/// A depth-specific setup must append its depth (also fixed by its R1CS shape).
pub fn parameter_descriptor() -> Vec<u8> {
    format!("HRADA-Poseidon-Merkle-v2|BLS12-381-Fr|t3-alpha5-RF8-RP57|partial-first|M-times-column|H(tag,a,b)=perm([tag,a,b])[0]|leaf=H(145,index,p252)|empty=H(146,0,0)|node=H(147,left,right)|root=canonical-Fr-LE32-split128|stable-slots|depths=1..=20|append=stable-next-slot|grow=left-root-default-right|constants-blake2s={}|source-sha256={}", parameters::PARAMETER_BLAKE2S, parameters::SOURCE_SHA256).into_bytes()
}
fn permutation(mut state: [Fr; 3]) -> [Fr; 3] {
    let p = parameters();
    for r in 0..65 {
        for i in 0..3 {
            state[i] += p.ark[3 * r + i];
            if r < 4 || r >= 61 || i == 0 {
                state[i] = state[i].square().square() * state[i];
            }
        }
        state = std::array::from_fn(|i| (0..3).map(|j| p.mds[i][j] * state[j]).sum());
    }
    state
}
fn hash(tag: u64, a: Fr, b: Fr) -> Fr {
    permutation([Fr::from(tag), a, b])[0]
}
fn prime_field(p: &Integer) -> Fr {
    Fr::from_le_bytes_mod_order(&p.to_digits::<u8>(Order::Lsf))
}
fn encode(v: Fr) -> Hash {
    let mut bytes = vec![];
    v.write(&mut bytes).unwrap();
    let mut out = [0; 32];
    out.copy_from_slice(&bytes);
    out
}
fn limbs(v: Hash) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&v[..16]),
        Fr::from_le_bytes_mod_order(&v[16..]),
    ]
}
#[derive(Clone)]
pub struct PoseidonMerkleState {
    depth: usize,
    slots: Vec<Integer>,
    levels: Vec<BTreeMap<usize, Fr>>,
    defaults: Vec<Fr>,
}
impl PoseidonMerkleState {
    pub fn new(primes: &[Integer]) -> Result<Self, String> {
        Self::with_depth(primes, DEPTH)
    }
    pub fn with_depth(primes: &[Integer], depth: usize) -> Result<Self, String> {
        if !ALLOWED_DEPTHS.contains(&depth) {
            return Err("unsupported Poseidon tree depth".into());
        }
        if primes.len() > (1usize << depth) {
            return Err("Poseidon tree capacity exceeded".into());
        }
        for (i, p) in primes.iter().enumerate() {
            validate_prime(p)?;
            if primes[..i].contains(p) {
                return Err("duplicate state prime".into());
            }
        }
        let mut defaults = vec![hash(EMPTY, Fr::from(0u64), Fr::from(0u64))];
        for d in 0..depth {
            defaults.push(hash(NODE, defaults[d], defaults[d]));
        }
        let mut state = Self {
            depth,
            slots: primes.to_vec(),
            levels: vec![BTreeMap::new(); depth + 1],
            defaults,
        };
        for (i, p) in primes.iter().enumerate() {
            state.update_path(i, p);
        }
        Ok(state)
    }
    fn node(&self, d: usize, index: usize) -> Fr {
        self.levels[d]
            .get(&index)
            .copied()
            .unwrap_or(self.defaults[d])
    }
    fn update_path(&mut self, index: usize, p: &Integer) {
        self.levels[0].insert(index, hash(LEAF, Fr::from(index as u64), prime_field(p)));
        let mut i = index;
        for d in 0..self.depth {
            i >>= 1;
            let value = hash(NODE, self.node(d, 2 * i), self.node(d, 2 * i + 1));
            self.levels[d + 1].insert(i, value);
        }
    }
    pub fn depth(&self) -> usize {
        self.depth
    }
    pub fn len(&self) -> usize {
        self.slots.len()
    }
    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
    /// Append at the next stable slot. Capacity never silently grows.
    /// O(depth) hashes plus linear duplicate admission check.
    pub fn append(&mut self, prime: Integer) -> Result<(), String> {
        self.extend(std::slice::from_ref(&prime))
    }
    /// Validate the entire batch before mutation, so admission errors are atomic.
    /// O(batch * depth) hashes plus duplicate checks; existing leaves stay put.
    pub fn extend(&mut self, primes: &[Integer]) -> Result<(), String> {
        if primes.len() > (1usize << self.depth) - self.slots.len() {
            return Err("Poseidon tree capacity exceeded".into());
        }
        for (i, p) in primes.iter().enumerate() {
            validate_prime(p)?;
            if self.slots.contains(p) || primes[..i].contains(p) {
                return Err("duplicate state prime".into());
            }
        }
        for p in primes {
            self.update_path(self.slots.len(), p);
            self.slots.push(p.clone());
        }
        Ok(())
    }
    /// Increase depth without rehashing existing leaves/subtrees. Each new level
    /// places the previous root on the left and a default subtree on the right.
    /// Two hashes per added level (default and root), preserving every slot.
    /// This mutates tree state only; the larger membership circuit needs its CRS.
    pub fn grow_to_depth(&mut self, depth: usize) -> Result<(), String> {
        if !ALLOWED_DEPTHS.contains(&depth) || depth < self.depth {
            return Err("invalid or shrinking Poseidon tree depth".into());
        }
        while self.depth < depth {
            let old_root = self.node(self.depth, 0);
            let empty = self.defaults[self.depth];
            self.defaults.push(hash(NODE, empty, empty));
            let mut level = BTreeMap::new();
            level.insert(0, hash(NODE, old_root, empty));
            self.levels.push(level);
            self.depth += 1;
        }
        Ok(())
    }
    pub fn replace(&mut self, index: usize, new_prime: Integer) -> Result<(), String> {
        if index >= self.slots.len() {
            return Err("unassigned state slot".into());
        }
        validate_prime(&new_prime)?;
        if self
            .slots
            .iter()
            .enumerate()
            .any(|(i, p)| i != index && p == &new_prime)
        {
            return Err("duplicate state prime".into());
        }
        self.update_path(index, &new_prime);
        self.slots[index] = new_prime;
        Ok(())
    }
    pub fn root(&self) -> Hash {
        encode(self.node(self.depth, 0))
    }
    pub fn root_fields(&self) -> [Fr; 2] {
        limbs(self.root())
    }
    pub fn circuit(&self, prime: &Integer) -> Result<PoseidonMerkleCircuit, String> {
        let index = self
            .slots
            .iter()
            .position(|p| p == prime)
            .ok_or("nonmember state prime")?;
        Ok(PoseidonMerkleCircuit {
            depth: self.depth,
            prime: prime_field(prime),
            index,
            path: (0..self.depth)
                .map(|d| self.node(d, (index >> d) ^ 1))
                .collect(),
            root: self.root(),
        })
    }
}
#[derive(Clone)]
pub struct PoseidonMerkleCircuit {
    pub depth: usize,
    pub prime: Fr,
    pub index: usize,
    pub path: Vec<Fr>,
    pub root: Hash,
}
impl PoseidonMerkleCircuit {
    pub fn public_fields(&self) -> Vec<Fr> {
        limbs(self.root).to_vec()
    }
    /// Inline-composition entrypoint. The caller owns `prime`; this gadget
    /// allocates only the public root and private path/index.
    pub fn synthesize_with_allocated_prime(
        self,
        cs: ConstraintSystemRef<Fr>,
        prime: FpVar<Fr>,
    ) -> Result<(), SynthesisError> {
        if !ALLOWED_DEPTHS.contains(&self.depth)
            || self.path.len() != self.depth
            || self.index >= (1usize << self.depth)
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        let root = limbs(self.root)
            .iter()
            .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;
        let bits = prime.to_bits_le()?;
        bits[251].enforce_equal(&Boolean::TRUE)?;
        for bit in &bits[252..] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        let index_bits = (0..self.depth)
            .map(|depth| {
                Boolean::new_witness(cs.clone(), || Ok((self.index >> depth) & 1 == 1))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let index = Boolean::le_bits_to_fp_var(&index_bits)?;
        let mut current = hash_var(LEAF, index, prime)?;
        for (depth, sibling) in self.path.iter().enumerate() {
            let other = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
            let left = FpVar::conditionally_select(&index_bits[depth], &other, &current)?;
            let right = FpVar::conditionally_select(&index_bits[depth], &current, &other)?;
            current = hash_var(NODE, left, right)?;
        }
        let computed_bits = current.to_bits_le()?;
        Boolean::le_bits_to_fp_var(&computed_bits[..128])?.enforce_equal(&root[0])?;
        Boolean::le_bits_to_fp_var(&computed_bits[128..])?.enforce_equal(&root[1])?;
        Ok(())
    }
}
fn hash_var(tag: u64, a: FpVar<Fr>, b: FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let p = parameters();
    let mut state = vec![FpVar::constant(Fr::from(tag)), a, b];
    for r in 0..65 {
        for i in 0..3 {
            state[i] += p.ark[3 * r + i];
            if r < 4 || r >= 61 || i == 0 {
                state[i] = state[i].square()?.square()? * &state[i];
            }
        }
        state = (0..3)
            .map(|i| {
                (0..3).fold(FpVar::constant(Fr::from(0u64)), |acc, j| {
                    acc + &state[j] * p.mds[i][j]
                })
            })
            .collect();
    }
    Ok(state.remove(0))
}
impl ConstraintSynthesizer<Fr> for PoseidonMerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let prime = FpVar::new_input(cs.clone(), || Ok(self.prime))?;
        self.synthesize_with_allocated_prime(cs, prime)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    fn prime(offset: u32) -> Integer {
        let mut p: Integer = Integer::from(1) << 251;
        p += offset;
        p.next_prime_mut();
        p
    }
    fn satisfied(c: PoseidonMerkleCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        if c.generate_constraints(cs.clone()).is_err() {
            return false;
        }
        assert_eq!(cs.num_instance_variables(), 4);
        cs.is_satisfied().unwrap()
    }
    #[test]
    fn author_reference_and_native_r1cs_agree() {
        let got = permutation([Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)]);
        for i in 0..3 {
            assert_eq!(got[i], Fr::from_str(parameters::REFERENCE_012[i]).unwrap());
        }
        let cs = ConstraintSystem::<Fr>::new_ref();
        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();
        let out = hash_var(0, a, b).unwrap();
        out.enforce_equal(&FpVar::constant(got[0])).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_ne!(
            hash(LEAF, Fr::from(1u64), Fr::from(2u64)),
            hash(NODE, Fr::from(1u64), Fr::from(2u64))
        );
    }
    #[test]
    fn mutations_and_noncanonical_root_are_rejected() {
        let p = prime(5);
        let q = prime(10000);
        let r = prime(20000);
        let mut state = PoseidonMerkleState::new(&[p.clone(), q.clone()]).unwrap();
        let c = state.circuit(&q).unwrap();
        assert!(satisfied(c.clone()));
        let mut bad = c.clone();
        bad.prime = Fr::from(5u64);
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.prime = prime_field(&r);
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.index = 0;
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.path[0] += Fr::from(1u64);
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.root[0] ^= 1;
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.root[31] ^= 1;
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.index = 16;
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.path.pop();
        assert!(!satisfied(bad));
        let modulus = Integer::from_str_radix(
            "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
            16,
        )
        .unwrap();
        let mut alias = Integer::from_digits(&c.root, Order::Lsf);
        alias += modulus;
        let bytes = alias.to_digits::<u8>(Order::Lsf);
        assert!(bytes.len() <= 32);
        let mut bad = c.clone();
        bad.root = [0; 32];
        bad.root[..bytes.len()].copy_from_slice(&bytes);
        assert!(!satisfied(bad));
        let old = state.root();
        state.replace(0, r).unwrap();
        assert_ne!(old, state.root());
        assert!(state.circuit(&p).is_err());
        assert!(satisfied(state.circuit(&q).unwrap()));
        assert!(PoseidonMerkleState::new(&[q.clone(), q.clone()]).is_err());
        assert!(state.replace(0, q).is_err());
        assert!(PoseidonMerkleState::with_depth(&[], usize::MAX).is_err());
        assert!(PoseidonMerkleState::new(&[Integer::from(5)]).is_err());
    }
    #[test]
    fn sparse_defaults_match_dense_and_high_indices() {
        let mut primes = vec![];
        let mut p = prime(5);
        for _ in 0..130 {
            primes.push(p.clone());
            p.next_prime_mut();
        }
        let state = PoseidonMerkleState::with_depth(&primes, 8).unwrap();
        assert!(satisfied(state.circuit(&primes[129]).unwrap()));
        let mut dense = (0..256)
            .map(|i| {
                if i < primes.len() {
                    hash(LEAF, Fr::from(i as u64), prime_field(&primes[i]))
                } else {
                    hash(EMPTY, Fr::from(0u64), Fr::from(0u64))
                }
            })
            .collect::<Vec<_>>();
        for _ in 0..8 {
            dense = dense.chunks(2).map(|p| hash(NODE, p[0], p[1])).collect();
        }
        assert_eq!(encode(dense[0]), state.root());
        let deep = PoseidonMerkleState::with_depth(&primes[..2], 20).unwrap();
        assert_eq!(deep.circuit(&primes[1]).unwrap().path.len(), 20);
        assert!(satisfied(deep.circuit(&primes[1]).unwrap()));
    }
    #[test]
    fn incremental_minimum_depth_growth_and_atomic_admission() {
        let mut primes = vec![];
        let mut p = prime(5);
        for _ in 0..18 {
            primes.push(p.clone());
            p.next_prime_mut();
        }
        let mut tree = PoseidonMerkleState::with_depth(&primes[..8], 3).unwrap();
        let oldroot = tree.root();
        assert!(tree.append(primes[8].clone()).is_err());
        assert_eq!(tree.root(), oldroot);
        tree.grow_to_depth(4).unwrap();
        tree.extend(&primes[8..16]).unwrap();
        assert_eq!(
            tree.root(),
            PoseidonMerkleState::with_depth(&primes[..16], 4)
                .unwrap()
                .root()
        );
        assert!(tree.append(primes[16].clone()).is_err());
        tree.grow_to_depth(5).unwrap();
        tree.append(primes[16].clone()).unwrap();
        assert_eq!(
            tree.root(),
            PoseidonMerkleState::with_depth(&primes[..17], 5)
                .unwrap()
                .root()
        );
        assert_eq!(tree.len(), 17);
        assert_eq!(tree.depth(), 5);
        for i in 0..17 {
            assert_eq!(tree.circuit(&primes[i]).unwrap().index, i);
        }
        assert!(satisfied(tree.circuit(&primes[16]).unwrap()));
        let root = tree.root();
        assert!(tree
            .extend(&[primes[17].clone(), primes[0].clone()])
            .is_err());
        assert_eq!(tree.len(), 17);
        assert_eq!(tree.root(), root);
        assert!(tree.grow_to_depth(4).is_err());
        assert!(tree.grow_to_depth(21).is_err());
        assert!(tree.grow_to_depth(0).is_err());
        assert_eq!(tree.root(), root);
        let mut empty = PoseidonMerkleState::with_depth(&[], 1).unwrap();
        empty.grow_to_depth(5).unwrap();
        assert_eq!(
            empty.root(),
            PoseidonMerkleState::with_depth(&[], 5).unwrap().root()
        );
        assert!(empty.is_empty());
    }
    #[test]
    fn real_depth3_depth5_proofs_and_cross_crs_rejection() {
        use crate::protocols::{hrada_link, hrada_membership::StateMembership};
        use rand::rngs::OsRng;
        let mut primes = vec![];
        let mut p = prime(5);
        for _ in 0..17 {
            primes.push(p.clone());
            p.next_prime_mut();
        }
        let cp = StateMembership::setup_os().unwrap();
        let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
        let old = PoseidonMerkleState::with_depth(&primes[..8], 3).unwrap();
        let mut new = old.clone();
        new.grow_to_depth(5).unwrap();
        new.extend(&primes[8..]).unwrap();
        let l3 = hrada_link::setup(&mut OsRng, ck, old.circuit(&primes[0]).unwrap(), 2).unwrap();
        let l5 = hrada_link::setup(&mut OsRng, ck, new.circuit(&primes[0]).unwrap(), 2).unwrap();
        let mut d3 = parameter_descriptor();
        d3.extend(3u64.to_le_bytes());
        let mut d5 = parameter_descriptor();
        d5.extend(5u64.to_le_bytes());
        let h3 = hrada_link::parameter_digest(&l3, &d3).unwrap();
        let h5 = hrada_link::parameter_digest(&l5, &d5).unwrap();
        let r = Integer::from(123);
        let c = cp.commit(&primes[0], &r).unwrap();
        let p3 = hrada_link::prove(&mut OsRng, &l3, old.circuit(&primes[0]).unwrap(), &r).unwrap();
        let p5 = hrada_link::prove(&mut OsRng, &l5, new.circuit(&primes[0]).unwrap(), &r).unwrap();
        assert!(hrada_link::verify(&l3, ck, &d3, &h3, &p3, &old.root_fields(), &c).unwrap());
        assert!(hrada_link::verify(&l5, ck, &d5, &h5, &p5, &new.root_fields(), &c).unwrap());
        assert!(!hrada_link::verify(&l3, ck, &d3, &h3, &p5, &new.root_fields(), &c).unwrap());
        assert!(!hrada_link::verify(&l5, ck, &d5, &h5, &p3, &old.root_fields(), &c).unwrap());
        assert!(!hrada_link::verify(&l3, ck, &d3, &h3, &p3, &new.root_fields(), &c).unwrap());
    }
}
