//! Capacity scaling control for the unchanged full-Blake2s Merkle relation.
//! Dense rebuilding intentionally matches the original baseline; this is not an
//! optimized update implementation. Depth is public circuit configuration.
//! Trusted SR assigns stable slots and checks probable primality before insertion.
//! The circuit proves exact 252-bit state membership, not primality or freshness.
use crate::protocols::hrada_membership::validate_prime;
use ark_bls12_381::Fr;
use ark_crypto_primitives::prf::blake2s::constraints::evaluate_blake2s;
use ark_ff::{PrimeField, ToBytes};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use blake2::{Blake2s, Digest};
use rug::{integer::Order, Integer};

pub type Hash = [u8; 32];
pub const ALLOWED_DEPTHS: [usize; 5] = [4, 8, 12, 16, 20];
const LEAF: u8 = 0x91;
const EMPTY: u8 = 0x92;
const NODE: u8 = 0x93;
fn hash(domain: u8, data: &[u8]) -> Hash {
    let mut bytes = vec![domain];
    bytes.extend_from_slice(data);
    let mut out = [0; 32];
    out.copy_from_slice(&Blake2s::digest(&bytes));
    out
}
fn prime_field(p: &Integer) -> Fr {
    Fr::from_le_bytes_mod_order(&p.to_digits::<u8>(Order::Lsf))
}
fn field_bytes(value: Fr) -> Vec<u8> {
    let mut out = vec![];
    value.write(&mut out).unwrap();
    out
}
fn leaf(index: usize, prime: Option<&Integer>) -> Hash {
    let mut data = field_bytes(Fr::from(index as u64));
    match prime {
        Some(p) => {
            data.extend(field_bytes(prime_field(p)));
            hash(LEAF, &data)
        }
        None => hash(EMPTY, &data),
    }
}
fn limbs(root: Hash) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&root[..16]),
        Fr::from_le_bytes_mod_order(&root[16..]),
    ]
}
#[derive(Clone)]
pub struct ScaledMerkleState {
    depth: usize,
    slots: Vec<Option<Integer>>,
    levels: Vec<Vec<Hash>>,
}
impl ScaledMerkleState {
    pub fn new(primes: &[Integer], depth: usize) -> Result<Self, String> {
        if !ALLOWED_DEPTHS.contains(&depth) {
            return Err("unsupported Merkle scaling depth".into());
        }
        let capacity = 1usize << depth;
        if primes.len() > capacity {
            return Err("Merkle baseline capacity exceeded".into());
        }
        for (i, p) in primes.iter().enumerate() {
            validate_prime(p)?;
            if primes[..i].contains(p) {
                return Err("duplicate state prime".into());
            }
        }
        let mut slots = vec![None; capacity];
        for (slot, p) in slots.iter_mut().zip(primes) {
            *slot = Some(p.clone());
        }
        let mut state = Self {
            depth,
            slots,
            levels: vec![],
        };
        state.rebuild();
        Ok(state)
    }
    fn rebuild(&mut self) {
        self.levels = vec![self
            .slots
            .iter()
            .enumerate()
            .map(|(i, p)| leaf(i, p.as_ref()))
            .collect()];
        for depth in 0..self.depth {
            let next = self.levels[depth]
                .chunks(2)
                .map(|pair| hash(NODE, &[pair[0].as_ref(), pair[1].as_ref()].concat()))
                .collect();
            self.levels.push(next);
        }
    }
    /// Replaces one assigned slot; all unrelated slot assignments remain stable.
    pub fn replace(&mut self, index: usize, new_prime: Integer) -> Result<(), String> {
        if index >= self.slots.len() || self.slots[index].is_none() {
            return Err("unassigned state slot".into());
        }
        validate_prime(&new_prime)?;
        if self
            .slots
            .iter()
            .enumerate()
            .any(|(i, p)| i != index && p.as_ref() == Some(&new_prime))
        {
            return Err("duplicate state prime".into());
        }
        self.slots[index] = Some(new_prime);
        self.rebuild();
        Ok(())
    }
    pub fn root(&self) -> Hash {
        self.levels[self.depth][0]
    }
    pub fn root_fields(&self) -> [Fr; 2] {
        limbs(self.root())
    }
    pub fn circuit(&self, prime: &Integer) -> Result<ScaledMerkleCircuit, String> {
        let index = self
            .slots
            .iter()
            .position(|p| p.as_ref() == Some(prime))
            .ok_or("nonmember state prime")?;
        let path = (0..self.depth)
            .map(|d| self.levels[d][(index >> d) ^ 1])
            .collect();
        Ok(ScaledMerkleCircuit {
            depth: self.depth,
            prime: prime_field(prime),
            index,
            path,
            root: self.root(),
        })
    }
}
#[derive(Clone)]
pub struct ScaledMerkleCircuit {
    pub depth: usize,
    pub prime: Fr,
    pub index: usize,
    pub path: Vec<Hash>,
    pub root: Hash,
}
impl ScaledMerkleCircuit {
    pub fn public_fields(&self) -> Vec<Fr> {
        limbs(self.root).to_vec()
    }
}
fn hash_var(domain: u8, data: &[UInt8<Fr>]) -> Result<Vec<UInt8<Fr>>, SynthesisError> {
    let mut input = vec![UInt8::constant(domain)];
    input.extend_from_slice(data);
    let bits = input
        .iter()
        .map(|b| b.to_bits_le())
        .collect::<Result<Vec<_>, _>>()?
        .concat();
    let mut out = vec![];
    for word in evaluate_blake2s(&bits)? {
        out.extend(word.to_bytes()?);
    }
    Ok(out)
}
impl ConstraintSynthesizer<Fr> for ScaledMerkleCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        if !ALLOWED_DEPTHS.contains(&self.depth)
            || self.path.len() != self.depth
            || self.index >= (1usize << self.depth)
        {
            return Err(SynthesisError::Unsatisfiable);
        }
        // Link instance order is exactly [1, prime, root low128, root high128].
        let prime = FpVar::new_input(cs.clone(), || Ok(self.prime))?;
        let public_root = limbs(self.root)
            .iter()
            .map(|x| FpVar::new_input(cs.clone(), || Ok(*x)))
            .collect::<Result<Vec<_>, _>>()?;
        let bits = prime.to_bits_le()?;
        bits[251].enforce_equal(&Boolean::TRUE)?;
        for bit in &bits[252..] {
            bit.enforce_equal(&Boolean::FALSE)?;
        }
        let index_bits = (0..self.depth)
            .map(|d| Boolean::new_witness(cs.clone(), || Ok((self.index >> d) & 1 == 1)))
            .collect::<Result<Vec<_>, _>>()?;
        let index = Boolean::le_bits_to_fp_var(&index_bits)?;
        let mut data = index.to_bytes()?;
        data.extend(prime.to_bytes()?);
        let mut current = hash_var(LEAF, &data)?;
        for (depth, sibling) in self.path.iter().enumerate() {
            let other = UInt8::new_witness_vec(cs.clone(), sibling)?;
            let mut pair = vec![];
            for i in 0..32 {
                pair.push(UInt8::conditionally_select(
                    &index_bits[depth],
                    &other[i],
                    &current[i],
                )?);
            }
            for i in 0..32 {
                pair.push(UInt8::conditionally_select(
                    &index_bits[depth],
                    &current[i],
                    &other[i],
                )?);
            }
            current = hash_var(NODE, &pair)?;
        }
        for (part, expected) in current.chunks(16).zip(public_root) {
            let bits = part
                .iter()
                .map(|b| b.to_bits_le())
                .collect::<Result<Vec<_>, _>>()?
                .concat();
            Boolean::le_bits_to_fp_var(&bits)?.enforce_equal(&expected)?;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::hrada_merkle_baseline::MerkleState;
    use ark_relations::r1cs::ConstraintSystem;
    fn prime(offset: u32) -> Integer {
        let mut p: Integer = Integer::from(1) << 251;
        p += offset;
        p.next_prime_mut();
        p
    }
    fn satisfied(circuit: ScaledMerkleCircuit) -> bool {
        let cs = ConstraintSystem::<Fr>::new_ref();
        if circuit.generate_constraints(cs.clone()).is_err() {
            return false;
        }
        assert_eq!(cs.num_instance_variables(), 4);
        cs.is_satisfied().unwrap()
    }
    #[test]
    fn depth_four_matches_original_and_rejects_mutations() {
        let p = prime(5);
        let q = prime(10000);
        let r = prime(20000);
        let primes = vec![p.clone(), q.clone()];
        let mut state = ScaledMerkleState::new(&primes, 4).unwrap();
        let mut original = MerkleState::new(&primes).unwrap();
        assert_eq!(state.root(), original.root());
        let c = state.circuit(&q).unwrap();
        let original_c = original.circuit(&q).unwrap();
        assert_eq!(c.path, original_c.path);
        assert_eq!(c.public_fields(), original_c.public_fields());
        assert!(satisfied(c.clone()));
        let mut bad = c.clone();
        bad.prime = prime_field(&r);
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.prime = Fr::from(5u64);
        assert!(!satisfied(bad));
        let mut bad = c.clone();
        bad.path[0][0] ^= 1;
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
        state.replace(0, r.clone()).unwrap();
        original.replace(0, r).unwrap();
        assert_eq!(state.root(), original.root());
        assert!(state.circuit(&p).is_err());
        assert!(satisfied(state.circuit(&q).unwrap()));
        assert!(ScaledMerkleState::new(&[p.clone(), p], 4).is_err());
        assert!(ScaledMerkleState::new(&[Integer::from(5)], 4).is_err());
        assert!(ScaledMerkleState::new(&[], 21).is_err());
        assert!(ScaledMerkleState::new(&[], usize::MAX).is_err());
        assert!(state.replace(0, q).is_err());
    }
    #[test]
    fn depth_eight_accepts_high_slot_and_binds_index() {
        let mut primes = vec![];
        let mut p = prime(5);
        for _ in 0..130 {
            primes.push(p.clone());
            p.next_prime_mut();
        }
        let state = ScaledMerkleState::new(&primes, 8).unwrap();
        let c = state.circuit(&primes[129]).unwrap();
        assert_eq!(c.index, 129);
        assert_eq!(c.path.len(), 8);
        assert!(satisfied(c.clone()));
        let mut bad = c;
        bad.index = 1;
        assert!(!satisfied(bad));
    }
}
