//! Sparse fixed-slot indexed revocation set. Registry insertion updates only
//! the predecessor and a fresh slot; the authenticated root commits the linked
//! sorted-set invariant.
use crate::{
    merkle::{path_root_var, MerklePath},
    poseidon::{hash, hash_var, Domain},
    Fr,
};
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
pub const SERIAL_BITS: usize = 252;
pub fn upper_sentinel() -> Fr {
    let mut b = [0xff; 32];
    b[31] = 0x0f;
    Fr::from_le_bytes_mod_order(&b)
}
/// Explicit low-252-bit derivation. The issuer retains `(rk,counter)`; callers
/// increment counter if the reserved zero or upper sentinel is produced.
pub fn derive_serial(rk: [u8; 32], counter: u32) -> Result<Fr, RevocationError> {
    let lo = Fr::from_le_bytes_mod_order(&rk[..16]);
    let hi = Fr::from_le_bytes_mod_order(&rk[16..]);
    let h = hash(Domain::RevocationSerial, &[lo, hi, Fr::from(counter)]);
    let mut bits = h.into_bigint().to_bits_le();
    bits.truncate(SERIAL_BITS);
    let mut b = [0u8; 32];
    for (i, v) in bits.iter().enumerate() {
        if *v {
            b[i / 8] |= 1 << (i % 8)
        }
    }
    let sn = Fr::from_le_bytes_mod_order(&b);
    if valid(sn) {
        Ok(sn)
    } else {
        Err(RevocationError::Invalid)
    }
}
fn ord(x: Fr) -> [u8; 32] {
    let mut b = [0; 32];
    let r = x.into_bigint().to_bytes_be();
    b[32 - r.len()..].copy_from_slice(&r);
    b
}
fn valid(x: Fr) -> bool {
    x != Fr::zero()
        && x != upper_sentinel()
        && x.into_bigint().to_bits_le()[SERIAL_BITS..]
            .iter()
            .all(|v| !*v)
}
#[derive(Clone, Debug)]
struct Record {
    slot: u32,
    value: Fr,
    next_slot: u32,
    next: Fr,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRevocationLeaf {
    pub slot: u32,
    pub value: Fr,
    pub next_slot: u32,
    pub next: Fr,
    pub leaf: Fr,
}
fn leaf(r: &Record) -> Fr {
    hash(
        Domain::RevLeaf,
        &[Fr::from(r.slot), r.value, Fr::from(r.next_slot), r.next],
    )
}
fn empty() -> Fr {
    hash(Domain::RevLeaf, &[Fr::zero(); 4])
}
#[derive(Debug, Error)]
pub enum RevocationError {
    #[error("invalid, sentinel, or duplicate serial")]
    Invalid,
    #[error("capacity exceeded")]
    Capacity,
}
#[derive(Clone, Debug)]
pub struct NonMembershipWitness {
    pub predecessor_slot: u32,
    pub predecessor: Fr,
    pub successor_slot: u32,
    pub successor: Fr,
    pub path: MerklePath,
}
#[derive(Clone, Debug)]
pub struct IndexedRevocationTree {
    depth: usize,
    next_slot: u32,
    by_value: BTreeMap<[u8; 32], u32>,
    records: BTreeMap<u32, Record>,
}
impl IndexedRevocationTree {
    pub fn new(depth: usize) -> Result<Self, RevocationError> {
        if depth == 0 || depth > 32 {
            return Err(RevocationError::Capacity);
        }
        let mut records = BTreeMap::new();
        records.insert(
            0,
            Record {
                slot: 0,
                value: Fr::zero(),
                next_slot: 1,
                next: upper_sentinel(),
            },
        );
        records.insert(
            1,
            Record {
                slot: 1,
                value: upper_sentinel(),
                next_slot: 1,
                next: upper_sentinel(),
            },
        );
        let mut by_value = BTreeMap::new();
        by_value.insert(ord(Fr::zero()), 0);
        by_value.insert(ord(upper_sentinel()), 1);
        Ok(Self {
            depth,
            next_slot: 2,
            by_value,
            records,
        })
    }
    pub fn insert(&mut self, x: Fr) -> Result<(), RevocationError> {
        let k = ord(x);
        if !valid(x) || self.by_value.contains_key(&k) {
            return Err(RevocationError::Invalid);
        }
        if self.next_slot as u64 >= 1u64 << self.depth {
            return Err(RevocationError::Capacity);
        }
        let pred = *self
            .by_value
            .range(..k)
            .next_back()
            .ok_or(RevocationError::Invalid)?
            .1;
        let old = self.records[&pred].clone();
        let slot = self.next_slot;
        self.next_slot += 1;
        self.records.insert(
            slot,
            Record {
                slot,
                value: x,
                next_slot: old.next_slot,
                next: old.next,
            },
        );
        let p = self.records.get_mut(&pred).unwrap();
        p.next_slot = slot;
        p.next = x;
        self.by_value.insert(k, slot);
        Ok(())
    }
    fn sparse(&self) -> (Fr, Vec<BTreeMap<u32, Fr>>, Vec<Fr>) {
        let mut defs = vec![empty()];
        for d in 0..self.depth {
            defs.push(hash(Domain::RevNode, &[defs[d], defs[d]]));
        }
        let mut levels: Vec<BTreeMap<u32, Fr>> =
            vec![self.records.iter().map(|(i, r)| (*i, leaf(r))).collect()];
        for d in 0..self.depth {
            let ps = levels[d].keys().map(|i| i >> 1).collect::<BTreeSet<_>>();
            let mut n = BTreeMap::new();
            for p in ps {
                let l = *levels[d].get(&(2 * p)).unwrap_or(&defs[d]);
                let r = *levels[d].get(&(2 * p + 1)).unwrap_or(&defs[d]);
                n.insert(p, hash(Domain::RevNode, &[l, r]));
            }
            levels.push(n)
        }
        (
            *levels[self.depth].get(&0).unwrap_or(&defs[self.depth]),
            levels,
            defs,
        )
    }
    pub fn root(&self) -> Fr {
        self.sparse().0
    }
    pub fn public_leaves(&self) -> Vec<PublicRevocationLeaf> {
        self.records
            .values()
            .map(|record| PublicRevocationLeaf {
                slot: record.slot,
                value: record.value,
                next_slot: record.next_slot,
                next: record.next,
                leaf: leaf(record),
            })
            .collect()
    }
    pub fn prove_nonmember(&self, x: Fr) -> Result<NonMembershipWitness, RevocationError> {
        let k = ord(x);
        if !valid(x) || self.by_value.contains_key(&k) {
            return Err(RevocationError::Invalid);
        }
        let slot = *self
            .by_value
            .range(..k)
            .next_back()
            .ok_or(RevocationError::Invalid)?
            .1;
        let r = &self.records[&slot];
        let (_, levels, defs) = self.sparse();
        let (mut i, mut siblings, mut directions) = (slot, vec![], vec![]);
        for d in 0..self.depth {
            directions.push(i & 1 == 1);
            siblings.push(*levels[d].get(&(i ^ 1)).unwrap_or(&defs[d]));
            i >>= 1;
        }
        Ok(NonMembershipWitness {
            predecessor_slot: r.slot,
            predecessor: r.value,
            successor_slot: r.next_slot,
            successor: r.next,
            path: MerklePath {
                siblings,
                directions,
            },
        })
    }
}
fn lt(a: &[Boolean<Fr>], b: &[Boolean<Fr>]) -> Result<Boolean<Fr>, SynthesisError> {
    let (mut l, mut e) = (Boolean::FALSE, Boolean::TRUE);
    for i in (0..SERIAL_BITS).rev() {
        l = l.or(&e.and(&a[i].not().and(&b[i])?)?)?;
        e = e.and(&a[i].xor(&b[i])?.not())?
    }
    Ok(l)
}
fn bits(v: &FpVar<Fr>, nz: bool) -> Result<Vec<Boolean<Fr>>, SynthesisError> {
    let b = v.to_bits_le()?;
    for x in &b[SERIAL_BITS..] {
        x.enforce_equal(&Boolean::FALSE)?
    }
    if nz {
        Boolean::kary_or(&b[..SERIAL_BITS])?.enforce_equal(&Boolean::TRUE)?
    }
    Ok(b)
}
pub fn enforce_nonmembership(
    cs: ConstraintSystemRef<Fr>,
    serial: &FpVar<Fr>,
    root: &FpVar<Fr>,
    w: &NonMembershipWitness,
) -> Result<(), SynthesisError> {
    let p = FpVar::new_witness(cs.clone(), || Ok(w.predecessor))?;
    let n = FpVar::new_witness(cs.clone(), || Ok(w.successor))?;
    lt(&bits(&p, false)?, &bits(serial, true)?)?.enforce_equal(&Boolean::TRUE)?;
    lt(&bits(serial, true)?, &bits(&n, true)?)?.enforce_equal(&Boolean::TRUE)?;
    let l = hash_var(
        Domain::RevLeaf,
        &[
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(w.predecessor_slot)))?,
            p,
            FpVar::new_witness(cs.clone(), || Ok(Fr::from(w.successor_slot)))?,
            n,
        ],
    )?;
    path_root_var(cs, l, &w.path, Domain::RevNode)?.enforce_equal(root)
}

/// Conditional non-membership without substituting a magic serial. Disabled
/// slots have a unique all-zero witness and impose no statement about the set.
pub fn enforce_nonmembership_if(
    cs: ConstraintSystemRef<Fr>,
    enabled: &Boolean<Fr>,
    serial: &FpVar<Fr>,
    root: &FpVar<Fr>,
    w: &NonMembershipWitness,
) -> Result<(), SynthesisError> {
    let ps = FpVar::new_witness(cs.clone(), || Ok(Fr::from(w.predecessor_slot)))?;
    let p = FpVar::new_witness(cs.clone(), || Ok(w.predecessor))?;
    let ns = FpVar::new_witness(cs.clone(), || Ok(Fr::from(w.successor_slot)))?;
    let n = FpVar::new_witness(cs.clone(), || Ok(w.successor))?;
    let gate = |condition: Boolean<Fr>| -> Result<(), SynthesisError> {
        enabled
            .and(&condition.not())?
            .enforce_equal(&Boolean::FALSE)
    };
    gate(lt(&bits(&p, false)?, &bits(serial, false)?)?)?;
    gate(lt(&bits(serial, false)?, &bits(&n, false)?)?)?;
    let serial_bits = serial.to_bits_le()?;
    for b in &serial_bits[SERIAL_BITS..] {
        b.enforce_equal(&Boolean::FALSE)?
    }
    let ps_bits = ps.to_bits_le()?;
    let ns_bits = ns.to_bits_le()?;
    for b in &ps_bits[w.path.siblings.len()..] {
        b.enforce_equal(&Boolean::FALSE)?
    }
    for b in &ns_bits[w.path.siblings.len()..] {
        b.enforce_equal(&Boolean::FALSE)?
    }
    gate(Boolean::kary_or(&serial_bits[..SERIAL_BITS])?)?;
    let mut computed = hash_var(
        Domain::RevLeaf,
        &[ps.clone(), p.clone(), ns.clone(), n.clone()],
    )?;
    if w.path.siblings.len() != w.path.directions.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    for (i, (s, d)) in w.path.siblings.iter().zip(&w.path.directions).enumerate() {
        let sv = FpVar::new_witness(cs.clone(), || Ok(*s))?;
        let dv = Boolean::new_witness(cs.clone(), || Ok(*d))?;
        dv.enforce_equal(&ps_bits[i])?;
        enabled
            .not()
            .and(&sv.is_zero()?.not())?
            .enforce_equal(&Boolean::FALSE)?;
        enabled.not().and(&dv)?.enforce_equal(&Boolean::FALSE)?;
        let left = FpVar::conditionally_select(&dv, &sv, &computed)?;
        let right = FpVar::conditionally_select(&dv, &computed, &sv)?;
        computed = hash_var(Domain::RevNode, &[left, right])?;
    }
    gate(computed.is_eq(root)?)?;
    for v in [&ps, &p, &ns, &n] {
        enabled
            .not()
            .and(&v.is_zero()?.not())?
            .enforce_equal(&Boolean::FALSE)?
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    #[test]
    fn sparse_insert_and_nonmember() {
        let mut t = IndexedRevocationTree::new(20).unwrap();
        t.insert(Fr::from(9u64)).unwrap();
        t.insert(Fr::from(20u64)).unwrap();
        assert!(t.insert(Fr::from(9u64)).is_err());
        let w = t.prove_nonmember(Fr::from(10u64)).unwrap();
        let cs = ConstraintSystem::new_ref();
        let s = FpVar::new_witness(cs.clone(), || Ok(Fr::from(10u64))).unwrap();
        let r = FpVar::new_input(cs.clone(), || Ok(t.root())).unwrap();
        enforce_nonmembership(cs.clone(), &s, &r, &w).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert!(t.prove_nonmember(Fr::from(9u64)).is_err());
    }
}

/// Service mutation entrypoint: possession of `(rk,counter)` is checked
/// against the claimed serial before the unique monotonic insertion.
pub fn revoke_by_capability(
    tree: &mut IndexedRevocationTree,
    rk: [u8; 32],
    counter: u32,
    claimed: Fr,
) -> Result<Fr, RevocationError> {
    let derived = derive_serial(rk, counter)?;
    if derived != claimed {
        return Err(RevocationError::Invalid);
    }
    tree.insert(derived)?;
    Ok(tree.root())
}
