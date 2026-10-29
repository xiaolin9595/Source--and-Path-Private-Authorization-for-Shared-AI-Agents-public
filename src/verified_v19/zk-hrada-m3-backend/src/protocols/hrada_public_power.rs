//! Public fixed-base comb exponentiation (HAC 14.116/117, v = 1).
//! Only server-side public state exponents may use this variable-time table.
//! The table depends on the public RSA modulus and accumulator base, never its order.
use super::hrada_membership::RsaElem;
use accumulator::{
    group::{ElemFrom, ElemToBytes, Group, Rsa2048, UnknownOrderGroup},
    Accumulator, AccumulatorWithoutHashToPrime,
};
use rug::{integer::Order, Integer};
use serde::Serialize;

pub struct PublicPower {
    max_bits: usize,
    width: usize,
    stride: usize,
    modulus: Integer,
    table: Vec<Integer>,
}
#[derive(Debug, Serialize)]
pub struct PublicPowerStats {
    pub max_bits: usize,
    pub width: usize,
    pub stride: usize,
    pub padded_capacity_bits: usize,
    pub entries: usize,
    /// Sum of canonical group-element byte lengths, without framing.
    pub canonical_table_bytes: usize,
    pub table_vec_capacity_bytes: usize,
    pub table_integer_capacity_bytes: usize,
    /// Struct + Vec allocation + GMP limb capacities; not allocator overhead or RSS.
    pub resident_payload_estimate_bytes: usize,
}
impl PublicPower {
    pub fn new(max_bits: usize, width: usize) -> Result<Self, String> {
        if !(1..=16).contains(&width) || max_bits == 0 || max_bits > u32::MAX as usize - 16 {
            return Err(
                "comb requires width 1..16 and a positive u32-compatible bit capacity".into(),
            );
        }
        let stride = (max_bits + width - 1) / width;
        let modulus = Rsa2048::rsa_modulus().map_err(|_| "RSA modulus unavailable")?;
        let base = Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty().value;
        let mut basis = Vec::with_capacity(width);
        let mut current = Integer::from_digits(&Rsa2048::elem_to_bytes(&base), Order::MsfBe);
        for j in 0..width {
            basis.push(current.clone());
            if j + 1 < width {
                for _ in 0..stride {
                    current.square_mut();
                    current %= &modulus;
                }
            }
        }
        let mut table = Vec::with_capacity(1 << width);
        table.push(Integer::from(1));
        for mask in 1usize..(1 << width) {
            let j = mask.trailing_zeros() as usize;
            let rest = mask & (mask - 1);
            let mut entry = Integer::from(&table[rest] * &basis[j]);
            entry %= &modulus;
            table.push(entry);
        }
        Ok(Self {
            max_bits,
            width,
            stride,
            modulus,
            table,
        })
    }
    pub fn max_bits(&self) -> usize {
        self.max_bits
    }
    pub fn pow(&self, exponent: &Integer) -> Result<RsaElem, String> {
        if exponent < &0 || exponent.significant_bits() as usize > self.max_bits {
            return Err("comb exponent is negative or exceeds declared capacity".into());
        }
        let mut acc = Integer::from(1);
        for i in (0..self.stride).rev() {
            acc.square_mut();
            acc %= &self.modulus;
            let mut mask = 0;
            for j in 0..self.width {
                if exponent.get_bit((i + j * self.stride) as u32) {
                    mask |= 1 << j;
                }
            }
            if mask != 0 {
                acc *= &self.table[mask];
                acc %= &self.modulus;
            }
        }
        Ok(Rsa2048::elem(acc))
    }
    pub fn stats(&self) -> PublicPowerStats {
        let canonical_table_bytes = self
            .table
            .iter()
            .map(|x| Rsa2048::elem_to_bytes(&Rsa2048::elem(x.clone())).len())
            .sum();
        let table_vec_capacity_bytes = self.table.capacity() * std::mem::size_of::<Integer>();
        let table_integer_capacity_bytes = self
            .table
            .iter()
            .map(|x| (x.capacity() as usize + 7) / 8)
            .sum::<usize>();
        PublicPowerStats {
            max_bits: self.max_bits,
            width: self.width,
            stride: self.stride,
            padded_capacity_bits: self.width * self.stride,
            entries: self.table.len(),
            canonical_table_bytes,
            table_vec_capacity_bytes,
            table_integer_capacity_bytes,
            resident_payload_estimate_bytes: std::mem::size_of::<Self>()
                + table_vec_capacity_bytes
                + table_integer_capacity_bytes
                + (self.modulus.capacity() as usize + 7) / 8,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_comb_matches_modexp_boundaries() {
        let base = Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty().value;
        for width in [1, 2, 5, 8] {
            let power = PublicPower::new(513, width).unwrap();
            let mut cases = vec![
                Integer::from(0),
                Integer::from(1),
                Integer::from(1) << 512,
                (Integer::from(1) << 513) - 1,
            ];
            let mut sparse = Integer::from(1);
            sparse.set_bit(257, true);
            sparse.set_bit(511, true);
            cases.push(sparse);
            let mut rng = rug::rand::RandState::new();
            rng.seed(&Integer::from(12345));
            for _ in 0..8 {
                cases.push(Integer::from(Integer::random_bits(513, &mut rng)));
            }
            for exponent in cases {
                assert_eq!(
                    power.pow(&exponent).unwrap(),
                    Rsa2048::exp(&base, &exponent)
                );
            }
            assert!(power.pow(&Integer::from(-1)).is_err());
            assert!(power.pow(&(Integer::from(1) << 513)).is_err());
            assert_eq!(power.stats().entries, 1 << width);
        }
        assert!(PublicPower::new(0, 1).is_err());
        assert!(PublicPower::new(1, 0).is_err());
        assert!(PublicPower::new(1, 17).is_err());
    }
}
