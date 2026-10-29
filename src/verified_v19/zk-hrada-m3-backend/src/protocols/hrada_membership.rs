//! Experimental prime-state CP-RSA membership. Single-party OS-entropy setup;
//! small public-set rebuilding, not a production ceremony or update service.
use super::hrada_public_power::PublicPower;
use crate::{
    commitments::Commitment,
    parameters::Parameters,
    protocols::{hash_to_prime::snark_range, membership},
    utils::curve::Field,
};
use accumulator::{
    group::{ElemToBytes, Group, Rsa2048, UnknownOrderGroup},
    Accumulator, AccumulatorWithoutHashToPrime,
};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_serialize::CanonicalSerialize;
use merlin::Transcript;
use rand::{rngs::OsRng, RngCore};
use rug::{
    integer::{IsPrime, Order},
    rand::RandState,
    Integer,
};
use std::{cell::RefCell, collections::BTreeSet, sync::Arc};

pub type CpProtocol = membership::Protocol<Rsa2048, G1Projective, snark_range::Protocol<Bls12_381>>;
pub type CpProof = membership::Proof<Rsa2048, G1Projective, snark_range::Protocol<Bls12_381>>;
pub type CpStatement = membership::Statement<Rsa2048, G1Projective>;
pub type RsaElem = <Rsa2048 as Group>::Elem;
type Acc = Accumulator<Rsa2048, Integer, AccumulatorWithoutHashToPrime>;

fn secret_rng() -> RandState<'static> {
    let mut seed = [0u8; 64];
    OsRng.fill_bytes(&mut seed);
    let mut r = RandState::new();
    r.seed(&Integer::from_digits(&seed, Order::MsfBe));
    // No seed is logged/serialized; this is not a memory-erasure guarantee.
    r
}
pub fn validate_prime(p: &Integer) -> Result<(), String> {
    if p <= &0 || p.significant_bits() != 252 || p.is_probably_prime(64) == IsPrime::No {
        return Err("state ID must be a positive 252-bit probable prime (GMP 64 reps)".into());
    }
    Ok(())
}
pub fn allocate_prime() -> Integer {
    loop {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes[0] = (bytes[0] & 7) | 8;
        bytes[31] |= 1;
        let p = Integer::from_digits(&bytes, Order::MsfBe);
        if validate_prime(&p).is_ok() {
            return p;
        }
    }
}
/// Immutable, state-bound cached witness. Fields are private to prevent unvalidated construction.
pub struct PreparedWitness {
    accumulator: RsaElem,
    prime: Integer,
    witness: RsaElem,
}
#[derive(Clone)]
pub struct StateSet {
    pub accumulator: RsaElem,
    primes: Vec<Integer>,
}
impl StateSet {
    pub fn rebuild(primes: &[Integer]) -> Result<Self, String> {
        for (i, p) in primes.iter().enumerate() {
            validate_prime(p)?;
            if primes[..i].contains(p) {
                return Err("duplicate state prime".into());
            }
        }
        Ok(Self {
            accumulator: Acc::empty().add(primes).value,
            primes: primes.to_vec(),
        })
    }
    pub fn prepare_witness(&self, prime: &Integer) -> Result<PreparedWitness, String> {
        Ok(PreparedWitness {
            accumulator: self.accumulator.clone(),
            prime: prime.clone(),
            witness: self.witness(prime)?,
        })
    }
    /// Refresh one locally held witness across an explicitly supplied replacement burst.
    /// No target-indexed server cache, trapdoor, or external update message is introduced.
    /// This checks the transition sequence, not an authenticated epoch order: commuting
    /// replacements can be permuted without changing the state. Callers must enforce epochs.
    /// The supplied old state and change log have nonzero storage/validation costs.
    pub fn refresh_prepared_from(
        &self,
        previous: &StateSet,
        prepared: &PreparedWitness,
        changes: &[(usize, Integer, Integer)],
    ) -> Result<PreparedWitness, String> {
        if prepared.accumulator != previous.accumulator
            || !previous.primes.contains(&prepared.prime)
            || Rsa2048::exp(&prepared.witness, &prepared.prime) != previous.accumulator
        {
            return Err("prepared witness does not bind the previous state".into());
        }
        let mut replay = previous.primes.clone();
        let mut deleted = Integer::from(1);
        let mut inserted = Integer::from(1);
        for (slot, old, new) in changes {
            if replay.get(*slot) != Some(old) {
                return Err("replacement slot or old prime does not match".into());
            }
            if old == &prepared.prime {
                return Err("target was revoked during replacement burst".into());
            }
            if old == new || replay.contains(new) {
                return Err("replacement is unchanged or duplicates a member".into());
            }
            validate_prime(new)?;
            replay[*slot] = new.clone();
            deleted *= old;
            inserted *= new;
        }
        if replay != self.primes {
            return Err("replacement log does not produce the current state".into());
        }
        // Cancel transient insertions/deletions before computing signed exponents.
        let common = Integer::from(deleted.gcd_ref(&inserted));
        deleted /= &common;
        inserted /= &common;
        let (gcd, a, b) =
            <(Integer, Integer, Integer)>::from(prepared.prime.gcd_cofactors_ref(&deleted));
        if gcd != 1 {
            return Err("target is not coprime to deletion product".into());
        }
        // a*p + b*D = 1; A_new = A_old^(I/D) for the validated transition.
        let exponent = Integer::from(&b * &inserted);
        let witness = Rsa2048::op(
            &Rsa2048::exp(&prepared.witness, &exponent),
            &Rsa2048::exp(&self.accumulator, &a),
        );
        if Rsa2048::exp(&witness, &prepared.prime) != self.accumulator {
            return Err("refreshed witness does not match the current accumulator".into());
        }
        Ok(PreparedWitness {
            accumulator: self.accumulator.clone(),
            prime: prepared.prime.clone(),
            witness,
        })
    }
    pub fn witness(&self, prime: &Integer) -> Result<RsaElem, String> {
        if !self.primes.contains(prime) {
            return Err("nonmember state prime".into());
        }
        let others: Vec<_> = self
            .primes
            .iter()
            .filter(|p| *p != prime)
            .cloned()
            .collect();
        Ok(Acc::empty().add(&others).value)
    }
}
/// Public-exponent maintenance with a single last-replaced-slot cofactor cache.
/// No group order or trapdoor is used. A slot change recomputes the cofactor.
pub struct MaintainedState {
    state: StateSet,
    validated: BTreeSet<Integer>,
    product: Integer,
    cofactor: Option<(usize, RsaElem)>,
    public_power: Option<Arc<PublicPower>>,
}
impl MaintainedState {
    pub fn new(primes: &[Integer]) -> Result<Self, String> {
        let state = StateSet::rebuild(primes)?;
        let mut product = Integer::from(1);
        for prime in primes {
            product *= prime;
        }
        Ok(Self {
            state,
            validated: primes.iter().cloned().collect(),
            product,
            cofactor: None,
            public_power: None,
        })
    }
    /// Optional public server-side comb table. Witness generation remains unchanged.
    pub fn new_with_power(primes: &[Integer], power: Arc<PublicPower>) -> Result<Self, String> {
        let required = primes
            .len()
            .checked_mul(252)
            .ok_or("state capacity overflow")?;
        if required > power.max_bits() {
            return Err("public power capacity is smaller than 252 * member count".into());
        }
        let mut state = Self::new(primes)?;
        state.public_power = Some(power);
        Ok(state)
    }
    pub fn state(&self) -> &StateSet {
        &self.state
    }
    /// Returns whether the last-slot cofactor was reused. All validation precedes mutation.
    pub fn replace(&mut self, index: usize, new_prime: Integer) -> Result<bool, String> {
        let old = self
            .state
            .primes
            .get(index)
            .ok_or("state index out of bounds")?;
        if old == &new_prime {
            return Err("state replacement must change prime".into());
        }
        if self.validated.contains(&new_prime) {
            return Err("duplicate state prime".into());
        }
        validate_prime(&new_prime)?;
        let quotient = Integer::from(&self.product / old);
        if Integer::from(&quotient * old) != self.product {
            return Err("state product division was not exact".into());
        }
        let hit = self
            .cofactor
            .as_ref()
            .map_or(false, |(slot, _)| *slot == index);
        let cofactor = if hit {
            self.cofactor.as_ref().unwrap().1.clone()
        } else {
            match &self.public_power {
                Some(power) => power.pow(&quotient)?,
                None => Rsa2048::exp(&Acc::empty().value, &quotient),
            }
        };
        let accumulator = Rsa2048::exp(&cofactor, &new_prime);
        let product = Integer::from(&quotient * &new_prime);
        self.validated.remove(old);
        self.validated.insert(new_prime.clone());
        self.state.primes[index] = new_prime;
        self.state.accumulator = accumulator;
        self.product = product;
        self.cofactor = Some((index, cofactor));
        Ok(hit)
    }
    pub fn witness(&self, prime: &Integer) -> Result<RsaElem, String> {
        if !self.validated.contains(prime) {
            return Err("nonmember state prime".into());
        }
        let quotient = Integer::from(&self.product / prime);
        Ok(Rsa2048::exp(&Acc::empty().value, &quotient))
    }
    pub fn prepare_witness(&self, prime: &Integer) -> Result<PreparedWitness, String> {
        Ok(PreparedWitness {
            accumulator: self.state.accumulator.clone(),
            prime: prime.clone(),
            witness: self.witness(prime)?,
        })
    }
}
pub struct StateMembership {
    pub protocol: CpProtocol,
}
impl StateMembership {
    pub fn setup_os() -> Result<Self, String> {
        let (p, _) = Parameters::from_curve::<Fr>().map_err(|e| format!("{:?}", e))?;
        let d = 1u32
            + (u32::from(p.security_zk) + u32::from(p.security_soundness) + 2)
                / u32::from(p.hash_to_prime_bits);
        if p.field_size_bits as usize != Fr::size_in_bits()
            || p.hash_to_prime_bits != 252
            || d * u32::from(p.hash_to_prime_bits) + 2 > Fr::size_in_bits() as u32
        {
            return Err("actual curve parameter precondition failed".into());
        }
        let protocol =
            CpProtocol::setup(&p, &mut secret_rng(), &mut OsRng).map_err(|e| format!("{:?}", e))?;
        Ok(Self { protocol })
    }
    pub fn commit(&self, p: &Integer, r: &Integer) -> Result<G1Projective, String> {
        validate_prime(p)?;
        if r < &0 || r >= &Fr::modulus() {
            return Err("noncanonical commitment randomness".into());
        }
        self.protocol
            .crs
            .crs_modeq
            .pedersen_commitment_parameters
            .commit(p, r)
            .map_err(|e| format!("{:?}", e))
    }
    pub fn prove(
        &self,
        set: &StateSet,
        p: &Integer,
        r: &Integer,
        context: &[u8],
    ) -> Result<(CpStatement, CpProof), String> {
        let statement = CpStatement {
            c_p: set.accumulator.clone(),
            c_e_q: self.commit(p, r)?,
        };
        let witness = membership::Witness {
            e: p.clone(),
            r_q: r.clone(),
            w: set.witness(p)?,
        };
        let proof = self.prove_witness(&statement, &witness, context)?;
        Ok((statement, proof))
    }
    /// Fresh proof and commitment randomness over a previously prepared immutable witness.
    pub fn prove_prepared(
        &self,
        set: &StateSet,
        p: &Integer,
        prepared: &PreparedWitness,
        r: &Integer,
        context: &[u8],
    ) -> Result<(CpStatement, CpProof), String> {
        if prepared.accumulator != set.accumulator
            || &prepared.prime != p
            || !set.primes.contains(p)
        {
            return Err("prepared_witness_state_or_prime_mismatch".into());
        }
        let statement = CpStatement {
            c_p: set.accumulator.clone(),
            c_e_q: self.commit(p, r)?,
        };
        let witness = membership::Witness {
            e: p.clone(),
            r_q: r.clone(),
            w: prepared.witness.clone(),
        };
        let proof = self.prove_witness(&statement, &witness, context)?;
        Ok((statement, proof))
    }
    fn prove_witness(
        &self,
        s: &CpStatement,
        w: &membership::Witness<Rsa2048>,
        ctx: &[u8],
    ) -> Result<CpProof, String> {
        let transcript = RefCell::new(self.transcript(s, ctx)?);
        let mut channel =
            membership::transcript::TranscriptVerifierChannel::new(&self.protocol.crs, &transcript);
        self.protocol
            .prove(&mut channel, &mut secret_rng(), &mut OsRng, s, w)
            .map_err(|e| format!("{:?}", e))?;
        channel.proof().map_err(|e| format!("{:?}", e))
    }
    pub fn verify(&self, s: &CpStatement, p: &CpProof, ctx: &[u8]) -> Result<(), String> {
        let transcript = RefCell::new(self.transcript(s, ctx)?);
        let mut channel = membership::transcript::TranscriptProverChannel::new(
            &self.protocol.crs,
            &transcript,
            p,
        );
        self.protocol
            .verify(&mut channel, s)
            .map_err(|e| format!("{:?}", e))
    }
    fn transcript(&self, s: &CpStatement, ctx: &[u8]) -> Result<Transcript, String> {
        let mut t = Transcript::new(b"hrada-prime-membership-v1");
        t.append_message(b"context", ctx);
        t.append_message(b"cp-parameters", &self.canonical_parameters()?);
        t.append_message(b"accumulator", &Rsa2048::elem_to_bytes(&s.c_p));
        let mut b = vec![];
        s.c_e_q.serialize(&mut b).map_err(|e| format!("{:?}", e))?;
        t.append_message(b"prime-commitment", &b);
        Ok(t)
    }
    /// Length-prefixed canonical public verifier parameters; no prover randomness.
    pub fn canonical_parameters(&self) -> Result<Vec<u8>, String> {
        let mut out = b"hrada-cp-rsa2048-bls12381-prime-v1".to_vec();
        fn put(out: &mut Vec<u8>, b: &[u8]) {
            out.extend_from_slice(&(b.len() as u64).to_le_bytes());
            out.extend_from_slice(b);
        }
        let c = &self.protocol.crs;
        for p in [
            &c.parameters,
            &c.crs_root.parameters,
            &c.crs_modeq.parameters,
            &c.crs_hash_to_prime.parameters,
        ]
        .iter()
        {
            for v in [
                p.security_level,
                p.security_zk,
                p.security_soundness,
                p.hash_to_prime_bits,
                p.field_size_bits,
            ]
            .iter()
            {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
        put(
            &mut out,
            &Rsa2048::rsa_modulus()
                .map_err(|e| format!("{:?}", e))?
                .to_digits::<u8>(Order::MsfBe),
        );
        put(
            &mut out,
            &Rsa2048::elem_to_bytes(&Rsa2048::unknown_order_elem()),
        );
        for ic in [
            &c.crs_root.integer_commitment_parameters,
            &c.crs_modeq.integer_commitment_parameters,
        ]
        .iter()
        {
            put(&mut out, &Rsa2048::elem_to_bytes(&ic.g));
            put(&mut out, &Rsa2048::elem_to_bytes(&ic.h));
        }
        for pc in [
            &c.crs_modeq.pedersen_commitment_parameters,
            &c.crs_hash_to_prime.pedersen_commitment_parameters,
        ]
        .iter()
        {
            for point in [&pc.g, &pc.h].iter() {
                let mut b = vec![];
                point.serialize(&mut b).map_err(|e| format!("{:?}", e))?;
                put(&mut out, &b);
            }
        }
        let mut b = vec![];
        c.crs_hash_to_prime
            .hash_to_prime_parameters
            .vk
            .serialize(&mut b)
            .map_err(|e| format!("{:?}", e))?;
        put(&mut out, &b);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn burst_refresh_equivalence_and_failures() {
        let pool: Vec<_> = (0..8).map(|_| allocate_prime()).collect();
        let previous = StateSet::rebuild(&pool[..3]).unwrap();
        let prepared = previous.prepare_witness(&pool[0]).unwrap();
        let saved = (
            prepared.accumulator.clone(),
            prepared.prime.clone(),
            prepared.witness.clone(),
        );
        let log = vec![
            (1, pool[1].clone(), pool[3].clone()),
            (1, pool[3].clone(), pool[4].clone()),
            (2, pool[2].clone(), pool[5].clone()),
            (1, pool[4].clone(), pool[1].clone()),
        ];
        let mut members = pool[..3].to_vec();
        for i in 0..log.len() {
            members[log[i].0] = log[i].2.clone();
            let current = StateSet::rebuild(&members).unwrap();
            let fresh = current
                .refresh_prepared_from(&previous, &prepared, &log[..=i])
                .unwrap();
            assert_eq!(fresh.witness, current.witness(&pool[0]).unwrap());
        }
        let current = StateSet::rebuild(&members).unwrap();
        assert_eq!(
            previous
                .refresh_prepared_from(&previous, &prepared, &[])
                .unwrap()
                .witness,
            prepared.witness
        );
        let mut invalid = vec![log[..3].to_vec(), vec![]];
        for field in 0..4 {
            let mut bad = log.clone();
            match field {
                0 => bad[0].0 = 9,
                1 => bad[0].1 = pool[6].clone(),
                2 => bad[0].2 = Integer::from(17),
                _ => bad[0].2 = pool[2].clone(),
            }
            invalid.push(bad);
        }
        invalid.push(vec![(1, pool[1].clone(), pool[1].clone())]);
        for bad in invalid {
            assert!(current
                .refresh_prepared_from(&previous, &prepared, &bad)
                .is_err());
        }
        assert!(current
            .refresh_prepared_from(&current, &prepared, &[])
            .is_err());
        let revoke_restore = vec![
            (0, pool[0].clone(), pool[6].clone()),
            (0, pool[6].clone(), pool[0].clone()),
        ];
        assert!(previous
            .refresh_prepared_from(&previous, &prepared, &revoke_restore)
            .is_err());
        let mut malformed = current.clone();
        malformed.accumulator = previous.accumulator.clone();
        assert!(malformed
            .refresh_prepared_from(&previous, &prepared, &log)
            .is_err());
        assert_eq!(
            saved,
            (
                prepared.accumulator.clone(),
                prepared.prime.clone(),
                prepared.witness.clone()
            )
        );
    }
    #[test]
    fn burst_refresh_real_proof_and_stale_rejection() {
        let cp = StateMembership::setup_os().unwrap();
        let pool: Vec<_> = (0..3).map(|_| allocate_prime()).collect();
        let previous = StateSet::rebuild(&pool[..2]).unwrap();
        let old = previous.prepare_witness(&pool[0]).unwrap();
        let current = StateSet::rebuild(&[pool[0].clone(), pool[2].clone()]).unwrap();
        let log = vec![(1, pool[1].clone(), pool[2].clone())];
        let fresh = current
            .refresh_prepared_from(&previous, &old, &log)
            .unwrap();
        assert!(cp
            .prove_prepared(&current, &pool[0], &old, &Integer::from(19), b"burst-fresh")
            .is_err());
        let (statement, proof) = cp
            .prove_prepared(
                &current,
                &pool[0],
                &fresh,
                &Integer::from(23),
                b"burst-fresh",
            )
            .unwrap();
        cp.verify(&statement, &proof, b"burst-fresh").unwrap();
        assert!(cp
            .verify(&statement, &proof, b"burst-other-request")
            .is_err());
    }
    fn check_maintained(m: &MaintainedState) {
        let reference = StateSet::rebuild(&m.state.primes).unwrap();
        assert_eq!(reference.accumulator, m.state.accumulator);
        for p in &m.state.primes {
            assert_eq!(reference.witness(p).unwrap(), m.witness(p).unwrap());
            assert_eq!(
                m.prepare_witness(p).unwrap().witness,
                reference.witness(p).unwrap()
            );
        }
    }
    #[test]
    fn public_comb_maintained_equivalence_and_atomicity() {
        let pool: Vec<_> = (0..8).map(|_| allocate_prime()).collect();
        let power = Arc::new(PublicPower::new(3 * 252, 5).unwrap());
        assert!(MaintainedState::new_with_power(&pool[..4], power.clone()).is_err());
        let mut m = MaintainedState::new_with_power(&pool[..3], power).unwrap();
        check_maintained(&m);
        for (index, p, hit) in [
            (1, 3, false),
            (1, 4, true),
            (2, 5, false),
            (1, 6, false),
            (0, 7, false),
            (0, 0, true),
        ] {
            assert_eq!(m.replace(index, pool[p].clone()).unwrap(), hit);
            check_maintained(&m);
        }
        for (index, p) in [
            (0, pool[0].clone()),
            (0, pool[5].clone()),
            (3, pool[2].clone()),
            (1, Integer::from(17)),
        ] {
            let before = (
                m.state.accumulator.clone(),
                m.state.primes.clone(),
                m.product.clone(),
                m.validated.clone(),
                m.cofactor.clone(),
            );
            assert!(m.replace(index, p).is_err());
            assert_eq!(
                before,
                (
                    m.state.accumulator.clone(),
                    m.state.primes.clone(),
                    m.product.clone(),
                    m.validated.clone(),
                    m.cofactor.clone()
                )
            );
        }
    }
    #[test]
    fn public_comb_rejects_stale_prepared() {
        let cp = StateMembership::setup_os().unwrap();
        let pool: Vec<_> = (0..3).map(|_| allocate_prime()).collect();
        let mut m = MaintainedState::new_with_power(
            &pool[..2],
            Arc::new(PublicPower::new(504, 4).unwrap()),
        )
        .unwrap();
        let stale = m.prepare_witness(&pool[0]).unwrap();
        m.replace(1, pool[2].clone()).unwrap();
        assert!(cp
            .prove_prepared(
                m.state(),
                &pool[0],
                &stale,
                &Integer::from(17),
                b"comb-changed-state"
            )
            .is_err());
    }
    #[test]
    fn maintained_replacements_match_rebuild() {
        let pool: Vec<_> = (0..8).map(|_| allocate_prime()).collect();
        let mut m = MaintainedState::new(&pool[..3]).unwrap();
        check_maintained(&m);
        // Hot slot, rotation, revisit (miss), target replacement, then restored old prime.
        for (index, p, expected_hit) in [
            (1, 3, false),
            (1, 4, true),
            (2, 5, false),
            (1, 6, false),
            (0, 7, false),
            (0, 0, true),
        ] {
            assert_eq!(m.replace(index, pool[p].clone()).unwrap(), expected_hit);
            check_maintained(&m);
        }
        let mut singleton = MaintainedState::new(&pool[..1]).unwrap();
        singleton.replace(0, pool[1].clone()).unwrap();
        check_maintained(&singleton);
        assert_eq!(singleton.witness(&pool[1]).unwrap(), Acc::empty().value);
        let mut empty = MaintainedState::new(&[]).unwrap();
        check_maintained(&empty);
        assert!(empty.replace(0, pool[0].clone()).is_err());
        assert!(empty.witness(&pool[0]).is_err());
    }
    #[test]
    fn maintained_failed_replacement_is_atomic() {
        let pool: Vec<_> = (0..4).map(|_| allocate_prime()).collect();
        let mut m = MaintainedState::new(&pool[..2]).unwrap();
        m.replace(0, pool[2].clone()).unwrap();
        let composite = Integer::from(1) << 251;
        for (index, prime) in [
            (0, pool[1].clone()),
            (0, pool[2].clone()),
            (0, composite),
            (0, Integer::from(17)),
            (2, pool[3].clone()),
        ] {
            let before = (
                m.state.accumulator.clone(),
                m.state.primes.clone(),
                m.validated.clone(),
                m.product.clone(),
                m.cofactor.clone(),
            );
            assert!(m.replace(index, prime).is_err());
            assert_eq!(
                before,
                (
                    m.state.accumulator.clone(),
                    m.state.primes.clone(),
                    m.validated.clone(),
                    m.product.clone(),
                    m.cofactor.clone()
                )
            );
        }
        assert!(m.replace(0, pool[0].clone()).unwrap());
        check_maintained(&m);
        assert!(MaintainedState::new(&[pool[0].clone(), pool[0].clone()]).is_err());
    }
    #[test]
    fn maintained_real_proof_and_stale_witness() {
        let cp = StateMembership::setup_os().unwrap();
        let primes: Vec<_> = (0..4).map(|_| allocate_prime()).collect();
        let mut m = MaintainedState::new(&primes[..2]).unwrap();
        let old = m.prepare_witness(&primes[0]).unwrap();
        m.replace(1, primes[2].clone()).unwrap();
        assert!(cp
            .prove_prepared(
                m.state(),
                &primes[0],
                &old,
                &Integer::from(19),
                b"new-state"
            )
            .is_err());
        let fresh = m.prepare_witness(&primes[0]).unwrap();
        let (statement, proof) = cp
            .prove_prepared(
                m.state(),
                &primes[0],
                &fresh,
                &Integer::from(23),
                b"new-state",
            )
            .unwrap();
        cp.verify(&statement, &proof, b"new-state").unwrap();
        m.replace(0, primes[3].clone()).unwrap();
        assert!(m.prepare_witness(&primes[0]).is_err());
        assert!(cp
            .prove_prepared(
                m.state(),
                &primes[0],
                &fresh,
                &Integer::from(29),
                b"target-replaced"
            )
            .is_err());
        let fresh = m.prepare_witness(&primes[3]).unwrap();
        let (statement, proof) = cp
            .prove_prepared(
                m.state(),
                &primes[3],
                &fresh,
                &Integer::from(31),
                b"target-replaced",
            )
            .unwrap();
        cp.verify(&statement, &proof, b"target-replaced").unwrap();
    }
    #[test]
    fn real_prime_cp_accept_and_reject() {
        let cp = StateMembership::setup_os().unwrap();
        let p = allocate_prime();
        let q = allocate_prime();
        let outsider = allocate_prime();
        let set = StateSet::rebuild(&[p.clone(), q.clone()]).unwrap();
        let prepared = set.prepare_witness(&p).unwrap();
        let (ps, pp) = cp
            .prove_prepared(&set, &p, &prepared, &Integer::from(29), b"cached-fresh-1")
            .unwrap();
        cp.verify(&ps, &pp, b"cached-fresh-1").unwrap();
        let (ps2, pp2) = cp
            .prove_prepared(&set, &p, &prepared, &Integer::from(31), b"cached-fresh-2")
            .unwrap();
        cp.verify(&ps2, &pp2, b"cached-fresh-2").unwrap();
        assert_ne!(ps.c_e_q, ps2.c_e_q);
        assert!(cp.verify(&ps2, &pp2, b"cached-fresh-1").is_err());
        assert!(cp
            .prove_prepared(&set, &q, &prepared, &Integer::from(29), b"bad-prime")
            .is_err());
        let changed = StateSet::rebuild(&[p.clone(), outsider.clone()]).unwrap();
        assert!(cp
            .prove_prepared(&changed, &p, &prepared, &Integer::from(29), b"bad-state")
            .is_err());
        let r = Integer::from(19);
        let (s, proof) = cp.prove(&set, &p, &r, b"params-header-request").unwrap();
        cp.verify(&s, &proof, b"params-header-request").unwrap();
        assert!(cp.verify(&s, &proof, b"different-request").is_err());
        let wrong = CpStatement {
            c_p: s.c_p.clone(),
            c_e_q: cp.commit(&q, &r).unwrap(),
        };
        assert!(cp.verify(&wrong, &proof, b"params-header-request").is_err());
        assert!(cp
            .prove(&set, &outsider, &r, b"params-header-request")
            .is_err());
        let forged = CpStatement {
            c_p: s.c_p.clone(),
            c_e_q: cp.commit(&outsider, &r).unwrap(),
        };
        let fake = membership::Witness {
            e: outsider,
            r_q: r,
            w: set.witness(&p).unwrap(),
        };
        let bad = cp
            .prove_witness(&forged, &fake, b"params-header-request")
            .expect(
                "negative test must generate an actual proof; infrastructure errors fail this test",
            );
        assert!(cp.verify(&forged, &bad, b"params-header-request").is_err());
        let revoked = StateSet::rebuild(&[q.clone()]).unwrap();
        let stale = CpStatement {
            c_p: revoked.accumulator.clone(),
            c_e_q: s.c_e_q,
        };
        assert!(cp.verify(&stale, &proof, b"params-header-request").is_err());
        let (retained, retained_proof) = cp
            .prove(&revoked, &q, &Integer::from(23), b"updated-header")
            .unwrap();
        cp.verify(&retained, &retained_proof, b"updated-header")
            .unwrap();
        assert!(StateSet::rebuild(&[p.clone(), p]).is_err());
        assert!(validate_prime(&Integer::from(17)).is_err());
        // New immutable-per-run public artifacts, never an old benchmark CRS.
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::path::PathBuf::from("target/hrada-membership-tests").join(format!(
            "{}-{}",
            std::process::id(),
            stamp
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("cp-public-parameters.bin"),
            cp.canonical_parameters().unwrap(),
        )
        .unwrap();
        let mut range_pk = vec![];
        cp.protocol
            .crs
            .crs_hash_to_prime
            .hash_to_prime_parameters
            .serialize(&mut range_pk)
            .unwrap();
        std::fs::write(dir.join("range-proving-key.bin"), range_pk).unwrap();
        std::fs::write(dir.join("result.txt"),"member accepted; actual invalid-witness proof rejected; wrong commitment/context and revoked state rejected; independent member reproved; experimental OS-entropy single-party setup; probable-prime admission; not complete HRADA\n").unwrap();
        println!("new public setup artifacts: {}", dir.display());
        println!("real prime CP: member accepted; outsider, bad witness, wrong commitment/context, revoked state rejected");
    }
}

/// Experimental verifier cost decomposition and parameter-bound PVK reuse.
pub mod verifier_screen;
