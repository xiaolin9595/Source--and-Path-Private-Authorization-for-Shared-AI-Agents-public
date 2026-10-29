//! Narrow experimental regularization of five witness-value closures.
//!
//! This changes no constraints. `Mode::Native` is the default. The fixed mode
//! uses a thread-local, nestable guard so one prover thread cannot change
//! another prover thread's mode. It regularizes the explicit inversion control
//! flow, but does not claim that the underlying field multiplication and
//! reduction implementation is constant-time.

use ark_ff::{Field, PrimeField};
use bls12_381::Scalar;
use core::cell::Cell;
use core::convert::TryInto;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Public witness-generation mode for a single prover thread.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    /// Unmodified arkworks witness-value behavior.
    Native,
    /// Fixed public exponent schedule at the five patched closure families.
    FixedWitness,
}

std::thread_local! {
    static MODE: Cell<Mode> = const { Cell::new(Mode::Native) };
}

/// Restores the previous thread-local mode on drop. It is intentionally not
/// transferable across threads.
#[must_use]
pub struct Guard {
    previous: Mode,
    _not_send: core::marker::PhantomData<*mut ()>,
}

impl Drop for Guard {
    fn drop(&mut self) {
        MODE.with(|mode| mode.set(self.previous));
    }
}

/// Enter a public synthesis mode for the current thread until the guard drops.
pub fn enter(mode: Mode) -> Guard {
    let previous = MODE.with(|current| current.replace(mode));
    Guard {
        previous,
        _not_send: core::marker::PhantomData,
    }
}

/// Return the current thread's public mode.
#[inline]
pub fn mode() -> Mode {
    MODE.with(Cell::get)
}

/// The four Edwards closure families, used only by compile-time diagnostics.
#[derive(Clone, Copy, Debug)]
pub(crate) enum InverseKind {
    AddX,
    AddY,
    DoubleX,
    DoubleY,
}

#[inline(always)]
fn exact_scalar_modulus<F: PrimeField>() -> bool {
    const MODULUS: [u64; 4] = [
        0xffffffff00000001,
        0x53bda402fffe5bfe,
        0x3339d80809a1d805,
        0x73eda753299d7d48,
    ];
    F::MODULUS.as_ref() == MODULUS
}

fn to_scalar<F: PrimeField>(value: F) -> Scalar {
    let limbs = value.into_bigint();
    assert_eq!(limbs.as_ref().len(), 4);
    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.chunks_exact_mut(8).zip(limbs.as_ref()) {
        chunk.copy_from_slice(&limb.to_le_bytes());
    }
    Option::<Scalar>::from(Scalar::from_bytes(&bytes)).expect("canonical exact-modulus conversion")
}

fn from_scalar<F: PrimeField>(value: Scalar) -> F {
    let bytes = value.to_bytes();
    let mut repr = F::BigInt::default();
    assert_eq!(repr.as_ref().len(), 4);
    for (limb, chunk) in repr.as_mut().iter_mut().zip(bytes.chunks_exact(8)) {
        *limb = u64::from_le_bytes(chunk.try_into().expect("eight-byte chunk"));
    }
    F::from_bigint(repr).expect("canonical exact-modulus conversion")
}

/// The reviewed `bls12_381::Scalar::invert` addition chain has a fixed public
/// exponent schedule and returns `CtOption`; its field multiplications are
/// implemented by that crate. This special path is used only for the exact
/// BLS12-381 scalar modulus. Other prime fields retain native behavior.
#[inline(never)]
fn fixed_scalar_inverse<F: PrimeField>(value: F) -> (F, Choice) {
    assert!(exact_scalar_modulus::<F>());
    let scalar = to_scalar(value);
    let is_zero = scalar.ct_eq(&Scalar::zero());
    let inverse = Scalar::invert(&scalar).unwrap_or(Scalar::zero());
    (from_scalar(inverse), is_zero)
}

#[cfg(feature = "synthesis-patch-diagnostics")]
mod diagnostics {
    use super::InverseKind;
    use core::cell::Cell;
    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    pub struct Counters {
        pub eq_zero: u64,
        pub eq_one: u64,
        pub eq_general: u64,
        pub add_x_zero: u64,
        pub add_x_one: u64,
        pub add_x_general: u64,
        pub add_y_zero: u64,
        pub add_y_one: u64,
        pub add_y_general: u64,
        pub double_x_zero: u64,
        pub double_x_one: u64,
        pub double_x_general: u64,
        pub double_y_zero: u64,
        pub double_y_one: u64,
        pub double_y_general: u64,
    }
    std::thread_local! { static COUNTERS: Cell<Counters> = Cell::new(Counters::default()); }
    pub(super) fn record(kind: Option<InverseKind>, class: u8) {
        COUNTERS.with(|slot| {
            let mut c = slot.get();
            let target = match (kind, class) {
                (None, 0) => &mut c.eq_zero,
                (None, 1) => &mut c.eq_one,
                (None, _) => &mut c.eq_general,
                (Some(InverseKind::AddX), 0) => &mut c.add_x_zero,
                (Some(InverseKind::AddX), 1) => &mut c.add_x_one,
                (Some(InverseKind::AddX), _) => &mut c.add_x_general,
                (Some(InverseKind::AddY), 0) => &mut c.add_y_zero,
                (Some(InverseKind::AddY), 1) => &mut c.add_y_one,
                (Some(InverseKind::AddY), _) => &mut c.add_y_general,
                (Some(InverseKind::DoubleX), 0) => &mut c.double_x_zero,
                (Some(InverseKind::DoubleX), 1) => &mut c.double_x_one,
                (Some(InverseKind::DoubleX), _) => &mut c.double_x_general,
                (Some(InverseKind::DoubleY), 0) => &mut c.double_y_zero,
                (Some(InverseKind::DoubleY), 1) => &mut c.double_y_one,
                (Some(InverseKind::DoubleY), _) => &mut c.double_y_general,
            };
            *target += 1;
            slot.set(c);
        });
    }
    pub fn take_counters() -> Counters {
        COUNTERS.with(|slot| slot.replace(Counters::default()))
    }
}

#[cfg(feature = "synthesis-patch-diagnostics")]
pub use diagnostics::{take_counters, Counters};

#[inline]
#[cfg(feature = "synthesis-patch-diagnostics")]
fn class<F: Field>(value: &F) -> u8 {
    if value.is_zero() {
        0
    } else if value.is_one() {
        1
    } else {
        2
    }
}

/// Equality multiplier: fixed mode always performs the complete exponentiation,
/// then selects one for a zero difference without a secret-dependent branch.
pub(crate) fn equality_multiplier<F: PrimeField>(difference: F, native_is_neq: bool) -> F {
    #[cfg(feature = "synthesis-patch-diagnostics")]
    diagnostics::record(None, class(&difference));
    if mode() == Mode::Native || !exact_scalar_modulus::<F>() {
        if native_is_neq {
            difference.inverse().expect("nonzero difference")
        } else {
            F::one()
        }
    } else {
        let (candidate, is_zero) = fixed_scalar_inverse(difference);
        from_scalar(Scalar::conditional_select(
            &to_scalar(candidate),
            &Scalar::one(),
            is_zero,
        ))
    }
}

/// Edwards denominator inversion. Fixed mode performs the complete exponent
/// schedule before the delayed zero/error decision, preserving `None` exactly.
pub(crate) fn denominator_inverse<F: Field>(_kind: InverseKind, denominator: F) -> Option<F> {
    #[cfg(feature = "synthesis-patch-diagnostics")]
    diagnostics::record(Some(_kind), class(&denominator));
    if mode() == Mode::Native
        || F::extension_degree() != 1
        || !exact_scalar_modulus::<F::BasePrimeField>()
    {
        denominator.inverse()
    } else {
        let base = denominator
            .to_base_prime_field_elements()
            .next()
            .expect("degree-one field");
        let (candidate, is_zero) = fixed_scalar_inverse(base);
        let selected = F::from_base_prime_field(candidate);
        if bool::from(is_zero) {
            None
        } else {
            Some(selected)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_377::Fr as OtherFr;
    use ark_bls12_381::Fr;
    use ark_ff::Field;
    use ark_std::{One, Zero};

    #[test]
    fn fixed_semantics_cover_zero_one_and_general() {
        let _guard = enter(Mode::FixedWitness);
        assert_eq!(equality_multiplier(Fr::zero(), false), Fr::one());
        assert_eq!(equality_multiplier(Fr::one(), true), Fr::one());
        let general = Fr::from(7u64);
        assert_eq!(
            equality_multiplier(general, true),
            general.inverse().unwrap()
        );
        assert!(denominator_inverse(InverseKind::AddX, Fr::zero()).is_none());
        assert_eq!(
            denominator_inverse(InverseKind::DoubleY, Fr::one()),
            Some(Fr::one())
        );
        assert_eq!(
            denominator_inverse(InverseKind::AddY, general),
            general.inverse()
        );
    }

    #[test]
    fn guard_is_nested_and_restores_native() {
        assert_eq!(mode(), Mode::Native);
        let outer = enter(Mode::FixedWitness);
        assert_eq!(mode(), Mode::FixedWitness);
        {
            let _inner = enter(Mode::Native);
            assert_eq!(mode(), Mode::Native);
        }
        assert_eq!(mode(), Mode::FixedWitness);
        drop(outer);
        assert_eq!(mode(), Mode::Native);
    }

    #[test]
    fn non_target_modulus_retains_native_semantics() {
        let _guard = enter(Mode::FixedWitness);
        let value = OtherFr::from(11u64);
        assert_eq!(equality_multiplier(value, true), value.inverse().unwrap());
        assert_eq!(
            denominator_inverse(InverseKind::DoubleX, value),
            value.inverse()
        );
    }

    #[cfg(feature = "synthesis-patch-diagnostics")]
    #[test]
    fn diagnostic_counts_classes_separately() {
        let _ = take_counters();
        let _guard = enter(Mode::FixedWitness);
        let _ = equality_multiplier(Fr::zero(), false);
        let _ = equality_multiplier(Fr::one(), true);
        let _ = equality_multiplier(Fr::from(9u64), true);
        let _ = denominator_inverse(InverseKind::AddX, Fr::zero());
        let _ = denominator_inverse(InverseKind::DoubleY, Fr::one());
        let _ = denominator_inverse(InverseKind::AddY, Fr::from(9u64));
        let counters = take_counters();
        assert_eq!(
            (counters.eq_zero, counters.eq_one, counters.eq_general),
            (1, 1, 1)
        );
        assert_eq!(counters.add_x_zero, 1);
        assert_eq!(counters.double_y_one, 1);
        assert_eq!(counters.add_y_general, 1);
    }
}
