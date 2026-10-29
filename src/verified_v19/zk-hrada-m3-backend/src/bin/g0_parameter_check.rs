//! Executes actual library parameter derivation against the actual scalar field.
//! This checks numeric premises only; it does not certify the full CP protocol.
use ark_bls12_381::Fr;
use cpsnarks_set::{parameters::Parameters, utils::curve::Field};

fn valid_for_actual_field(p: &Parameters) -> bool {
    if p.hash_to_prime_bits == 0 || p.field_size_bits as usize != Fr::size_in_bits() {
        return false;
    }
    let d = 1u32
        + (u32::from(p.security_zk) + u32::from(p.security_soundness) + 2)
            / u32::from(p.hash_to_prime_bits);
    d * u32::from(p.hash_to_prime_bits) + 2 <= Fr::size_in_bits() as u32 && p.is_valid().is_ok()
}

fn main() {
    let old = Parameters::from_security_level(128).expect("legacy self-check");
    assert!(old.is_valid().is_ok()); // exposes the old field-agnostic acceptance
    assert!(!valid_for_actual_field(&old));
    let mut mu_only = old.clone();
    mu_only.field_size_bits = Fr::size_in_bits() as u16;
    mu_only.hash_to_prime_bits = 252;
    assert!(!valid_for_actual_field(&mu_only));
    let (derived, level) = Parameters::from_curve::<Fr>().expect("curve derivation");
    assert_eq!(
        (
            derived.field_size_bits,
            derived.hash_to_prime_bits,
            derived.security_zk,
            derived.security_soundness,
            level
        ),
        (255, 252, 124, 125, 127)
    );
    assert!(valid_for_actual_field(&derived));
    println!(
        "derived: nu={}, mu={}, lambda_z={}, lambda_s={}, nominal_lambda={}",
        derived.field_size_bits,
        derived.hash_to_prime_bits,
        derived.security_zk,
        derived.security_soundness,
        level
    );
    println!(
        "actual Fr bits={}; legacy rejected; mu-only rejected; derived numeric premises passed",
        Fr::size_in_bits()
    );
    println!("FULL CP-RSA PROFILE: NOT APPROVED (relation, domain, setup and composition audit required)");
}
