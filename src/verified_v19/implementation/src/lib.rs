#![forbid(unsafe_code)]
//! Scheme-A prototype. Claims are limited to the relation implemented here.

pub mod contract;
pub mod fixture;
pub mod indexed_revocation;
pub mod joint;
pub mod merkle;
pub mod plain;
pub mod poseidon;
pub mod signature;
pub mod state_registry;

pub use ark_bls12_381::Fr;
