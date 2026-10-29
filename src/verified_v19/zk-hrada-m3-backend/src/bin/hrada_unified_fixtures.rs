//! Public random prime pools for the separate unified scaling experiment.
use cpsnarks_set::protocols::hrada_membership::allocate_prime;
use serde_json::json;
use std::{collections::HashSet, fs};
fn main() {
    let args: Vec<String> = std::env::args().collect();
    assert_eq!(args.len(), 4, "output trials count");
    let trials: usize = args[2].parse().unwrap();
    let count: usize = args[3].parse().unwrap();
    assert!(!std::path::Path::new(&args[1]).exists());
    let mut fixtures = Vec::new();
    let mut seen = HashSet::new();
    for trial in 0..trials {
        let mut pool = Vec::new();
        while pool.len() < count {
            let p = allocate_prime().to_string_radix(16);
            if seen.insert(p.clone()) {
                pool.push(p);
            }
        }
        fixtures.push(json!({"trial":trial,"prime_pool_hex":pool}));
        println!("Generated trial {}: {} public primes", trial, count);
    }
    fs::write(&args[1], serde_json::to_vec_pretty(&json!({"kind":"public capacity and state prime fixtures; not user identities", "fixtures":fixtures})).unwrap()).unwrap();
}
