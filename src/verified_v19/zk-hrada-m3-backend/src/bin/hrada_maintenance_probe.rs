//! Maintenance-only ablation: no zero-knowledge proof or durable commit is timed here.
use accumulator::group::{ElemToBytes, Rsa2048};
use cpsnarks_set::protocols::{
    hrada_membership::{allocate_prime, MaintainedState, StateSet},
    hrada_poseidon_baseline::PoseidonMerkleState,
};
use rug::Integer;
use serde_json::{json, Value};
use std::{fs, path::PathBuf, time::Instant};
fn cpu() -> f64 {
    extern "C" {
        fn clock() -> std::os::raw::c_long;
    }
    let t = unsafe { clock() };
    assert!(t >= 0);
    t as f64 / 1_000_000.0
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect()
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let out = PathBuf::from(
        args.windows(2)
            .find(|w| w[0] == "--output")
            .expect("--output required")[1]
            .clone(),
    );
    assert!(!out.exists(), "will not overwrite evidence");
    let mut records = Vec::<Value>::new();
    let mut fixtures = Vec::<Value>::new();
    for rep in 0..3usize {
        let mut pool = Vec::new();
        while pool.len() < 457 {
            let p = allocate_prime();
            if !pool.contains(&p) {
                pool.push(p)
            }
        }
        fixtures.push(json!({"rep":rep,"prime_pool_hex":pool.iter().map(|x|x.to_string_radix(16)).collect::<Vec<_>>()}));
        for ni in 0..3usize {
            let n = [17usize, 65, 257][(ni + rep) % 3];
            let depth = (usize::BITS - (n - 1).leading_zeros()) as usize;
            for pattern in ["hot", "rotating"].iter() {
                for k in [1usize, 10, 100].iter() {
                    let mut cp_roots: Vec<Vec<Vec<u8>>> = vec![];
                    let mut cp_witnesses: Vec<Vec<Vec<u8>>> = vec![];
                    for si in 0..3usize {
                        let strategy = ["rebuild", "maintained", "merkle"][(si + rep) % 3];
                        let mut primes = pool[..n].to_vec();
                        let t = Instant::now();
                        let c = cpu();
                        let mut old = None;
                        let mut optimized = None;
                        let mut tree = None;
                        match strategy {
                            "rebuild" => old = Some(StateSet::rebuild(&primes).unwrap()),
                            "maintained" => {
                                optimized = Some(MaintainedState::new(&primes).unwrap())
                            }
                            _ => {
                                tree =
                                    Some(PoseidonMerkleState::with_depth(&primes, depth).unwrap())
                            }
                        }
                        let init_cpu = cpu() - c;
                        let init_ms = t.elapsed().as_secs_f64() * 1000.;
                        let mut roots = vec![];
                        let mut witnesses = vec![];
                        let mut rows = vec![];
                        for cycle in 1..=2usize {
                            let mut update_cpu = 0.;
                            let mut update_ms = 0.;
                            let mut hits = 0;
                            let mut misses = 0;
                            for j in 0..*k {
                                let i = (cycle - 1) * k + j;
                                let slot = if *pattern == "hot" {
                                    1
                                } else {
                                    1 + i % (n - 1)
                                };
                                let replacement = pool[n + i].clone();
                                let t = Instant::now();
                                let c = cpu();
                                primes[slot] = replacement.clone();
                                match strategy {
                                    "rebuild" => old = Some(StateSet::rebuild(&primes).unwrap()),
                                    "maintained" => {
                                        if optimized
                                            .as_mut()
                                            .unwrap()
                                            .replace(slot, replacement)
                                            .unwrap()
                                        {
                                            hits += 1
                                        } else {
                                            misses += 1
                                        }
                                    }
                                    _ => tree.as_mut().unwrap().replace(slot, replacement).unwrap(),
                                }
                                update_cpu += cpu() - c;
                                update_ms += t.elapsed().as_secs_f64() * 1000.;
                                if strategy != "merkle" {
                                    let a = if strategy == "rebuild" {
                                        &old.as_ref().unwrap().accumulator
                                    } else {
                                        &optimized.as_ref().unwrap().state().accumulator
                                    };
                                    roots.push(Rsa2048::elem_to_bytes(a));
                                }
                            }
                            let t = Instant::now();
                            let c = cpu();
                            let w = match strategy {
                                "rebuild" => {
                                    Some(old.as_ref().unwrap().witness(&primes[0]).unwrap())
                                }
                                "maintained" => {
                                    Some(optimized.as_ref().unwrap().witness(&primes[0]).unwrap())
                                }
                                _ => {
                                    let path = tree.as_ref().unwrap().circuit(&primes[0]).unwrap();
                                    std::hint::black_box(path);
                                    None
                                }
                            };
                            let witness_cpu = cpu() - c;
                            let witness_ms = t.elapsed().as_secs_f64() * 1000.;
                            if let Some(w) = w {
                                witnesses.push(Rsa2048::elem_to_bytes(&w));
                            }
                            let public_state = if strategy == "merkle" {
                                hex(&tree.as_ref().unwrap().root())
                            } else {
                                hex(roots.last().unwrap())
                            };
                            rows.push(json!({"cycle":cycle,"updates":k,"update_cpu_seconds":update_cpu,"update_ms":update_ms,"witness_cpu_seconds":witness_cpu,"witness_ms":witness_ms,"cache_hits":hits,"cache_misses":misses,"public_state_hex":public_state}));
                            if strategy == "maintained" {
                                let expected = if *pattern == "hot" {
                                    k - if cycle == 1 { 1 } else { 0 }
                                } else {
                                    0
                                };
                                assert_eq!(hits, expected);
                                assert_eq!(misses, k - expected);
                            }
                        }
                        if strategy != "merkle" {
                            cp_roots.push(roots);
                            cp_witnesses.push(witnesses);
                        }
                        records.push(json!({"rep":rep,"n":n,"depth":depth,"pattern":pattern,"k":k,"strategy":strategy,"initialization_cpu_seconds":init_cpu,"initialization_ms":init_ms,"cycles":rows}));
                    }
                    assert_eq!(cp_roots.len(), 2);
                    assert_eq!(cp_roots[0], cp_roots[1]);
                    assert_eq!(cp_witnesses[0], cp_witnesses[1]);
                    eprintln!("VERIFIED rep={} n={} pattern={} k={}", rep, n, pattern, k);
                }
            }
        }
    }
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(out,serde_json::to_vec_pretty(&json!({"status":"complete","scope":"maintenance-only; no ZK proof or durable commit; prime allocation and equality checks outside timers; initialization separate; same preallocated trace per strategy","records":records,"fixtures":fixtures,"root_and_witness_equivalence_groups":54})).unwrap()).unwrap();
}
