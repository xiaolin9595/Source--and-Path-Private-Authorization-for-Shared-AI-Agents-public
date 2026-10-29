//! Candidate screen: no ZK proof or durable state submission.
use accumulator::group::{ElemToBytes, Group, Rsa2048, UnknownOrderGroup};
use cpsnarks_set::protocols::{
    hrada_membership::{validate_prime, MaintainedState, RsaElem, StateSet},
    hrada_public_power::PublicPower,
};
use rug::Integer;
use serde_json::{json, Value};
use std::{fs, path::PathBuf, process::Command, sync::Arc, time::Instant};
fn cpu() -> f64 {
    extern "C" {
        fn clock() -> std::os::raw::c_long;
    }
    let x = unsafe { clock() };
    assert!(x >= 0);
    x as f64 / 1_000_000.
}
fn rss() -> u64 {
    let x = Command::new("ps")
        .args(["-p", &std::process::id().to_string(), "-o", "rss="])
        .output()
        .unwrap();
    String::from_utf8(x.stdout)
        .unwrap()
        .trim()
        .parse::<u64>()
        .unwrap()
        * 1024
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|b| format!("{:02x}", b)).collect()
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let arg = |s: &str| args.windows(2).find(|w| w[0] == s).expect(s)[1].clone();
    let mode = arg("--mode");
    assert!(["maintained", "comb", "eager"].contains(&mode.as_str()));
    let width = arg("--width").parse::<usize>().unwrap();
    let out = PathBuf::from(arg("--output"));
    assert!(!out.exists());
    let fixture: Value = serde_json::from_slice(&fs::read(arg("--fixture")).unwrap()).unwrap();
    let n = fixture["n"].as_u64().unwrap() as usize;
    let primes: Vec<Integer> = fixture["primes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| Integer::from_str_radix(v.as_str().unwrap(), 16).unwrap())
        .collect();
    assert!(primes.len() >= n + 200);
    let rss_before = rss();
    let t = Instant::now();
    let c = cpu();
    let table = if mode == "comb" {
        Some(Arc::new(PublicPower::new(252 * n, width).unwrap()))
    } else {
        None
    };
    let table_cpu = cpu() - c;
    let table_ms = t.elapsed().as_secs_f64() * 1000.;
    let rss_after_table = rss();
    let sc = cpu();
    let table_stats = table.as_ref().map(|t| t.stats());
    let table_stats_cpu = cpu() - sc;
    let mut rows = vec![];
    let ks = if mode == "eager" {
        vec![1usize, 10]
    } else {
        vec![1usize, 10, 100]
    };
    for k in ks {
        let t = Instant::now();
        let c = cpu();
        let mut state = if let Some(t) = table.as_ref() {
            MaintainedState::new_with_power(&primes[..n], Arc::clone(t)).unwrap()
        } else {
            MaintainedState::new(&primes[..n]).unwrap()
        };
        let mut members = primes[..n].to_vec();
        let mut eager = if mode == "eager" {
            (0..n)
                .map(|i| state.witness(&members[i]).unwrap())
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let mut accumulator = state.state().accumulator.clone();
        let init_cpu = cpu() - c;
        let init_ms = t.elapsed().as_secs_f64() * 1000.;
        let rss_after_init = rss();
        let mut cycles = vec![];
        for cycle in 1..=2usize {
            let mut update_cpu = 0.;
            let mut update_ms = 0.;
            let mut operations = vec![];
            for j in 0..k {
                let index = (cycle - 1) * k + j;
                let slot = 1 + index % (n - 1);
                let replacement = primes[n + index].clone();
                let old = members[slot].clone();
                let t = Instant::now();
                let c = cpu();
                if mode == "eager" {
                    validate_prime(&replacement).unwrap();
                    assert!(!members.contains(&replacement));
                    let next_acc = Rsa2048::exp(&eager[slot], &replacement);
                    let mut next: Vec<RsaElem> = Vec::with_capacity(n);
                    for i in 0..n {
                        if i == slot {
                            next.push(eager[i].clone());
                            continue;
                        }
                        let (g, a, b) =
                            <(Integer, Integer, Integer)>::from(members[i].gcd_cofactors_ref(&old));
                        assert_eq!(g, 1);
                        let exponent = Integer::from(&replacement * &b);
                        let x = Rsa2048::exp(&eager[i], &exponent);
                        let y = Rsa2048::exp(&next_acc, &a);
                        next.push(Rsa2048::op(&x, &y));
                    }
                    eager = next;
                    accumulator = next_acc;
                } else {
                    assert!(!state.replace(slot, replacement.clone()).unwrap());
                    accumulator = state.state().accumulator.clone();
                }
                members[slot] = replacement.clone();
                update_cpu += cpu() - c;
                update_ms += t.elapsed().as_secs_f64() * 1000.;
                operations.push(json!({"index":index,"slot":slot,"old_hex":old.to_string_radix(16),"new_hex":replacement.to_string_radix(16),"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&accumulator))}));
            }
            let t = Instant::now();
            let c = cpu();
            let witness = if mode == "eager" {
                eager[0].clone()
            } else {
                state.witness(&members[0]).unwrap()
            };
            let witness_cpu = cpu() - c;
            let witness_ms = t.elapsed().as_secs_f64() * 1000.;
            // Reference rebuild and witness checking are deliberately outside measurements.
            let reference = StateSet::rebuild(&members).unwrap();
            assert_eq!(reference.accumulator, accumulator);
            assert_eq!(reference.witness(&members[0]).unwrap(), witness);
            if mode == "eager" {
                for i in 0..n {
                    assert_eq!(Rsa2048::exp(&eager[i], &members[i]), accumulator);
                }
            }
            cycles.push(json!({"cycle":cycle,"update_cpu_seconds":update_cpu,"update_ms":update_ms,"witness_cpu_seconds":witness_cpu,"witness_ms":witness_ms,"operations":operations,"target_witness_hex":hex(&Rsa2048::elem_to_bytes(&witness)),"reference_check":true,"rss_after_cycle_bytes":rss()}));
        }
        rows.push(json!({"k":k,"initialization_cpu_seconds":init_cpu,"initialization_ms":init_ms,"rss_after_init_bytes":rss_after_init,"cycles":cycles}));
    }
    let mut capacity = Value::Null;
    if let Some(old) = table.as_ref() {
        let too_large = Integer::from(1) << (old.max_bits() as u32);
        assert!(old.pow(&too_large).is_err());
        let t = Instant::now();
        let c = cpu();
        let larger = PublicPower::new(252 * (n + 1), width).unwrap();
        let build_cpu = cpu() - c;
        let build_ms = t.elapsed().as_secs_f64() * 1000.;
        let exponent = Integer::from(1) << ((252 * n) as u32);
        assert_eq!(
            larger.pow(&exponent).unwrap(),
            Rsa2048::exp(&Rsa2048::unknown_order_elem(), &exponent)
        );
        capacity = json!({"old_limit_rejected":true,"new_max_bits":252*(n+1),"full_rebuild_cpu_seconds":build_cpu,"full_rebuild_ms":build_ms,"rss_with_both_tables_bytes":rss(),"new_stats":larger.stats()});
    }
    let result = json!({"status":"complete","n":n,"mode":mode,"width":width,"scope":"maintenance only; no ZK or durable commit; table is server-side only, target witness keeps GMP; prime allocation excluded; reference checks outside timers","table_cpu_seconds":table_cpu,"table_ms":table_ms,"table_stats":table_stats,"table_stats_cpu_seconds":table_stats_cpu,"rss_before_bytes":rss_before,"rss_after_table_bytes":rss_after_table,"rows":rows,"capacity_probe":capacity});
    fs::write(out, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
}
