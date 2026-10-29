//! Local maintenance/witness + actual per-record sync screen. No ZK timed.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_joint::{Header, JointVerifier},
    hrada_membership::{MaintainedState, StateSet},
    hrada_poseidon_baseline::PoseidonMerkleState,
    hrada_public_power::PublicPower,
};
use rug::Integer;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Result as IoResult, Write},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
fn cpu() -> f64 {
    extern "C" {
        fn clock() -> std::os::raw::c_long;
    }
    unsafe { clock() as f64 / 1_000_000. }
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
fn hex(x: &[u8]) -> String {
    x.iter().map(|b| format!("{:02x}", b)).collect()
}
fn enc<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut b = vec![];
    x.serialize(&mut b).unwrap();
    b
}
struct CountWriter<'a> {
    f: &'a mut fs::File,
    calls: usize,
    bytes: usize,
}
impl Write for CountWriter<'_> {
    fn write(&mut self, b: &[u8]) -> IoResult<usize> {
        self.calls += 1;
        let n = self.f.write(b)?;
        self.bytes += n;
        Ok(n)
    }
    fn flush(&mut self) -> IoResult<()> {
        self.f.flush()
    }
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let arg = |s: &str| args.windows(2).find(|w| w[0] == s).expect(s)[1].clone();
    let mode = arg("--mode");
    let out = PathBuf::from(arg("--output-dir"));
    fs::create_dir(&out).unwrap();
    let fixture: Value = serde_json::from_slice(&fs::read(arg("--fixture")).unwrap()).unwrap();
    let pool: Vec<Integer> = fixture["primes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| Integer::from_str_radix(x.as_str().unwrap(), 16).unwrap())
        .collect();
    let n = 257;
    assert!(pool.len() >= 457);
    let is_cp = mode.starts_with("cp");
    let incremental = mode.contains("inc");
    let line = !mode.contains("fragment");
    let width = if mode.contains("16") {
        16
    } else if mode.contains("12") {
        12
    } else {
        8
    };
    assert!([
        "cp_fragment",
        "mt_fragment",
        "cp_line",
        "mt_line",
        "cp_inc8",
        "cp_inc12",
        "cp_inc16"
    ]
    .contains(&mode.as_str()));
    let t = Instant::now();
    let c = cpu();
    let power = if is_cp {
        Some(Arc::new(PublicPower::new(252 * n, width).unwrap()))
    } else {
        None
    };
    let table_ms = ms(t);
    let table_cpu = cpu() - c;
    let t = Instant::now();
    let c = cpu();
    let stats = power.as_ref().map(|p| p.stats());
    let stats_ms = ms(t);
    let stats_cpu = cpu() - c;
    let params = [3u8; 32];
    let mut rows = vec![];
    for k in [1usize, 10, 100] {
        let t = Instant::now();
        let c = cpu();
        let mut primes = pool[..n].to_vec();
        let mut cp = power
            .as_ref()
            .map(|p| MaintainedState::new_with_power(&primes, Arc::clone(p)).unwrap());
        let mut mt = if is_cp {
            None
        } else {
            Some(PoseidonMerkleState::with_depth(&primes, 9).unwrap())
        };
        let mut prepared = cp.as_ref().map(|s| s.prepare_witness(&primes[0]).unwrap());
        if let Some(s) = mt.as_ref() {
            std::hint::black_box(s.circuit(&primes[0]).unwrap());
        }
        let mut verifier = cp.as_ref().map(|s| {
            JointVerifier::new(
                Header::new(s.state().accumulator.clone(), 0, &params),
                params,
            )
        });
        let init_ms = ms(t);
        let init_cpu = cpu() - c;
        let mut cycles = vec![];
        for cycle in 1..=2 {
            let path = out.join(format!("k{}-c{}.jsonl", k, cycle));
            let start = Instant::now();
            let start_cpu = cpu();
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)
                .unwrap();
            let old_state = if incremental {
                Some(cp.as_ref().unwrap().state().clone())
            } else {
                None
            };
            let mut changes = vec![];
            let mut expected = Vec::<Vec<u8>>::new();
            let mut operations = vec![];
            for j in 0..k {
                let index = (cycle - 1) * k + j;
                let slot = 1 + index % (n - 1);
                let old = primes[slot].clone();
                let new = pool[n + index].clone();
                let t = Instant::now();
                let c = cpu();
                if is_cp {
                    assert!(!cp.as_mut().unwrap().replace(slot, new.clone()).unwrap());
                } else {
                    mt.as_mut().unwrap().replace(slot, new.clone()).unwrap();
                }
                let replace_ms = ms(t);
                let replace_cpu = cpu() - c;
                primes[slot] = new.clone();
                if incremental {
                    changes.push((slot, old.clone(), new.clone()));
                }
                let epoch = index as u64 + 1;
                let t = Instant::now();
                let c = cpu();
                let (hd, state) = if is_cp {
                    let h = Header::new(
                        cp.as_ref().unwrap().state().accumulator.clone(),
                        epoch,
                        &params,
                    );
                    let d = hex(&h.digest);
                    let v = json!({"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&h.accumulator))});
                    verifier.as_mut().unwrap().replace_header(h).unwrap();
                    (d, v)
                } else {
                    let m = mt.as_ref().unwrap();
                    let mut b = b"HRADA-POSEIDON-MERKLE-HEADER-V1".to_vec();
                    b.extend(params);
                    b.extend(epoch.to_le_bytes());
                    b.extend(m.root());
                    (
                        hex(&Blake2s::digest(&b)),
                        json!({"root_hex":hex(&m.root()),"root_fields":m.root_fields().iter().map(|x|hex(&enc(x))).collect::<Vec<_>>()}),
                    )
                };
                let row = json!({"strategy":if is_cp{"cp"}else{"reserved"},"trajectory":format!("b{}",k),"k":k,"cycle":cycle,"update_in_cycle":j,"slot":slot,"pattern":"rotating","epoch":epoch,"prime_index":n+index,"new_prime_hex":new.to_string_radix(16),"previous_prime_hex":old.to_string_radix(16),"target_prime_hex":primes[0].to_string_radix(16),"header_digest":hd,"parameters_digest":hex(&params),"public_state":state,"operation":"commit_actual_individual_state_update"});
                let header_ms = ms(t);
                let header_cpu = cpu() - c;
                let t = Instant::now();
                let c = cpu();
                let bytes = if line {
                    Some(format!("{}\n", row).into_bytes())
                } else {
                    None
                };
                let encode_ms = ms(t);
                let encode_cpu = cpu() - c;
                let t = Instant::now();
                let c = cpu();
                let mut writer = CountWriter {
                    f: &mut file,
                    calls: 0,
                    bytes: 0,
                };
                if let Some(b) = bytes.as_ref() {
                    writer.write_all(b).unwrap()
                } else {
                    writeln!(writer, "{}", row).unwrap()
                };
                let calls = writer.calls;
                let count = writer.bytes;
                let write_ms = ms(t);
                let write_cpu = cpu() - c;
                let t = Instant::now();
                let c = cpu();
                file.sync_data().unwrap();
                let sync_ms = ms(t);
                let sync_cpu = cpu() - c;
                operations.push(json!({"index":index,"slot":slot,"epoch":epoch,"root":row["public_state"],"replace_ms":replace_ms,"replace_cpu":replace_cpu,"header_ms":header_ms,"header_cpu":header_cpu,"encode_ms":encode_ms,"encode_cpu":encode_cpu,"write_ms":write_ms,"write_cpu":write_cpu,"sync_ms":sync_ms,"sync_cpu":sync_cpu,"write_calls":calls,"bytes":count,"sync_calls":1}));
                // Diagnostic byte expectation is excluded from component totals (outer elapsed includes it).
                expected.push(format!("{}\n", row).into_bytes());
            }
            let t = Instant::now();
            let c = cpu();
            if is_cp {
                let s = cp.as_ref().unwrap().state();
                prepared = Some(if incremental {
                    s.refresh_prepared_from(
                        old_state.as_ref().unwrap(),
                        prepared.as_ref().unwrap(),
                        &changes,
                    )
                    .unwrap()
                } else {
                    cp.as_ref().unwrap().prepare_witness(&primes[0]).unwrap()
                });
            } else {
                std::hint::black_box(mt.as_ref().unwrap().circuit(&primes[0]).unwrap());
            }
            let witness_ms = ms(t);
            let witness_cpu = cpu() - c;
            let outer_ms = ms(start);
            let outer_cpu = cpu() - start_cpu;
            let actual = fs::read(&path).unwrap();
            assert_eq!(actual, expected.concat());
            if is_cp {
                assert_eq!(
                    cp.as_ref().unwrap().state().accumulator,
                    StateSet::rebuild(&primes).unwrap().accumulator
                )
            } else {
                assert_eq!(
                    mt.as_ref().unwrap().root(),
                    PoseidonMerkleState::with_depth(&primes, 9).unwrap().root()
                )
            }
            cycles.push(json!({"cycle":cycle,"operations":operations,"witness_ms":witness_ms,"witness_cpu":witness_cpu,"outer_ms":outer_ms,"outer_cpu":outer_cpu,"journal_bytes":actual.len(),"journal_blake2s":hex(&Blake2s::digest(&actual)),"journal_byte_equivalence":true,"reference_root_equal":true}));
        }
        rows.push(json!({"k":k,"init_ms":init_ms,"init_cpu":init_cpu,"cycles":cycles}));
    }
    fs::write(out.join("results.json"),serde_json::to_vec_pretty(&json!({"status":"complete","mode":mode,"n":n,"width":if is_cp{width}else{0},"table_ms":table_ms,"table_cpu":table_cpu,"stats_ms":stats_ms,"stats_cpu":stats_cpu,"table_stats":stats,"rows":rows,"scope":"local private state and journals, no new external messages; incremental changes retained in same worker; no free remote update delivery assumed; every row sync_data; outer timings include diagnostics, component sums exclude reference formatting/checks"})).unwrap()).unwrap();
}
