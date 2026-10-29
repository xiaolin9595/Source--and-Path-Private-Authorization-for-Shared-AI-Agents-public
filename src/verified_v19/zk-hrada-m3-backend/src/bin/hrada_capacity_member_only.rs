#![recursion_limit = "256"]
//! Member-only capacity lifecycle worker.
//!
//! This binary is deliberately independent of the authorization/resource
//! lifecycle. It performs only CP-RSA membership and Poseidon-Merkle
//! membership proofs over the configured prime-state fixture.

use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::protocols::{
    hrada_link,
    hrada_membership::{CpProof, MaintainedState, StateMembership},
    hrada_poseidon_baseline::{self, PoseidonMerkleState},
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    collections::HashMap, fs, io::Write, path::PathBuf, process::Command, sync::Arc, time::Instant,
};
fn cp_proof_bytes(p: &CpProof) -> usize {
    let mut bytes = Vec::new();
    let mut put = |value: Vec<u8>| {
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend(value);
    };
    for value in [
        &p.c_e,
        &p.proof_root.message1.c_w,
        &p.proof_root.message1.c_r,
        &p.proof_root.message2.alpha1,
        &p.proof_root.message2.alpha2,
        &p.proof_root.message2.alpha3,
        &p.proof_root.message2.alpha4,
        &p.proof_modeq.message1.alpha1,
    ] {
        put(Rsa2048::elem_to_bytes(value));
    }
    let root = &p.proof_root.message3;
    let modeq = &p.proof_modeq.message2;
    for value in [
        &root.s_e,
        &root.s_r,
        &root.s_r_2,
        &root.s_r_3,
        &root.s_beta,
        &root.s_delta,
        &modeq.s_e,
        &modeq.s_r,
    ] {
        let mut encoded = vec![if *value < Integer::from(0) { 1 } else { 0 }];
        encoded.extend(value.clone().abs().to_digits::<u8>(Order::MsfBe));
        put(encoded);
    }
    put(enc(&p.proof_modeq.message1.alpha2));
    put(enc(&modeq.s_r_q));
    put(enc(&p.proof_hash_to_prime));
    bytes.len()
}

fn enc<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize(&mut bytes).unwrap();
    bytes
}

fn elapsed_ms(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn utc_now() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .expect("date -u is required for run provenance");
    String::from_utf8(output.stdout)
        .expect("date output must be UTF-8")
        .trim()
        .to_owned()
}

#[derive(Clone)]
struct Args {
    trial: usize,
    trajectory: String,
    ratio: usize,
    strategy: String,
    out: PathBuf,
    fixture: PathBuf,
}

fn args() -> Args {
    let values = std::env::args().collect::<Vec<_>>();
    let required = |name: &str| {
        values
            .windows(2)
            .find(|pair| pair[0] == name)
            .unwrap_or_else(|| panic!("missing {}", name))[1]
            .clone()
    };
    let strategy = values
        .windows(2)
        .find(|pair| pair[0] == "--strategy")
        .map(|pair| pair[1].clone())
        .unwrap_or_else(|| "both".to_owned());
    assert!(matches!(strategy.as_str(), "cp" | "merkle" | "both"));
    Args {
        trial: required("--trial").parse().unwrap(),
        trajectory: required("--trajectory"),
        ratio: required("--ratio").parse().unwrap(),
        strategy,
        out: PathBuf::from(required("--out")),
        fixture: PathBuf::from(required("--fixture")),
    }
}

fn checkpoints(trajectory: &str) -> Vec<usize> {
    match trajectory {
        "short" => vec![16, 20, 24, 32],
        "medium" => vec![16, 32, 48, 64],
        "long" => vec![16, 64, 128, 256],
        _ => panic!("unsupported trajectory {}", trajectory),
    }
}

fn tree_depth(n: usize) -> usize {
    (n - 1).next_power_of_two().trailing_zeros() as usize
}

fn fixture_primes(fixture: &Value, trial: usize, max_n: usize) -> Vec<Integer> {
    fixture["fixtures"][trial]["prime_pool_hex"]
        .as_array()
        .unwrap()
        .iter()
        .take(max_n + 16)
        .map(|value| Integer::from_str_radix(value.as_str().unwrap(), 16).unwrap())
        .collect()
}

fn descriptor(depth: usize) -> Vec<u8> {
    let mut descriptor = hrada_poseidon_baseline::parameter_descriptor();
    descriptor.extend((depth as u64).to_le_bytes());
    descriptor
}

fn selected(args: &Args, strategy: &str) -> bool {
    args.strategy == "both" || args.strategy == strategy
}

fn boundary_checks(
    cp: &StateMembership,
    power: &Arc<cpsnarks_set::protocols::hrada_public_power::PublicPower>,
    pool: &[Integer],
    cp_capacity: usize,
    merkle_capacity: usize,
    merkle_depth: usize,
) -> Value {
    let cp_exact = MaintainedState::new_with_power(&pool[..cp_capacity], Arc::clone(power)).is_ok();
    let cp_over =
        MaintainedState::new_with_power(&pool[..cp_capacity + 1], Arc::clone(power)).is_err();
    let merkle_exact =
        PoseidonMerkleState::with_depth(&pool[..merkle_capacity], merkle_depth).is_ok();
    let merkle_over =
        PoseidonMerkleState::with_depth(&pool[..merkle_capacity + 1], merkle_depth).is_err();
    let mut duplicate_tree =
        PoseidonMerkleState::with_depth(&pool[..merkle_capacity], merkle_depth).unwrap();
    let merkle_duplicate = duplicate_tree
        .extend(std::slice::from_ref(&pool[0]))
        .is_err();
    let cp_commitment = cp.commit(&pool[0], &Integer::from(7)).is_ok();
    json!({
        "cp_exact_capacity_accepted": cp_exact,
        "cp_over_capacity_rejected": cp_over,
        "merkle_exact_capacity_accepted": merkle_exact,
        "merkle_over_capacity_rejected": merkle_over,
        "merkle_duplicate_rejected": merkle_duplicate,
        "cp_member_commitment_accepted": cp_commitment,
        "all_required": cp_exact && cp_over && merkle_exact && merkle_over && merkle_duplicate && cp_commitment,
    })
}

fn main() {
    let args = args();
    fs::create_dir_all(&args.out).unwrap();
    let ns = checkpoints(&args.trajectory);
    let max_n = *ns.iter().max().unwrap();
    let reserved_capacity = 16usize
        .checked_mul(args.ratio)
        .expect("reserved capacity overflow");
    let merkle_capacity = max_n.max(reserved_capacity);
    let merkle_depth = tree_depth(merkle_capacity);
    let fixture: Value = serde_json::from_slice(&fs::read(&args.fixture).unwrap()).unwrap();
    let pool = fixture_primes(&fixture, args.trial, max_n.max(reserved_capacity));
    assert!(pool.len() > max_n.max(reserved_capacity));
    assert!(pool.windows(2).all(|pair| pair[0] != pair[1]));

    let run_id = format!(
        "member-only-t{}-{}-r{}-{}",
        args.trial, args.trajectory, args.ratio, args.strategy
    );
    let mut metadata = json!({
        "run_id": run_id,
        "mode": "member-only",
        "trial": args.trial,
        "trajectory": args.trajectory,
        "requested_ratio": args.ratio,
        "reserved_capacity": reserved_capacity,
        "n0": 16,
        "started_utc": utc_now(),
        "pid": std::process::id(),
        "argv": std::env::args().collect::<Vec<_>>(),
        "rayon_num_threads": std::env::var("RAYON_NUM_THREADS").unwrap_or_default(),
        "scope": "member-only; no Auth setup/download/load/prove; no resource access",
    });
    fs::write(
        args.out.join("run_metadata.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();

    let cp = StateMembership::setup_os().unwrap();
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let power = Arc::new(
        cpsnarks_set::protocols::hrada_public_power::PublicPower::new(max_n * 252, 12).unwrap(),
    );
    let boundaries = boundary_checks(&cp, &power, &pool, max_n, merkle_capacity, merkle_depth);
    assert!(boundaries["all_required"].as_bool().unwrap());
    let mut rows = Vec::new();

    for strategy in ["cp", "merkle"] {
        if !selected(&args, strategy) {
            continue;
        }
        let strategy_start = Instant::now();
        let mut current = pool[..16].to_vec();
        let mut cp_state =
            Some(MaintainedState::new_with_power(&current, Arc::clone(&power)).unwrap());
        let mut tree: Option<PoseidonMerkleState> = None;
        let mut mt_parameters = HashMap::new();
        let mut events = Vec::new();

        for (step, &n) in ns.iter().enumerate() {
            let target_depth = tree_depth(n.max(reserved_capacity));
            let previous = current.clone();
            let update_start = Instant::now();
            if step > 0 {
                current = pool[..n].to_vec();
                if strategy == "cp" {
                    cp_state = Some(
                        MaintainedState::new_with_power(&current, Arc::clone(&power)).unwrap(),
                    );
                } else {
                    let mut state = tree.take().unwrap();
                    if state.depth() < target_depth {
                        state.grow_to_depth(target_depth).unwrap();
                    }
                    state.extend(&current[previous.len()..]).unwrap();
                    tree = Some(state);
                }
            } else if strategy == "merkle" {
                tree = Some(PoseidonMerkleState::with_depth(&current, target_depth).unwrap());
            }
            let update_ms = elapsed_ms(update_start);
            let depth_now = if strategy == "cp" {
                None
            } else {
                Some(tree.as_ref().unwrap().depth())
            };

            if let Some(depth) = depth_now {
                if !mt_parameters.contains_key(&depth) {
                    let template = tree.as_ref().unwrap().circuit(&current[0]).unwrap();
                    let parameters = hrada_link::setup(&mut OsRng, ck, template, 2).unwrap();
                    mt_parameters.insert(depth, parameters);
                }
            }

            let witness_start = Instant::now();
            let mut proofs = Vec::new();
            for proof_index in 0..16 {
                let randomness =
                    Integer::from_digits(&enc(&Fr::from(OsRng.next_u64())), Order::Lsf);
                let context = format!(
                    "capacity-member-only/{}/{}/{}/{}/{}",
                    args.trial, args.trajectory, args.ratio, strategy, step
                )
                .into_bytes();
                let (prove_ms, verify_ms, verified, proof_bytes) = if strategy == "cp" {
                    let set = cp_state.as_ref().unwrap().state();
                    let witness = set.prepare_witness(&current[0]).unwrap();
                    let start = Instant::now();
                    let (statement, proof) = cp
                        .prove_prepared(set, &current[0], &witness, &randomness, &context)
                        .unwrap();
                    let prove_ms = elapsed_ms(start);
                    let start = Instant::now();
                    cp.verify(&statement, &proof, &context).unwrap();
                    (prove_ms, elapsed_ms(start), true, cp_proof_bytes(&proof))
                } else {
                    let state = tree.as_ref().unwrap();
                    let depth = depth_now.unwrap();
                    let parameters = mt_parameters.get(&depth).unwrap();
                    let circuit = state.circuit(&current[0]).unwrap();
                    let commitment = cp.commit(&current[0], &randomness).unwrap();
                    let start = Instant::now();
                    let proof =
                        hrada_link::prove(&mut OsRng, parameters, circuit, &randomness).unwrap();
                    let prove_ms = elapsed_ms(start);
                    let start = Instant::now();
                    let verified = hrada_link::verify(
                        parameters,
                        ck,
                        &descriptor(depth),
                        &hrada_link::parameter_digest(parameters, &descriptor(depth)).unwrap(),
                        &proof,
                        &state.root_fields(),
                        &commitment,
                    )
                    .unwrap();
                    (prove_ms, elapsed_ms(start), verified, enc(&proof).len())
                };
                assert!(verified);
                proofs.push(json!({
                    "proof_index": proof_index,
                    "prove_ms": prove_ms,
                    "verify_ms": verify_ms,
                    "verified": verified,
                    "bytes": proof_bytes,
                }));
            }

            let negative_start = Instant::now();
            let (wrong_context_rejected, nonmember_rejected, wrong_root_rejected) =
                if strategy == "cp" {
                    let set = cp_state.as_ref().unwrap().state();
                    let witness = set.prepare_witness(&current[0]).unwrap();
                    let randomness = Integer::from(7);
                    let (statement, proof) = cp
                        .prove_prepared(set, &current[0], &witness, &randomness, b"negative")
                        .unwrap();
                    let wrong_context = cp.verify(&statement, &proof, b"wrong-context");
                    let nonmember = set.prepare_witness(&pool[max_n]).is_err();
                    (wrong_context.is_err(), nonmember, true)
                } else {
                    let state = tree.as_ref().unwrap();
                    let depth = depth_now.unwrap();
                    let parameters = mt_parameters.get(&depth).unwrap();
                    let randomness = Integer::from(7);
                    let commitment = cp.commit(&current[0], &randomness).unwrap();
                    let proof = hrada_link::prove(
                        &mut OsRng,
                        parameters,
                        state.circuit(&current[0]).unwrap(),
                        &randomness,
                    )
                    .unwrap();
                    let mut wrong_root = state.root_fields();
                    wrong_root[0] += Fr::from(1u64);
                    let wrong_root_result = hrada_link::verify(
                        parameters,
                        ck,
                        &descriptor(depth),
                        &hrada_link::parameter_digest(parameters, &descriptor(depth)).unwrap(),
                        &proof,
                        &wrong_root,
                        &commitment,
                    );
                    let nonmember = state.circuit(&pool[max_n]).is_err();
                    (
                        true,
                        nonmember,
                        wrong_root_result.map(|verified| !verified).unwrap_or(true),
                    )
                };
            let negative_ms = elapsed_ms(negative_start);
            let all_negative = wrong_context_rejected && nonmember_rejected && wrong_root_rejected;
            assert!(all_negative);
            let actual_capacity = if strategy == "cp" {
                n
            } else {
                1usize << depth_now.unwrap()
            };
            events.push(json!({
                "event": "checkpoint",
                "strategy": strategy,
                "trial": args.trial,
                "trajectory": args.trajectory,
                "requested_ratio": args.ratio,
                "step": step,
                "n": n,
                "actual_capacity": actual_capacity,
                "depth": depth_now,
                "maintenance_mode": if strategy == "cp" { "rebuild" } else { "append_and_grow" },
                "update_ms": update_ms,
                "witness_ms": elapsed_ms(witness_start),
                "proofs": proofs,
                "proof_count": 16,
                "negative_checks": {
                    "wrong_context_rejected": wrong_context_rejected,
                    "nonmember_rejected": nonmember_rejected,
                    "wrong_root_rejected": wrong_root_rejected,
                    "all_required": all_negative,
                    "elapsed_ms": negative_ms,
                },
                "boundary_checks": boundaries,
            }));
        }
        rows.push(json!({
            "strategy": strategy,
            "trajectory": args.trajectory,
            "requested_ratio": args.ratio,
            "events": events,
            "wall_ms": elapsed_ms(strategy_start),
        }));
    }

    metadata["finished_utc"] = json!(utc_now());
    metadata["status"] = json!("complete");
    metadata["strategies"] = json!(rows
        .iter()
        .map(|row| row["strategy"].clone())
        .collect::<Vec<_>>());
    fs::write(
        args.out.join("results.json"),
        serde_json::to_vec_pretty(&json!({
            "metadata": metadata,
            "boundary_checks": boundaries,
            "rows": rows,
        }))
        .unwrap(),
    )
    .unwrap();
    std::io::stdout()
        .write_all(format!("member-only complete {}\n", args.out.display()).as_bytes())
        .unwrap();
}
