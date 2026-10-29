#![recursion_limit = "256"]
//! Round-3 member-only capacity worker.
//!
//! One process executes one strategy only.  The positive-proof cost window
//! contains setup, precomputation, state initialization, migration, witness
//! construction, proving and verification.  Negative checks and diagnostic
//! boundary probes are explicitly outside that window.

use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Fr, G1Projective};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::commitments::{pedersen::PedersenCommitment, Commitment};
use cpsnarks_set::protocols::{
    hrada_link,
    hrada_membership::{CpProof, MaintainedState, StateMembership},
    hrada_poseidon_baseline::{self, PoseidonMerkleState},
};
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    collections::HashMap, fs, io::Write, path::PathBuf, process::Command, sync::Arc, time::Instant,
};

fn cp_proof_bytes(proof: &CpProof) -> usize {
    let mut bytes = Vec::new();
    let mut put = |value: Vec<u8>| {
        bytes.extend_from_slice(&(value.len() as u32).to_le_bytes());
        bytes.extend(value);
    };
    for value in [
        &proof.c_e,
        &proof.proof_root.message1.c_w,
        &proof.proof_root.message1.c_r,
        &proof.proof_root.message2.alpha1,
        &proof.proof_root.message2.alpha2,
        &proof.proof_root.message2.alpha3,
        &proof.proof_root.message2.alpha4,
        &proof.proof_modeq.message1.alpha1,
    ] {
        put(Rsa2048::elem_to_bytes(value));
    }
    let root = &proof.proof_root.message3;
    let modeq = &proof.proof_modeq.message2;
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
    put(enc(&proof.proof_modeq.message1.alpha2));
    put(enc(&modeq.s_r_q));
    put(enc(&proof.proof_hash_to_prime));
    bytes.len()
}

fn enc<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    value.serialize(&mut bytes).unwrap();
    bytes
}

#[derive(Clone, Copy)]
struct Stamp {
    wall: Instant,
    cpu: f64,
}
impl Stamp {
    fn now() -> Self {
        Self {
            wall: Instant::now(),
            cpu: cpu_now(),
        }
    }
}
fn cpu_now() -> f64 {
    #[repr(C)]
    struct Timespec {
        tv_sec: i64,
        tv_nsec: i64,
    }
    extern "C" {
        fn clock_gettime(id: i32, tp: *mut Timespec) -> i32;
    }
    let mut t = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // macOS CLOCK_PROCESS_CPUTIME_ID; all process threads, seconds.
    assert_eq!(unsafe { clock_gettime(12, &mut t) }, 0);
    t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
}
fn elapsed_cpu(start: Stamp) -> f64 {
    cpu_now() - start.cpu
}

fn elapsed_ms(start: Stamp) -> f64 {
    start.wall.elapsed().as_secs_f64() * 1000.0
}

fn utc_now() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .expect("date -u is required for provenance");
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
        .unwrap_or_else(|| "cp".to_owned());
    assert!(matches!(strategy.as_str(), "cp" | "merkle"));
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

fn fixture_primes(fixture: &Value, trial: usize, needed: usize) -> Vec<Integer> {
    fixture["fixtures"][trial]["prime_pool_hex"]
        .as_array()
        .unwrap()
        .iter()
        .take(needed + 1)
        .map(|value| Integer::from_str_radix(value.as_str().unwrap(), 16).unwrap())
        .collect()
}

fn descriptor(depth: usize) -> Vec<u8> {
    let mut descriptor = hrada_poseidon_baseline::parameter_descriptor();
    descriptor.extend((depth as u64).to_le_bytes());
    descriptor
}

fn boundary_checks(pool: &[Integer], cp_capacity: usize, merkle_capacity: usize) -> Value {
    let cp_power = Arc::new(
        cpsnarks_set::protocols::hrada_public_power::PublicPower::new(cp_capacity * 252, 12)
            .unwrap(),
    );
    let cp_exact =
        MaintainedState::new_with_power(&pool[..cp_capacity], Arc::clone(&cp_power)).is_ok();
    let cp_over = MaintainedState::new_with_power(&pool[..cp_capacity + 1], cp_power).is_err();
    let depth = tree_depth(merkle_capacity);
    let merkle_exact = PoseidonMerkleState::with_depth(&pool[..merkle_capacity], depth).is_ok();
    let merkle_over = PoseidonMerkleState::with_depth(&pool[..merkle_capacity + 1], depth).is_err();
    let mut duplicate_tree =
        PoseidonMerkleState::with_depth(&pool[..merkle_capacity], depth).unwrap();
    let merkle_duplicate = duplicate_tree
        .extend(std::slice::from_ref(&pool[0]))
        .is_err();
    json!({
        "cp_exact_capacity_accepted": cp_exact,
        "cp_over_capacity_rejected": cp_over,
        "merkle_exact_capacity_accepted": merkle_exact,
        "merkle_over_capacity_rejected": merkle_over,
        "merkle_duplicate_rejected": merkle_duplicate,
        "all_required": cp_exact && cp_over && merkle_exact && merkle_over && merkle_duplicate,
        "scope": "diagnostic state-admission checks outside positive cost window"
    })
}

fn main() {
    let args = args();
    fs::create_dir_all(&args.out).unwrap();
    let ns = checkpoints(&args.trajectory);
    let trajectory_max = *ns.iter().max().unwrap();
    let reserved_capacity = 16usize.checked_mul(args.ratio).unwrap();
    let merkle_capacity = trajectory_max.max(reserved_capacity);
    let fixture: Value = serde_json::from_slice(&fs::read(&args.fixture).unwrap()).unwrap();
    let pool = fixture_primes(&fixture, args.trial, merkle_capacity);
    assert!(pool.len() > merkle_capacity);
    assert!(pool.windows(2).all(|pair| pair[0] != pair[1]));

    let run_id = format!(
        "member-only-round3-t{}-{}-r{}-{}",
        args.trial, args.trajectory, args.ratio, args.strategy
    );
    let mut metadata = json!({
        "run_id": run_id,
        "experiment": "capacity_tradeoff",
        "mode": "member-only-round3",
        "trial": args.trial,
        "trajectory": args.trajectory,
        "requested_ratio": args.ratio,
        "strategy": args.strategy,
        "n0": 16,
        "reserved_capacity": reserved_capacity,
        "capacity_policy": "start_at_n0; expand_on_overflow; endpoint not preallocated",
        "started_utc": utc_now(),
        "pid": std::process::id(),
        "argv": std::env::args().collect::<Vec<_>>(),
        "rayon_num_threads": std::env::var("RAYON_NUM_THREADS").unwrap_or_default(),
        "scope": "member-only compute lifecycle; no Auth setup/download/load/prove; no resource access",
    });
    fs::write(
        args.out.join("run_metadata.json"),
        serde_json::to_vec_pretty(&metadata).unwrap(),
    )
    .unwrap();

    // Diagnostic capacity admission is outside the measured positive-proof window.

    let positive_start = Stamp::now();
    let setup_start = Stamp::now();
    let cp = if args.strategy == "cp" {
        Some(StateMembership::setup_os().unwrap())
    } else {
        None
    };
    let ck_owned: PedersenCommitment<G1Projective> = match &cp {
        Some(cp) => cp
            .protocol
            .crs
            .crs_modeq
            .pedersen_commitment_parameters
            .clone(),
        None => PedersenCommitment::setup(&mut OsRng),
    };
    let ck = &ck_owned;
    let setup_ms = elapsed_ms(setup_start);
    let setup_cpu_s = elapsed_cpu(setup_start);
    let mut precompute_ms = 0.0;
    let mut precompute_cpu_s = 0.0;
    let mut state_init_cpu_s = 0.0;
    let mut migration_cpu_s = 0.0;
    let mut witness_cpu_s = 0.0;
    let mut prove_cpu_s = 0.0;
    let mut verify_cpu_s = 0.0;
    let mut state_init_ms = 0.0;
    let mut migration_ms = 0.0;
    let mut witness_ms_total = 0.0;
    let mut prove_ms_total = 0.0;
    let mut verify_ms_total = 0.0;
    let mut events = Vec::new();
    let mut rows = Vec::new();

    let mut cp_power: Option<Arc<cpsnarks_set::protocols::hrada_public_power::PublicPower>> = None;
    let mut cp_state: Option<MaintainedState> = None;
    let mut tree: Option<PoseidonMerkleState> = None;
    let mut mt_parameters = HashMap::new();
    let mut current_capacity = 16usize;
    let mut current_n = 16usize;

    for (step, &n) in ns.iter().enumerate() {
        let state_start = Stamp::now();
        let mut step_migration_ms = 0.0;
        let mut step_precompute_ms = 0.0;
        if args.strategy == "cp" {
            if cp_power.is_none() {
                let initial_power_start = Stamp::now();
                cp_power = Some(Arc::new(
                    cpsnarks_set::protocols::hrada_public_power::PublicPower::new(16 * 252, 12)
                        .unwrap(),
                ));
                step_precompute_ms += elapsed_ms(initial_power_start);
                precompute_ms += step_precompute_ms;
                precompute_cpu_s += elapsed_cpu(initial_power_start);
            }
            if n > current_capacity {
                let start = Stamp::now();
                cp_power = Some(Arc::new(
                    cpsnarks_set::protocols::hrada_public_power::PublicPower::new(n * 252, 12)
                        .unwrap(),
                ));
                step_precompute_ms = elapsed_ms(start);
                precompute_ms += step_precompute_ms;
                precompute_cpu_s += elapsed_cpu(start);
                current_capacity = n;
            }
            let start = Stamp::now();
            let state =
                MaintainedState::new_with_power(&pool[..n], Arc::clone(cp_power.as_ref().unwrap()))
                    .unwrap();
            cp_state = Some(state);
            if step == 0 {
                state_init_ms = elapsed_ms(start);
                state_init_cpu_s = elapsed_cpu(start);
            } else {
                step_migration_ms = elapsed_ms(start);
                migration_ms += step_migration_ms;
                migration_cpu_s += elapsed_cpu(start);
            }
        } else {
            let target_depth = tree_depth(n.max(reserved_capacity));
            if step == 0 {
                let start = Stamp::now();
                tree = Some(PoseidonMerkleState::with_depth(&pool[..16], target_depth).unwrap());
                state_init_ms = elapsed_ms(start);
                state_init_cpu_s = elapsed_cpu(start);
                current_capacity = 1usize << target_depth;
            } else {
                let start = Stamp::now();
                let mut state = tree.take().unwrap();
                if state.depth() < target_depth {
                    state.grow_to_depth(target_depth).unwrap();
                }
                state.extend(&pool[current_n..n]).unwrap();
                current_capacity = 1usize << state.depth();
                tree = Some(state);
                step_migration_ms = elapsed_ms(start);
                migration_ms += step_migration_ms;
                migration_cpu_s += elapsed_cpu(start);
            }
            let depth = tree.as_ref().unwrap().depth();
            if !mt_parameters.contains_key(&depth) {
                let start = Stamp::now();
                let template = tree.as_ref().unwrap().circuit(&pool[0]).unwrap();
                let parameters = hrada_link::setup(&mut OsRng, ck, template, 2).unwrap();
                mt_parameters.insert(depth, parameters);
                step_precompute_ms = elapsed_ms(start);
                precompute_ms += step_precompute_ms;
                precompute_cpu_s += elapsed_cpu(start);
            }
        }

        let mut proofs = Vec::new();
        for proof_index in 0..16 {
            let context = format!(
                "capacity-member-only-round3/{}/{}/{}/{}/{}",
                args.trial, args.trajectory, args.ratio, args.strategy, step
            )
            .into_bytes();
            let (witness_time, prove_time, verify_time, wc, pc, vc, verified, bytes) =
                if args.strategy == "cp" {
                    let set = cp_state.as_ref().unwrap().state();
                    let witness_start = Stamp::now();
                    let witness = set.prepare_witness(&pool[0]).unwrap();
                    let witness_time = elapsed_ms(witness_start);
                    let wc = elapsed_cpu(witness_start);
                    let randomness = hrada_link::sample_commitment_randomness(&mut OsRng);
                    let prove_start = Stamp::now();
                    let (statement, proof) = cp
                        .as_ref()
                        .unwrap()
                        .prove_prepared(set, &pool[0], &witness, &randomness, &context)
                        .unwrap();
                    let prove_time = elapsed_ms(prove_start);
                    let pc = elapsed_cpu(prove_start);
                    let verify_start = Stamp::now();
                    cp.as_ref()
                        .unwrap()
                        .verify(&statement, &proof, &context)
                        .unwrap();
                    (
                        witness_time,
                        prove_time,
                        elapsed_ms(verify_start),
                        wc,
                        pc,
                        elapsed_cpu(verify_start),
                        true,
                        cp_proof_bytes(&proof),
                    )
                } else {
                    let state = tree.as_ref().unwrap();
                    let depth = state.depth();
                    let parameters = mt_parameters.get(&depth).unwrap();
                    let witness_start = Stamp::now();
                    let circuit = state.circuit(&pool[0]).unwrap();
                    let witness_time = elapsed_ms(witness_start);
                    let wc = elapsed_cpu(witness_start);
                    let randomness = hrada_link::sample_commitment_randomness(&mut OsRng);
                    let commitment = ck.commit(&pool[0], &randomness).unwrap();
                    let prove_start = Stamp::now();
                    let proof =
                        hrada_link::prove(&mut OsRng, parameters, circuit, &randomness).unwrap();
                    let prove_time = elapsed_ms(prove_start);
                    let pc = elapsed_cpu(prove_start);
                    let verify_start = Stamp::now();
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
                    (
                        witness_time,
                        prove_time,
                        elapsed_ms(verify_start),
                        wc,
                        pc,
                        elapsed_cpu(verify_start),
                        verified,
                        enc(&proof).len(),
                    )
                };
            assert!(verified);
            witness_cpu_s += wc;
            prove_cpu_s += pc;
            verify_cpu_s += vc;
            witness_ms_total += witness_time;
            prove_ms_total += prove_time;
            verify_ms_total += verify_time;
            proofs.push(json!({
                "proof_index": proof_index,
                "witness_ms": witness_time, "witness_cpu_s": wc, "prove_cpu_s": pc, "verify_cpu_s": vc,
                "prove_ms": prove_time,
                "verify_ms": verify_time,
                "verified": verified,
                "bytes": bytes,
            }));
        }
        events.push(json!({
            "event": "checkpoint",
            "strategy": args.strategy,
            "trial": args.trial,
            "trajectory": args.trajectory,
            "requested_ratio": args.ratio,
            "step": step,
            "n": n,
            "actual_capacity": current_capacity,
            "depth": if args.strategy == "cp" { Value::Null } else { json!(tree.as_ref().unwrap().depth()) },
            "setup_ms": if step == 0 { setup_ms } else { 0.0 },
            "precompute_ms": step_precompute_ms,
            "state_init_ms": if step == 0 { state_init_ms } else { 0.0 },
            "migration_ms": step_migration_ms,
            "proof_count": 16,
            "proofs": proofs,
            "positive_checkpoint_ms": elapsed_ms(state_start),
            "timing_scope": "positive proofs only; negative checks follow outside this window",
        }));
        current_n = n;
    }
    let positive_end = Stamp::now();
    let positive_cost_wall_ms = elapsed_ms(positive_start);
    let positive_cost_cpu_s = elapsed_cpu(positive_start);

    // Negative checks are generated and verified after the positive cost window.
    let boundaries = boundary_checks(&pool, trajectory_max, merkle_capacity);
    assert!(boundaries["all_required"].as_bool().unwrap());
    let negative_start = Stamp::now();
    let mut negative_proof_generation_count = 0usize;
    let mut negative_verification_call_count = 0usize;
    let mut negative_events = Vec::new();
    for (step, &n) in ns.iter().enumerate() {
        if args.strategy == "cp" {
            let diagnostic_power = Arc::new(
                cpsnarks_set::protocols::hrada_public_power::PublicPower::new(n * 252, 12).unwrap(),
            );
            let diagnostic_state =
                MaintainedState::new_with_power(&pool[..n], diagnostic_power).unwrap();
            let set = diagnostic_state.state();
            let witness = set.prepare_witness(&pool[0]).unwrap();
            let randomness = Integer::from(7);
            let (statement, proof) = cp
                .as_ref()
                .unwrap()
                .prove_prepared(set, &pool[0], &witness, &randomness, b"negative-context")
                .unwrap();
            negative_proof_generation_count += 1;
            let wrong_context = cp
                .as_ref()
                .unwrap()
                .verify(&statement, &proof, b"wrong-context");
            negative_verification_call_count += 1;
            let nonmember_construction_rejected = set.prepare_witness(&pool[n]).is_err();
            negative_events.push(json!({
                "step": step,
                "n": n,
                "wrong_context": { "classification": "cryptographic_verifier_rejection", "rejected": wrong_context.is_err() },
                "nonmember": { "classification": "construction_rejection", "rejected": nonmember_construction_rejected },
                "wrong_root": { "classification": "not_applicable" },
            }));
        } else {
            let diagnostic_depth = tree_depth(n.max(reserved_capacity));
            let diagnostic_state =
                PoseidonMerkleState::with_depth(&pool[..n], diagnostic_depth).unwrap();
            let state = &diagnostic_state;
            let depth = state.depth();
            let parameters = mt_parameters.get(&depth).unwrap();
            let randomness = Integer::from(7);
            let commitment = ck.commit(&pool[0], &randomness).unwrap();
            let proof = hrada_link::prove(
                &mut OsRng,
                parameters,
                state.circuit(&pool[0]).unwrap(),
                &randomness,
            )
            .unwrap();
            negative_proof_generation_count += 1;
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
            negative_verification_call_count += 1;
            let nonmember_construction_rejected = state.circuit(&pool[n]).is_err();
            negative_events.push(json!({
                "step": step,
                "n": n,
                "wrong_context": { "classification": "not_applicable" },
                "nonmember": { "classification": "construction_rejection", "rejected": nonmember_construction_rejected },
                "wrong_root": { "classification": "cryptographic_verifier_rejection", "rejected": wrong_root_result.map(|verified| !verified).unwrap_or(true) },
            }));
        }
    }
    let negative_ms = elapsed_ms(negative_start);
    assert!(negative_events.iter().all(|event| {
        event["nonmember"]["rejected"].as_bool().unwrap()
            && (event["wrong_context"]["rejected"].as_bool().unwrap_or(true)
                || event["wrong_context"]["classification"] == "not_applicable")
            && (event["wrong_root"]["rejected"].as_bool().unwrap_or(true)
                || event["wrong_root"]["classification"] == "not_applicable")
    }));

    // Explicit release accounting is separate from the positive and negative proof calls.
    let release_start = Stamp::now();
    drop(mt_parameters);
    drop(tree);
    drop(cp_state);
    drop(cp_power);
    drop(cp);
    drop(ck_owned);
    let release_ms = elapsed_ms(release_start);
    let release_cpu_s = elapsed_cpu(release_start);
    let residual_cpu_s = positive_cost_cpu_s
        - (setup_cpu_s
            + precompute_cpu_s
            + state_init_cpu_s
            + migration_cpu_s
            + witness_cpu_s
            + prove_cpu_s
            + verify_cpu_s);
    let residual_ms = positive_cost_wall_ms
        - (setup_ms
            + precompute_ms
            + state_init_ms
            + migration_ms
            + witness_ms_total
            + prove_ms_total
            + verify_ms_total);
    let ledger = json!({
        "positive_cost_wall_ms": positive_cost_wall_ms,
        "positive_cost_cpu_s": positive_cost_cpu_s, "setup_cpu_s": setup_cpu_s,
        "precompute_cpu_s": precompute_cpu_s, "state_init_cpu_s": state_init_cpu_s,
        "migration_cpu_s": migration_cpu_s, "witness_cpu_s": witness_cpu_s,
        "prove_cpu_s": prove_cpu_s, "verify_cpu_s": verify_cpu_s,
        "residual_cpu_s": residual_cpu_s, "release_cpu_s": release_cpu_s,
        "setup_ms": setup_ms,
        "precompute_ms": precompute_ms,
        "state_init_ms": state_init_ms,
        "migration_ms": migration_ms,
        "witness_ms": witness_ms_total,
        "prove_ms": prove_ms_total,
        "verify_ms": verify_ms_total,
        "residual_ms": residual_ms,
        "negative_ms_outside_positive_window": negative_ms,
        "release_ms": release_ms,
        "parameter_io": { "status": "not_applicable", "reason": "member_only_compute_scope" },
        "http_distribution": { "status": "not_applicable", "reason": "member_only_compute_scope" },
        "auth_lifecycle": { "status": "not_applicable", "reason": "explicitly excluded" },
        "resource_access": { "status": "not_applicable", "reason": "explicitly excluded" },
        "negative_proof_generation_count": negative_proof_generation_count,
        "negative_verification_call_count": negative_verification_call_count,
        "positive_end_observed_utc": utc_now(),
        "positive_window_end_elapsed_ms": elapsed_ms(positive_end),
    });
    rows.push(json!({
        "strategy": args.strategy,
        "trajectory": args.trajectory,
        "requested_ratio": args.ratio,
        "events": events,
        "negative_events": negative_events,
        "proof_count": events.len() * 16,
        "ledger": ledger,
    }));

    metadata["finished_utc"] = json!(utc_now());
    metadata["status"] = json!("complete");
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
        .write_all(format!("member-only-round3 complete {}\n", args.out.display()).as_bytes())
        .unwrap();
}
