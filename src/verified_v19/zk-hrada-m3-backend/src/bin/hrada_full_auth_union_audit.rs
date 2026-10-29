//! Synthesis-only integration audit for the experiment-only full Auth private
//! Merkle union. No setup, proving, verification, or external service is used.
use ark_bls12_381::Fr;
use ark_ff::One;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, OptimizationGoal, SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::hrada_auth::{
    build_private_merkle_union_witness, AuthCircuit, AuthFixture,
    ExperimentalAuthWithPrivateMerkleUnion, ExperimentalAuthWithoutRequestHash,
    PrivateMerkleUnionWitness,
};
use serde::Serialize;
use serde_json::json;
use std::{env, fs, path::PathBuf, time::Instant};

const FIXTURE_SEED: u64 = 20261018;

#[derive(Clone, Debug, Serialize, PartialEq)]
struct Counts {
    constraints: usize,
    instance_variables: usize,
    witness_variables: usize,
    qap_radix2_domain_from_c_plus_i: usize,
}

#[derive(Clone, Debug, Serialize)]
struct Run {
    relation: String,
    case: String,
    expected: String,
    construction: String,
    synthesis_error: Option<String>,
    satisfied_pre_finalize: Option<bool>,
    satisfied_post_finalize: Option<bool>,
    pre_finalize: Option<Counts>,
    post_finalize: Option<Counts>,
    pass: bool,
}

fn counts(cs: &ark_relations::r1cs::ConstraintSystemRef<Fr>) -> Counts {
    let constraints = cs.num_constraints();
    let instance_variables = cs.num_instance_variables();
    Counts {
        constraints,
        instance_variables,
        witness_variables: cs.num_witness_variables(),
        qap_radix2_domain_from_c_plus_i: (constraints + instance_variables).next_power_of_two(),
    }
}

fn synthesize<C: ConstraintSynthesizer<Fr>>(
    relation: &str,
    case: &str,
    circuit: C,
    expected_satisfied: bool,
) -> Run {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    match circuit.generate_constraints(cs.clone()) {
        Err(error) => Run {
            relation: relation.to_owned(),
            case: case.to_owned(),
            expected: format!("satisfied={}", expected_satisfied),
            construction: "rejected".into(),
            synthesis_error: Some(format!("{:?}", error)),
            satisfied_pre_finalize: None,
            satisfied_post_finalize: None,
            pre_finalize: None,
            post_finalize: None,
            pass: false,
        },
        Ok(()) => {
            let pre_finalize = counts(&cs);
            let satisfied_pre_finalize = match cs.is_satisfied() {
                Ok(value) => value,
                Err(error) => {
                    return Run {
                        relation: relation.to_owned(),
                        case: case.to_owned(),
                        expected: format!("satisfied={}", expected_satisfied),
                        construction: "constructed_evaluation_error".into(),
                        synthesis_error: Some(format!("pre_finalize_evaluation: {:?}", error)),
                        satisfied_pre_finalize: None,
                        satisfied_post_finalize: None,
                        pre_finalize: Some(pre_finalize),
                        post_finalize: None,
                        pass: false,
                    }
                }
            };
            cs.finalize();
            let post_finalize = counts(&cs);
            let satisfied_post_finalize = match cs.is_satisfied() {
                Ok(value) => value,
                Err(error) => {
                    return Run {
                        relation: relation.to_owned(),
                        case: case.to_owned(),
                        expected: format!("satisfied={}", expected_satisfied),
                        construction: "constructed_evaluation_error".into(),
                        synthesis_error: Some(format!("post_finalize_evaluation: {:?}", error)),
                        satisfied_pre_finalize: Some(satisfied_pre_finalize),
                        satisfied_post_finalize: None,
                        pre_finalize: Some(pre_finalize),
                        post_finalize: Some(post_finalize),
                        pass: false,
                    }
                }
            };
            let pass = satisfied_pre_finalize == expected_satisfied
                && satisfied_post_finalize == expected_satisfied;
            Run {
                relation: relation.to_owned(),
                case: case.to_owned(),
                expected: format!("satisfied={}", expected_satisfied),
                construction: "constructed".into(),
                synthesis_error: None,
                satisfied_pre_finalize: Some(satisfied_pre_finalize),
                satisfied_post_finalize: Some(satisfied_post_finalize),
                pre_finalize: Some(pre_finalize),
                post_finalize: Some(post_finalize),
                pass,
            }
        }
    }
}

fn synthesize_builder_rejection(case: &str, circuit: AuthCircuit) -> Run {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    let result = ExperimentalAuthWithPrivateMerkleUnion::new(circuit)
        .generate_constraints(cs.clone());
    let rejected = matches!(result, Err(SynthesisError::Unsatisfiable));
    Run {
        relation: "ExperimentalAuthWithPrivateMerkleUnion".into(),
        case: case.into(),
        expected: "builder_rejected".into(),
        construction: if rejected { "rejected" } else { "constructed" }.into(),
        synthesis_error: result.err().map(|error| format!("{:?}", error)),
        satisfied_pre_finalize: None,
        satisfied_post_finalize: None,
        pre_finalize: None,
        post_finalize: None,
        pass: rejected,
    }
}

fn push_pair(runs: &mut Vec<Run>, case: &str, circuit: AuthCircuit, expected: bool) {
    runs.push(synthesize(
        "ExperimentalAuthWithoutRequestHash",
        case,
        ExperimentalAuthWithoutRequestHash(circuit.clone()),
        expected,
    ));
    runs.push(synthesize(
        "ExperimentalAuthWithPrivateMerkleUnion",
        case,
        ExperimentalAuthWithPrivateMerkleUnion::new(circuit),
        expected,
    ));
}

fn signature_digest(fixture: &AuthFixture) -> String {
    let mut bytes = Vec::new();
    for grant in &fixture.all_grants {
        grant.signature.prover_response.serialize(&mut bytes).unwrap();
        grant.signature.verifier_challenge.serialize(&mut bytes).unwrap();
    }
    hex(&Blake2s::digest(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn copy_current_state(target: &mut AuthCircuit, source: &AuthCircuit) {
    target.prime = source.prime;
    target.request.fields[2] = source.request.fields[2];
    target.auth_root = source.auth_root;
    target.state_version = source.state_version;
    target.state_status = source.state_status;
    target.state_expiry = source.state_expiry;
    target.transition = source.transition;
    target.sr_sig = source.sr_sig.clone();
}

fn csv(runs: &[Run]) -> String {
    let mut out = String::from("relation,case,expected,construction,synthesis_error,pre_satisfied,post_satisfied,pre_c,pre_i,pre_w,post_c,post_i,post_w,qap_domain,pass\n");
    for run in runs {
        let pre = run.pre_finalize.as_ref();
        let post = run.post_finalize.as_ref();
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            run.relation,
            run.case,
            run.expected,
            run.construction,
            run.synthesis_error.as_deref().unwrap_or(""),
            run.satisfied_pre_finalize.map(|v| v.to_string()).unwrap_or_default(),
            run.satisfied_post_finalize.map(|v| v.to_string()).unwrap_or_default(),
            pre.map(|v| v.constraints.to_string()).unwrap_or_default(),
            pre.map(|v| v.instance_variables.to_string()).unwrap_or_default(),
            pre.map(|v| v.witness_variables.to_string()).unwrap_or_default(),
            post.map(|v| v.constraints.to_string()).unwrap_or_default(),
            post.map(|v| v.instance_variables.to_string()).unwrap_or_default(),
            post.map(|v| v.witness_variables.to_string()).unwrap_or_default(),
            post.map(|v| v.qap_radix2_domain_from_c_plus_i.to_string()).unwrap_or_default(),
            run.pass,
        ));
    }
    out
}

fn checkpoint(output: &PathBuf, runs: &[Run]) -> Result<(), String> {
    fs::write(
        output.join("RUNS.partial.json"),
        serde_json::to_vec_pretty(runs).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(output.join("RUNS.partial.csv"), csv(runs)).map_err(|error| error.to_string())
}

fn main() -> Result<(), String> {
    let started = Instant::now();
    let output = PathBuf::from(env::args().nth(1).unwrap_or_else(|| {
        "../paper/pets_2027_english/work/full_auth_union_integration_2026-10-18".into()
    }));
    fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    let mut fixture = AuthFixture::new(FIXTURE_SEED);
    let initial_signature_digest = signature_digest(&fixture);
    let initial_grant_signature_count = fixture.grant_signatures;
    let initial_sr_signature_count = fixture.sr_signatures;
    let initial_padding_signature_count = fixture.padding_signatures.get();
    let initial_q = fixture.circuit_for("Q");
    let mut runs = Vec::new();

    runs.push(synthesize(
        "AuthCircuit",
        "initial_Q_default_count_guard",
        initial_q.clone(),
        true,
    ));
    checkpoint(&output, &runs)?;
    push_pair(
        &mut runs,
        "initial_P",
        fixture.circuit_for("P"),
        true,
    );
    checkpoint(&output, &runs)?;
    let default_guard = runs[0].post_finalize.as_ref().ok_or("default count guard rejected")?;
    let m_guard = runs[1].post_finalize.as_ref().ok_or("M count guard rejected")?;
    if default_guard.constraints != 2_140_389
        || default_guard.instance_variables != 18
        || default_guard.witness_variables != 2_062_697
        || m_guard.constraints != 1_935_685
        || m_guard.instance_variables != 18
        || m_guard.witness_variables != 1_862_841
    {
        return Err("default or M count regression; stopped before candidate matrix".into());
    }
    for path in ["P2", "Q", "short_Q", "prefix_P1", "prefix_P2"] {
        push_pair(
            &mut runs,
            &format!("initial_{}", path),
            fixture.circuit_for(path),
            true,
        );
        checkpoint(&output, &runs)?;
    }

    fixture.close_issuers();
    let grant_count_at_close = fixture.grant_signatures;
    let sr_count_at_close = fixture.sr_signatures;
    fixture.revoke_middle(fixture.base.prime + Fr::one());
    let after_middle_signature_digest = signature_digest(&fixture);
    for (path, expected) in [("P", false), ("P2", false), ("Q", true), ("short_Q", true)] {
        push_pair(
            &mut runs,
            &format!("after_revoke_grant1_{}", path),
            fixture.circuit_for(path),
            expected,
        );
        checkpoint(&output, &runs)?;
    }
    let mut forced_active = fixture.circuit_for("P");
    forced_active.grants[1].active = true;
    push_pair(
        &mut runs,
        "after_revoke_grant1_P_forced_active_current_tree",
        forced_active,
        false,
    );
    checkpoint(&output, &runs)?;
    let mut mixed_old_q = initial_q.clone();
    copy_current_state(&mut mixed_old_q, &fixture.base);
    push_pair(
        &mut runs,
        "after_revoke_grant1_Q_old_siblings_new_sr_state",
        mixed_old_q,
        false,
    );
    checkpoint(&output, &runs)?;

    fixture.all_grants[5].active = false;
    fixture.base.state_version += 1;
    fixture.base.request.fields[2] += Fr::one();
    fixture.base.transition = [5u8; 32];
    fixture.refresh_state(fixture.base.prime + Fr::one());
    let after_branch_signature_digest = signature_digest(&fixture);
    push_pair(
        &mut runs,
        "after_revoke_grant5_Q",
        fixture.circuit_for("Q"),
        false,
    );
    checkpoint(&output, &runs)?;
    push_pair(
        &mut runs,
        "after_revoke_grant5_short_Q",
        fixture.circuit_for("short_Q"),
        true,
    );
    checkpoint(&output, &runs)?;

    let current_valid = fixture.circuit_for("short_Q");
    let mut wrong_holder = current_valid.clone();
    wrong_holder.holder = fixture.keys[6].1 .0;
    push_pair(&mut runs, "wrong_holder", wrong_holder, false);
    checkpoint(&output, &runs)?;
    let mut prime_sr_mismatch = current_valid;
    prime_sr_mismatch.prime += Fr::one();
    push_pair(&mut runs, "prime_sr_root_signature_mismatch", prime_sr_mismatch, false);
    checkpoint(&output, &runs)?;
    let mut illegal_prefix = fixture.circuit_for("short_Q");
    illegal_prefix.enabled = [true, false, true];
    push_pair(&mut runs, "illegal_enabled_prefix", illegal_prefix, false);
    checkpoint(&output, &runs)?;
    let mut noncanonical_padding = fixture.circuit_for("short_Q");
    noncanonical_padding.grants[2].fields[8] = Fr::one();
    push_pair(&mut runs, "noncanonical_padding", noncanonical_padding, false);
    checkpoint(&output, &runs)?;

    let valid_short = fixture.circuit_for("short_Q");
    let mut missing_route = build_private_merkle_union_witness(&valid_short)
        .map_err(|error| format!("builder: {:?}", error))?;
    missing_route.query_routes[0] = [false; 3];
    runs.push(synthesize(
        "ExperimentalAuthWithPrivateMerkleUnion",
        "union_missing_query_route",
        ExperimentalAuthWithPrivateMerkleUnion::with_witness(valid_short.clone(), missing_route),
        false,
    ));
    checkpoint(&output, &runs)?;
    let mut wrong_child: PrivateMerkleUnionWitness = build_private_merkle_union_witness(&valid_short)
        .map_err(|error| format!("builder: {:?}", error))?;
    wrong_child.level0[0].left[0] ^= 1;
    runs.push(synthesize(
        "ExperimentalAuthWithPrivateMerkleUnion",
        "union_wrong_child",
        ExperimentalAuthWithPrivateMerkleUnion::with_witness(valid_short.clone(), wrong_child),
        false,
    ));
    checkpoint(&output, &runs)?;
    let mut malformed = valid_short;
    malformed.paths[0].pop();
    runs.push(synthesize_builder_rejection(
        "builder_rejects_wrong_path_shape",
        malformed,
    ));
    checkpoint(&output, &runs)?;

    let default_counts = runs
        .iter()
        .find(|run| run.relation == "AuthCircuit")
        .and_then(|run| run.post_finalize.clone())
        .ok_or_else(|| "missing default counts".to_string())?;
    let m_counts = runs
        .iter()
        .find(|run| run.relation == "ExperimentalAuthWithoutRequestHash" && run.pass)
        .and_then(|run| run.post_finalize.clone())
        .ok_or_else(|| "missing M counts".to_string())?;
    let union_counts = runs
        .iter()
        .find(|run| run.relation == "ExperimentalAuthWithPrivateMerkleUnion" && run.pass && run.construction == "constructed")
        .and_then(|run| run.post_finalize.clone())
        .ok_or_else(|| "missing union counts".to_string())?;
    let fixed_shape = runs.iter().filter(|run| run.construction == "constructed").all(|run| {
        let expected = if run.relation == "AuthCircuit" {
            &default_counts
        } else if run.relation == "ExperimentalAuthWithoutRequestHash" {
            &m_counts
        } else {
            &union_counts
        };
        run.post_finalize.as_ref() == Some(expected)
    });
    let semantic_runs_pass = runs.iter().all(|run| run.pass);
    let signatures_unchanged = initial_signature_digest == after_middle_signature_digest
        && initial_signature_digest == after_branch_signature_digest
        && fixture.grant_signatures == initial_grant_signature_count
        && fixture.grant_signatures == grant_count_at_close;
    let count_guards = default_counts.constraints == 2_140_389
        && default_counts.instance_variables == 18
        && default_counts.witness_variables == 2_062_697
        && m_counts.constraints == 1_935_685
        && m_counts.instance_variables == 18
        && m_counts.witness_variables == 1_862_841
        && union_counts.instance_variables == 18
        && union_counts.constraints < m_counts.constraints;
    let all_pass = semantic_runs_pass && signatures_unchanged && fixed_shape && count_guards;
    let source_hash = Blake2s::digest(include_bytes!("../protocols/hrada_auth.rs"));
    let audit_hash = Blake2s::digest(include_bytes!("hrada_full_auth_union_audit.rs"));
    let lock_hash = Blake2s::digest(include_bytes!("../../Cargo.lock"));
    let document = json!({
        "schema": "hrada-full-auth-private-merkle-union-audit-v1",
        "date": "2026-10-18",
        "scope": "full Auth R1CS synthesis only; no setup, NIZK, proof timing, CP/current-header replay test, or external service",
        "fixture_seed": FIXTURE_SEED,
        "command": "cargo run --release --locked --bin hrada_full_auth_union_audit -- ../paper/pets_2027_english/work/full_auth_union_integration_2026-10-18",
        "program_wall_seconds": started.elapsed().as_secs_f64(),
        "source_blake2s": hex(&source_hash),
        "audit_source_blake2s": hex(&audit_hash),
        "cargo_lock_blake2s": hex(&lock_hash),
        "default_counts": default_counts,
        "m_counts": m_counts,
        "union_counts": union_counts,
        "constraint_delta_union_minus_m": union_counts.constraints as i64 - m_counts.constraints as i64,
        "fixed_shape_counts_checked": fixed_shape,
        "matrix_digest_checked": false,
        "signature_accounting": {
            "initial_grant_signature_digest": initial_signature_digest,
            "after_middle_revoke_digest": after_middle_signature_digest,
            "after_branch_revoke_digest": after_branch_signature_digest,
            "grant_signatures_initial": initial_grant_signature_count,
            "grant_signatures_final": fixture.grant_signatures,
            "sr_signatures_initial": initial_sr_signature_count,
            "sr_signatures_at_close": sr_count_at_close,
            "sr_signatures_final": fixture.sr_signatures,
            "padding_signatures_initial": initial_padding_signature_count,
            "padding_signatures_final": fixture.padding_signatures.get(),
            "original_grant_signatures_unchanged": signatures_unchanged
        },
        "count_guards_pass": count_guards,
        "semantic_runs_pass": semantic_runs_pass,
        "all_pass": all_pass,
        "runs": runs,
        "limitations": [
            "C/I/W equality plus fixed-loop source review is not an R1CS matrix digest comparison.",
            "The pure Auth relation checks the supplied signed state. Current-header/CP freshness and replay of a wholly old Auth state are outside this audit.",
            "The QAP domain is computed from C+I as the next radix-2 power; it is not used as a fixed speed-ratio claim.",
            "Original grant signatures remain byte-identical; SR refresh signatures and terminal padding signatures are separately counted."
        ]
    });
    fs::write(output.join("RESULTS.json"), serde_json::to_vec_pretty(&document).unwrap())
        .map_err(|error| error.to_string())?;
    fs::write(output.join("RUNS.csv"), csv(&runs)).map_err(|error| error.to_string())?;
    println!("{}", serde_json::to_string_pretty(&document).unwrap());
    if all_pass {
        Ok(())
    } else {
        Err("one or more audit checks failed".into())
    }
}
