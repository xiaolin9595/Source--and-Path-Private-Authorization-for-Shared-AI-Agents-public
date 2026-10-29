//! Synthesis-only constraint attribution for the unchanged shared Auth relation.
//! This binary deliberately performs no setup, proving, verification, or timing benchmark.
use ark_bls12_381::Fr;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, OptimizationGoal,
};
use cpsnarks_set::protocols::hrada_auth::{
    reset_blake2s_constraint_records, take_blake2s_constraint_records, AuthCircuit,
    AuthConstraintSnapshot, AuthFixture, Blake2sConstraintRecord,
};
use serde::Serialize;
use serde_json::json;
use std::{env, fs, path::PathBuf};

#[derive(Clone, Debug, Serialize)]
struct SystemCounts {
    constraints: usize,
    instance_variables: usize,
    witness_variables: usize,
}

#[derive(Clone, Debug, Serialize)]
struct SystemRun {
    pre_finalize: SystemCounts,
    post_finalize: SystemCounts,
    satisfied_pre_finalize: bool,
    satisfied_post_finalize: bool,
}

#[derive(Clone, Debug, Serialize)]
struct PhaseDelta {
    phase: String,
    constraints: usize,
    instance_variables: usize,
    witness_variables: usize,
    cumulative_constraints: usize,
    cumulative_instance_variables: usize,
    cumulative_witness_variables: usize,
}

#[derive(Clone, Debug, Serialize)]
struct CaseAudit {
    case: String,
    enabled: [bool; 3],
    observer_off_baseline: SystemRun,
    observer_on_instrumented: SystemRun,
    observer_off_on_pre_match: bool,
    observer_off_on_post_match: bool,
    phase_deltas: Vec<PhaseDelta>,
    attributed_pre_finalize: SystemCounts,
    unattributed_pre_finalize_residual: SystemCounts,
    finalize_delta: SignedCounts,
    blake2s_calls: Vec<Blake2sConstraintRecord>,
    blake2s_constraints: usize,
    blake2s_percent_of_total: f64,
}

#[derive(Clone, Debug, Serialize)]
struct SignedCounts {
    constraints: i64,
    instance_variables: i64,
    witness_variables: i64,
}

fn counts(cs: &ConstraintSystemRef<Fr>) -> SystemCounts {
    SystemCounts {
        constraints: cs.num_constraints(),
        instance_variables: cs.num_instance_variables(),
        witness_variables: cs.num_witness_variables(),
    }
}

fn normal_run(circuit: AuthCircuit) -> SystemRun {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit.generate_constraints(cs.clone()).unwrap();
    let pre_finalize = counts(&cs);
    let satisfied_pre_finalize = cs.is_satisfied().unwrap();
    cs.finalize();
    let post_finalize = counts(&cs);
    let satisfied_post_finalize = cs.is_satisfied().unwrap();
    SystemRun {
        pre_finalize,
        post_finalize,
        satisfied_pre_finalize,
        satisfied_post_finalize,
    }
}

fn instrumented_run(circuit: AuthCircuit) -> (SystemRun, Vec<AuthConstraintSnapshot>) {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    let (_, snapshots) = circuit
        .synthesize_with_constraint_audit(cs.clone(), false)
        .unwrap();
    let pre_finalize = counts(&cs);
    let satisfied_pre_finalize = cs.is_satisfied().unwrap();
    cs.finalize();
    let post_finalize = counts(&cs);
    let satisfied_post_finalize = cs.is_satisfied().unwrap();
    (
        SystemRun {
            pre_finalize,
            post_finalize,
            satisfied_pre_finalize,
            satisfied_post_finalize,
        },
        snapshots,
    )
}

fn same_counts(a: &SystemCounts, b: &SystemCounts) -> bool {
    a.constraints == b.constraints
        && a.instance_variables == b.instance_variables
        && a.witness_variables == b.witness_variables
}

fn subtract(a: &SystemCounts, b: &SystemCounts) -> SignedCounts {
    SignedCounts {
        constraints: a.constraints as i64 - b.constraints as i64,
        instance_variables: a.instance_variables as i64 - b.instance_variables as i64,
        witness_variables: a.witness_variables as i64 - b.witness_variables as i64,
    }
}

fn audit_case(name: &str, circuit: AuthCircuit) -> CaseAudit {
    reset_blake2s_constraint_records();
    let enabled = circuit.enabled;
    let observer_off_baseline = normal_run(circuit.clone());
    reset_blake2s_constraint_records();
    let (instrumented, snapshots) = instrumented_run(circuit);
    let blake2s_calls = take_blake2s_constraint_records();
    let blake2s_constraints = blake2s_calls.iter().map(|call| call.constraints_delta).sum();
    let mut phase_deltas = Vec::new();
    for pair in snapshots.windows(2) {
        let before = &pair[0];
        let after = &pair[1];
        phase_deltas.push(PhaseDelta {
            phase: after.phase.clone(),
            constraints: after.constraints - before.constraints,
            instance_variables: after.instance_variables - before.instance_variables,
            witness_variables: after.witness_variables - before.witness_variables,
            cumulative_constraints: after.constraints,
            cumulative_instance_variables: after.instance_variables,
            cumulative_witness_variables: after.witness_variables,
        });
    }
    let first = snapshots.first().expect("start snapshot");
    let last = snapshots.last().expect("final snapshot");
    let attributed_pre_finalize = SystemCounts {
        constraints: last.constraints - first.constraints,
        instance_variables: last.instance_variables - first.instance_variables,
        witness_variables: last.witness_variables - first.witness_variables,
    };
    let residual = SystemCounts {
        constraints: instrumented.pre_finalize.constraints - last.constraints,
        instance_variables: instrumented.pre_finalize.instance_variables - last.instance_variables,
        witness_variables: instrumented.pre_finalize.witness_variables - last.witness_variables,
    };
    let pre_match = same_counts(
        &observer_off_baseline.pre_finalize,
        &instrumented.pre_finalize,
    );
    let post_match = same_counts(
        &observer_off_baseline.post_finalize,
        &instrumented.post_finalize,
    );
    assert!(pre_match && post_match, "observer changed relation counts");
    assert!(
        observer_off_baseline.satisfied_pre_finalize
            && observer_off_baseline.satisfied_post_finalize
    );
    assert!(instrumented.satisfied_pre_finalize && instrumented.satisfied_post_finalize);
    let blake2s_percent_of_total =
        100.0 * blake2s_constraints as f64 / instrumented.pre_finalize.constraints as f64;
    CaseAudit {
        case: name.to_owned(),
        enabled,
        observer_off_on_pre_match: pre_match,
        observer_off_on_post_match: post_match,
        finalize_delta: subtract(&instrumented.post_finalize, &instrumented.pre_finalize),
        observer_off_baseline,
        observer_on_instrumented: instrumented,
        phase_deltas,
        attributed_pre_finalize,
        unattributed_pre_finalize_residual: residual,
        blake2s_percent_of_total,
        blake2s_constraints,
        blake2s_calls,
    }
}

fn write_source_evidence(output: &PathBuf) {
    let instrumented = include_str!("../protocols/hrada_auth.rs");
    let instrumented_path = output.join("SOURCE_INSTRUMENTED_hrada_auth.rs");
    fs::write(&instrumented_path, instrumented).unwrap();
    fs::write(
        output.join("SOURCE_EVIDENCE_NOTE.txt"),
        "This run stores the actual compiled source only. It does not mechanically reconstruct or label a synthetic pre-edit source. The frozen prior audit archive remains the source of its own historical before/after evidence.\n",
    )
    .unwrap();
}

fn main() {
    let output = PathBuf::from(env::args().nth(1).unwrap_or_else(|| {
        "../paper/pets_2027_english/work/auth_constraint_audit_2026-10-17".to_owned()
    }));
    fs::create_dir_all(&output).unwrap();
    write_source_evidence(&output);
    let seed = 73_u64;
    let fixture = AuthFixture::new_with_expiry(seed, 86_400);
    let cases = vec![
        audit_case("full_q_three_active_slots", fixture.circuit_for("Q")),
        audit_case("short_q_two_active_slots", fixture.circuit_for("short_Q")),
    ];
    let document = json!({
        "schema": "hrada-auth-constraint-audit-v1",
        "scope": "synthesis only; no setup, proving, verification, or performance benchmark",
        "seed": seed,
        "optimization_goal": "Constraints (inline linear combinations on finalize)",
        "counts_note": "phase deltas are cumulative-system differences before finalize; post-finalize totals are reported separately",
        "baseline_note": "observer_off_baseline executes the current default relation through the same internal function with observer=None and retains the request hash; this run stores only the actual compiled source and does not reconstruct a synthetic pre-edit source",
        "cases": cases,
    });
    fs::write(
        output.join("COUNTS.json"),
        serde_json::to_vec_pretty(&document).unwrap(),
    )
    .unwrap();

    let mut csv = csv::Writer::from_path(output.join("COUNTS.csv")).unwrap();
    csv.write_record(&[
        "case",
        "phase",
        "constraints_delta",
        "instances_delta",
        "witnesses_delta",
        "cumulative_constraints",
        "cumulative_instances",
        "cumulative_witnesses",
    ])
    .unwrap();
    for case in document["cases"].as_array().unwrap() {
        let case_name = case["case"].as_str().unwrap();
        for phase in case["phase_deltas"].as_array().unwrap() {
            csv.write_record(&[
                case_name,
                phase["phase"].as_str().unwrap(),
                &phase["constraints"].to_string(),
                &phase["instance_variables"].to_string(),
                &phase["witness_variables"].to_string(),
                &phase["cumulative_constraints"].to_string(),
                &phase["cumulative_instance_variables"].to_string(),
                &phase["cumulative_witness_variables"].to_string(),
            ])
            .unwrap();
        }
    }
    csv.flush().unwrap();
    println!("{}", serde_json::to_string_pretty(&document).unwrap());
}
