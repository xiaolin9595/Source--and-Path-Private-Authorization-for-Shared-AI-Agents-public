//! Minimal local regression for the experiment-only Auth relation without the
//! final unused domain-8 request hash. This binary never mutates proof elements.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::{One, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::protocols::{
    hrada_auth::{AuthCircuit, AuthFixture, ExperimentalAuthWithoutRequestHash},
    hrada_joint::{self, Header, JointVerifier},
    hrada_link::{self, LinkParameters},
    hrada_membership::{allocate_prime, CpProof, CpStatement, StateMembership, StateSet},
};
use cpsnarks_set::utils::integer_to_bigint_mod_q;
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde::Serialize;
use std::{env, fs, path::PathBuf, time::Instant};

const FIXTURE_SEED: u64 = 20261017;
const REQUEST_FIELDS: usize = 16;

#[derive(Serialize)]
struct Shape {
    constraints: usize,
    instance_variables: usize,
    witness_variables: usize,
    satisfied: bool,
    expected_radix2_domain: usize,
}

#[derive(Serialize)]
struct KeyData {
    proving_key_bytes: usize,
    verifying_key_bytes: usize,
    h_query_len: usize,
    actual_qap_domain_from_h_query: usize,
    gamma_abc_len: usize,
    link_bases_len: usize,
}

#[derive(Clone, Serialize)]
struct ProofData {
    auth_proof_bytes: usize,
    cp_statement_bytes: usize,
    cp_prove_ms: u64,
    auth_prove_ms: u64,
    auth_verify_ms: u64,
    joint_verify_ms: u64,
}

#[derive(Serialize)]
struct VariantData {
    relation: String,
    setup_ms: u64,
    key_data: KeyData,
    proofs: Vec<ProofData>,
}

#[derive(Serialize)]
struct Check {
    id: String,
    pass: bool,
    detail: String,
}

struct Bundle {
    statement: CpStatement,
    cp: CpProof,
    auth: legogro16::Proof<Bls12_381>,
    fields: Vec<Fr>,
    metrics: ProofData,
}

fn canonical_len<T: CanonicalSerialize>(value: &T) -> usize {
    let mut bytes = Vec::new();
    value.serialize(&mut bytes).unwrap();
    bytes.len()
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis().min(u64::MAX as u128) as u64
}

fn write_checkpoint(output: &PathBuf, stage: &str, checks: &[Check]) -> Result<(), String> {
    let checkpoint = serde_json::json!({
        "schema": "hrada-request-hash-gate-checkpoint-v1",
        "stage": stage,
        "checks": checks,
    });
    fs::write(
        output.join("CHECKPOINT.json"),
        serde_json::to_vec_pretty(&checkpoint).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn scalar_integer() -> Integer {
    let mut bytes = Vec::new();
    Fr::rand(&mut OsRng).serialize(&mut bytes).unwrap();
    Integer::from_digits(&bytes, Order::Lsf)
}

fn shape<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<Shape, String> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    circuit
        .generate_constraints(cs.clone())
        .map_err(|e| format!("synthesis: {:?}", e))?;
    cs.finalize();
    let constraints = cs.num_constraints();
    let instance_variables = cs.num_instance_variables();
    let witness_variables = cs.num_witness_variables();
    let satisfied = cs
        .is_satisfied()
        .map_err(|e| format!("satisfaction: {:?}", e))?;
    Ok(Shape {
        constraints,
        instance_variables,
        witness_variables,
        satisfied,
        expected_radix2_domain: (constraints + instance_variables).next_power_of_two(),
    })
}

fn key_data(link: &LinkParameters) -> KeyData {
    KeyData {
        proving_key_bytes: canonical_len(&link.proving_key),
        verifying_key_bytes: canonical_len(&link.proving_key.vk),
        h_query_len: link.proving_key.h_query.len(),
        actual_qap_domain_from_h_query: link.proving_key.h_query.len() + 1,
        gamma_abc_len: link.proving_key.vk.gamma_abc_g1.len(),
        link_bases_len: link.proving_key.vk.link_bases.len(),
    }
}

fn update_header(fixture: &mut AuthFixture, header: &Header) {
    let digest = header.digest_fields();
    fixture.base.request.fields[0] = digest[0];
    fixture.base.request.fields[1] = digest[1];
    fixture.base.request.fields[2] = Fr::from(header.epoch);
}

fn verifier(header: &Header, parameters_digest: [u8; 32]) -> JointVerifier {
    JointVerifier::new(
        Header::new(header.accumulator.clone(), header.epoch, &parameters_digest),
        parameters_digest,
    )
}

fn make_bundle<C: ConstraintSynthesizer<Fr> + Clone>(
    circuit: C,
    fields: Vec<Fr>,
    prime: &Integer,
    set: &StateSet,
    cp: &StateMembership,
    link: &LinkParameters,
    digest: &[u8; 32],
) -> Result<Bundle, String> {
    let context = hrada_joint::context(digest, &fields)?;
    let randomness = scalar_integer();
    let cp_start = Instant::now();
    let (statement, cp_proof) = cp.prove(set, prime, &randomness, &context)?;
    let cp_prove_ms = elapsed_ms(cp_start);
    let auth_start = Instant::now();
    let auth = hrada_link::prove(&mut OsRng, link, circuit, &randomness)
        .map_err(|e| format!("authorization proof: {:?}", e))?;
    let auth_prove_ms = elapsed_ms(auth_start);
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let cp_bytes = cp.canonical_parameters()?;
    let verify_start = Instant::now();
    let accepted = hrada_link::verify(
        link,
        ck,
        &cp_bytes,
        digest,
        &auth,
        &fields,
        &statement.c_e_q,
    )
    .map_err(|e| format!("authorization verification: {:?}", e))?;
    let auth_verify_ms = elapsed_ms(verify_start);
    if !accepted {
        return Err("valid authorization proof rejected".into());
    }
    cp.verify(&statement, &cp_proof, &context)?;
    let metrics = ProofData {
        auth_proof_bytes: canonical_len(&auth),
        cp_statement_bytes: canonical_len(&statement.c_e_q)
            + Rsa2048::elem_to_bytes(&statement.c_p).len(),
        cp_prove_ms,
        auth_prove_ms,
        auth_verify_ms,
        joint_verify_ms: 0,
    };
    Ok(Bundle {
        statement,
        cp: cp_proof,
        auth,
        fields,
        metrics,
    })
}

fn authorize(
    joint: &mut JointVerifier,
    cp: &StateMembership,
    link: &LinkParameters,
    bundle: &Bundle,
) -> Result<(), String> {
    joint.authorize(
        cp,
        link,
        &bundle.statement,
        &bundle.cp,
        &bundle.auth,
        &bundle.fields,
        &bundle.fields,
        500,
        550,
        || 500,
    )
}

fn record(
    checks: &mut Vec<Check>,
    id: &str,
    pass: bool,
    detail: impl Into<String>,
) -> Result<(), String> {
    let detail = detail.into();
    println!("{} {}: {}", if pass { "PASS" } else { "FAIL" }, id, detail);
    checks.push(Check {
        id: id.to_owned(),
        pass,
        detail,
    });
    if pass {
        Ok(())
    } else {
        Err(format!("failed check: {}", id))
    }
}

fn witness_rejected(circuit: AuthCircuit) -> Result<bool, String> {
    Ok(!shape(ExperimentalAuthWithoutRequestHash(circuit))?.satisfied)
}

fn main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    if args.next().as_deref() == Some("--serialization-smoke") {
        let smoke = ProofData {
            auth_proof_bytes: 336,
            cp_statement_bytes: 304,
            cp_prove_ms: 1,
            auth_prove_ms: 2,
            auth_verify_ms: 3,
            joint_verify_ms: 4,
        };
        println!(
            "{}",
            serde_json::to_string(&smoke).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    let output = PathBuf::from(env::args().nth(1).unwrap_or_else(|| {
        "../paper/pets_2027_english/work/request_hash_gate_2026-10-17".to_owned()
    }));
    fs::create_dir_all(&output).map_err(|e| e.to_string())?;
    let mut checks = Vec::new();

    println!("STAGE synthesis");
    let synthesis_fixture = AuthFixture::new(FIXTURE_SEED);
    let baseline_shape = shape(synthesis_fixture.circuit())?;
    let candidate_shape = shape(ExperimentalAuthWithoutRequestHash(
        synthesis_fixture.circuit(),
    ))?;
    record(
        &mut checks,
        "baseline_synthesis_satisfied",
        baseline_shape.satisfied,
        format!("{} constraints", baseline_shape.constraints),
    )?;
    record(
        &mut checks,
        "candidate_synthesis_satisfied",
        candidate_shape.satisfied,
        format!("{} constraints", candidate_shape.constraints),
    )?;
    record(
        &mut checks,
        "instance_count_preserved_at_18",
        baseline_shape.instance_variables == 18 && candidate_shape.instance_variables == 18,
        format!(
            "baseline={}, candidate={}",
            baseline_shape.instance_variables, candidate_shape.instance_variables
        ),
    )?;
    record(
        &mut checks,
        "candidate_removes_constraints",
        candidate_shape.constraints < baseline_shape.constraints,
        format!(
            "baseline={}, candidate={}, removed={}",
            baseline_shape.constraints,
            candidate_shape.constraints,
            baseline_shape.constraints - candidate_shape.constraints
        ),
    )?;
    write_checkpoint(&output, "synthesis_complete", &checks)?;
    drop(synthesis_fixture);

    println!("STAGE common CP setup");
    let cp = StateMembership::setup_os()?;
    let cp_bytes = cp.canonical_parameters()?;
    let prime = allocate_prime();
    let set = StateSet::rebuild(&[prime.clone()])?;
    let prime_field = integer_to_bigint_mod_q::<G1Projective>(&prime)
        .map_err(|e| format!("prime conversion: {:?}", e))?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;

    println!("STAGE baseline fresh setup and one proof");
    let mut baseline_fixture = AuthFixture::new(FIXTURE_SEED);
    baseline_fixture.refresh_state(prime_field);
    let setup_start = Instant::now();
    let baseline_link =
        hrada_link::setup(&mut OsRng, ck, baseline_fixture.circuit(), REQUEST_FIELDS)
            .map_err(|e| format!("baseline setup: {:?}", e))?;
    let baseline_setup_ms = elapsed_ms(setup_start);
    let baseline_keys = key_data(&baseline_link);
    record(
        &mut checks,
        "baseline_real_domain_matches_synthesis",
        baseline_keys.actual_qap_domain_from_h_query == baseline_shape.expected_radix2_domain,
        format!(
            "h_query={}, domain={}",
            baseline_keys.h_query_len, baseline_keys.actual_qap_domain_from_h_query
        ),
    )?;
    let baseline_digest = hrada_link::parameter_digest(&baseline_link, &cp_bytes)
        .map_err(|e| format!("baseline digest: {:?}", e))?;
    let baseline_header = Header::new(set.accumulator.clone(), 1, &baseline_digest);
    update_header(&mut baseline_fixture, &baseline_header);
    let mut baseline_bundle = make_bundle(
        baseline_fixture.circuit(),
        baseline_fixture.circuit().public_fields(),
        &prime,
        &set,
        &cp,
        &baseline_link,
        &baseline_digest,
    )?;
    let joint_start = Instant::now();
    let baseline_joint = authorize(
        &mut verifier(&baseline_header, baseline_digest),
        &cp,
        &baseline_link,
        &baseline_bundle,
    );
    baseline_bundle.metrics.joint_verify_ms = elapsed_ms(joint_start);
    record(
        &mut checks,
        "baseline_valid_joint_proof",
        baseline_joint.is_ok(),
        format!("{:?}", baseline_joint),
    )?;
    write_checkpoint(&output, "baseline_complete", &checks)?;
    let baseline = VariantData {
        relation: "default AuthCircuit with domain-8 request hash".into(),
        setup_ms: baseline_setup_ms,
        key_data: baseline_keys,
        proofs: vec![baseline_bundle.metrics.clone()],
    };
    drop(baseline_bundle);
    drop(baseline_link);
    drop(baseline_fixture);

    println!("STAGE candidate fresh setup and two proofs");
    let mut candidate_fixture = AuthFixture::new(FIXTURE_SEED);
    candidate_fixture.refresh_state(prime_field);
    let setup_start = Instant::now();
    let candidate_link = hrada_link::setup(
        &mut OsRng,
        ck,
        ExperimentalAuthWithoutRequestHash(candidate_fixture.circuit()),
        REQUEST_FIELDS,
    )
    .map_err(|e| format!("candidate setup: {:?}", e))?;
    let candidate_setup_ms = elapsed_ms(setup_start);
    let candidate_keys = key_data(&candidate_link);
    record(
        &mut checks,
        "candidate_real_domain_matches_synthesis",
        candidate_keys.actual_qap_domain_from_h_query == candidate_shape.expected_radix2_domain,
        format!(
            "h_query={}, domain={}",
            candidate_keys.h_query_len, candidate_keys.actual_qap_domain_from_h_query
        ),
    )?;
    record(
        &mut checks,
        "candidate_full_instance_and_link_vectors",
        candidate_keys.gamma_abc_len == 18 && candidate_keys.link_bases_len == 19,
        format!(
            "gamma_abc={}, link_bases={}",
            candidate_keys.gamma_abc_len, candidate_keys.link_bases_len
        ),
    )?;
    let candidate_digest = hrada_link::parameter_digest(&candidate_link, &cp_bytes)
        .map_err(|e| format!("candidate digest: {:?}", e))?;
    record(
        &mut checks,
        "baseline_candidate_use_fresh_keys",
        baseline_digest != candidate_digest,
        "independently randomized setup digests differ".to_owned(),
    )?;
    let candidate_header = Header::new(set.accumulator.clone(), 1, &candidate_digest);
    update_header(&mut candidate_fixture, &candidate_header);

    let original_circuit = candidate_fixture.circuit();
    let mut original_bundle = make_bundle(
        ExperimentalAuthWithoutRequestHash(original_circuit.clone()),
        original_circuit.public_fields(),
        &prime,
        &set,
        &cp,
        &candidate_link,
        &candidate_digest,
    )?;

    for index in 0..REQUEST_FIELDS {
        let mut changed = original_bundle.fields.clone();
        changed[index] += Fr::one();
        let accepted = hrada_link::verify(
            &candidate_link,
            ck,
            &cp_bytes,
            &candidate_digest,
            &original_bundle.auth,
            &changed,
            &original_bundle.statement.c_e_q,
        )
        .map_err(|e| format!("field {} verification: {:?}", index, e))?;
        record(
            &mut checks,
            &format!("candidate_expected_request_field_{}_rejected", index),
            !accepted,
            "direct hrada_link verification".to_owned(),
        )?;
    }

    let mut wrong_terminal = original_circuit.clone();
    wrong_terminal.request.fields[14] += Fr::one();
    record(
        &mut checks,
        "candidate_wrong_terminal_witness_unsatisfied",
        witness_rejected(wrong_terminal)?,
        "terminal x differs from selected holder".to_owned(),
    )?;
    let mut wrong_policy = original_circuit.clone();
    wrong_policy.request.fields[7] += Fr::one();
    record(
        &mut checks,
        "candidate_wrong_policy_witness_unsatisfied",
        witness_rejected(wrong_policy)?,
        "resource differs from enabled grants".to_owned(),
    )?;

    let mut serial = verifier(&candidate_header, candidate_digest);
    let joint_start = Instant::now();
    let original_joint = authorize(&mut serial, &cp, &candidate_link, &original_bundle);
    original_bundle.metrics.joint_verify_ms = elapsed_ms(joint_start);
    record(
        &mut checks,
        "candidate_valid_joint_proof",
        original_joint.is_ok(),
        format!("{:?}", original_joint),
    )?;
    let duplicate = authorize(&mut serial, &cp, &candidate_link, &original_bundle);
    record(
        &mut checks,
        "candidate_duplicate_nonce_rejected",
        duplicate == Err("nonce_already_consumed".into()),
        format!("{:?}", duplicate),
    )?;

    let mut fresh_nonce_circuit = original_circuit.clone();
    fresh_nonce_circuit.request.fields[10] += Fr::one();
    let mut fresh_nonce_bundle = make_bundle(
        ExperimentalAuthWithoutRequestHash(fresh_nonce_circuit.clone()),
        fresh_nonce_circuit.public_fields(),
        &prime,
        &set,
        &cp,
        &candidate_link,
        &candidate_digest,
    )?;
    let joint_start = Instant::now();
    let fresh_nonce_joint = authorize(&mut serial, &cp, &candidate_link, &fresh_nonce_bundle);
    fresh_nonce_bundle.metrics.joint_verify_ms = elapsed_ms(joint_start);
    record(
        &mut checks,
        "candidate_fresh_nonce_joint_proof",
        fresh_nonce_joint.is_ok(),
        format!("{:?}", fresh_nonce_joint),
    )?;
    let mut transitioned = verifier(&candidate_header, candidate_digest);
    transitioned.replace_header(Header::new(set.accumulator.clone(), 2, &candidate_digest))?;
    let old_header = authorize(&mut transitioned, &cp, &candidate_link, &original_bundle);
    record(
        &mut checks,
        "candidate_old_header_rejected",
        old_header == Err("stale_header".into()),
        format!("{:?}", old_header),
    )?;
    write_checkpoint(&output, "candidate_complete", &checks)?;

    let candidate = VariantData {
        relation: "ExperimentalAuthWithoutRequestHash".into(),
        setup_ms: candidate_setup_ms,
        key_data: candidate_keys,
        proofs: vec![original_bundle.metrics, fresh_nonce_bundle.metrics],
    };

    let all_pass = checks.iter().all(|check| check.pass);
    let result = serde_json::json!({
        "schema": "hrada-request-hash-gate-v1",
        "date": "2026-10-17",
        "fixture_seed": FIXTURE_SEED,
        "scope": "single local diagnostic run; no statistical performance claim",
        "default_protocol_changed": false,
        "candidate_is_explicit_experiment_wrapper": true,
        "active_proof_component_redirection_probe_executed": false,
        "active_probe_note": "not executed by explicit narrowed authorization",
        "external_network_or_system_used": false,
        "auth_proof_count": 3,
        "baseline_shape": baseline_shape,
        "candidate_shape": candidate_shape,
        "baseline": baseline,
        "candidate": candidate,
        "checks": checks,
        "all_checks_pass": all_pass,
    });
    fs::write(
        output.join("RESULTS.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    println!("RESULTS {}", output.join("RESULTS.json").display());
    if all_pass {
        Ok(())
    } else {
        Err("one or more checks failed".into())
    }
}
