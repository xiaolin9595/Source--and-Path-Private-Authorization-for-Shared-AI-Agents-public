//! Synthetic shared-agent document export, backed by real CP–RSA/Lego proofs.
//! The verifier/PEP builds its expected request from a separately held job
//! intent. Alternative source-choice executions use fresh verifier snapshots;
//! they are not simultaneous uses of one nonce.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::{One, PrimeField, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_admission::{
        admit_state_roots, AdmissionAuthority, BusinessEntitlement, InMemoryEntitlementLedger,
    },
    hrada_auth::{AuthCircuit, AuthFixture, ExperimentalAuthWithoutRequestHash},
    hrada_joint::{self, Header, JointVerifier},
    hrada_link::{self, LinkParameters},
    hrada_membership::{allocate_prime, CpProof, CpStatement, StateMembership, StateSet},
};
use cpsnarks_set::utils::integer_to_bigint_mod_q;
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    convert::TryFrom,
    fs,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

struct Presentation {
    statement: CpStatement,
    member: CpProof,
    auth: legogro16::Proof<Bls12_381>,
    fields: Vec<Fr>,
}

/// PEP-owned mapping from the public resource/action pair to the only local
/// operation this synthetic application offers. Callers cannot provide an
/// arbitrary source path to the authorization-to-execution boundary.
struct PepCatalog {
    document_42: PathBuf,
}
impl PepCatalog {
    fn new(application_root: &Path) -> Self {
        Self {
            document_42: application_root.join("source_project_document_42.txt"),
        }
    }
    fn resolve_export(&self, job: &ExportJob) -> Result<&Path, String> {
        if job.resource != 42 {
            return Err("pep_unknown_resource".into());
        }
        if job.action != 1 {
            return Err("pep_unsupported_action".into());
        }
        Ok(&self.document_42)
    }
}

#[derive(Clone)]
struct ExportJob {
    job_id: &'static str,
    system: u64,
    verifier: u64,
    pep: u64,
    resource: u64,
    action: u64,
    request_time: u64,
    nonce: u64,
    expiry: u64,
    terminal: [Fr; 2],
}
impl ExportJob {
    fn context_digest(&self) -> [u8; 32] {
        let mut input = b"HRADA-SYNTHETIC-EXPORT-JOB-V1".to_vec();
        input.extend_from_slice(self.job_id.as_bytes());
        let mut digest = [0; 32];
        digest.copy_from_slice(&Blake2s::digest(&input));
        digest
    }
    /// Constructed by the application from job metadata, before seeing a proof.
    fn expected_request(&self, header: &Header) -> Vec<Fr> {
        let h = header.digest_fields();
        let context = self.context_digest();
        vec![
            h[0],
            h[1],
            Fr::from(header.epoch),
            Fr::from(self.system),
            Fr::from(1u64),
            Fr::from(self.verifier),
            Fr::from(self.pep),
            Fr::from(self.resource),
            Fr::from(self.action),
            Fr::from(self.request_time),
            Fr::from(self.nonce),
            Fr::from(self.expiry),
            Fr::from_le_bytes_mod_order(&context[..16]),
            Fr::from_le_bytes_mod_order(&context[16..]),
            self.terminal[0],
            self.terminal[1],
        ]
    }
    fn public_metadata(&self, epoch: u64) -> Value {
        json!({"job_id":self.job_id,"epoch":epoch,"system":self.system,
            "verifier":self.verifier,"pep":self.pep,"resource":self.resource,
            "action":self.action,"request_time":self.request_time,
            "nonce":self.nonce,"expiry":self.expiry,
            "context_digest":hex(&self.context_digest())})
    }
}

struct Evidence {
    out: PathBuf,
    checks: Vec<Value>,
    proofs: Vec<Value>,
    status: &'static str,
    failure: Option<String>,
}
impl Evidence {
    fn save(&self) -> Result<(), String> {
        fs::create_dir_all(&self.out).map_err(|e| e.to_string())?;
        let report = json!({"kind":"pc-full-f-control-v1",
            "benchmark_setup_id":std::env::var("BENCHMARK_SETUP_ID").ok(),
            "benchmark_seed":std::env::var("BENCHMARK_SEED").ok(),
            "benchmark_pair_id":std::env::var("BENCHMARK_PAIR_ID").ok(),
            "benchmark_side":std::env::var("BENCHMARK_SIDE").ok(),
            "scope":"local serial verifier and PEP, trusted SR/header, synthetic entitlements and jobs",
            "source_choice":"two alternative valid witnesses for the same public request; alternative verifier snapshots",
            "production_workload":false,"relation":"ExperimentalAuthWithoutRequestHash","run_status":self.status,"failure":self.failure,
            "checks":self.checks,"proofs":self.proofs});
        fs::write(
            self.out.join("application_workflow.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        let mut jsonl = String::new();
        for (index, row) in self.proofs.iter().enumerate() {
            jsonl.push_str(
                &serde_json::to_string(&json!({"row_type":"proof_stage",
                "index":index,"data":row}))
                .unwrap(),
            );
            jsonl.push('\n');
        }
        for (index, row) in self.checks.iter().enumerate() {
            jsonl.push_str(
                &serde_json::to_string(&json!({"row_type":"gate_or_commit_stage",
                "index":index,"data":row}))
                .unwrap(),
            );
            jsonl.push('\n');
        }
        fs::write(self.out.join("raw_stages.jsonl"), jsonl).map_err(|e| e.to_string())
    }
    fn check(&mut self, id: &str, pass: bool, detail: Value) -> Result<(), String> {
        println!("{} {}", if pass { "PASS" } else { "FAIL" }, id);
        self.checks
            .push(json!({"id":id,"pass":pass,"detail":detail}));
        self.save()?;
        if pass {
            Ok(())
        } else {
            Err(format!("check failed: {}", id))
        }
    }
}

fn enc<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = vec![];
    v.serialize(&mut b).unwrap();
    b
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{:02x}", v)).collect()
}
fn random_integer() -> Integer {
    Integer::from_digits(&enc(&Fr::rand(&mut OsRng)), Order::Lsf)
}
fn milliseconds(duration: Duration) -> Result<u64, String> {
    u64::try_from(duration.as_millis()).map_err(|_| "duration exceeds u64 milliseconds".into())
}
fn encode_cp(proof: &CpProof) -> Value {
    let root = &proof.proof_root;
    let modeq = &proof.proof_modeq;
    json!({"encoding":"hrada-cp-components-v1",
        "c_e":hex(&Rsa2048::elem_to_bytes(&proof.c_e)),
        "root_message1":[hex(&Rsa2048::elem_to_bytes(&root.message1.c_w)),
            hex(&Rsa2048::elem_to_bytes(&root.message1.c_r))],
        "root_message2":[hex(&Rsa2048::elem_to_bytes(&root.message2.alpha1)),
            hex(&Rsa2048::elem_to_bytes(&root.message2.alpha2)),
            hex(&Rsa2048::elem_to_bytes(&root.message2.alpha3)),
            hex(&Rsa2048::elem_to_bytes(&root.message2.alpha4))],
        "root_message3":[root.message3.s_e.to_string(),root.message3.s_r.to_string(),
            root.message3.s_r_2.to_string(),root.message3.s_r_3.to_string(),
            root.message3.s_beta.to_string(),root.message3.s_delta.to_string()],
        "modeq_message1":[hex(&Rsa2048::elem_to_bytes(&modeq.message1.alpha1)),
            hex(&enc(&modeq.message1.alpha2))],
        "modeq_message2":[modeq.message2.s_e.to_string(),
            modeq.message2.s_r.to_string(),hex(&enc(&modeq.message2.s_r_q))],
        "range_lego":hex(&enc(&proof.proof_hash_to_prime))})
}
fn prime_fr(p: &Integer) -> Result<Fr, String> {
    integer_to_bigint_mod_q::<G1Projective>(p).map_err(|e| format!("{:?}", e))
}
fn circuit_satisfied(c: AuthCircuit) -> Result<bool, String> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone())
        .map_err(|e| format!("{:?}", e))?;
    cs.is_satisfied().map_err(|e| format!("{:?}", e))
}
fn make_presentation(
    label: &str,
    circuit: AuthCircuit,
    prime: &Integer,
    set: &StateSet,
    cp: &StateMembership,
    link: &LinkParameters,
    digest: &[u8; 32],
    evidence: &mut Evidence,
) -> Result<Presentation, String> {
    let fields = circuit.public_fields();
    let context = hrada_joint::context(digest, &fields)?;
    let opening = random_integer();
    let start = Instant::now();
    let (statement, member) = cp.prove(set, prime, &opening, &context)?;
    let member_ms = milliseconds(start.elapsed())?;
    let start = Instant::now();
    let auth = hrada_link::prove(
        &mut OsRng,
        link,
        ExperimentalAuthWithoutRequestHash(circuit),
        &opening,
    )
    .map_err(|e| format!("authorization proof: {:?}", e))?;
    let auth_ms = milliseconds(start.elapsed())?;
    let artifact_start = Instant::now();
    let auth_encoding = enc(&auth);
    let proof_record = json!({"name":label,
        "public_fields_le":fields.iter().map(|f|hex(&enc(f))).collect::<Vec<_>>(),
        "accumulator":hex(&Rsa2048::elem_to_bytes(&statement.c_p)),
        "prime_commitment":hex(&enc(&statement.c_e_q)),
        "cp_proof":encode_cp(&member),"authorization_lego":hex(&auth_encoding)});
    let proof_file = format!("proof_{}.json", label);
    let proof_record_bytes = serde_json::to_vec_pretty(&proof_record).unwrap();
    fs::write(evidence.out.join(&proof_file), &proof_record_bytes).map_err(|x| x.to_string())?;
    let artifact_serialize_write_ms = milliseconds(artifact_start.elapsed())?;
    evidence
        .proofs
        .push(json!({"label":label,"member_prove_ms":member_ms,
        "auth_prove_ms":auth_ms,"artifact_serialize_write_ms":artifact_serialize_write_ms,
        "artifact_bytes":proof_record_bytes.len(),"auth_proof_canonical_bytes":auth_encoding.len(),
        "artifact":proof_file,
        "header_accumulator":hex(&Rsa2048::elem_to_bytes(&statement.c_p)),
        "source_commitment":hex(&enc(&statement.c_e_q)),
        "member_proof_kind":"real CP-RSA", "auth_proof_kind":"real LegoGroth16"}));
    evidence.save()?;
    Ok(Presentation {
        statement,
        member,
        auth,
        fields,
    })
}
fn submit(
    verifier: &mut JointVerifier,
    cp: &StateMembership,
    link: &LinkParameters,
    presentation: &Presentation,
    expected: &[Fr],
    job: &ExportJob,
) -> Result<(), String> {
    verifier.authorize(
        cp,
        link,
        &presentation.statement,
        &presentation.member,
        &presentation.auth,
        &presentation.fields,
        expected,
        job.request_time,
        job.expiry,
        || job.request_time,
    )
}
fn submit_and_export(
    verifier: &mut JointVerifier,
    cp: &StateMembership,
    link: &LinkParameters,
    presentation: &Presentation,
    job: &ExportJob,
    catalog: &PepCatalog,
    output: &Path,
) -> Result<(), String> {
    // The PEP constructs expected fields from its own job record, never from
    // the presentation. Intent mismatch is checked first; the local operation
    // is then resolved from the catalog before permit commit or file access.
    let expected = job.expected_request(&verifier.header);
    if presentation.fields != expected {
        return Err("request_mismatch".into());
    }
    let source_document = catalog.resolve_export(job)?;
    submit(verifier, cp, link, presentation, &expected, job)?;
    let contents = fs::read(source_document).map_err(|x| x.to_string())?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|x| x.to_string())?;
    }
    let mut exported = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(|x| x.to_string())?;
    exported.write_all(&contents).map_err(|x| x.to_string())?;
    exported.sync_all().map_err(|x| x.to_string())
}

struct CommitTimings {
    joint_verify_and_nonce_commit_ms: u64,
    commit_ack_ms: u64,
    serial_total_ms: u64,
}

fn submit_and_export_measured(
    verifier: &mut JointVerifier,
    cp: &StateMembership,
    link: &LinkParameters,
    presentation: &Presentation,
    job: &ExportJob,
    catalog: &PepCatalog,
    output: &Path,
) -> Result<CommitTimings, String> {
    let serial_start = Instant::now();
    let expected = job.expected_request(&verifier.header);
    if presentation.fields != expected {
        return Err("request_mismatch".into());
    }
    let source_document = catalog.resolve_export(job)?;
    let verify_start = Instant::now();
    submit(verifier, cp, link, presentation, &expected, job)?;
    let joint_verify_and_nonce_commit_ms = milliseconds(verify_start.elapsed())?;
    let commit_start = Instant::now();
    let contents = fs::read(source_document).map_err(|error| error.to_string())?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut exported = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .map_err(|error| error.to_string())?;
    exported
        .write_all(&contents)
        .map_err(|error| error.to_string())?;
    exported.sync_all().map_err(|error| error.to_string())?;
    Ok(CommitTimings {
        joint_verify_and_nonce_commit_ms,
        commit_ack_ms: milliseconds(commit_start.elapsed())?,
        serial_total_ms: milliseconds(serial_start.elapsed())?,
    })
}
fn export_count(dir: &Path) -> Result<usize, String> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0;
    for entry in fs::read_dir(dir).map_err(|x| x.to_string())? {
        let entry = entry.map_err(|x| x.to_string())?;
        let name = entry.file_name();
        // On exFAT, macOS may add `._name` AppleDouble metadata alongside a
        // real export. Ignore only a sidecar paired with an existing file;
        // orphan sidecars and every other unexpected entry still count.
        let paired_appledouble = name
            .to_str()
            .and_then(|n| n.strip_prefix("._"))
            .filter(|base| !base.is_empty())
            .map(|base| dir.join(base).is_file())
            .unwrap_or(false);
        if !paired_appledouble {
            count += 1;
        }
    }
    Ok(count)
}
fn apply_request(f: &mut AuthFixture, request: &[Fr]) {
    f.base.request.fields.copy_from_slice(request);
}
fn grant_ids(f: &AuthFixture) -> Vec<[u8; 32]> {
    f.all_grants.iter().map(|g| g.id()).collect()
}
fn original_grant_portfolio_digest(fixtures: &[&AuthFixture]) -> String {
    let mut hasher = Blake2s::new();
    hasher.update(b"HRADA-F-ORIGINAL-GRANT-PORTFOLIO-V1");
    for fixture in fixtures {
        for id in grant_ids(fixture) {
            hasher.update(&id);
        }
    }
    hex(&hasher.finalize())
}

fn run(e: &mut Evidence) -> Result<(), String> {
    fs::create_dir_all(&e.out).map_err(|x| x.to_string())?;
    let source_document = e.out.join("source_project_document_42.txt");
    let source_contents = b"Synthetic project document 42\nApproved asynchronous export example.\n";
    let mut source_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source_document)
        .map_err(|x| x.to_string())?;
    source_file
        .write_all(source_contents)
        .map_err(|x| x.to_string())?;
    source_file.sync_all().map_err(|x| x.to_string())?;
    let catalog = PepCatalog::new(&e.out);
    let selected_exports = e.out.join("selected_world_exports");
    let alternate_exports = e.out.join("alternate_world_exports");
    let intent_exports = e.out.join("intent_test_exports");
    let cp_setup_start = Instant::now();
    let cp = StateMembership::setup_os()?;
    let cp_setup_ms = milliseconds(cp_setup_start.elapsed())?;
    let state_init_start = Instant::now();
    let p_a = allocate_prime();
    let p_b = allocate_prime();
    let p_a_next = allocate_prime();
    let set = StateSet::rebuild(&[p_a.clone(), p_b.clone()])?;
    let state_init_ms = milliseconds(state_init_start.elapsed())?;
    let benchmark_seed = std::env::var("BENCHMARK_SEED")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    let fixture_seed = 2026102301u64
        .checked_add(benchmark_seed)
        .ok_or("benchmark seed overflow")?;
    let grant_prep_start = Instant::now();
    let mut a = AuthFixture::new(fixture_seed);
    let mut b = a.second_user(
        fixture_seed
            .checked_add(1)
            .ok_or("benchmark seed overflow")?,
    );
    let shared_grant_prep_ms = milliseconds(grant_prep_start.elapsed())?;
    let state_prime_binding_start = Instant::now();
    a.refresh_state(prime_fr(&p_a)?);
    b.refresh_state(prime_fr(&p_b)?);
    let pc_state_prime_binding_ms = milliseconds(state_prime_binding_start.elapsed())?;
    let original_grant_portfolio_digest_hex = original_grant_portfolio_digest(&[&a, &b]);

    // Business-admission checks are supplied by hrada_admission (the separate
    // root-grant policy gate), before a presentation is generated.
    let (authority, ledger, positive_native_admission_ms) = admission_checks(&a, &b, e)?;
    e.check(
        "pc_control_initialization_stages",
        true,
        json!({"cp_setup_ms":cp_setup_ms,"state_set_and_witness_init_ms":state_init_ms,
            "shared_grant_preparation_ms":shared_grant_prep_ms,
            "pc_state_prime_binding_ms":pc_state_prime_binding_ms,
            "positive_native_admission_ms":positive_native_admission_ms,
            "negative_admission_gates_timed":false,
            "original_grant_portfolio_digest_hex":original_grant_portfolio_digest_hex}),
    )?;

    let agent = [a.keys[5].0.x, a.keys[5].0.y];
    let job = ExportJob {
        job_id: "project-document-export-001",
        system: 1,
        verifier: 17,
        pep: 18,
        resource: 42,
        action: 1,
        request_time: 500,
        nonce: 99,
        expiry: 550,
        terminal: agent,
    };
    e.check(
        "pep_catalog_maps_export_to_document_42",
        catalog.resolve_export(&job)? == source_document.as_path(),
        json!({"resource":42,"action":1,"source":"source_project_document_42.txt"}),
    )?;
    let cp_bytes = cp.canonical_parameters()?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let setup_start = Instant::now();
    let link = hrada_link::setup(
        &mut OsRng,
        ck,
        ExperimentalAuthWithoutRequestHash(a.circuit()),
        16,
    )
    .map_err(|x| format!("authorization setup: {:?}", x))?;
    let setup_ms = milliseconds(setup_start.elapsed())?;
    let digest = hrada_link::parameter_digest(&link, &cp_bytes)
        .map_err(|x| format!("parameter digest: {:?}", x))?;
    fs::write(e.out.join("cp_public_parameters.bin"), &cp_bytes).map_err(|x| x.to_string())?;
    fs::write(
        e.out.join("authorization_verifying_key.bin"),
        enc(&link.proving_key.vk),
    )
    .map_err(|x| x.to_string())?;
    e.check(
        "real_joint_setup",
        true,
        json!({"auth_setup_ms":setup_ms,"parameters_digest":hex(&digest),
            "cp_parameters_bytes":cp_bytes.len(),
            "auth_vk_canonical_bytes":enc(&link.proving_key.vk).len(),
            "auth_pk_canonical_bytes_not_written":link.proving_key.serialized_size(),
            "auth_pk_retention":"omitted due size; VK, parameter digest and source manifest retained; exact randomized PK is unavailable after process exit"}),
    )?;
    let header = Header::new(set.accumulator.clone(), 1, &digest);
    let expected = job.expected_request(&header); // PEP-owned intent, before proof.
    apply_request(&mut a, &expected);
    apply_request(&mut b, &expected);
    e.check(
        "two_distinct_registered_users_same_public_intent",
        a.base.user_pk != b.base.user_pk
            && a.circuit().public_fields() == b.circuit().public_fields(),
        json!({"candidate_count":2,"visible_job":job.public_metadata(header.epoch),
            "source_user_in_job_metadata":false,"path_in_job_metadata":false}),
    )?;
    e.check(
        "dependent_path_initially_valid",
        circuit_satisfied(a.circuit_for("P"))?,
        json!({"path":"P","real_proof_generated":false}),
    )?;

    let proof_a = make_presentation(
        "user_a_independent_path",
        a.circuit_for("Q"),
        &p_a,
        &set,
        &cp,
        &link,
        &digest,
        e,
    )?;
    let proof_b = make_presentation(
        "user_b_independent_path",
        b.circuit_for("Q"),
        &p_b,
        &set,
        &cp,
        &link,
        &digest,
        e,
    )?;
    e.check(
        "same_public_q_distinct_source_commitments",
        proof_a.fields == expected
            && proof_b.fields == expected
            && proof_a.statement.c_e_q != proof_b.statement.c_e_q,
        json!({"same_header":true,"same_agent_resource_action_context_nonce":true,
            "distinct_commitments":true}),
    )?;
    let mut selected_verifier =
        JointVerifier::new(Header::new(set.accumulator.clone(), 1, &digest), digest);
    let mut alternative_verifier =
        JointVerifier::new(Header::new(set.accumulator.clone(), 1, &digest), digest);
    let selected_output = selected_exports.join("export_epoch1.txt");
    let selected = submit_and_export(
        &mut selected_verifier,
        &cp,
        &link,
        &proof_a,
        &job,
        &catalog,
        &selected_output,
    );
    e.check(
        "user_a_joint_proof_executes_document_export",
        selected.is_ok() && fs::read(&selected_output).ok().as_deref() == Some(source_contents),
        json!({"result":selected,"export_count":export_count(&selected_exports)?}),
    )?;
    let alternative_output = alternate_exports.join("export_epoch1.txt");
    let alternative = submit_and_export(
        &mut alternative_verifier,
        &cp,
        &link,
        &proof_b,
        &job,
        &catalog,
        &alternative_output,
    );
    e.check(
        "user_b_alternative_joint_proof_executes_document_export",
        alternative.is_ok()
            && fs::read(&alternative_output).ok().as_deref() == Some(source_contents),
        json!({"result":alternative,"verifier_snapshot":"independent",
            "export_count":export_count(&alternate_exports)?}),
    )?;
    let replay = submit_and_export(
        &mut selected_verifier,
        &cp,
        &link,
        &proof_a,
        &job,
        &catalog,
        &selected_exports.join("replayed_export.txt"),
    );
    let replay_exports = export_count(&selected_exports)?;
    e.check(
        "same_verifier_replay_rejected",
        replay == Err("nonce_already_consumed".into()) && replay_exports == 1,
        json!({"result":replay,"selected_export_count":replay_exports}),
    )?;

    // A different intended document must not be authorized by a proof for this
    // document, even though it is otherwise a well-formed request.
    let mut substituted = job.clone();
    substituted.resource = 43;
    let different_expected = substituted.expected_request(&header);
    let unknown_resource_exports = export_count(&selected_exports)?;
    e.check(
        "pep_catalog_rejects_unknown_resource",
        catalog.resolve_export(&substituted) == Err("pep_unknown_resource".into())
            && unknown_resource_exports == 1,
        json!({"requested_resource":43,"catalog_resource":42,
            "selected_export_count":unknown_resource_exports}),
    )?;
    e.check(
        "different_document_resource_is_publicly_distinguishable",
        expected[7] != different_expected[7],
        json!({"same_source_privacy_candidate_set":false,
            "reason":"resource is an intentional public request field"}),
    )?;
    let mut intent_verifier =
        JointVerifier::new(Header::new(set.accumulator.clone(), 1, &digest), digest);
    let wrong_intent = submit_and_export(
        &mut intent_verifier,
        &cp,
        &link,
        &proof_a,
        &substituted,
        &catalog,
        &intent_exports.join("wrong_document.txt"),
    );
    let wrong_intent_exports = export_count(&intent_exports)?;
    e.check(
        "pep_request_intent_substitution_rejected",
        wrong_intent == Err("request_mismatch".into()) && wrong_intent_exports == 0,
        json!({"result":wrong_intent,"actual_resource":42,"expected_resource":43,
            "export_count":wrong_intent_exports}),
    )?;
    let valid_after_failed_intent = submit_and_export(
        &mut intent_verifier,
        &cp,
        &link,
        &proof_a,
        &job,
        &catalog,
        &intent_exports.join("valid_after_failed_intent.txt"),
    );
    let intent_exports_after_valid = export_count(&intent_exports)?;
    e.check(
        "failed_intent_does_not_consume_nonce",
        valid_after_failed_intent.is_ok() && intent_exports_after_valid == 1,
        json!({"result":valid_after_failed_intent,"request":"original job",
            "export_count":intent_exports_after_valid}),
    )?;

    // Grants authorize action bit 2 as well, but the PEP's application catalog
    // offers only document export (bit 1). First prove action 2 cryptographically
    // in a separate verifier snapshot, then show the PEP blocks its file effect.
    let mut other_action = job.clone();
    other_action.action = 2;
    let other_action_expected = other_action.expected_request(&header);
    apply_request(&mut a, &other_action_expected);
    let action2_proof = make_presentation(
        "user_a_authorized_but_unsupported_action2",
        a.circuit_for("Q"),
        &p_a,
        &set,
        &cp,
        &link,
        &digest,
        e,
    )?;
    apply_request(&mut a, &expected);
    let cryptographic_action2 = submit(
        &mut JointVerifier::new(Header::new(set.accumulator.clone(), 1, &digest), digest),
        &cp,
        &link,
        &action2_proof,
        &other_action_expected,
        &other_action,
    );
    e.check(
        "action2_joint_proof_is_cryptographically_valid",
        cryptographic_action2.is_ok(),
        json!({"result":cryptographic_action2,"grant_action_mask":3,"requested_action":2}),
    )?;
    let mut policy_verifier =
        JointVerifier::new(Header::new(set.accumulator.clone(), 1, &digest), digest);
    let policy_rejected = submit_and_export(
        &mut policy_verifier,
        &cp,
        &link,
        &action2_proof,
        &other_action,
        &catalog,
        &selected_exports.join("unsupported_action2.txt"),
    );
    let policy_rejected_exports = export_count(&selected_exports)?;
    e.check(
        "pep_rejects_valid_proof_for_unsupported_action_without_export",
        policy_rejected == Err("pep_unsupported_action".into()) && policy_rejected_exports == 1,
        json!({"result":policy_rejected,"selected_export_count":policy_rejected_exports}),
    )?;
    let proof_after_policy_rejection = submit(
        &mut policy_verifier,
        &cp,
        &link,
        &action2_proof,
        &other_action_expected,
        &other_action,
    );
    let exports_after_policy_rejection = export_count(&selected_exports)?;
    e.check(
        "pep_policy_rejection_does_not_consume_verifier_nonce",
        proof_after_policy_rejection.is_ok() && exports_after_policy_rejection == 1,
        json!({"result":proof_after_policy_rejection,"requested_action":2,
            "selected_export_count":exports_after_policy_rejection}),
    )?;

    let epoch1_fixture = a.clone();
    let ids_before = grant_ids(&a);
    let signatures_before = a.grant_signatures;
    let sr_before = a.sr_signatures;
    let version_before = a.base.state_version;
    let root_before = a.base.auth_root;
    let prime_before = a.base.prime;
    a.close_issuers();
    e.check(
        "grant_issuers_offline_before_revocation",
        (0..5).all(|i| a.issuer_sign(i, [1; 32]).is_err()),
        json!({"original_grant_issuers_available":false}),
    )?;
    let update_refresh_start = Instant::now();
    a.revoke_middle(prime_fr(&p_a_next)?);
    let successor_admission = admit_state_roots(&authority, &ledger, &a.base, &a.all_grants, 500);
    e.check(
        "successor_state_business_admission_before_publication",
        successor_admission.is_ok(),
        json!({"receipts":successor_admission.as_ref().map(|v|v.len()).ok()}),
    )?;
    let new_set = StateSet::rebuild(&[p_a_next.clone(), p_b.clone()])?;
    let update_receipt_refresh_ms = milliseconds(update_refresh_start.elapsed())?;
    let new_header = Header::new(new_set.accumulator.clone(), 2, &digest);
    let mut next_job = job.clone();
    next_job.nonce = 100;
    let expected_next = next_job.expected_request(&new_header);
    apply_request(&mut a, &expected_next);
    e.check(
        "real_leaf_revocation_preserves_independent_grants",
        !a.all_grants[1].active
            && a.base.state_version == version_before + 1
            && a.base.auth_root != root_before
            && a.base.prime != prime_before
            && p_a != p_a_next
            && new_set.witness(&p_a).is_err()
            && new_set.witness(&p_a_next).is_ok()
            && a.sr_signatures == sr_before + 1
            && a.grant_signatures == signatures_before
            && grant_ids(&a) == ids_before,
        json!({"revoked_leaf_index":1,"old_state_prime_removed":true,
            "new_state_prime_admitted":true,"original_grant_signatures_retained":true}),
    )?;
    e.check(
        "middle_grant_update_receipt_and_membership_refresh_timing",
        true,
        json!({"epoch":2,"wall_ms":update_receipt_refresh_ms,
            "includes_sr_state_refresh":true,"includes_native_admission_receipt":true,
            "includes_cp_set_rebuild":true,"cp_witness_refresh":"included later in cp_prove API"}),
    )?;
    e.check(
        "revoked_dependent_path_constraints_reject",
        !circuit_satisfied(a.circuit_for("P"))?,
        json!({"path":"P","new_proof_generated":false}),
    )?;
    let stale = submit_and_export(
        &mut JointVerifier::new(Header::new(new_set.accumulator.clone(), 2, &digest), digest),
        &cp,
        &link,
        &proof_a,
        &next_job,
        &catalog,
        &selected_exports.join("stale_old_proof.txt"),
    );
    let stale_exports = export_count(&selected_exports)?;
    e.check(
        "old_joint_proof_rejected_under_successor_header",
        (stale == Err("request_mismatch".into()) || stale == Err("stale_header".into()))
            && stale_exports == 1,
        json!({"result":stale,"selected_export_count":stale_exports}),
    )?;
    // Verify stale-header specifically against the original expected request.
    let stale_exact = submit(
        &mut JointVerifier::new(Header::new(new_set.accumulator.clone(), 2, &digest), digest),
        &cp,
        &link,
        &proof_a,
        &expected,
        &job,
    );
    let stale_exact_exports = export_count(&selected_exports)?;
    e.check(
        "old_proof_fails_current_header",
        stale_exact == Err("stale_header".into()) && stale_exact_exports == 1,
        json!({"result":stale_exact,"selected_export_count":stale_exact_exports}),
    )?;
    let recovered = make_presentation(
        "user_a_recovered_independent_path",
        a.circuit_for("Q"),
        &p_a_next,
        &new_set,
        &cp,
        &link,
        &digest,
        e,
    )?;
    let mut successor_verifier =
        JointVerifier::new(Header::new(new_set.accumulator.clone(), 2, &digest), digest);
    let recovered_output = selected_exports.join("export_epoch2.txt");
    let recovered_result = submit_and_export(
        &mut successor_verifier,
        &cp,
        &link,
        &recovered,
        &next_job,
        &catalog,
        &recovered_output,
    );
    e.check(
        "independent_path_new_joint_proof_executes_second_export",
        recovered_result.is_ok()
            && recovered.fields == expected_next
            && fs::read(&recovered_output).ok().as_deref() == Some(source_contents)
            && export_count(&selected_exports)? == 2,
        json!({"result":recovered_result,"original_grants_resigned":false,
            "new_sr_signature_count":a.sr_signatures-sr_before,
            "selected_export_count":export_count(&selected_exports)?}),
    )?;

    // Three accepted, fresh-nonce repetitions per live epoch. Each request has
    // an independent verifier snapshot and reaches the same local commit/ACK
    // path used above.
    for (epoch, template, state_prime, state_set, epoch_header, nonce_base) in [
        (
            1u64,
            &epoch1_fixture,
            &p_a,
            &set,
            Header::new(set.accumulator.clone(), 1, &digest),
            1_001u64,
        ),
        (
            2u64,
            &a,
            &p_a_next,
            &new_set,
            Header::new(new_set.accumulator.clone(), 2, &digest),
            2_001u64,
        ),
    ] {
        for repetition in 0..3u64 {
            let mut fixture = template.clone();
            let mut repeated_job = job.clone();
            repeated_job.request_time = 500 + (epoch - 1);
            repeated_job.expiry = 550 + (epoch - 1);
            repeated_job.nonce = nonce_base + repetition;
            let repeated_expected = repeated_job.expected_request(&epoch_header);
            apply_request(&mut fixture, &repeated_expected);
            let label = format!("pc_epoch{}_repetition{}", epoch, repetition);
            let proof = make_presentation(
                &label,
                fixture.circuit_for("Q"),
                state_prime,
                state_set,
                &cp,
                &link,
                &digest,
                e,
            )?;
            let mut verifier = JointVerifier::new(
                Header::new(state_set.accumulator.clone(), epoch, &digest),
                digest,
            );
            let output = e
                .out
                .join("pc_control_exports")
                .join(format!("epoch{}_repetition{}.txt", epoch, repetition));
            let accepted = submit_and_export_measured(
                &mut verifier,
                &cp,
                &link,
                &proof,
                &repeated_job,
                &catalog,
                &output,
            );
            if accepted.is_ok() {
                let artifact_dir = e.out.join("pc_control_artifacts");
                fs::create_dir_all(&artifact_dir).map_err(|error| error.to_string())?;
                let public_fields = proof
                    .fields
                    .iter()
                    .map(|field| hex(&enc(field)))
                    .collect::<Vec<_>>();
                fs::write(
                    artifact_dir.join(format!(
                        "epoch{}_repetition{}_permit.json",
                        epoch, repetition
                    )),
                    serde_json::to_vec_pretty(&json!({"format":"HRADA-PC-PERMIT-V1",
                        "epoch":epoch,"nonce":repeated_job.nonce,"resource":repeated_job.resource,
                        "action":repeated_job.action,"complete_q":public_fields,
                        "parameters_digest":hex(&digest)}))
                    .unwrap(),
                )
                .map_err(|error| error.to_string())?;
                let exported = fs::read(&output).map_err(|error| error.to_string())?;
                fs::write(
                    artifact_dir.join(format!("epoch{}_repetition{}_ack.json", epoch, repetition)),
                    serde_json::to_vec_pretty(&json!({"format":"HRADA-PC-RESOURCE-ACK-V1",
                        "epoch":epoch,"nonce":repeated_job.nonce,"resource":repeated_job.resource,
                        "action":repeated_job.action,"export_path":output,
                        "export_blake2s":hex(&Blake2s::digest(&exported))}))
                    .unwrap(),
                )
                .map_err(|error| error.to_string())?;
            }
            e.check(
                &format!("pc_epoch{}_repetition{}_commit_ack", epoch, repetition),
                accepted.is_ok() && fs::read(&output).ok().as_deref() == Some(source_contents),
                json!({"epoch":epoch,"repetition":repetition,"nonce":repeated_job.nonce,
                    "joint_verify_and_nonce_commit_ms":accepted.as_ref().map(|timing|timing.joint_verify_and_nonce_commit_ms).ok(),
                    "resource_export_sync_ms":accepted.as_ref().map(|timing|timing.commit_ack_ms).ok(),
                    "uninstrumented_serial_total_ms":accepted.as_ref().map(|timing|timing.serial_total_ms).ok(),
                    "result":accepted.as_ref().map(|_|"ok").map_err(|error|error.as_str()),
                    "artifact":output}),
            )?;
        }
    }

    // Remove the final support for the selected terminal from both authentic
    // source archives. Issuer signatures and grant IDs remain unchanged.
    let a_ids_before_last = grant_ids(&a);
    let b_ids_before_last = grant_ids(&b);
    b.close_issuers();
    for fixture in [&mut a, &mut b] {
        for index in [2usize, 6, 7] {
            fixture.all_grants[index].active = false;
        }
        fixture.base.state_version += 1;
        fixture.base.request.fields[2] = Fr::from(3u64);
        fixture.base.transition = [6u8; 32];
        fixture.refresh_state(fixture.base.prime + Fr::one());
    }
    let no_support_a =
        !circuit_satisfied(a.circuit_for("Q"))? && !circuit_satisfied(a.circuit_for("short_Q"))?;
    let no_support_b =
        !circuit_satisfied(b.circuit_for("Q"))? && !circuit_satisfied(b.circuit_for("short_Q"))?;
    let final_admission_a = admit_state_roots(&authority, &ledger, &a.base, &a.all_grants, 500);
    let final_admission_b = admit_state_roots(&authority, &ledger, &b.base, &b.all_grants, 500);
    e.check(
        "last_shared_terminal_support_removed_without_resigning_grants",
        no_support_a
            && no_support_b
            && a_ids_before_last == grant_ids(&a)
            && b_ids_before_last == grant_ids(&b)
            && a.issuers_closed
            && b.issuers_closed
            && final_admission_a.is_ok()
            && final_admission_b.is_ok(),
        json!({"epoch":3,"eligible_terminal_paths":0,"ack_attempted":false,
            "original_grant_archives_preserved":true,"issuer_keys_offline":true,
            "admission_receipts":[final_admission_a.as_ref().map(|x|x.len()).ok(),
                final_admission_b.as_ref().map(|x|x.len()).ok()]}),
    )?;
    Ok(())
}

// Kept small so the application admits roots through the separately audited
// business-entitlement module before any expensive setup/proving occurs.
fn admission_checks(
    a: &AuthFixture,
    b: &AuthFixture,
    e: &mut Evidence,
) -> Result<(AdmissionAuthority, InMemoryEntitlementLedger, u64), String> {
    let authority =
        AdmissionAuthority::new(a.base.params.clone(), a.base.ra_pk, a.base.sr_pk, 1, 1);
    let entitled = |f: &AuthFixture| BusinessEntitlement {
        user_commitment: f.base.user_commitment(),
        system: 1,
        resource: 42,
        action_mask: 3,
        not_before: 0,
        not_after: 2000,
        active: true,
        max_delegation_depth: 2,
    };
    let ledger = InMemoryEntitlementLedger {
        records: vec![entitled(a), entitled(b)],
    };
    let positive_start = Instant::now();
    let accepted_a = admit_state_roots(&authority, &ledger, &a.base, &a.all_grants, 500);
    let accepted_b = admit_state_roots(&authority, &ledger, &b.base, &b.all_grants, 500);
    let positive_native_admission_ms = milliseconds(positive_start.elapsed())?;
    e.check(
        "two_business_entitlements_admit_both_users",
        accepted_a.is_ok() && accepted_b.is_ok(),
        json!({"user_a_receipts":accepted_a.as_ref().map(|v|v.len()).ok(),
            "user_b_receipts":accepted_b.as_ref().map(|v|v.len()).ok()}),
    )?;
    let mut wrong_resource = entitled(a);
    wrong_resource.resource = 43;
    let denied_resource = admit_state_roots(
        &authority,
        &InMemoryEntitlementLedger {
            records: vec![wrong_resource],
        },
        &a.base,
        &a.all_grants,
        500,
    );
    e.check(
        "unauthorized_root_resource_rejected",
        denied_resource.is_err(),
        json!({"granted_resource":42,"entitlement_resource":43,
            "error":denied_resource.err().map(|v|format!("{:?}",v))}),
    )?;
    let mut wrong_action = entitled(a);
    wrong_action.action_mask = 1;
    let denied_action = admit_state_roots(
        &authority,
        &InMemoryEntitlementLedger {
            records: vec![wrong_action],
        },
        &a.base,
        &a.all_grants,
        500,
    );
    e.check(
        "unauthorized_root_action_rejected",
        denied_action.is_err(),
        json!({"grant_action_mask":3,"entitlement_action_mask":1,
            "error":denied_action.err().map(|v|format!("{:?}",v))}),
    )?;
    Ok((authority, ledger, positive_native_admission_ms))
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 || args[1] != "--output" {
        eprintln!("usage: hrada_pc_full_f_control --output DIRECTORY");
        std::process::exit(2);
    }
    let output = PathBuf::from(&args[2]);
    if output.exists() {
        let empty = output.is_dir()
            && fs::read_dir(&output)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
        if !empty {
            eprintln!(
                "output must be a new or empty directory: {}",
                output.display()
            );
            std::process::exit(2);
        }
    }
    let mut evidence = Evidence {
        out: output,
        checks: vec![],
        proofs: vec![],
        status: "running",
        failure: None,
    };
    if let Err(err) = run(&mut evidence) {
        evidence.status = "failed";
        evidence.failure = Some(err.clone());
        let _ = evidence.save();
        eprintln!("{}", err);
        std::process::exit(1);
    }
    evidence.status = "complete";
    evidence.save().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn export_count_ignores_only_paired_appledouble_metadata() {
        let dir = std::env::temp_dir().join(format!(
            "hrada-export-count-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("export_epoch1.txt"), b"document").unwrap();
        fs::write(dir.join("._export_epoch1.txt"), b"appledouble").unwrap();
        assert_eq!(export_count(&dir).unwrap(), 1);
        fs::write(dir.join("._orphan.txt"), b"unexpected").unwrap();
        assert_eq!(export_count(&dir).unwrap(), 2);
        fs::write(dir.join("other_output.txt"), b"unexpected").unwrap();
        assert_eq!(export_count(&dir).unwrap(), 3);
        fs::remove_dir_all(&dir).unwrap();
    }
}
