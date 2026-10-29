//! E1 local recovery: real issuer process faults, matched proofs, monotonic permit checks.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::{PrimeField, UniformRand, Zero};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::{
    protocols::{
        hrada_auth::{AuthCircuit, AuthFixture},
        hrada_issuer_service::{serve_child, IssuerCluster},
        hrada_joint::{self, Header, JointVerifier},
        hrada_link::{self, LinkParameters},
        hrada_membership::{allocate_prime, CpProof, StateMembership, StateSet},
        hrada_poseidon_baseline::{parameter_descriptor, PoseidonMerkleState as MerkleState},
    },
    utils::integer_to_bigint_mod_q,
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    io::{Read, Write},
    path::PathBuf,
    time::Instant,
};
fn enc<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut b = vec![];
    x.serialize(&mut b).unwrap();
    b
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn fr(p: &Integer) -> Fr {
    integer_to_bigint_mod_q::<G1Projective>(p).unwrap()
}
fn random() -> Integer {
    Integer::from_digits(&enc(&Fr::rand(&mut OsRng)), Order::Lsf)
}
fn hash(b: &[u8]) -> [u8; 32] {
    let mut h = [0; 32];
    h.copy_from_slice(&Blake2s::digest(b));
    h
}
fn limbs(h: &[u8; 32]) -> [Fr; 2] {
    use ark_ff::PrimeField;
    [
        Fr::from_le_bytes_mod_order(&h[..16]),
        Fr::from_le_bytes_mod_order(&h[16..]),
    ]
}
fn sat(c: AuthCircuit) -> Result<bool, String> {
    let cs = ConstraintSystem::new_ref();
    c.generate_constraints(cs.clone())
        .map_err(|e| format!("{:?}", e))?;
    cs.is_satisfied().map_err(|e| format!("{:?}", e))
}
// Measured component encoding, not a deployed transport: each component u32 LE
// length-prefixed; integers signed magnitude (one sign byte + unsigned BE digits).
fn cp_components(p: &CpProof) -> Vec<u8> {
    let mut out = vec![];
    let mut put = |b: Vec<u8>| {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend(b);
    };
    for e in [
        &p.c_e,
        &p.proof_root.message1.c_w,
        &p.proof_root.message1.c_r,
        &p.proof_root.message2.alpha1,
        &p.proof_root.message2.alpha2,
        &p.proof_root.message2.alpha3,
        &p.proof_root.message2.alpha4,
        &p.proof_modeq.message1.alpha1,
    ]
    .iter()
    {
        put(Rsa2048::elem_to_bytes(e));
    }
    let a = &p.proof_root.message3;
    let b = &p.proof_modeq.message2;
    for i in [
        &a.s_e, &a.s_r, &a.s_r_2, &a.s_r_3, &a.s_beta, &a.s_delta, &b.s_e, &b.s_r,
    ]
    .iter()
    {
        let mut v = vec![if **i < Integer::from(0) { 1 } else { 0 }];
        v.extend((**i).clone().abs().to_digits::<u8>(Order::MsfBe));
        put(v);
    }
    put(enc(&p.proof_modeq.message1.alpha2));
    put(enc(&b.s_r_q));
    put(enc(&p.proof_hash_to_prime));
    out
}
#[derive(Clone)]
struct MHeader {
    root: [u8; 32],
    epoch: u64,
    digest: [u8; 32],
}
impl MHeader {
    fn new(root: [u8; 32], epoch: u64, params: &[u8; 32]) -> Self {
        let mut b = b"HRADA-POSEIDON-MERKLE-HEADER-V1".to_vec();
        b.extend(params);
        b.extend(epoch.to_le_bytes());
        b.extend(root);
        Self {
            root,
            epoch,
            digest: hash(&b),
        }
    }
}
struct MBundle {
    membership: legogro16::Proof<Bls12_381>,
    auth: legogro16::Proof<Bls12_381>,
    commitment: G1Projective,
    fields: Vec<Fr>,
    root: [Fr; 2],
    request_time: u64,
    permit_until: u64,
}
struct MVerifier {
    header: MHeader,
    consumed: HashSet<Vec<u8>>,
}
struct MParameters<'a> {
    cp: &'a StateMembership,
    auth: &'a LinkParameters,
    member: &'a LinkParameters,
    descriptor: Vec<u8>,
    member_digest: [u8; 32],
    auth_descriptor: Vec<u8>,
    digest: [u8; 32],
}
impl MVerifier {
    fn authorize<F: FnMut() -> u64>(
        &mut self,
        p: &MParameters,
        b: &MBundle,
        expected: &[Fr],
        request_time: u64,
        permit_until: u64,
        mut clock: F,
    ) -> Result<(), String> {
        if b.fields.len() != 16 || b.fields != expected {
            return Err("request_mismatch".into());
        }
        let q = &b.fields;
        let hd = limbs(&self.header.digest);
        if b.root != limbs(&self.header.root)
            || q[0] != hd[0]
            || q[1] != hd[1]
            || q[2] != Fr::from(self.header.epoch)
        {
            return Err("stale_header".into());
        }
        // Same independent interval binding as the CP verifier.
        if q[9] != Fr::from(request_time)
            || q[11] != Fr::from(permit_until)
            || request_time > permit_until
        {
            return Err("invalid_request_interval".into());
        }
        let before = clock();
        if before < request_time || before > permit_until {
            return Err("request_outside_validity".into());
        }
        let mut nonce = vec![];
        for i in [3, 5, 6, 10].iter() {
            nonce.extend(enc(&q[*i]));
        }
        if self.consumed.contains(&nonce) {
            return Err("nonce_already_consumed".into());
        }
        let ck = &p.cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
        if !hrada_link::verify(
            p.member,
            ck,
            &p.descriptor,
            &p.member_digest,
            &b.membership,
            &b.root,
            &b.commitment,
        )
        .map_err(|e| format!("{:?}", e))?
        {
            return Err("member_link_rejected".into());
        }
        if !hrada_link::verify(
            p.auth,
            ck,
            &p.auth_descriptor,
            &p.digest,
            &b.auth,
            q,
            &b.commitment,
        )
        .map_err(|e| format!("{:?}", e))?
        {
            return Err("authorization_link_rejected".into());
        }
        let end = clock();
        if end < before || end > permit_until {
            return Err("expired_before_commit".into());
        }
        self.consumed.insert(nonce);
        Ok(())
    }
}
fn mver(h: &MHeader) -> MVerifier {
    MVerifier {
        header: h.clone(),
        consumed: HashSet::new(),
    }
}
struct CBundle {
    statement: cpsnarks_set::protocols::hrada_membership::CpStatement,
    membership: CpProof,
    auth: legogro16::Proof<Bls12_381>,
    fields: Vec<Fr>,
    request_time: u64,
    permit_until: u64,
}

struct Log {
    dir: PathBuf,
    fault: String,
    origin: Instant,
    service_origin: Option<Instant>,
    checks: Vec<Value>,
    samples: Vec<Value>,
    events: Vec<Value>,
    setup: Value,
    nonce: u64,
    executions: usize,
}
impl Log {
    fn now(&self) -> u64 {
        500 + self
            .service_origin
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0)
    }
    fn save(&self, status: &str, failure: Option<&str>) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(&json!({
            "status":status,"failure":failure,"fault":self.fault,
            "checks":self.checks,"samples":self.samples,"events":self.events,"setup":self.setup,
            "elapsed_ms":ms(self.origin),"real_joint_proofs":self.samples.len(),"resource_executions":self.executions,
            "scope":"single trusted parent SR/prover/verifier/PEP; two users' original issuers are ten child processes; no distributed service or network transport claim",
            "clock":"logical seconds = 500 + floor(real monotonic elapsed since service-ready); per-request permit 120 seconds; no frozen verifier clock",
            "expected_joint_proofs":6,"configured_lambda_s":125,"effective_fs_challenge_bits":120
        })).map_err(|e| e.to_string())?;
        fs::write(self.dir.join("results.json.tmp"), bytes).map_err(|e| e.to_string())?;
        fs::rename(
            self.dir.join("results.json.tmp"),
            self.dir.join("results.json"),
        )
        .map_err(|e| e.to_string())
    }
    fn event(&mut self, kind: &str, details: Value) -> Result<(), String> {
        self.events.push(json!({"seq":self.events.len(),"event":kind,"elapsed_ms":ms(self.origin),"logical_time":self.now(),"details":details}));
        self.save("running", None)
    }
    fn check(&mut self, id: &str, pass: bool) -> Result<(), String> {
        println!("{} {}", if pass { "PASS" } else { "FAIL" }, id);
        self.checks
            .push(json!({"id":id,"pass":pass,"elapsed_ms":ms(self.origin)}));
        self.save("running", None)?;
        if pass {
            Ok(())
        } else {
            Err(format!("check_failed:{}", id))
        }
    }
    fn request(&mut self, scheme: &str, name: &str) -> Result<(u64, u64, u64), String> {
        let now = self.now();
        if now + 120 > 1000 {
            return Err("trial_time_budget_exhausted_before_submission".into());
        }
        self.nonce = self.nonce.checked_add(1).ok_or("nonce_overflow")?;
        self.event("request_queued",json!({"scheme":scheme,"case":name,"nonce":self.nonce,"request_time":now,"permit_until":now+120,"queue_model":"immediate sequential local dispatch"}))?;
        Ok((now, now + 120, self.nonce))
    }
    // Actual local append is the resource operation. Only call after authorize Ok.
    fn execute(&mut self, scheme: &str, name: &str, nonce: u64) -> Result<(), String> {
        let row = json!({"execution":self.executions,"scheme":scheme,"case":name,"nonce":nonce,"logical_time":self.now(),"elapsed_ms":ms(self.origin),"operation":"append_authorized_resource_access"});
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("resource_executions.jsonl"))
            .map_err(|e| e.to_string())?;
        writeln!(f, "{}", row).map_err(|e| e.to_string())?;
        f.sync_data().map_err(|e| e.to_string())?;
        self.executions += 1;
        self.event("resource_executed", row)
    }
}
fn artifact<T: CanonicalSerialize>(
    dir: &std::path::Path,
    name: &str,
    key: &T,
) -> Result<Value, String> {
    let path = dir.join(name);
    let mut f = fs::File::create(&path).map_err(|e| e.to_string())?;
    key.serialize(&mut f).map_err(|e| format!("{:?}", e))?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    file_hash(&path)
}
fn file_hash(path: &std::path::Path) -> Result<Value, String> {
    let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = Blake2s::new();
    let mut b = vec![0u8; 1024 * 1024];
    let mut size = 0;
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
        size += n;
    }
    Ok(
        json!({"file":path.file_name().unwrap().to_string_lossy(),"bytes":size,"blake2s":hex(&h.finalize())}),
    )
}
fn bind(c: &mut AuthCircuit, header: [Fr; 2], epoch: u64, start: u64, end: u64, nonce: u64) {
    c.request.fields[0] = header[0];
    c.request.fields[1] = header[1];
    c.request.fields[2] = Fr::from(epoch);
    c.request.fields[9] = Fr::from(start);
    c.request.fields[10] = Fr::from(nonce);
    c.request.fields[11] = Fr::from(end);
}
fn cp_request(
    log: &mut Log,
    name: &str,
    f: &AuthFixture,
    path: &str,
    prime: &Integer,
    set: &StateSet,
    cp: &StateMembership,
    auth: &LinkParameters,
    digest: &[u8; 32],
    v: &mut JointVerifier,
) -> Result<CBundle, String> {
    let (start, end, nonce) = log.request("cp_rsa", name)?;
    let origin = Instant::now();
    log.event(
        "request_dispatched",
        json!({"scheme":"cp_rsa","case":name,"nonce":nonce}),
    )?;
    let t = Instant::now();
    let mut c = f.circuit_for(path);
    bind(
        &mut c,
        v.header.digest_fields(),
        v.header.epoch,
        start,
        end,
        nonce,
    );
    let fields = c.public_fields();
    let r = random();
    let prep = ms(t);
    log.event(
        "prepare_completed",
        json!({"scheme":"cp_rsa","case":name,"ms":prep}),
    )?;
    let ctx = hrada_joint::context(digest, &fields)?;
    let t = Instant::now();
    let (statement, membership) = cp.prove(set, prime, &r, &ctx)?;
    let member_ms = ms(t);
    log.event(
        "membership_proved",
        json!({"scheme":"cp_rsa","case":name,"ms":member_ms}),
    )?;
    let t = Instant::now();
    let proof =
        hrada_link::prove(&mut OsRng, auth, c, &r).map_err(|e| format!("auth_prove:{:?}", e))?;
    let auth_ms = ms(t);
    log.event(
        "authorization_proved",
        json!({"scheme":"cp_rsa","case":name,"ms":auth_ms}),
    )?;
    let t = Instant::now();
    v.authorize(
        cp,
        auth,
        &statement,
        &membership,
        &proof,
        &fields,
        &fields,
        start,
        end,
        || log.now(),
    )
    .map_err(|e| format!("valid_cp_request_failed:{}", e))?;
    let verify_ms = ms(t);
    log.event(
        "permit_committed",
        json!({"scheme":"cp_rsa","case":name,"nonce":nonce,"ms":verify_ms}),
    )?;
    log.execute("cp_rsa", name, nonce)?;
    let member = cp_components(&membership);
    let ab = enc(&proof);
    fs::write(log.dir.join(format!("cp-{}-member.bin", name)), &member)
        .map_err(|e| e.to_string())?;
    fs::write(log.dir.join(format!("cp-{}-auth.bin", name)), &ab).map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"cp_rsa","case":name,"nonce":nonce,"request_time":start,"permit_until":end,"prepare_ms":prep,"membership_ms":member_ms,"auth_ms":auth_ms,"verify_ms":verify_ms,"through_resource_execution_and_artifact_ms":ms(origin),"member_bytes":member.len(),"auth_bytes":ab.len(),"commitment_hex":hex(&enc(&statement.c_e_q)),"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&statement.c_p)),"public_fields":fields.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>(),"accepted":true}));
    log.save("running", None)?;
    let count = log.executions;
    let err = v
        .authorize(
            cp,
            auth,
            &statement,
            &membership,
            &proof,
            &fields,
            &fields,
            start,
            end,
            || log.now(),
        )
        .err();
    log.check(
        &format!("cp_{}_replay_rejected", name),
        err.as_deref() == Some("nonce_already_consumed"),
    )?;
    log.check(
        &format!("cp_{}_replay_no_resource_execution", name),
        log.executions == count,
    )?;
    Ok(CBundle {
        statement,
        membership,
        auth: proof,
        fields,
        request_time: start,
        permit_until: end,
    })
}
fn mt_request(
    log: &mut Log,
    name: &str,
    f: &AuthFixture,
    path: &str,
    prime: &Integer,
    set: &MerkleState,
    p: &MParameters,
    v: &mut MVerifier,
) -> Result<MBundle, String> {
    let (start, end, nonce) = log.request("poseidon_lego", name)?;
    let origin = Instant::now();
    log.event(
        "request_dispatched",
        json!({"scheme":"poseidon_lego","case":name,"nonce":nonce}),
    )?;
    let t = Instant::now();
    let mut c = f.circuit_for(path);
    bind(
        &mut c,
        limbs(&v.header.digest),
        v.header.epoch,
        start,
        end,
        nonce,
    );
    let fields = c.public_fields();
    let r = random();
    let prep = ms(t);
    log.event(
        "prepare_completed",
        json!({"scheme":"poseidon_lego","case":name,"ms":prep}),
    )?;
    let t = Instant::now();
    let commitment = p.cp.commit(prime, &r)?;
    let membership = hrada_link::prove(&mut OsRng, p.member, set.circuit(prime)?, &r)
        .map_err(|e| format!("member_prove:{:?}", e))?;
    let member_ms = ms(t);
    log.event(
        "membership_proved",
        json!({"scheme":"poseidon_lego","case":name,"ms":member_ms}),
    )?;
    let t = Instant::now();
    let auth =
        hrada_link::prove(&mut OsRng, p.auth, c, &r).map_err(|e| format!("auth_prove:{:?}", e))?;
    let auth_ms = ms(t);
    log.event(
        "authorization_proved",
        json!({"scheme":"poseidon_lego","case":name,"ms":auth_ms}),
    )?;
    let b = MBundle {
        membership,
        auth,
        commitment,
        fields,
        root: set.root_fields(),
        request_time: start,
        permit_until: end,
    };
    let t = Instant::now();
    v.authorize(p, &b, &b.fields, start, end, || log.now())
        .map_err(|e| format!("valid_merkle_request_failed:{}", e))?;
    let verify_ms = ms(t);
    log.event(
        "permit_committed",
        json!({"scheme":"poseidon_lego","case":name,"nonce":nonce,"ms":verify_ms}),
    )?;
    log.execute("poseidon_lego", name, nonce)?;
    let mb = enc(&b.membership);
    let ab = enc(&b.auth);
    fs::write(log.dir.join(format!("poseidon-{}-member.bin", name)), &mb)
        .map_err(|e| e.to_string())?;
    fs::write(log.dir.join(format!("poseidon-{}-auth.bin", name)), &ab)
        .map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"poseidon_lego","case":name,"nonce":nonce,"request_time":start,"permit_until":end,"prepare_ms":prep,"membership_ms":member_ms,"auth_ms":auth_ms,"verify_ms":verify_ms,"through_resource_execution_and_artifact_ms":ms(origin),"member_bytes":mb.len(),"auth_bytes":ab.len(),"commitment_hex":hex(&enc(&b.commitment)),"root_fields":b.root.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>(),"public_fields":b.fields.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>(),"accepted":true}));
    log.save("running", None)?;
    let count = log.executions;
    let err = v
        .authorize(p, &b, &b.fields, start, end, || log.now())
        .err();
    log.check(
        &format!("poseidon_{}_replay_rejected", name),
        err.as_deref() == Some("nonce_already_consumed"),
    )?;
    log.check(
        &format!("poseidon_{}_replay_no_resource_execution", name),
        log.executions == count,
    )?;
    Ok(b)
}

fn bootstrap(f: &mut AuthFixture, cluster: &mut IssuerCluster) -> Result<(), String> {
    let map = [
        (None, 0usize),
        (Some(0usize), 1),
        (Some(1), 2),
        (Some(1), 2),
        (None, 0),
        (Some(4), 3),
        (Some(5), 4),
        (Some(4), 3),
    ];
    for (i, (parent, issuer)) in map.iter().enumerate() {
        f.all_grants[i].parent = parent
            .map(|p| f.all_grants[p].id())
            .unwrap_or_else(|| f.base.reg_hash());
        let msg = f.all_grants[i].core();
        f.all_grants[i].signature = cluster.sign(*issuer, msg)?;
    }
    f.refresh_state(f.base.prime);
    f.close_issuers();
    Ok(())
}
fn original_ids(f: &AuthFixture) -> Vec<[u8; 32]> {
    f.all_grants.iter().map(|g| g.id()).collect()
}
fn protocol_signs(c: &IssuerCluster) -> u64 {
    c.counters().iter().map(|x| x.protocol_signatures).sum()
}
fn run(log: &mut Log, order: &str) -> Result<(), String> {
    log.event(
        "initialization_started",
        json!({"order":order,"fresh_setup_each_trial":true}),
    )?;
    let primes = (0..8).map(|_| allocate_prime()).collect::<Vec<_>>();
    let newp = allocate_prime();
    // Random fixture seeds are never logged, persisted or passed as process argv.
    let mut f = AuthFixture::new(OsRng.next_u64() >> 1);
    f.refresh_state(fr(&primes[0]));
    let mut other = f.second_user(OsRng.next_u64() >> 1);
    other.refresh_state(fr(&primes[1]));
    let mut issuers = IssuerCluster::spawn(&f)?;
    let mut other_issuers = IssuerCluster::spawn(&other)?;
    bootstrap(&mut f, &mut issuers)?;
    bootstrap(&mut other, &mut other_issuers)?;
    log.check(
        "sixteen_original_grants_signed_by_child_processes",
        protocol_signs(&issuers) == 8 && protocol_signs(&other_issuers) == 8,
    )?;
    log.check(
        "parent_original_issuer_key_slots_zeroed",
        f.keys[..5].iter().all(|k| k.1 .0.is_zero())
            && other.keys[..5].iter().all(|k| k.1 .0.is_zero()),
    )?;
    let ids = original_ids(&f);
    let other_ids = original_ids(&other);
    let initial_sr = f.sr_signatures;
    let other_sr = other.sr_signatures;
    log.event("issuer_bootstrap_completed",json!({"primary":issuers.counters(),"other_user":other_issuers.counters(),"secret_boundary":"original issuer key slots zeroed in parent fixture; parent retains SR/RA fixture material and terminal keys; no physical erasure claim"}))?;
    let set = StateSet::rebuild(&primes)?;
    let mt = MerkleState::new(&primes)?;
    let t = Instant::now();
    let cp = StateMembership::setup_os()?;
    let cp_setup = ms(t);
    let cpbytes = cp.canonical_parameters()?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    println!("SETUP fresh shared authorization CRS");
    let t = Instant::now();
    let auth = hrada_link::setup(&mut OsRng, ck, f.circuit(), 16)
        .map_err(|e| format!("setup_auth:{:?}", e))?;
    let auth_setup = ms(t);
    let cpdigest = hrada_link::parameter_digest(&auth, &cpbytes).map_err(|e| format!("{:?}", e))?;
    let t = Instant::now();
    let member = hrada_link::setup(&mut OsRng, ck, mt.circuit(&primes[0])?, 2)
        .map_err(|e| format!("setup_member:{:?}", e))?;
    let member_setup = ms(t);
    let mut descriptor = b"HRADA-POSEIDON-MERKLE-LEGO-DEPTH4-V1".to_vec();
    descriptor.extend(parameter_descriptor());
    descriptor.extend(enc(&ck.g));
    descriptor.extend(enc(&ck.h));
    let md = hrada_link::parameter_digest(&member, &descriptor).map_err(|e| format!("{:?}", e))?;
    let mut ad = b"HRADA-POSEIDON-MERKLE-AUTH-V1".to_vec();
    ad.extend(md);
    let digest = hrada_link::parameter_digest(&auth, &ad).map_err(|e| format!("{:?}", e))?;
    let mp = MParameters {
        cp: &cp,
        auth: &auth,
        member: &member,
        descriptor,
        member_digest: md,
        auth_descriptor: ad,
        digest,
    };
    fs::write(log.dir.join("cp_parameters.bin"), &cpbytes).map_err(|e| e.to_string())?;
    fs::write(log.dir.join("poseidon_descriptor.bin"), &mp.descriptor)
        .map_err(|e| e.to_string())?;
    let mut artifacts = vec![
        artifact(&log.dir, "shared_auth_pk.bin", &auth.proving_key)?,
        artifact(&log.dir, "poseidon_member_pk.bin", &member.proving_key)?,
        artifact(
            &log.dir,
            "cp_range_pk.bin",
            &cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters,
        )?,
        file_hash(&log.dir.join("cp_parameters.bin"))?,
        file_hash(&log.dir.join("poseidon_descriptor.bin"))?,
    ];
    artifacts.push(artifact(
        &log.dir,
        "shared_auth_vk.bin",
        &auth.proving_key.vk,
    )?);
    log.setup = json!({"order":order,"cp_setup_ms":cp_setup,"shared_auth_setup_ms":auth_setup,"poseidon_member_setup_ms":member_setup,"artifacts":artifacts,"cp_digest":hex(&cpdigest),"poseidon_digest":hex(&digest),"shared_auth_vk_blake2s":hex(&hash(&enc(&auth.proving_key.vk))),"population":8,"poseidon_depth":4,"auth_constraints":2140389});
    log.check(
        "same_authorization_pk_object_both_backends",
        std::ptr::eq(&auth, mp.auth),
    )?;
    log.service_origin = Some(Instant::now());
    log.event("service_ready",json!({"order":order,"issuer_primary":issuers.counters(),"issuer_other":other_issuers.counters()}))?;
    log.check("pre_P_constraint_positive_only", sat(f.circuit_for("P"))?)?;
    log.check(
        "pre_Z_constraint_positive_only",
        sat(other.circuit_for("Q"))?,
    )?;
    let mut cv = JointVerifier::new(Header::new(set.accumulator.clone(), 1, &cpdigest), cpdigest);
    let mut mv = mver(&MHeader::new(mt.root(), 1, &digest));
    let (old_cp, old_mt) = if order == "cp_first" {
        let c = cp_request(
            log, "before_Q", &f, "Q", &primes[0], &set, &cp, &auth, &cpdigest, &mut cv,
        )?;
        let m = mt_request(log, "before_Q", &f, "Q", &primes[0], &mt, &mp, &mut mv)?;
        (c, m)
    } else {
        let m = mt_request(log, "before_Q", &f, "Q", &primes[0], &mt, &mp, &mut mv)?;
        let c = cp_request(
            log, "before_Q", &f, "Q", &primes[0], &set, &cp, &auth, &cpdigest, &mut cv,
        )?;
        (c, m)
    };
    log.check(
        "all_ten_issuers_healthy_before_fault",
        issuers.check_live()?.iter().all(|x| *x) && other_issuers.check_live()?.iter().all(|x| *x),
    )?;
    log.event("fault_injection_started", json!({"fault":log.fault}))?;
    match log.fault.as_str() {
        "online" => {}
        "one_offline" => {
            issuers.stop_one(3)?;
        }
        "all_offline" => {
            issuers.stop_all()?;
            other_issuers.stop_all()?;
        }
        _ => return Err("unknown_fault".into()),
    }
    let alive = issuers.check_live()?;
    let other_alive = other_issuers.check_live()?;
    let wanted = match log.fault.as_str() {
        "online" => 10,
        "one_offline" => 9,
        _ => 0,
    };
    log.check(
        "fault_process_liveness_matches",
        alive
            .iter()
            .chain(other_alive.iter())
            .filter(|x| **x)
            .count()
            == wanted,
    )?;
    log.event("fault_injected",json!({"primary_alive":alive,"other_alive":other_alive,"primary":issuers.counters(),"other":other_issuers.counters()}))?;
    let signs = (protocol_signs(&issuers), protocol_signs(&other_issuers));
    let t = Instant::now();
    f.revoke_middle(fr(&newp));
    let sr_refresh = ms(t);
    let mut updated = primes.clone();
    updated[0] = newp.clone();
    let t = Instant::now();
    let newset = StateSet::rebuild(&updated)?;
    let cp_update = ms(t);
    let t = Instant::now();
    let mut newmt = mt.clone();
    newmt.replace(0, newp.clone())?;
    let mt_update = ms(t);
    cv.replace_header(Header::new(newset.accumulator.clone(), 2, &cpdigest))?;
    mv.header = MHeader::new(newmt.root(), 2, &digest);
    log.event("state_committed",json!({"epoch":2,"shared_sr_refresh_ms":sr_refresh,"cp_state_update_ms":cp_update,"poseidon_state_update_ms":mt_update,"local_atomic_scope":"single parent sequential state transition, no distributed CAS"}))?;
    let before_negative = log.executions;
    log.check("revoked_P_constraint_rejected", !sat(f.circuit_for("P"))?)?;
    log.check("revoked_P2_constraint_rejected", !sat(f.circuit_for("P2"))?)?;
    log.check("cp_old_prime_removed", newset.witness(&primes[0]).is_err())?;
    log.check(
        "poseidon_old_prime_removed",
        newmt.circuit(&primes[0]).is_err(),
    )?;
    let err = cv
        .authorize(
            &cp,
            &auth,
            &old_cp.statement,
            &old_cp.membership,
            &old_cp.auth,
            &old_cp.fields,
            &old_cp.fields,
            old_cp.request_time,
            old_cp.permit_until,
            || log.now(),
        )
        .err();
    log.check(
        "cp_old_bundle_rejected_by_current_header",
        err.as_deref() == Some("stale_header"),
    )?;
    let err = mv
        .authorize(
            &mp,
            &old_mt,
            &old_mt.fields,
            old_mt.request_time,
            old_mt.permit_until,
            || log.now(),
        )
        .err();
    log.check(
        "poseidon_old_bundle_rejected_by_current_header",
        err.as_deref() == Some("stale_header"),
    )?;
    log.check(
        "all_revocation_negatives_no_resource_execution",
        log.executions == before_negative,
    )?;
    // Each backend's service window starts immediately before its Q/Z queue.
    // Shared state-commit-to-completion includes experiment ordering, not a fair latency comparison.
    for scheme in if order == "cp_first" {
        ["cp_rsa", "poseidon_lego"]
    } else {
        ["poseidon_lego", "cp_rsa"]
    }
    .iter()
    {
        let t = Instant::now();
        log.event("backend_recovery_started",json!({"scheme":scheme,"order":order,"reason":"independent local dispatch origin; excludes other backend's deliberate experiment queue"}))?;
        if *scheme == "cp_rsa" {
            cp_request(
                log, "after_Q", &f, "Q", &newp, &newset, &cp, &auth, &cpdigest, &mut cv,
            )?;
            cp_request(
                log, "after_Z", &other, "Q", &primes[1], &newset, &cp, &auth, &cpdigest, &mut cv,
            )?;
        } else {
            mt_request(log, "after_Q", &f, "Q", &newp, &newmt, &mp, &mut mv)?;
            mt_request(
                log, "after_Z", &other, "Q", &primes[1], &newmt, &mp, &mut mv,
            )?;
        }
        log.event("backend_recovery_completed",json!({"scheme":scheme,"dispatch_to_both_resources_ms":ms(t),"excludes_other_backend_queue":true}))?;
    }
    log.check(
        "original_grant_ids_and_signatures_unchanged",
        original_ids(&f) == ids && original_ids(&other) == other_ids,
    )?;
    log.check(
        "exactly_one_primary_sr_refresh",
        f.sr_signatures == initial_sr + 1,
    )?;
    log.check("other_user_no_sr_refresh", other.sr_signatures == other_sr)?;
    log.check(
        "zero_recovery_protocol_signatures",
        signs == (protocol_signs(&issuers), protocol_signs(&other_issuers)),
    )?;
    let final_alive = issuers.check_live()?;
    let final_other = other_issuers.check_live()?;
    log.check(
        "issuer_availability_unchanged_through_recovery",
        final_alive == alive && final_other == other_alive,
    )?;
    log.check(
        "six_real_joint_proofs_and_resource_executions",
        log.samples.len() == 6 && log.executions == 6,
    )?;
    log.check(
        "service_trial_under_500_monotonic_seconds",
        log.now() < 1000,
    )?;
    log.event("recovery_finished",json!({"primary":issuers.counters(),"other":other_issuers.counters(),"primary_sr_signatures":f.sr_signatures,"other_sr_signatures":other.sr_signatures,"padding_signatures":f.padding_signatures.get()+other.padding_signatures.get(),"original_grants_signature_fixture_counter":f.grant_signatures+other.grant_signatures,"child_protocol_signatures":protocol_signs(&issuers)+protocol_signs(&other_issuers)}))?;
    issuers.stop_all()?;
    other_issuers.stop_all()?;
    log.event(
        "issuer_cleanup_completed",
        json!({"primary":issuers.counters(),"other":other_issuers.counters()}),
    )?;
    Ok(())
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    if args.iter().any(|a| a == "--issuer-child") {
        if let Err(e) = serve_child() {
            eprintln!("issuer child terminated: {}", e);
            std::process::exit(1);
        }
        return;
    }
    let value = |key: &str| -> Option<String> {
        args.windows(2).find(|w| w[0] == key).map(|w| w[1].clone())
    };
    let fault = value("--fault").unwrap_or_else(|| "online".into());
    let order = value("--order").unwrap_or_else(|| "cp_first".into());
    if !["online", "one_offline", "all_offline"].contains(&fault.as_str())
        || !["cp_first", "poseidon_first"].contains(&order.as_str())
    {
        eprintln!("invalid fault or order");
        std::process::exit(2);
    }
    let dir = match value("--output-dir") {
        Some(x) => PathBuf::from(x),
        None => {
            eprintln!("required --output-dir <new directory>");
            std::process::exit(2)
        }
    };
    if dir.exists() {
        eprintln!("output directory already exists; refusing overwrite");
        std::process::exit(2);
    }
    fs::create_dir_all(&dir).unwrap();
    let mut log = Log {
        dir,
        fault,
        origin: Instant::now(),
        service_origin: None,
        checks: vec![],
        samples: vec![],
        events: vec![],
        setup: json!({}),
        nonce: 100,
        executions: 0,
    };
    log.save("running", None).unwrap();
    match run(&mut log, &order) {
        Ok(()) => {
            log.save("complete", None).unwrap();
            println!(
                "DONE {} checks, {} actual joint proofs, {} resource executions",
                log.checks.len(),
                log.samples.len(),
                log.executions
            );
        }
        Err(e) => {
            log.save("failed", Some(&e)).unwrap();
            eprintln!("FAILED {}", e);
            std::process::exit(1);
        }
    }
}
