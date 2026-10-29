//! Three-layer experiment, full pipeline layer; frozen 5 repetitions per main case.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::{One, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::{
    protocols::{
        hrada_auth::{AuthCircuit, AuthFixture},
        hrada_joint::{self, Header, JointVerifier},
        hrada_link::{self, LinkParameters},
        hrada_membership::{allocate_prime, CpProof, StateMembership, StateSet},
        hrada_merkle_baseline::MerkleState,
    },
    utils::integer_to_bigint_mod_q,
};
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
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
struct Log {
    dir: PathBuf,
    checks: Vec<Value>,
    samples: Vec<Value>,
    lifecycle: Vec<Value>,
    setup: Value,
}
impl Log {
    fn save(&self, status: &str, failure: Option<&str>) -> Result<(), String> {
        fs::write(self.dir.join("results.json"),serde_json::to_vec_pretty(&json!({"status":status,"failure":failure,"checks":self.checks,"samples":self.samples,"lifecycle":self.lifecycle,"setup":self.setup,"scope":"matched AuthCircuit/Auth PK; 3 private grant slots; depth-4 global Merkle vs CP-RSA; local serial trusted state","repetitions":5,"publication_grade_scaling":false})).unwrap()).map_err(|e|e.to_string())
    }
    fn check(&mut self, id: &str, ok: bool) -> Result<(), String> {
        println!("{} {}", if ok { "PASS" } else { "FAIL" }, id);
        self.checks.push(json!({"id":id,"pass":ok}));
        self.save("running", None)?;
        if ok {
            Ok(())
        } else {
            Err(id.into())
        }
    }
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
        let mut b = b"HRADA-MERKLE-HEADER-V1".to_vec();
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
        // Matched experimental request interval, independently checked as in CP verifier.
        if q[9] != Fr::from(500u64) || q[11] != Fr::from(550u64) {
            return Err("invalid_request_interval".into());
        }
        let before = clock();
        if before < 500 || before > 550 {
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
        if end < before || end > 550 {
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
}
fn cp_trial(
    log: &mut Log,
    name: &str,
    rep: usize,
    f: &AuthFixture,
    path: &str,
    prime: &Integer,
    set: &StateSet,
    cp: &StateMembership,
    link: &LinkParameters,
    digest: &[u8; 32],
    epoch: u64,
) -> Result<CBundle, String> {
    println!("PROVE CP {} {}", name, rep);
    let h = Header::new(set.accumulator.clone(), epoch, digest);
    let total = Instant::now();
    let t = Instant::now();
    let mut c = f.circuit_for(path);
    let hd = h.digest_fields();
    c.request.fields[0] = hd[0];
    c.request.fields[1] = hd[1];
    c.request.fields[2] = Fr::from(epoch);
    c.request.fields[10] = Fr::from(99 + rep as u64);
    let fields = c.public_fields();
    let prepare = ms(t);
    let r = random();
    let ctx = hrada_joint::context(digest, &fields)?;
    let t = Instant::now();
    let (s, proof) = cp.prove(set, prime, &r, &ctx)?;
    let member_ms = ms(t);
    let t = Instant::now();
    let auth = hrada_link::prove(&mut OsRng, link, c, &r).map_err(|e| format!("{:?}", e))?;
    let auth_ms = ms(t);
    let prove_ms = ms(total);
    let mut v = JointVerifier::new(Header::new(set.accumulator.clone(), epoch, digest), *digest);
    let t = Instant::now();
    v.authorize(
        cp,
        link,
        &s,
        &proof,
        &auth,
        &fields,
        &fields,
        500,
        550,
        || 500,
    )?;
    let verify_ms = ms(t);
    let cb = cp_components(&proof);
    let ab = enc(&auth);
    let commitment = enc(&s.c_e_q);
    let prefix = format!("cp-{}-{}", name, rep);
    fs::write(log.dir.join(format!("{}-member.bin", prefix)), &cb).map_err(|e| e.to_string())?;
    fs::write(log.dir.join(format!("{}-auth.bin", prefix)), &ab).map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"cp_rsa","case":name,"rep":rep,"prepare_ms":prepare,"membership_prove_including_witness_ms":member_ms,"authorization_prove_including_precheck_ms":auth_ms,"prove_total_ms":prove_ms,"verify_total_ms":verify_ms,"membership_component_bytes":cb.len(),"authorization_bytes":ab.len(),"commitment_bytes":commitment.len(),"proof_components_bytes":cb.len()+ab.len()+commitment.len(),"header_state_bytes":Rsa2048::elem_to_bytes(&h.accumulator).len(),"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&h.accumulator)),"commitment_hex":hex(&commitment),"public_request_le":fields.iter().map(|v|hex(&enc(v))).collect::<Vec<_>>(),"accepted":true,"performance_sample":(["before_Q","short_Q","after_Q"].contains(&name))}));
    log.save("running", None)?;
    if rep == 0 && name == "before_Q" {
        log.check(
            "cp_replay_rejected",
            v.authorize(
                cp,
                link,
                &s,
                &proof,
                &auth,
                &fields,
                &fields,
                500,
                550,
                || 500,
            )
            .err()
            .as_deref()
                == Some("nonce_already_consumed"),
        )?;
        let mut fresh =
            JointVerifier::new(Header::new(set.accumulator.clone(), epoch, digest), *digest);
        let mut n = 0;
        log.check(
            "cp_expiry_during_verify_rejected",
            fresh
                .authorize(
                    cp,
                    link,
                    &s,
                    &proof,
                    &auth,
                    &fields,
                    &fields,
                    500,
                    550,
                    || {
                        n += 1;
                        if n == 1 {
                            500
                        } else {
                            551
                        }
                    },
                )
                .err()
                .as_deref()
                == Some("expired_before_commit"),
        )?;
        log.check(
            "cp_expiry_does_not_consume",
            fresh
                .authorize(
                    cp,
                    link,
                    &s,
                    &proof,
                    &auth,
                    &fields,
                    &fields,
                    500,
                    550,
                    || 500,
                )
                .is_ok(),
        )?;
        let mut wrong = fields.clone();
        wrong[7] += Fr::one();
        let mut fv =
            JointVerifier::new(Header::new(set.accumulator.clone(), epoch, digest), *digest);
        log.check(
            "cp_request_mutation_rejected",
            fv.authorize(
                cp,
                link,
                &s,
                &proof,
                &auth,
                &wrong,
                &wrong,
                500,
                550,
                || 500,
            )
            .is_err(),
        )?;
        let mut stale = JointVerifier::new(
            Header::new(set.accumulator.clone(), epoch + 1, digest),
            *digest,
        );
        let t = Instant::now();
        let rejected = stale
            .authorize(
                cp,
                link,
                &s,
                &proof,
                &auth,
                &fields,
                &fields,
                500,
                550,
                || 500,
            )
            .err()
            .as_deref()
            == Some("stale_header");
        let cost = ms(t);
        log.check("cp_stale_attempt_rejected", rejected)?;
        log.lifecycle.push(json!({"scheme":"cp_rsa","operation":"stale_attempt_rejection","ms":cost,"retry_proof_in":"after_Q","discarded_proof_case":"before_Q","note":"one stale attempt followed by one fresh proof; no probabilistic retry rate inferred"}));
    }
    Ok(CBundle {
        statement: s,
        membership: proof,
        auth,
        fields,
    })
}
fn merkle_trial(
    log: &mut Log,
    name: &str,
    rep: usize,
    f: &AuthFixture,
    path: &str,
    prime: &Integer,
    set: &MerkleState,
    p: &MParameters,
    epoch: u64,
) -> Result<MBundle, String> {
    println!("PROVE MERKLE {} {}", name, rep);
    let h = MHeader::new(set.root(), epoch, &p.digest);
    let total = Instant::now();
    let t = Instant::now();
    let mut c = f.circuit_for(path);
    let hd = limbs(&h.digest);
    c.request.fields[0] = hd[0];
    c.request.fields[1] = hd[1];
    c.request.fields[2] = Fr::from(epoch);
    c.request.fields[10] = Fr::from(99 + rep as u64);
    let fields = c.public_fields();
    let prepare = ms(t);
    let r = random();
    let t = Instant::now();
    let commitment = p.cp.commit(prime, &r)?;
    let membership = hrada_link::prove(&mut OsRng, p.member, set.circuit(prime)?, &r)
        .map_err(|e| format!("{:?}", e))?;
    let member_ms = ms(t);
    let t = Instant::now();
    let auth = hrada_link::prove(&mut OsRng, p.auth, c, &r).map_err(|e| format!("{:?}", e))?;
    let auth_ms = ms(t);
    let prove_ms = ms(total);
    let b = MBundle {
        membership,
        auth,
        commitment,
        fields,
        root: set.root_fields(),
    };
    let mut v = mver(&h);
    let t = Instant::now();
    v.authorize(p, &b, &b.fields, || 500)?;
    let verify_ms = ms(t);
    let mb = enc(&b.membership);
    let ab = enc(&b.auth);
    let cb = enc(&b.commitment);
    let prefix = format!("merkle-{}-{}", name, rep);
    fs::write(log.dir.join(format!("{}-member.bin", prefix)), &mb).map_err(|e| e.to_string())?;
    fs::write(log.dir.join(format!("{}-auth.bin", prefix)), &ab).map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"merkle_lego","case":name,"rep":rep,"prepare_ms":prepare,"membership_prove_including_witness_ms":member_ms,"authorization_prove_including_precheck_ms":auth_ms,"prove_total_ms":prove_ms,"verify_total_ms":verify_ms,"membership_component_bytes":mb.len(),"authorization_bytes":ab.len(),"commitment_bytes":cb.len(),"proof_components_bytes":mb.len()+ab.len()+cb.len(),"header_state_bytes":32,"root_hex":hex(&h.root),"commitment_hex":hex(&cb),"public_request_le":b.fields.iter().map(|v|hex(&enc(v))).collect::<Vec<_>>(),"accepted":true,"performance_sample":(["before_Q","short_Q","after_Q"].contains(&name))}));
    log.save("running", None)?;
    if rep == 0 && name == "before_Q" {
        log.check(
            "merkle_replay_rejected",
            v.authorize(p, &b, &b.fields, || 500).err().as_deref()
                == Some("nonce_already_consumed"),
        )?;
        let mut fresh = mver(&h);
        let mut n = 0;
        log.check(
            "merkle_expiry_during_verify_rejected",
            fresh
                .authorize(p, &b, &b.fields, || {
                    n += 1;
                    if n == 1 {
                        500
                    } else {
                        551
                    }
                })
                .err()
                .as_deref()
                == Some("expired_before_commit"),
        )?;
        log.check(
            "merkle_expiry_does_not_consume",
            fresh.authorize(p, &b, &b.fields, || 500).is_ok(),
        )?;
        let mut stale = mver(&MHeader::new(set.root(), epoch + 1, &p.digest));
        let t = Instant::now();
        let rejected =
            stale.authorize(p, &b, &b.fields, || 500).err().as_deref() == Some("stale_header");
        let cost = ms(t);
        log.check("merkle_stale_attempt_rejected", rejected)?;
        log.lifecycle.push(json!({"scheme":"merkle_lego","operation":"stale_attempt_rejection","ms":cost,"retry_proof_in":"after_Q","discarded_proof_case":"before_Q"}));
        let ck = &p.cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
        for i in 0..16 {
            let mut q = b.fields.clone();
            q[i] += Fr::one();
            log.check(
                &format!("merkle_auth_public_field_{}_rejected", i),
                !hrada_link::verify(
                    p.auth,
                    ck,
                    &p.auth_descriptor,
                    &p.digest,
                    &b.auth,
                    &q,
                    &b.commitment,
                )
                .map_err(|e| format!("{:?}", e))?,
            )?;
        }
        let mut wrong = p.digest;
        wrong[0] ^= 1;
        log.check(
            "merkle_wrong_parameters_rejected",
            !hrada_link::verify(
                p.auth,
                ck,
                &p.auth_descriptor,
                &wrong,
                &b.auth,
                &b.fields,
                &b.commitment,
            )
            .map_err(|e| format!("{:?}", e))?,
        )?;
    }
    Ok(b)
}
fn lifecycle(log: &mut Log, primes: &[Integer], newp: &Integer) -> Result<(), String> {
    for n in [2usize, 8, 16].iter() {
        for rep in 0..5 {
            let ps = &primes[..*n];
            let t = Instant::now();
            let old = StateSet::rebuild(ps)?;
            let cp_build = ms(t);
            let t = Instant::now();
            let mt = MerkleState::new(ps)?;
            let mt_build = ms(t);
            let mut changed = ps.to_vec();
            changed[0] = newp.clone();
            let t = Instant::now();
            let current = StateSet::rebuild(&changed)?;
            let cp_update = ms(t);
            let t = Instant::now();
            let mut newer = mt.clone();
            newer.replace(0, newp.clone())?;
            let mt_update = ms(t);
            let t = Instant::now();
            let cw = current.witness(&changed[0])?;
            let cp_witness = ms(t);
            let t = Instant::now();
            let mc = newer.circuit(&changed[0])?;
            let mt_witness = ms(t);
            let t = Instant::now();
            let mut cp_bytes = 0;
            for prime in &changed {
                cp_bytes += Rsa2048::elem_to_bytes(&current.witness(prime)?).len();
            }
            let cp_all = ms(t);
            let t = Instant::now();
            for prime in &changed {
                let _ = newer.circuit(prime)?;
            }
            let mt_all = ms(t);
            log.lifecycle.push(json!({"operation":"global_replace_and_refresh","n":n,"rep":rep,"cp_build_ms":cp_build,"merkle_build_ms":mt_build,"cp_replace_rebuild_ms":cp_update,"merkle_replace_ms":mt_update,"cp_selected_witness_ms":cp_witness,"merkle_selected_witness_ms":mt_witness,"cp_all_witnesses_ms":cp_all,"merkle_all_witnesses_ms":mt_all,"cp_selected_witness_bytes":Rsa2048::elem_to_bytes(&cw).len(),"merkle_selected_path_bytes":mc.path.len()*32,"cp_all_witness_bytes":cp_bytes,"merkle_all_path_bytes":n*mc.path.len()*32,"cp_root_changed":old.accumulator!=current.accumulator,"merkle_root_changed":mt.root()!=newer.root(),"global_merkle_depth":4}));
        }
    }
    log.save("running", None)
}
fn run(log: &mut Log) -> Result<(), String> {
    let t = Instant::now();
    let primes = (0..16).map(|_| allocate_prime()).collect::<Vec<_>>();
    let newp = allocate_prime();
    let allocate_ms = ms(t);
    lifecycle(log, &primes, &newp)?;
    let set = StateSet::rebuild(&primes[..8])?;
    let mt = MerkleState::new(&primes[..8])?;
    let mut f = AuthFixture::new(20260906);
    f.refresh_state(fr(&primes[0]));
    let mut other = f.second_user(20260908);
    other.refresh_state(fr(&primes[1]));
    let ids = f.all_grants.iter().map(|g| g.id()).collect::<Vec<_>>();
    let grants = f.grant_signatures;
    let sr = f.sr_signatures;
    let t = Instant::now();
    let cp = StateMembership::setup_os()?;
    let cp_setup = ms(t);
    let cpbytes = cp.canonical_parameters()?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    println!("SETUP shared authorization CRS");
    let t = Instant::now();
    let auth =
        hrada_link::setup(&mut OsRng, ck, f.circuit(), 16).map_err(|e| format!("{:?}", e))?;
    let auth_setup = ms(t);
    let cpdigest = hrada_link::parameter_digest(&auth, &cpbytes).map_err(|e| format!("{:?}", e))?;
    println!("SETUP Merkle membership CRS");
    let t = Instant::now();
    let member = hrada_link::setup(&mut OsRng, ck, mt.circuit(&primes[0])?, 2)
        .map_err(|e| format!("{:?}", e))?;
    let mt_setup = ms(t);
    let mut descriptor = b"HRADA-MERKLE-LEGO-DEPTH4-V1".to_vec();
    descriptor.extend(enc(&ck.g));
    descriptor.extend(enc(&ck.h));
    let md = hrada_link::parameter_digest(&member, &descriptor).map_err(|e| format!("{:?}", e))?;
    let mut ad = b"HRADA-MERKLE-AUTH-V1".to_vec();
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
    let cs = ConstraintSystem::new_ref();
    mt.circuit(&primes[0])?
        .generate_constraints(cs.clone())
        .map_err(|e| format!("{:?}", e))?;
    let merkle_constraints = cs.num_constraints();
    drop(cs);
    let ap = enc(&auth.proving_key);
    let mk = enc(&member.proving_key);
    let range = enc(&cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters);
    fs::write(log.dir.join("shared_auth_pk.bin"), &ap).map_err(|e| e.to_string())?;
    fs::write(log.dir.join("merkle_pk.bin"), &mk).map_err(|e| e.to_string())?;
    fs::write(log.dir.join("cp_range_pk.bin"), &range).map_err(|e| e.to_string())?;
    fs::write(log.dir.join("cp_parameters.bin"), &cpbytes).map_err(|e| e.to_string())?;
    // Authenticated local cache format; not the compressed distribution size.
    let caches = [
        ("shared_auth_pk.uncompressed.bin", &auth.proving_key),
        ("merkle_pk.uncompressed.bin", &member.proving_key),
        (
            "cp_range_pk.uncompressed.bin",
            &cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters,
        ),
    ];
    for (name, key) in caches.iter() {
        let mut bytes = Vec::new();
        key.serialize_uncompressed(&mut bytes)
            .map_err(|e| format!("{:?}", e))?;
        fs::write(log.dir.join(name), bytes).map_err(|e| e.to_string())?;
    }
    log.setup = json!({"allocate_17_primes_ms":allocate_ms,"cp_membership_setup_ms":cp_setup,"merkle_membership_setup_ms":mt_setup,"shared_auth_setup_ms":auth_setup,"shared_auth_pk_bytes":ap.len(),"merkle_pk_bytes":mk.len(),"cp_range_pk_bytes":range.len(),"shared_auth_vk_bytes":enc(&auth.proving_key.vk).len(),"merkle_vk_bytes":enc(&member.proving_key.vk).len(),"cp_parameters_bytes":cpbytes.len(),"auth_constraints":2140389,"merkle_membership_constraints":merkle_constraints,"cp_parameters_digest":hex(&cpdigest),"merkle_parameters_digest":hex(&digest),"global_population":8,"global_capacity":16,"actual_field_bits":255,"prime_bits":252,"configured_lambda_s":125,"effective_fs_challenge_bits":120});
    drop(ap);
    drop(mk);
    drop(range);
    log.save("running", None)?;
    let mut retained = None;
    let mut retained_cp = None;
    for rep in 0..5 {
        if rep % 2 == 0 {
            let cb = cp_trial(
                log, "before_Q", rep, &f, "Q", &primes[0], &set, &cp, &auth, &cpdigest, 1,
            )?;
            if rep == 0 {
                retained_cp = Some(cb);
            }
            let b = merkle_trial(log, "before_Q", rep, &f, "Q", &primes[0], &mt, &mp, 1)?;
            if rep == 0 {
                retained = Some(b)
            }
        } else {
            merkle_trial(log, "before_Q", rep, &f, "Q", &primes[0], &mt, &mp, 1)?;
            cp_trial(
                log, "before_Q", rep, &f, "Q", &primes[0], &set, &cp, &auth, &cpdigest, 1,
            )?;
        }
    }
    for rep in 0..5 {
        if rep % 2 == 0 {
            merkle_trial(log, "short_Q", rep, &f, "short_Q", &primes[0], &mt, &mp, 1)?;
            cp_trial(
                log, "short_Q", rep, &f, "short_Q", &primes[0], &set, &cp, &auth, &cpdigest, 1,
            )?;
        } else {
            cp_trial(
                log, "short_Q", rep, &f, "short_Q", &primes[0], &set, &cp, &auth, &cpdigest, 1,
            )?;
            merkle_trial(log, "short_Q", rep, &f, "short_Q", &primes[0], &mt, &mp, 1)?;
        }
    }
    cp_trial(
        log,
        "other_user_Q",
        0,
        &other,
        "Q",
        &primes[1],
        &set,
        &cp,
        &auth,
        &cpdigest,
        1,
    )?;
    let ob = merkle_trial(log, "other_user_Q", 0, &other, "Q", &primes[1], &mt, &mp, 1)?;
    let old = retained.take().unwrap();
    log.check(
        "merkle_two_users_same_public_request",
        old.fields == ob.fields,
    )?;
    let splice = MBundle {
        membership: ob.membership.clone(),
        auth: old.auth.clone(),
        commitment: ob.commitment,
        fields: old.fields.clone(),
        root: old.root,
    };
    log.check(
        "merkle_cross_user_splice_rejected",
        mver(&MHeader::new(mt.root(), 1, &digest))
            .authorize(&mp, &splice, &splice.fields, || 500)
            .err()
            .as_deref()
            == Some("authorization_link_rejected"),
    )?;
    cp_trial(
        log,
        "single_P",
        0,
        &f,
        "prefix_P1",
        &primes[0],
        &set,
        &cp,
        &auth,
        &cpdigest,
        1,
    )?;
    merkle_trial(log, "single_P", 0, &f, "prefix_P1", &primes[0], &mt, &mp, 1)?;
    f.close_issuers();
    other.close_issuers();
    log.check(
        "five_original_issuers_closed",
        (0..5).all(|i| f.issuer_sign(i, [0; 32]).is_err()),
    )?;
    let t = Instant::now();
    f.revoke_middle(fr(&newp));
    let sr_refresh = ms(t);
    log.check(
        "unchanged_original_grant_signatures",
        ids == f.all_grants.iter().map(|g| g.id()).collect::<Vec<_>>()
            && grants == f.grant_signatures,
    )?;
    log.check("one_sr_state_refresh", f.sr_signatures == sr + 1)?;
    log.check("revoked_P_constraints_rejected", !sat(f.circuit_for("P"))?)?;
    log.check(
        "revoked_P2_constraints_rejected",
        !sat(f.circuit_for("P2"))?,
    )?;
    let mut updated = primes[..8].to_vec();
    updated[0] = newp.clone();
    let t = Instant::now();
    let newset = StateSet::rebuild(&updated)?;
    let cpupdate = ms(t);
    let mut newmt = mt.clone();
    let t = Instant::now();
    newmt.replace(0, newp.clone())?;
    let mtupdate = ms(t);
    log.lifecycle.push(json!({"operation":"actual_revocation","sr_refresh_ms_shared":sr_refresh,"cp_global_rebuild_ms":cpupdate,"merkle_replace_ms":mtupdate,"grant_signature_delta":f.grant_signatures-grants,"sr_signature_delta":f.sr_signatures-sr}));
    log.check("cp_old_prime_removed", newset.witness(&primes[0]).is_err())?;
    log.check(
        "merkle_old_prime_removed",
        newmt.circuit(&primes[0]).is_err(),
    )?;
    let cb = retained_cp.take().unwrap();
    let mut cv = JointVerifier::new(
        Header::new(newset.accumulator.clone(), 2, &cpdigest),
        cpdigest,
    );
    log.check(
        "cp_actual_updated_root_rejects_old_bundle",
        cv.authorize(
            &cp,
            &auth,
            &cb.statement,
            &cb.membership,
            &cb.auth,
            &cb.fields,
            &cb.fields,
            500,
            550,
            || 500,
        )
        .err()
        .as_deref()
            == Some("stale_header"),
    )?;
    log.check(
        "merkle_actual_updated_root_rejects_old_bundle",
        mver(&MHeader::new(newmt.root(), 2, &digest))
            .authorize(&mp, &old, &old.fields, || 500)
            .err()
            .as_deref()
            == Some("stale_header"),
    )?;
    let other_sr = other.sr_signatures;
    cp_trial(
        log,
        "after_other_Q",
        0,
        &other,
        "Q",
        &primes[1],
        &newset,
        &cp,
        &auth,
        &cpdigest,
        2,
    )?;
    merkle_trial(
        log,
        "after_other_Q",
        0,
        &other,
        "Q",
        &primes[1],
        &newmt,
        &mp,
        2,
    )?;
    log.check(
        "other_user_recovery_no_sr_resign",
        other.sr_signatures == other_sr,
    )?;
    cp_trial(
        log,
        "after_short_Q",
        0,
        &f,
        "short_Q",
        &newp,
        &newset,
        &cp,
        &auth,
        &cpdigest,
        2,
    )?;
    merkle_trial(
        log,
        "after_short_Q",
        0,
        &f,
        "short_Q",
        &newp,
        &newmt,
        &mp,
        2,
    )?;
    for rep in 0..5 {
        if rep % 2 == 0 {
            merkle_trial(log, "after_Q", rep, &f, "Q", &newp, &newmt, &mp, 2)?;
            cp_trial(
                log, "after_Q", rep, &f, "Q", &newp, &newset, &cp, &auth, &cpdigest, 2,
            )?;
        } else {
            cp_trial(
                log, "after_Q", rep, &f, "Q", &newp, &newset, &cp, &auth, &cpdigest, 2,
            )?;
            merkle_trial(log, "after_Q", rep, &f, "Q", &newp, &newmt, &mp, 2)?;
        }
    }
    for case in [
        "before_Q",
        "short_Q",
        "after_Q",
        "other_user_Q",
        "single_P",
        "after_other_Q",
        "after_short_Q",
    ]
    .iter()
    {
        for rep in 0..if ["before_Q", "short_Q", "after_Q"].contains(case) {
            5
        } else {
            1
        } {
            let rows = log
                .samples
                .iter()
                .filter(|r| r["case"] == *case && r["rep"] == rep)
                .collect::<Vec<_>>();
            log.check(
                &format!("matched_request_{}_{}", case, rep),
                rows.len() == 2
                    && rows[0]["public_request_le"].as_array().unwrap()[2..]
                        == rows[1]["public_request_le"].as_array().unwrap()[2..],
            )?;
        }
    }
    for scheme in ["cp_rsa", "merkle_lego"].iter() {
        let sizes = log
            .samples
            .iter()
            .filter(|r| r["scheme"] == *scheme)
            .map(|r| r["authorization_bytes"].as_u64().unwrap())
            .collect::<Vec<_>>();
        log.check(
            &format!("{}_fixed_authorization_proof_size", scheme),
            sizes.iter().all(|n| *n == sizes[0]),
        )?;
    }
    log.check(
        "thirty_eight_real_joint_proof_bundles",
        log.samples.len() == 38,
    )?;
    Ok(())
}
fn main() {
    let dir = PathBuf::from("target/hrada-three-layer-e2e").join(format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    fs::create_dir_all(&dir).unwrap();
    println!("ARTIFACTS {}", dir.display());
    let mut log = Log {
        dir,
        checks: vec![],
        samples: vec![],
        lifecycle: vec![],
        setup: json!({}),
    };
    match run(&mut log) {
        Ok(()) => {
            log.save("complete", None).unwrap();
            println!(
                "DONE {} checks; {} real joint bundles",
                log.checks.len(),
                log.samples.len()
            );
        }
        Err(e) => {
            log.save("failed", Some(&e)).unwrap();
            eprintln!("FAILED {}", e);
            std::process::exit(1);
        }
    }
}
