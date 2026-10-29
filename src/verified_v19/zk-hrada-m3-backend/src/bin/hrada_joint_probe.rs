//! Actual CP-RSA + Lego HRADA pilot; deterministic users, OS-random proof setup.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::{One, UniformRand};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::protocols::{
    hrada_auth::{AuthCircuit, AuthFixture},
    hrada_joint::{self, Header, JointVerifier},
    hrada_link::{self, LinkParameters},
    hrada_membership::{allocate_prime, CpProof, CpStatement, StateMembership, StateSet},
};
use cpsnarks_set::utils::integer_to_bigint_mod_q;
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

struct Bundle {
    s: CpStatement,
    cp: CpProof,
    lego: legogro16::Proof<Bls12_381>,
    fields: Vec<Fr>,
}
struct Log {
    path: PathBuf,
    checks: Vec<Value>,
    bundles: Vec<String>,
    status: String,
    failure: Option<String>,
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{:02x}", v)).collect()
}
fn canonical<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut b = vec![];
    value.serialize(&mut b).unwrap();
    b
}
impl Log {
    fn save(&self) -> Result<(), String> {
        let pass = self.checks.iter().filter(|v| v["pass"] == true).count();
        let report = json!({"kind":"actual-CP-RSA-Lego-HRADA-three-slot-pilot","checks":self.checks,
   "run_status":self.status,"failure":self.failure,
   "passed":pass,"total":self.checks.len(),"real_joint_proof_bundles":self.bundles,
   "scope":"one to three private enabled grants, depth-3 private SMT, trusted SR, local serial verifier",
   "setup":"OS entropy, local single-party; deterministic user fixture keys only",
   "production_security_certification":false});
        fs::write(
            self.path.join("results.json"),
            serde_json::to_vec_pretty(&report).unwrap(),
        )
        .map_err(|e| e.to_string())
    }
    fn check(&mut self, id: &str, actual: bool) -> Result<(), String> {
        println!("{} {}", if actual { "PASS" } else { "FAIL" }, id);
        self.checks.push(json!({"id":id,"pass":actual}));
        self.save()?;
        if !actual {
            return Err(format!("failed: {}", id));
        }
        Ok(())
    }
}
fn witness_valid(c: AuthCircuit) -> Result<bool, String> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    c.generate_constraints(cs.clone())
        .map_err(|e| format!("{:?}", e))?;
    cs.is_satisfied().map_err(|e| format!("{:?}", e))
}
fn scalar_integer() -> Integer {
    Integer::from_digits(&canonical(&Fr::rand(&mut OsRng)), Order::Lsf)
}
fn update_header(f: &mut AuthFixture, h: &Header) {
    let fields = h.digest_fields();
    f.base.request.fields[0] = fields[0];
    f.base.request.fields[1] = fields[1];
    f.base.request.fields[2] = Fr::from(h.epoch);
}
fn verifier(h: &Header, digest: [u8; 32]) -> JointVerifier {
    JointVerifier::new(Header::new(h.accumulator.clone(), h.epoch, &digest), digest)
}
fn auth(
    v: &mut JointVerifier,
    cp: &StateMembership,
    link: &LinkParameters,
    b: &Bundle,
) -> Result<(), String> {
    v.authorize(
        cp,
        link,
        &b.s,
        &b.cp,
        &b.lego,
        &b.fields,
        &b.fields,
        500,
        550,
        || 500,
    )
}
fn encode_cp(proof: &CpProof) -> Value {
    let r = &proof.proof_root;
    let m = &proof.proof_modeq;
    json!({"encoding":"hrada-cp-components-v1","c_e":hex(&Rsa2048::elem_to_bytes(&proof.c_e)),
  "root_message1":[hex(&Rsa2048::elem_to_bytes(&r.message1.c_w)),hex(&Rsa2048::elem_to_bytes(&r.message1.c_r))],
  "root_message2":[hex(&Rsa2048::elem_to_bytes(&r.message2.alpha1)),hex(&Rsa2048::elem_to_bytes(&r.message2.alpha2)),hex(&Rsa2048::elem_to_bytes(&r.message2.alpha3)),hex(&Rsa2048::elem_to_bytes(&r.message2.alpha4))],
  "root_message3":[r.message3.s_e.to_string(),r.message3.s_r.to_string(),r.message3.s_r_2.to_string(),r.message3.s_r_3.to_string(),r.message3.s_beta.to_string(),r.message3.s_delta.to_string()],
  "modeq_message1":[hex(&Rsa2048::elem_to_bytes(&m.message1.alpha1)),hex(&canonical(&m.message1.alpha2))],
  "modeq_message2":[m.message2.s_e.to_string(),m.message2.s_r.to_string(),hex(&canonical(&m.message2.s_r_q))],
  "range_lego":hex(&canonical(&proof.proof_hash_to_prime))})
}
fn bundle(
    name: &str,
    c: AuthCircuit,
    prime: &Integer,
    set: &StateSet,
    cp: &StateMembership,
    link: &LinkParameters,
    digest: &[u8; 32],
    log: &mut Log,
) -> Result<Bundle, String> {
    println!("PROVING {}", name);
    let fields = c.public_fields();
    let ctx = hrada_joint::context(digest, &fields)?;
    let random = scalar_integer();
    let (s, proof) = cp.prove(set, prime, &random, &ctx)?;
    let lego = hrada_link::prove(&mut OsRng, link, c, &random)
        .map_err(|e| format!("authorization proof: {:?}", e))?;
    cp.verify(&s, &proof, &ctx)?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let linked = hrada_link::verify(
        link,
        ck,
        &cp.canonical_parameters()?,
        digest,
        &lego,
        &fields,
        &s.c_e_q,
    )
    .map_err(|e| format!("{:?}", e))?;
    log.check(&format!("{}_joint_crypto", name), linked)?;
    let record = json!({"name":name,"public_fields_le":fields.iter().map(|v|hex(&canonical(v))).collect::<Vec<_>>(),
  "accumulator":hex(&Rsa2048::elem_to_bytes(&s.c_p)),"prime_commitment":hex(&canonical(&s.c_e_q)),
  "cp_proof":encode_cp(&proof),"authorization_lego":hex(&canonical(&lego))});
    fs::write(
        log.path.join(format!("{}.json", name)),
        serde_json::to_vec_pretty(&record).unwrap(),
    )
    .map_err(|e| e.to_string())?;
    log.bundles.push(name.to_string());
    log.save()?;
    Ok(Bundle {
        s,
        cp: proof,
        lego,
        fields,
    })
}
fn signed_records(f: &AuthFixture) -> Vec<[u8; 32]> {
    f.all_grants.iter().map(|g| g.id()).collect()
}

fn run(log: &mut Log) -> Result<(), String> {
    let cp = StateMembership::setup_os()?;
    let cp_bytes = cp.canonical_parameters()?;
    fs::write(log.path.join("cp_public_parameters.bin"), &cp_bytes).map_err(|e| e.to_string())?;
    fs::write(
        log.path.join("cp_range_pk.bin"),
        canonical(&cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters),
    )
    .map_err(|e| e.to_string())?;
    let p = allocate_prime();
    let other = allocate_prime();
    let new_p = allocate_prime();
    let set = StateSet::rebuild(&[p.clone(), other.clone()])?;
    let mut f = AuthFixture::new(20260906);
    let mut f2 = f.second_user(20260907);
    f.refresh_state(integer_to_bigint_mod_q::<G1Projective>(&p).map_err(|e| format!("{:?}", e))?);
    f2.refresh_state(
        integer_to_bigint_mod_q::<G1Projective>(&other).map_err(|e| format!("{:?}", e))?,
    );
    log.check(
        "distinct_users_same_terminal",
        f.base.user_pk != f2.base.user_pk
            && f.circuit().public_fields() == f2.circuit().public_fields(),
    )?;
    let cs = ConstraintSystem::<Fr>::new_ref();
    f.circuit()
        .generate_constraints(cs.clone())
        .map_err(|e| format!("{:?}", e))?;
    log.check(
        "initial_full_authorization_constraints",
        cs.is_satisfied().map_err(|e| format!("{:?}", e))?,
    )?;
    fs::write(
        log.path.join("circuit_shape.json"),
        json!({"constraints":cs.num_constraints(),"instance_variables":cs.num_instance_variables(),
  "witness_variables":cs.num_witness_variables(),"prime_bits":252,"field_bits":255})
        .to_string(),
    )
    .map_err(|e| e.to_string())?;
    drop(cs);
    println!("SETTING UP authorization Lego CRS");
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let link =
        hrada_link::setup(&mut OsRng, ck, f.circuit(), 16).map_err(|e| format!("{:?}", e))?;
    let digest = hrada_link::parameter_digest(&link, &cp_bytes).map_err(|e| format!("{:?}", e))?;
    fs::write(
        log.path.join("authorization_pk.bin"),
        canonical(&link.proving_key),
    )
    .map_err(|e| e.to_string())?;
    fs::write(log.path.join("parameters_digest.txt"), hex(&digest)).map_err(|e| e.to_string())?;
    let header = Header::new(set.accumulator.clone(), 1, &digest);
    update_header(&mut f, &header);
    update_header(&mut f2, &header);
    let before_p = bundle(
        "before_P",
        f.circuit_for("P"),
        &p,
        &set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    let before_p2 = bundle(
        "before_P2",
        f.circuit_for("P2"),
        &p,
        &set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    let before_q = bundle(
        "before_Q",
        f.circuit_for("Q"),
        &p,
        &set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    let before_short = bundle(
        "before_short_Q",
        f.circuit_for("short_Q"),
        &p,
        &set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    let before_single = bundle(
        "before_single_P",
        f.circuit_for("prefix_P1"),
        &p,
        &set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    let before_other = bundle(
        "before_other_user_Q",
        f2.circuit(),
        &other,
        &set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    log.check(
        "same_public_request_two_and_three_grants",
        before_short.fields == before_q.fields,
    )?;
    log.check(
        "same_proof_size_two_and_three_grants",
        canonical(&before_short.lego).len() == canonical(&before_q.lego).len(),
    )?;
    log.check(
        "short_Q_authorized",
        auth(&mut verifier(&header, digest), &cp, &link, &before_short).is_ok(),
    )?;
    log.check(
        "single_grant_authorized",
        auth(&mut verifier(&header, digest), &cp, &link, &before_single).is_ok(),
    )?;
    for (name, b) in [
        ("P", &before_p),
        ("P2", &before_p2),
        ("Q", &before_q),
        ("other", &before_other),
    ]
    .iter()
    {
        log.check(
            &format!("before_{}_authorized", name),
            auth(&mut verifier(&header, digest), &cp, &link, b).is_ok(),
        )?;
    }
    // Two independently legal users, same trusted header and same complete request.
    log.check(
        "splice_has_same_request",
        before_q.fields == before_other.fields,
    )?;
    let splice = verifier(&header, digest).authorize(
        &cp,
        &link,
        &before_q.s,
        &before_q.cp,
        &before_other.lego,
        &before_q.fields,
        &before_q.fields,
        500,
        550,
        || 500,
    );
    log.check(
        "cross_user_prime_link_splice_rejected",
        splice == Err("authorization_link_rejected".into()),
    )?;
    let cp_ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    for i in 0..16 {
        let mut q = before_q.fields.clone();
        q[i] += Fr::one();
        log.check(
            &format!("linked_public_field_{}_mutation", i),
            !hrada_link::verify(
                &link,
                cp_ck,
                &cp_bytes,
                &digest,
                &before_q.lego,
                &q,
                &before_q.s.c_e_q,
            )
            .map_err(|e| format!("{:?}", e))?,
        )?;
    }
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    log.check(
        "wrong_parameters_digest",
        !hrada_link::verify(
            &link,
            cp_ck,
            &cp_bytes,
            &wrong_digest,
            &before_q.lego,
            &before_q.fields,
            &before_q.s.c_e_q,
        )
        .map_err(|e| format!("{:?}", e))?,
    )?;
    let mut serial = verifier(&header, digest);
    log.check(
        "first_nonce",
        auth(&mut serial, &cp, &link, &before_q).is_ok(),
    )?;
    log.check(
        "replayed_nonce",
        auth(&mut serial, &cp, &link, &before_q) == Err("nonce_already_consumed".into()),
    )?;
    let mut expiring = verifier(&header, digest);
    let mut clock_call = 0;
    let expired = expiring.authorize(
        &cp,
        &link,
        &before_q.s,
        &before_q.cp,
        &before_q.lego,
        &before_q.fields,
        &before_q.fields,
        500,
        550,
        || {
            clock_call += 1;
            if clock_call == 1 {
                500
            } else {
                551
            }
        },
    );
    log.check(
        "expiry_during_real_verification",
        expired == Err("expired_before_commit".into()),
    )?;
    log.check(
        "expiry_failure_does_not_consume_nonce",
        auth(&mut expiring, &cp, &link, &before_q).is_ok(),
    )?;
    let original_ids = signed_records(&f);
    let old_leaves = f.all_grants.iter().map(|g| g.leaf()).collect::<Vec<_>>();
    f.close_issuers();
    for i in 0..5 {
        log.check(
            &format!("issuer_{}_disabled", i),
            f.issuer_sign(i, [1; 32]).is_err(),
        )?;
    }
    let old_grant_signatures = f.grant_signatures;
    let old_sr_signatures = f.sr_signatures;
    let old_root = f.base.auth_root;
    let old_version = f.base.state_version;
    f.revoke_middle(
        integer_to_bigint_mod_q::<G1Projective>(&new_p).map_err(|e| format!("{:?}", e))?,
    );
    let fresh_set = StateSet::rebuild(&[new_p.clone(), other.clone()])?;
    let fresh_header = Header::new(fresh_set.accumulator.clone(), 2, &digest);
    update_header(&mut f, &fresh_header);
    update_header(&mut f2, &fresh_header);
    log.check(
        "only_target_leaf_changes",
        old_leaves
            .iter()
            .enumerate()
            .filter(|(i, h)| f.all_grants[*i].leaf() != **h)
            .map(|(i, _)| i)
            .collect::<Vec<_>>()
            == vec![1],
    )?;
    log.check(
        "root_and_version_updated",
        f.base.auth_root != old_root && f.base.state_version == old_version + 1,
    )?;
    log.check(
        "no_grant_resigning",
        signed_records(&f) == original_ids && f.grant_signatures == old_grant_signatures,
    )?;
    log.check(
        "one_sr_state_signature",
        f.sr_signatures == old_sr_signatures + 1,
    )?;
    for (name, b) in [
        ("P", &before_p),
        ("P2", &before_p2),
        ("Q", &before_q),
        ("other", &before_other),
    ]
    .iter()
    {
        log.check(
            &format!("old_{}_stale", name),
            auth(&mut verifier(&fresh_header, digest), &cp, &link, b) == Err("stale_header".into()),
        )?;
        let ctx = hrada_joint::context(&digest, &b.fields)?;
        log.check(
            &format!("old_{}_historical_crypto", name),
            cp.verify(&b.s, &b.cp, &ctx).is_ok()
                && hrada_link::verify(
                    &link, cp_ck, &cp_bytes, &digest, &b.lego, &b.fields, &b.s.c_e_q,
                )
                .map_err(|e| format!("{:?}", e))?,
        )?;
    }
    log.check(
        "revoked_P_constraints_reject",
        !witness_valid(f.circuit_for("P"))?,
    )?;
    log.check(
        "revoked_P2_constraints_reject",
        !witness_valid(f.circuit_for("P2"))?,
    )?;
    let fresh_q = bundle(
        "refreshed_Q",
        f.circuit(),
        &new_p,
        &fresh_set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    let padding_before = f.padding_signatures.get();
    let fresh_short = bundle(
        "refreshed_short_Q",
        f.circuit_for("short_Q"),
        &new_p,
        &fresh_set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    log.check(
        "short_recovery_has_one_terminal_padding_signature",
        f.padding_signatures.get() == padding_before + 1,
    )?;
    log.check(
        "short_recovery_no_original_grant_signatures",
        f.grant_signatures == old_grant_signatures,
    )?;
    let fresh_other = bundle(
        "refreshed_other_user_Q",
        f2.circuit(),
        &other,
        &fresh_set,
        &cp,
        &link,
        &digest,
        log,
    )?;
    log.check(
        "refreshed_Q_authorized",
        auth(&mut verifier(&fresh_header, digest), &cp, &link, &fresh_q).is_ok(),
    )?;
    log.check(
        "refreshed_other_user_authorized",
        auth(
            &mut verifier(&fresh_header, digest),
            &cp,
            &link,
            &fresh_other,
        )
        .is_ok(),
    )?;
    log.check(
        "refreshed_short_Q_authorized",
        auth(
            &mut verifier(&fresh_header, digest),
            &cp,
            &link,
            &fresh_short,
        )
        .is_ok(),
    )?;
    // Mutations are classified as constraint-system rejection, not invalid proofs.
    let mut cases = Vec::new();
    let clean = f.circuit();
    let mut x = f.circuit_for("P");
    x.grants[1].active = true;
    cases.push(("forged_active", x));
    let mut x = clean.clone();
    x.grants[1].parent = [0; 32];
    cases.push(("bad_parent_id", x));
    let mut x = clean.clone();
    x.grants[1].fields[14] += Fr::one();
    cases.push(("signed_leaf_index", x));
    let mut x = clean.clone();
    x.prime += Fr::one();
    cases.push(("unsigned_state_prime", x));
    let mut x = clean.clone();
    x.ra_sig.prover_response += ark_ed_on_bls12_381::Fr::one();
    cases.push(("bad_ra_signature", x));
    let mut x = clean.clone();
    x.reg_serial = 0;
    cases.push(("zero_registration_serial", x));
    let mut x = clean.clone();
    x.sr_sig.prover_response += ark_ed_on_bls12_381::Fr::one();
    cases.push(("bad_sr_signature", x));
    let mut x = clean.clone();
    x.grants[1].signature.prover_response += ark_ed_on_bls12_381::Fr::one();
    cases.push(("bad_grant_signature", x));
    let mut x = clean.clone();
    x.holder += ark_ed_on_bls12_381::Fr::one();
    cases.push(("wrong_secret_holder", x));
    let mut x = clean.clone();
    x.paths[0][0][0] ^= 1;
    cases.push(("wrong_merkle_path", x));
    let mut x = clean.clone();
    x.request.fields[11] = Fr::from(1001u64);
    cases.push(("permit_outlives_grant", x));
    let mut x = clean.clone();
    x.request.fields[8] = Fr::from(3u64);
    cases.push(("non_one_hot_action", x));
    let mut x = clean.clone();
    x.request.fields[9] = Fr::from(99u64);
    cases.push(("request_before_grant", x));
    let mut x = clean.clone();
    x.enabled = [false; 3];
    cases.push(("empty_enabled_prefix", x));
    let mut x = clean.clone();
    x.enabled = [true, false, true];
    cases.push(("enabled_gap", x));
    let mut x = f.circuit_for("short_Q");
    x.enabled = [true, true, true];
    cases.push(("padding_as_real_grant", x));
    let mut x = f.circuit_for("P");
    x.enabled = [true, false, true];
    cases.push(("hidden_revoked_ancestor_with_live_child", x));
    for (name, c) in cases {
        log.check(&format!("constraint_{}", name), !witness_valid(c)?)?;
    }
    let mut transition = verifier(&header, digest);
    transition.replace_header(Header::new(fresh_set.accumulator.clone(), 2, &digest))?;
    log.check(
        "atomic_header_transition_stales_old_request",
        auth(&mut transition, &cp, &link, &before_q) == Err("stale_header".into()),
    )?;
    log.check(
        "atomic_header_transition_allows_fresh_request",
        auth(&mut transition, &cp, &link, &fresh_q).is_ok(),
    )?;
    log.check(
        "duplicate_epoch_transition_rejected",
        transition
            .replace_header(Header::new(fresh_set.accumulator, 2, &digest))
            .is_err(),
    )?;
    Ok(())
}
fn main() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target/hrada-joint-probes")
        .join(format!("{}-{}", std::process::id(), stamp));
    fs::create_dir_all(&path).unwrap();
    println!("ARTIFACTS {}", path.display());
    let mut log = Log {
        path,
        checks: vec![],
        bundles: vec![],
        status: "running".into(),
        failure: None,
    };
    if let Err(e) = run(&mut log) {
        log.status = "failed".into();
        log.failure = Some(e.clone());
        let _ = fs::write(log.path.join("failure.txt"), &e);
        let _ = log.save();
        eprintln!("FAILED {}", e);
        std::process::exit(1)
    }
    log.status = "complete".into();
    log.save().unwrap();
    println!(
        "DONE {} checks, {} real joint proof bundles",
        log.checks.len(),
        log.bundles.len()
    );
}
