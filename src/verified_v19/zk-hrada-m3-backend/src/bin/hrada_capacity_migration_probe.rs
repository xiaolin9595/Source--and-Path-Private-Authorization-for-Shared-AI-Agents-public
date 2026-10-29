//! Actual member-layer capacity migration; one sample per case, not a benchmark.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::Fr;
use ark_ff::UniformRand;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_link::{self, LinkParameters},
    hrada_membership::{allocate_prime, CpProof, CpStatement, StateMembership, StateSet},
    hrada_poseidon_baseline::{parameter_descriptor, PoseidonMerkleState},
};
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
fn enc<T: CanonicalSerialize>(v: &T) -> Vec<u8> {
    let mut b = vec![];
    v.serialize(&mut b).unwrap();
    b
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn hash(b: &[u8]) -> String {
    hex(&Blake2s::digest(b))
}
struct Log {
    dir: PathBuf,
    checks: Vec<Value>,
    setups: Vec<Value>,
    samples: Vec<Value>,
    states: Vec<Value>,
}
impl Log {
    fn save(&self, status: &str, error: Option<&str>) -> Result<(), String> {
        let v = json!({"status":status,"error":error,"checks":self.checks,"setups":self.setups,"samples":self.samples,"states":self.states,"actual_proofs":self.samples.len(),"scope":"member-layer capacity migration only; no AuthCircuit setup or Auth migration measured","repetitions_per_case":1,"performance_statistics":false,"population_transition":[8,17],"source_blake2s":hash(include_bytes!("hrada_capacity_migration_probe.rs")),"limitations":["CP StateSet rebuild and witness maintenance remain measured costs","Poseidon adaptive depth4 capacity16 migrates to depth8 capacity256","reserved depth8 avoids migration; original Auth source unchanged is not evidence of Auth migration"]});
        fs::write(
            self.dir.join("results.pending.json"),
            serde_json::to_vec_pretty(&v).unwrap(),
        )
        .map_err(|e| e.to_string())?;
        fs::rename(
            self.dir.join("results.pending.json"),
            self.dir.join("results.json"),
        )
        .map_err(|e| e.to_string())
    }
    fn check(&mut self, id: &str, pass: bool) -> Result<(), String> {
        println!("{} {}", if pass { "PASS" } else { "FAIL" }, id);
        self.checks.push(json!({"id":id,"pass":pass}));
        self.save("running", None)?;
        if pass {
            Ok(())
        } else {
            Err(id.into())
        }
    }
    fn raw(&self, name: &str, bytes: &[u8]) -> Result<(), String> {
        fs::write(self.dir.join(name), bytes).map_err(|e| e.to_string())
    }
}
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
fn tree_setup(
    log: &mut Log,
    cp: &StateMembership,
    tree: &PoseidonMerkleState,
    p: &Integer,
    id: &str,
    depth: usize,
) -> Result<(LinkParameters, Vec<u8>, [u8; 32]), String> {
    let t = Instant::now();
    let link = hrada_link::setup(
        &mut OsRng,
        &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters,
        tree.circuit(p)?,
        2,
    )
    .map_err(|e| format!("{:?}", e))?;
    let setup_ms = ms(t);
    let pk = enc(&link.proving_key);
    let vk = enc(&link.proving_key.vk);
    let mut descriptor = parameter_descriptor();
    descriptor.extend((depth as u64).to_le_bytes());
    let t = Instant::now();
    let digest =
        hrada_link::parameter_digest(&link, &descriptor).map_err(|e| format!("{:?}", e))?;
    let descriptor_digest_ms = ms(t);
    log.raw(&format!("{}_pk.bin", id), &pk)?;
    log.raw(&format!("{}_vk.bin", id), &vk)?;
    log.raw(&format!("{}_descriptor.bin", id), &descriptor)?;
    log.setups.push(json!({"id":id,"scheme":"poseidon_lego","depth":depth,"setup_ms":setup_ms,"descriptor_digest_ms":descriptor_digest_ms,"pk_bytes":pk.len(),"vk_bytes":vk.len(),"pk_blake2s":hash(&pk),"vk_blake2s":hash(&vk),"parameter_digest":hex(&digest)}));
    log.save("running", None)?;
    Ok((link, descriptor, digest))
}
fn tree_pair(
    log: &mut Log,
    cp: &StateMembership,
    p: &Integer,
    r: &Integer,
    old: &PoseidonMerkleState,
    new: &PoseidonMerkleState,
    old_setup: &(LinkParameters, Vec<u8>, [u8; 32]),
    new_setup: &(LinkParameters, Vec<u8>, [u8; 32]),
    name: &str,
) -> Result<(), String> {
    let commitment = cp.commit(p, r)?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let mut proofs = vec![];
    for (phase, tree, setup) in [("n8", old, old_setup), ("n17", new, new_setup)].iter() {
        let t = Instant::now();
        let circuit = tree.circuit(p)?;
        let witness_ms = ms(t);
        let t = Instant::now();
        let proof =
            hrada_link::prove(&mut OsRng, &setup.0, circuit, r).map_err(|e| format!("{:?}", e))?;
        let prove_ms = ms(t);
        let t = Instant::now();
        let accepted = hrada_link::verify(
            &setup.0,
            ck,
            &setup.1,
            &setup.2,
            &proof,
            &tree.root_fields(),
            &commitment,
        )
        .map_err(|e| format!("{:?}", e))?;
        let verify_ms = ms(t);
        let id = format!("{}_{}", name, phase);
        let bytes = enc(&proof);
        log.raw(&format!("{}.proof.bin", id), &bytes)?;
        log.samples.push(json!({"id":id,"scheme":"poseidon_lego","witness_ms":witness_ms,"prove_ms":prove_ms,"verify_ms":verify_ms,"proof_bytes":bytes.len(),"proof_blake2s":hash(&bytes),"commitment_hex":hex(&enc(&commitment)),"root_hex":hex(&tree.root()),"parameter_digest":hex(&setup.2),"accepted":accepted}));
        log.check(&format!("{}_accepted", id), accepted)?;
        proofs.push(proof);
    }
    let stale = hrada_link::verify(
        &new_setup.0,
        ck,
        &new_setup.1,
        &new_setup.2,
        &proofs[0],
        &new.root_fields(),
        &commitment,
    )
    .map_err(|e| format!("{:?}", e))?;
    log.check(
        &format!("{}_old_proof_rejected_under_new_state", name),
        !stale,
    )?;
    let historical = hrada_link::verify(
        &old_setup.0,
        ck,
        &old_setup.1,
        &old_setup.2,
        &proofs[0],
        &old.root_fields(),
        &commitment,
    )
    .map_err(|e| format!("{:?}", e))?;
    log.check(
        &format!("{}_old_proof_still_valid_historically", name),
        historical,
    )?;
    if name == "adaptive" {
        let invalid = hrada_link::verify(
            &old_setup.0,
            ck,
            &old_setup.1,
            &old_setup.2,
            &proofs[1],
            &new.root_fields(),
            &commitment,
        )
        .map_err(|e| format!("{:?}", e))?;
        log.check(
            "adaptive_new_depth8_proof_rejected_by_old_depth4_crs",
            !invalid,
        )?;
    }
    Ok(())
}
fn run(log: &mut Log) -> Result<(), String> {
    let t = Instant::now();
    let primes = (0..17).map(|_| allocate_prime()).collect::<Vec<_>>();
    let prime_generation_ms = ms(t);
    let r = Integer::from_digits(&enc(&Fr::rand(&mut OsRng)), Order::Lsf);
    let p = &primes[0];
    let t = Instant::now();
    let cp = StateMembership::setup_os()?;
    let setup_ms = ms(t);
    let params = cp.canonical_parameters()?;
    let pk = enc(&cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters);
    let vk = enc(&cp
        .protocol
        .crs
        .crs_hash_to_prime
        .hash_to_prime_parameters
        .vk);
    log.raw("cp_parameters.bin", &params)?;
    log.raw("cp_range_pk.bin", &pk)?;
    log.setups.push(json!({"id":"cp_shared","scheme":"cp_rsa","setup_ms":setup_ms,"pk_bytes":pk.len(),"vk_bytes":vk.len(),"parameters_bytes":params.len(),"parameter_blake2s":hash(&params),"pk_blake2s":hash(&pk),"vk_blake2s":hash(&vk)}));
    let t = Instant::now();
    let old = StateSet::rebuild(&primes[..8])?;
    let old_ms = ms(t);
    let t = Instant::now();
    let new = StateSet::rebuild(&primes)?;
    let new_ms = ms(t);
    log.states.push(json!({"scheme":"cp_rsa","n8_build_ms":old_ms,"n17_rebuild_ms":new_ms,"prime_generation_17_ms":prime_generation_ms,"maintenance":"whole-set rebuild, not free or optimized incremental update"}));
    let ctx = b"HRADA-capacity-migration-member-v1";
    let mut proofs = vec![];
    for (n, set) in [(8, &old), (17, &new)].iter() {
        let t = Instant::now();
        let witness = set.witness(p)?;
        let witness_ms = ms(t);
        let t = Instant::now();
        let (st, proof) = cp.prove(set, p, &r, ctx)?;
        let prove_ms = ms(t);
        let t = Instant::now();
        let accepted = cp.verify(&st, &proof, ctx).is_ok();
        let verify_ms = ms(t);
        let bytes = cp_components(&proof);
        log.raw(&format!("cp_n{}.proof.bin", n), &bytes)?;
        log.samples.push(json!({"id":format!("cp_n{}",n),"scheme":"cp_rsa","n":n,"witness_ms":witness_ms,"witness_bytes":Rsa2048::elem_to_bytes(&witness).len(),"prove_ms":prove_ms,"prove_includes_witness_rebuild":true,"verify_ms":verify_ms,"proof_bytes":bytes.len(),"proof_blake2s":hash(&bytes),"parameter_blake2s":hash(&params),"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&st.c_p)),"commitment_hex":hex(&enc(&st.c_e_q)),"context_hex":hex(ctx),"accepted":accepted}));
        log.check(&format!("cp_n{}_accepted", n), accepted)?;
        proofs.push((st, proof));
    }
    log.check(
        "cp_same_crs_after_growth",
        cp.canonical_parameters()? == params,
    )?;
    let stale = CpStatement {
        c_p: new.accumulator.clone(),
        c_e_q: proofs[0].0.c_e_q,
    };
    log.check(
        "cp_old_proof_rejected_under_new_state",
        cp.verify(&stale, &proofs[0].1, ctx).is_err(),
    )?;
    log.check(
        "cp_old_proof_still_valid_historically",
        cp.verify(&proofs[0].0, &proofs[0].1, ctx).is_ok(),
    )?;
    let t = Instant::now();
    let old4 = PoseidonMerkleState::with_depth(&primes[..8], 4)?;
    let old4_ms = ms(t);
    let t = Instant::now();
    let rejection = PoseidonMerkleState::with_depth(&primes, 4).is_err();
    let reject_ms = ms(t);
    log.check("depth4_capacity16_rejects_n17", rejection)?;
    let t = Instant::now();
    let new8 = PoseidonMerkleState::with_depth(&primes, 8)?;
    let new8_ms = ms(t);
    let t = Instant::now();
    let old8 = PoseidonMerkleState::with_depth(&primes[..8], 8)?;
    let old8_ms = ms(t);
    log.states.push(json!({"scheme":"poseidon_lego","n8_depth4_build_ms":old4_ms,"n17_depth4_rejection_ms":reject_ms,"n17_depth8_build_ms":new8_ms,"n8_depth8_build_ms":old8_ms,"n17_state_shared_across_adaptive_and_reserved":true,"maintenance":"sparse-default tree construction, no insertion API claimed"}));
    let adaptive4 = tree_setup(log, &cp, &old4, p, "adaptive_d4", 4)?;
    let adaptive8 = tree_setup(log, &cp, &new8, p, "adaptive_d8", 8)?;
    let reserved8 = tree_setup(log, &cp, &old8, p, "reserved_d8", 8)?;
    log.check("adaptive_crs_changed", adaptive4.2 != adaptive8.2)?;
    tree_pair(
        log, &cp, p, &r, &old4, &new8, &adaptive4, &adaptive8, "adaptive",
    )?;
    tree_pair(
        log, &cp, p, &r, &old8, &new8, &reserved8, &reserved8, "reserved",
    )?;
    log.check("six_actual_member_proofs", log.samples.len() == 6)?;
    let commitments = log
        .samples
        .iter()
        .map(|x| x["commitment_hex"].clone())
        .collect::<Vec<_>>();
    log.check(
        "all_cases_same_prime_commitment",
        commitments.iter().all(|c| c == &commitments[0]),
    )?;
    Ok(())
}
fn main() {
    let dir = PathBuf::from("target/hrada-capacity-migration").join(format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    println!("ARTIFACTS {}", dir.display());
    let mut log = Log {
        dir,
        checks: vec![],
        setups: vec![],
        samples: vec![],
        states: vec![],
    };
    log.raw(
        "probe_source.rs",
        include_bytes!("hrada_capacity_migration_probe.rs"),
    )
    .unwrap();
    match run(&mut log) {
        Ok(()) => {
            log.save("complete", None).unwrap();
            println!(
                "DONE {} checks, {} real member proofs",
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
