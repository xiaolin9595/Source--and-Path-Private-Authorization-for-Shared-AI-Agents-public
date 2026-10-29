//! Component/capacity layer, separate from full authorization timings.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::protocols::{
    hrada_link::{self, LinkParameters},
    hrada_membership::{allocate_prime, CpProof, StateMembership, StateSet},
    hrada_poseidon_baseline::{parameter_descriptor, PoseidonMerkleState as ScaledMerkleState},
};
use rand::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
const COMPONENT_DEPTHS: [usize; 5] = [4, 8, 12, 16, 20];
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
fn random() -> Integer {
    Integer::from_digits(&enc(&Fr::rand(&mut OsRng)), Order::Lsf)
}
struct Log {
    dir: PathBuf,
    samples: Vec<Value>,
    setups: Vec<Value>,
    updates: Vec<Value>,
    checks: Vec<Value>,
}
impl Log {
    fn save(&self, status: &str, error: Option<&str>) -> Result<(), String> {
        fs::write(self.dir.join("results.json"),serde_json::to_vec_pretty(&json!({"status":status,"error":error,"samples":self.samples,"setups":self.setups,"updates":self.updates,"checks":self.checks,"depths":[4,8,12,16,20],"component_population":8,"proof_repetitions":5,"setup_repetitions":3,"update_populations":[2,8,16,64,256],"update_repetitions":3,"interpretation":"actual API cost; Poseidon sparse-default Merkle rebuilding; capacity is not active population; setups 1 and 2 measure setup only"})).unwrap()).map_err(|e|e.to_string())
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
fn cp_trial(
    log: &mut Log,
    cp: &StateMembership,
    set: &StateSet,
    p: &Integer,
    depth: usize,
    rep: usize,
) -> Result<(), String> {
    let context = format!("HRADA-component-depth-{}-rep-{}", depth, rep).into_bytes();
    let r = random();
    let t = Instant::now();
    let (s, proof) = cp.prove(set, p, &r, &context)?;
    let prove_ms = ms(t);
    let t = Instant::now();
    cp.verify(&s, &proof, &context)?;
    let verify_ms = ms(t);
    let bytes = cp_components(&proof);
    let name = format!("cp-d{}-r{}.bin", depth, rep);
    fs::write(log.dir.join(&name), &bytes).map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"cp_rsa","paired_depth":depth,"rep":rep,"prove_ms":prove_ms,"verify_ms":verify_ms,"proof_bytes":bytes.len(),"witness_component_bytes":Rsa2048::elem_to_bytes(&set.witness(p)?).len(),"accepted":true,"proof_file":name,"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&s.c_p)),"commitment_hex":hex(&enc(&s.c_e_q)),"context_hex":hex(&context)}));
    if rep == 0 {
        log.check(
            &format!("cp_context_mutation_d{}", depth),
            cp.verify(&s, &proof, b"wrong-context").is_err(),
        )?;
    }
    log.save("running", None)
}
fn merkle_trial(
    log: &mut Log,
    cp: &StateMembership,
    state: &ScaledMerkleState,
    link: &LinkParameters,
    desc: &[u8],
    digest: &[u8; 32],
    p: &Integer,
    depth: usize,
    rep: usize,
) -> Result<(), String> {
    let r = random();
    let t = Instant::now();
    let c = cp.commit(p, &r)?;
    let circuit = state.circuit(p)?;
    let proof = hrada_link::prove(&mut OsRng, link, circuit, &r).map_err(|e| format!("{:?}", e))?;
    let prove_ms = ms(t);
    let fields = state.root_fields();
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let t = Instant::now();
    let accepted = hrada_link::verify(link, ck, desc, digest, &proof, &fields, &c)
        .map_err(|e| format!("{:?}", e))?;
    let verify_ms = ms(t);
    if !accepted {
        return Err("valid Merkle proof rejected".into());
    }
    let bytes = enc(&proof);
    let name = format!("merkle-d{}-r{}.bin", depth, rep);
    fs::write(log.dir.join(&name), &bytes).map_err(|e| e.to_string())?;
    log.samples.push(json!({"scheme":"poseidon_lego","paired_depth":depth,"rep":rep,"prove_ms":prove_ms,"verify_ms":verify_ms,"proof_bytes":bytes.len(),"witness_component_bytes":depth*32,"accepted":true,"proof_file":name,"root_hex":hex(&state.root()),"commitment_hex":hex(&enc(&c))}));
    if rep == 0 {
        let mut wrong = fields;
        wrong[0] += Fr::from(1u64);
        log.check(
            &format!("merkle_root_mutation_d{}", depth),
            !hrada_link::verify(link, ck, desc, digest, &proof, &wrong, &c)
                .map_err(|e| format!("{:?}", e))?,
        )?;
    }
    log.save("running", None)
}
fn run(log: &mut Log) -> Result<(), String> {
    let primes = (0..256).map(|_| allocate_prime()).collect::<Vec<_>>();
    let replacement = allocate_prime();
    let set = StateSet::rebuild(&primes[..8])?;
    let mut cp = None;
    for rep in 0..3 {
        let t = Instant::now();
        let protocol = StateMembership::setup_os()?;
        let setup_ms = ms(t);
        let key = &protocol
            .protocol
            .crs
            .crs_hash_to_prime
            .hash_to_prime_parameters;
        let bytes = enc(key);
        log.setups.push(json!({"scheme":"cp_rsa","depth":0,"rep":rep,"setup_ms":setup_ms,"pk_bytes":bytes.len(),"vk_bytes":enc(&key.vk).len()}));
        if rep == 0 {
            fs::write(log.dir.join("cp_range_pk.bin"), bytes).map_err(|e| e.to_string())?;
            fs::write(
                log.dir.join("cp_parameters.bin"),
                protocol.canonical_parameters()?,
            )
            .map_err(|e| e.to_string())?;
            cp = Some(protocol);
        }
        log.save("running", None)?;
    }
    let cp = cp.unwrap();
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let mut update_link = None;
    for depth in COMPONENT_DEPTHS.iter().copied() {
        println!("CAPACITY depth {} population 8", depth);
        let t = Instant::now();
        let tree = ScaledMerkleState::with_depth(&primes[..8], depth)?;
        let dense_build_ms = ms(t);
        let cs = ConstraintSystem::new_ref();
        tree.circuit(&primes[0])?
            .generate_constraints(cs.clone())
            .map_err(|e| format!("{:?}", e))?;
        let constraints = cs.num_constraints();
        if !cs.is_satisfied().map_err(|e| format!("{:?}", e))? {
            return Err("Merkle CS unsatisfied".into());
        }
        drop(cs);
        let mut link = None;
        for rep in 0..3 {
            let t = Instant::now();
            let parameters = hrada_link::setup(&mut OsRng, ck, tree.circuit(&primes[0])?, 2)
                .map_err(|e| format!("{:?}", e))?;
            let setup_ms = ms(t);
            let bytes = enc(&parameters.proving_key);
            log.setups.push(json!({"scheme":"poseidon_lego","depth":depth,"rep":rep,"setup_ms":setup_ms,"pk_bytes":bytes.len(),"vk_bytes":enc(&parameters.proving_key.vk).len(),"constraints":constraints,"tree_build_ms":dense_build_ms,"tree_build_shared_across_setup_repetitions":true}));
            if rep == 0 {
                fs::write(log.dir.join(format!("merkle_d{}_pk.bin", depth)), bytes)
                    .map_err(|e| e.to_string())?;
                link = Some(parameters);
            }
            log.save("running", None)?;
        }
        let link = link.unwrap();
        let mut desc = b"HRADA-POSEIDON-MERKLE-CAPACITY-CONTROL-V1".to_vec();
        desc.extend(parameter_descriptor());
        desc.extend((depth as u64).to_le_bytes());
        let digest = hrada_link::parameter_digest(&link, &desc).map_err(|e| format!("{:?}", e))?;
        fs::write(
            log.dir.join(format!("merkle_d{}_descriptor.bin", depth)),
            &desc,
        )
        .map_err(|e| e.to_string())?;
        for rep in 0..5 {
            println!("COMPONENT depth {} rep {}", depth, rep);
            if rep % 2 == 0 {
                cp_trial(log, &cp, &set, &primes[0], depth, rep)?;
                merkle_trial(
                    log, &cp, &tree, &link, &desc, &digest, &primes[0], depth, rep,
                )?;
            } else {
                merkle_trial(
                    log, &cp, &tree, &link, &desc, &digest, &primes[0], depth, rep,
                )?;
                cp_trial(log, &cp, &set, &primes[0], depth, rep)?;
            }
        }
        if depth == 8 {
            update_link = Some(link);
        }
    }
    let update_link = update_link.expect("depth8 setup");
    let mut update_desc = b"HRADA-POSEIDON-MERKLE-CAPACITY-CONTROL-V1".to_vec();
    update_desc.extend(parameter_descriptor());
    update_desc.extend(8u64.to_le_bytes());
    let update_digest =
        hrada_link::parameter_digest(&update_link, &update_desc).map_err(|e| format!("{:?}", e))?;
    for n in [2usize, 8, 16, 64, 256].iter().copied() {
        for rep in 0..3 {
            println!("UPDATE n {} rep {}", n, rep);
            let build_cp = || -> Result<_, String> {
                let t = Instant::now();
                let x = StateSet::rebuild(&primes[..n])?;
                Ok((x, ms(t)))
            };
            let build_merkle = || -> Result<_, String> {
                let t = Instant::now();
                let x = ScaledMerkleState::with_depth(&primes[..n], 8)?;
                Ok((x, ms(t)))
            };
            let ((old, cp_build_ms), (mut tree, merkle_build_ms)) = if rep % 2 == 0 {
                (build_cp()?, build_merkle()?)
            } else {
                let m = build_merkle()?;
                (build_cp()?, m)
            };
            let oldroot = tree.root();
            let mut changed = primes[..n].to_vec();
            changed[0] = replacement.clone();
            let update_cp = || -> Result<_, String> {
                let t = Instant::now();
                let x = StateSet::rebuild(&changed)?;
                Ok((x, ms(t)))
            };
            let ((newset, cp_update_ms), merkle_update_ms) = if rep % 2 == 0 {
                let c = update_cp()?;
                let t = Instant::now();
                tree.replace(0, replacement.clone())?;
                (c, ms(t))
            } else {
                let t = Instant::now();
                tree.replace(0, replacement.clone())?;
                let m = ms(t);
                (update_cp()?, m)
            };
            if old.accumulator == newset.accumulator || oldroot == tree.root() {
                return Err("replacement root did not change".into());
            }
            let t = Instant::now();
            let _ = newset.witness(&changed[1])?;
            let cp_survivor_witness_ms = ms(t);
            let t = Instant::now();
            let survivor = tree.circuit(&changed[1])?;
            let merkle_survivor_witness_ms = ms(t);
            if survivor.index != 1 {
                return Err("survivor slot changed".into());
            }
            let all_cp = || -> Result<_, String> {
                let t = Instant::now();
                let mut bytes = 0;
                for p in &changed {
                    bytes += Rsa2048::elem_to_bytes(&newset.witness(p)?).len();
                }
                Ok((bytes, ms(t)))
            };
            let all_merkle = || -> Result<_, String> {
                let t = Instant::now();
                let mut bytes = 0;
                for p in &changed {
                    bytes += tree.circuit(p)?.path.len() * 32;
                }
                Ok((bytes, ms(t)))
            };
            let ((cp_witness_bytes, cp_all_witness_ms), (merkle_path_bytes, merkle_all_witness_ms)) =
                if rep % 2 == 0 {
                    (all_cp()?, all_merkle()?)
                } else {
                    let m = all_merkle()?;
                    (all_cp()?, m)
                };
            if newset.witness(&primes[0]).is_ok() || tree.circuit(&primes[0]).is_ok() {
                return Err("old member not removed".into());
            }
            let recovery_proofs = if rep == 0 {
                let r = random();
                let ctx = format!("survivor-n{}", n).into_bytes();
                let (st, pr) = cp.prove(&newset, &changed[1], &r, &ctx)?;
                cp.verify(&st, &pr, &ctx)?;
                let mc = cp.commit(&changed[1], &r)?;
                let mp =
                    hrada_link::prove(&mut OsRng, &update_link, tree.circuit(&changed[1])?, &r)
                        .map_err(|e| format!("{:?}", e))?;
                if !hrada_link::verify(
                    &update_link,
                    ck,
                    &update_desc,
                    &update_digest,
                    &mp,
                    &tree.root_fields(),
                    &mc,
                )
                .map_err(|e| format!("{:?}", e))?
                {
                    return Err("updated survivor proof failed".into());
                }
                fs::write(
                    log.dir.join(format!("updated-survivor-n{}-cp.bin", n)),
                    cp_components(&pr),
                )
                .map_err(|e| e.to_string())?;
                fs::write(
                    log.dir.join(format!("updated-survivor-n{}-merkle.bin", n)),
                    enc(&mp),
                )
                .map_err(|e| e.to_string())?;
                2
            } else {
                0
            };
            log.updates.push(json!({"n":n,"depth":8,"rep":rep,"cp_update_ms":cp_update_ms,"cp_build_ms":cp_build_ms,"merkle_build_ms":merkle_build_ms,"merkle_update_ms":merkle_update_ms,"cp_all_witness_ms":cp_all_witness_ms,"merkle_all_witness_ms":merkle_all_witness_ms,"cp_witness_bytes":cp_witness_bytes,"merkle_path_bytes":merkle_path_bytes,"roots_changed":old.accumulator!=newset.accumulator && oldroot!=tree.root(),"old_member_removed":true,"cp_survivor_witness_ms":cp_survivor_witness_ms,"merkle_survivor_witness_ms":merkle_survivor_witness_ms,"verified_recovery_proofs":recovery_proofs}));
            log.save("running", None)?;
        }
    }
    log.check("fifty_actual_member_proofs", log.samples.len() == 50)?;
    log.check("eighteen_setups", log.setups.len() == 18)?;
    log.check("fifteen_update_cycles", log.updates.len() == 15)?;
    Ok(())
}
fn main() {
    let dir = PathBuf::from("target/hrada-poseidon-components").join(format!(
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
        samples: vec![],
        setups: vec![],
        updates: vec![],
        checks: vec![],
    };
    match run(&mut log) {
        Ok(()) => {
            log.save("complete", None).unwrap();
            println!(
                "DONE 50 timed member proofs + 10 recovery proofs, 18 setups, 15 update cycles"
            );
        }
        Err(e) => {
            log.save("failed", Some(&e)).unwrap();
            eprintln!("FAILED {}", e);
            std::process::exit(1);
        }
    }
}
