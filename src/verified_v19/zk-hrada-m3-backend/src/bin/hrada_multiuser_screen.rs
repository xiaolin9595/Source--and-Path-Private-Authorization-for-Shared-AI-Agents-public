//! Multiuser workload screen; unchanged algorithms, no Auth timing or E2E claim.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::protocols::{
    hrada_auth::AuthFixture,
    hrada_link,
    hrada_membership::{CpProof, MaintainedState, StateMembership},
    hrada_poseidon_baseline::{self, PoseidonMerkleState},
    hrada_public_power::PublicPower,
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{fs, io::Write, path::PathBuf, sync::Arc, time::Instant};
fn cpu() -> f64 {
    extern "C" {
        fn clock() -> std::os::raw::c_long;
    }
    unsafe { clock() as f64 / 1_000_000. }
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
fn enc<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut b = vec![];
    x.serialize(&mut b).unwrap();
    b
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let arg = |s: &str| args.windows(2).find(|w| w[0] == s).expect(s)[1].clone();
    let trial: usize = arg("--trial").parse().unwrap();
    let out = PathBuf::from(arg("--out"));
    fs::create_dir(&out).unwrap();
    let fixture: Value = serde_json::from_slice(&fs::read(arg("--fixture")).unwrap()).unwrap();
    let pool: Vec<Integer> = fixture["fixtures"][trial]["prime_pool_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| Integer::from_str_radix(s.as_str().unwrap(), 16).unwrap())
        .collect();
    assert!(pool.len() >= 261);
    let seed = OsRng.next_u64() >> 2;
    let t = Instant::now();
    let mut users = vec![AuthFixture::new(seed)];
    for i in 1..8 {
        users.push(users[0].second_user(seed + i as u64));
    }
    let mut credentials = vec![];
    for (i, u) in users.iter_mut().enumerate() {
        u.refresh_state(Fr::from_le_bytes_mod_order(
            &pool[i].to_digits::<u8>(Order::Lsf),
        ));
        let circuit = u.circuit_for("Q");
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        credentials.push(json!({"user":i,"prime_hex":pool[i].to_string_radix(16),"commitment":u.base.user_commitment(),"reg_serial":u.base.reg_serial,"constraints":cs.num_constraints(),"satisfied":true}));
    }
    for i in 0..8 {
        for j in 0..i {
            assert_ne!(
                users[i].base.user_commitment(),
                users[j].base.user_commitment()
            );
            assert_eq!(users[i].base.ra_pk, users[j].base.ra_pk);
            assert_eq!(users[i].base.sr_pk, users[j].base.sr_pk);
        }
    }
    let credential_ms = ms(t);
    let t = Instant::now();
    let mut transitions = vec![];
    for cycle in 0..4 {
        let u = &mut users[4 + cycle];
        u.refresh_state(Fr::from_le_bytes_mod_order(
            &pool[257 + cycle].to_digits::<u8>(Order::Lsf),
        ));
        let cs = ConstraintSystem::<Fr>::new_ref();
        u.circuit_for("Q").generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        transitions.push(json!({"slot":4+cycle,"new_prime_hex":pool[257+cycle].to_string_radix(16),"state_signature_refreshed":true,"satisfied":true}));
    }
    let transition_credential_ms = ms(t);
    fs::write(out.join("credentials.json"),serde_json::to_vec_pretty(&json!({"seed":seed,"users":credentials,"credential_ms":credential_ms,"transitions":transitions,"transition_credential_ms":transition_credential_ms,"scope":"eight real signed distinct users; same RA SR terminal; slots8..256 background only; no Auth proof yet"})).unwrap()).unwrap();
    let t = Instant::now();
    let c = cpu();
    let cp = StateMembership::setup_os().unwrap();
    let cp_setup_ms = ms(t);
    let cp_setup_cpu = cpu() - c;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let template = PoseidonMerkleState::with_depth(&pool[..257], 9).unwrap();
    let t = Instant::now();
    let c = cpu();
    let mt_params =
        hrada_link::setup(&mut OsRng, ck, template.circuit(&pool[0]).unwrap(), 2).unwrap();
    let mt_setup_ms = ms(t);
    let mt_setup_cpu = cpu() - c;
    let mut descriptor = hrada_poseidon_baseline::parameter_descriptor();
    descriptor.extend(9u64.to_le_bytes());
    let digest = hrada_link::parameter_digest(&mt_params, &descriptor).unwrap();
    fs::write(
        out.join("cp_parameters.bin"),
        cp.canonical_parameters().unwrap(),
    )
    .unwrap();
    fs::write(
        out.join("cp_range_pk.bin"),
        enc(&cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters),
    )
    .unwrap();
    fs::write(out.join("mt_pk.bin"), enc(&mt_params.proving_key)).unwrap();
    let mut rows = vec![];
    for a in [1usize, 4] {
        for q in [1usize, 4] {
            for is_cp in if (trial + a + q) % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let strategy = if is_cp { "cp" } else { "mt" };
                let ft = Instant::now();
                let fc = cpu();
                let mut background = (4..8)
                    .map(|i| {
                        let mut u = users[0].second_user(seed + i as u64);
                        u.refresh_state(Fr::from_le_bytes_mod_order(
                            &pool[i].to_digits::<u8>(Order::Lsf),
                        ));
                        u
                    })
                    .collect::<Vec<_>>();
                let fixture_reset_ms = ms(ft);
                let fixture_reset_cpu = cpu() - fc;
                let t = Instant::now();
                let c = cpu();
                let power = if is_cp {
                    Some(Arc::new(PublicPower::new(252 * 257, 12).unwrap()))
                } else {
                    None
                };
                let table_ms = ms(t);
                let table_cpu = cpu() - c;
                let t = Instant::now();
                let c = cpu();
                let table_stats = power.as_ref().map(|p| p.stats());
                let stats_ms = ms(t);
                let stats_cpu = cpu() - c;
                let t = Instant::now();
                let c = cpu();
                let mut primes = pool[..257].to_vec();
                let mut state = power
                    .as_ref()
                    .map(|p| MaintainedState::new_with_power(&primes, Arc::clone(p)).unwrap());
                let mut tree = if is_cp {
                    None
                } else {
                    Some(PoseidonMerkleState::with_depth(&primes, 9).unwrap())
                };
                let mut witnesses = state.as_ref().map(|s| {
                    (0..a)
                        .map(|i| s.prepare_witness(&primes[i]).unwrap())
                        .collect::<Vec<_>>()
                });
                let mut paths = tree.as_ref().map(|s| {
                    (0..a)
                        .map(|i| s.circuit(&primes[i]).unwrap())
                        .collect::<Vec<_>>()
                });
                let init_ms = ms(t);
                let init_cpu = cpu() - c;
                let mut updates = vec![];
                let mut shows = vec![];
                let mut journal = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(out.join(format!("a{}q{}-{}.jsonl", a, q, strategy)))
                    .unwrap();
                for cycle in 0..4 {
                    let t = Instant::now();
                    let c = cpu();
                    let previous = state.as_ref().map(|s| s.state().clone());
                    let slot = 4 + cycle;
                    let old = primes[slot].clone();
                    let new = pool[257 + cycle].clone();
                    let sign_t = Instant::now();
                    let sign_c = cpu();
                    background[cycle].refresh_state(Fr::from_le_bytes_mod_order(
                        &new.to_digits::<u8>(Order::Lsf),
                    ));
                    let state_sign_ms = ms(sign_t);
                    let state_sign_cpu = cpu() - sign_c;
                    if is_cp {
                        state.as_mut().unwrap().replace(slot, new.clone()).unwrap();
                    } else {
                        tree.as_mut().unwrap().replace(slot, new.clone()).unwrap();
                    }
                    primes[slot] = new.clone();
                    let record = json!({"epoch":cycle+1,"slot":slot,"old":old.to_string_radix(16),"new":new.to_string_radix(16),"root":if is_cp{Rsa2048::elem_to_bytes(&state.as_ref().unwrap().state().accumulator)}else{tree.as_ref().unwrap().root().to_vec()}});
                    let b = format!("{}\n", record);
                    journal.write_all(b.as_bytes()).unwrap();
                    journal.sync_data().unwrap();
                    let update_ms = ms(t);
                    let update_cpu = cpu() - c;
                    let t = Instant::now();
                    let c = cpu();
                    if is_cp {
                        let current = state.as_ref().unwrap().state();
                        let changes = vec![(slot, old, new)];
                        let old_ws = witnesses.take().unwrap();
                        witnesses = Some(
                            old_ws
                                .iter()
                                .map(|w| {
                                    current
                                        .refresh_prepared_from(
                                            previous.as_ref().unwrap(),
                                            w,
                                            &changes,
                                        )
                                        .unwrap()
                                })
                                .collect(),
                        );
                        drop(old_ws);
                    } else {
                        paths = Some(
                            (0..a)
                                .map(|i| tree.as_ref().unwrap().circuit(&primes[i]).unwrap())
                                .collect(),
                        );
                    }
                    drop(previous);
                    let witness_ms = ms(t);
                    let witness_cpu = cpu() - c;
                    updates.push(json!({"cycle":cycle,"state_sign_ms":state_sign_ms,"state_sign_cpu":state_sign_cpu,"update_ms":update_ms,"update_cpu":update_cpu,"witness_ms":witness_ms,"witness_cpu":witness_cpu,"journal_bytes":b.len(),"sync_calls":1}));
                    for j in 0..q {
                        let user = (cycle * q + j) % a;
                        let r = hrada_link::sample_commitment_randomness(&mut OsRng);
                        let ctx = format!(
                            "multiuser-screen/trial{}/a{}/q{}/epoch{}/show{}/nonce{}",
                            trial,
                            a,
                            q,
                            cycle + 1,
                            j,
                            OsRng.next_u64()
                        )
                        .into_bytes();
                        let t = Instant::now();
                        let c = cpu();
                        let (prove_ms, prove_cpu, verify_ms, verify_cpu, bytes) = if is_cp {
                            let (s, p) = cp
                                .prove_prepared(
                                    state.as_ref().unwrap().state(),
                                    &primes[user],
                                    &witnesses.as_ref().unwrap()[user],
                                    &r,
                                    &ctx,
                                )
                                .unwrap();
                            let pm = ms(t);
                            let pc = cpu() - c;
                            let t = Instant::now();
                            let c = cpu();
                            cp.verify(&s, &p, &ctx).unwrap();
                            let vm = ms(t);
                            let vc = cpu() - c;
                            let bytes = cp_components(&p);
                            fs::write(out.join(format!("a{}q{}-cp-c{}j{}.statement.json",a,q,cycle,j)),serde_json::to_vec(&json!({"context":ctx,"accumulator":Rsa2048::elem_to_bytes(&s.c_p),"commitment":enc(&s.c_e_q),"user":user})).unwrap()).unwrap();
                            (pm, pc, vm, vc, bytes)
                        } else {
                            let commitment = cp.commit(&primes[user], &r).unwrap();
                            let p = hrada_link::prove(
                                &mut OsRng,
                                &mt_params,
                                paths.as_ref().unwrap()[user].clone(),
                                &r,
                            )
                            .unwrap();
                            let pm = ms(t);
                            let pc = cpu() - c;
                            let t = Instant::now();
                            let c = cpu();
                            assert!(hrada_link::verify(
                                &mt_params,
                                ck,
                                &descriptor,
                                &digest,
                                &p,
                                &tree.as_ref().unwrap().root_fields(),
                                &commitment
                            )
                            .unwrap());
                            let vm = ms(t);
                            let vc = cpu() - c;
                            fs::write(out.join(format!("a{}q{}-mt-c{}j{}.statement.json",a,q,cycle,j)),serde_json::to_vec(&json!({"root_fields":tree.as_ref().unwrap().root_fields().iter().map(enc).collect::<Vec<_>>(),"commitment":enc(&commitment),"user":user})).unwrap()).unwrap();
                            (pm, pc, vm, vc, enc(&p))
                        };
                        fs::write(
                            out.join(format!(
                                "a{}q{}-{}-c{}j{}.proof.bin",
                                a, q, strategy, cycle, j
                            )),
                            &bytes,
                        )
                        .unwrap();
                        shows.push(json!({"cycle":cycle,"show":j,"user":user,"prove_ms":prove_ms,"prove_cpu":prove_cpu,"verify_ms":verify_ms,"verify_cpu":verify_cpu,"proof_bytes":bytes.len(),"verified":true}));
                    }
                }
                let t = Instant::now();
                let c = cpu();
                drop(witnesses);
                drop(paths);
                drop(state);
                drop(tree);
                drop(power);
                let drop_ms = ms(t);
                let drop_cpu = cpu() - c;
                rows.push(json!({"a":a,"q":q,"strategy":strategy,"fixture_reset_ms":fixture_reset_ms,"fixture_reset_cpu":fixture_reset_cpu,"table_ms":table_ms,"table_cpu":table_cpu,"stats_ms":stats_ms,"stats_cpu":stats_cpu,"table_stats":table_stats,"init_ms":init_ms,"init_cpu":init_cpu,"drop_ms":drop_ms,"drop_cpu":drop_cpu,"updates":updates,"shows":shows}));
                fs::write(
                    out.join("progress.json"),
                    serde_json::to_vec_pretty(&rows).unwrap(),
                )
                .unwrap();
            }
        }
    }
    fs::write(out.join("results.json"),serde_json::to_vec_pretty(&json!({"trial":trial,"n":257,"cycles":4,"rows":rows,"cp_setup_ms":cp_setup_ms,"cp_setup_cpu":cp_setup_cpu,"mt_setup_ms":mt_setup_ms,"mt_setup_cpu":mt_setup_cpu,"scope":"real membership proofs, same roots and all-active witness refresh; excludes commonAuth generation and verification; parameter setup separately charged; no latency SLA; rotating state prime of distinct background users slots4..7"})).unwrap()).unwrap();
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
