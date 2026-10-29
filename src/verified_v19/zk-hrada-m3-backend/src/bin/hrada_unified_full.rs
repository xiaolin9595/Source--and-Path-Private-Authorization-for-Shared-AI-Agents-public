//! Unified-scale single-cell full request experiment; unchanged proof relations and verifiers.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_auth::AuthFixture,
    hrada_link,
    hrada_membership::{CpProof, MaintainedState, StateMembership},
    hrada_poseidon_baseline::{self, PoseidonMerkleState},
    hrada_public_power::PublicPower,
};
use cpsnarks_set::protocols::{
    hrada_joint::{self, Header, JointVerifier},
    hrada_link::LinkParameters,
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::collections::HashSet;
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
    fn replace_header(&mut self, h: MHeader, params: &[u8; 32]) -> Result<(), String> {
        if h.epoch != self.header.epoch.checked_add(1).ok_or("epoch_overflow")? {
            return Err("nonconsecutive_epoch".into());
        }
        if h.digest != MHeader::new(h.root, h.epoch, params).digest {
            return Err("header_digest_mismatch".into());
        }
        self.header = h;
        Ok(())
    }
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

fn hash(b: &[u8]) -> [u8; 32] {
    let mut h = [0; 32];
    h.copy_from_slice(&Blake2s::digest(b));
    h
}
fn limbs(h: &[u8; 32]) -> [Fr; 2] {
    [
        Fr::from_le_bytes_mod_order(&h[..16]),
        Fr::from_le_bytes_mod_order(&h[16..]),
    ]
}
fn resource(f: &mut fs::File, record: &Value) {
    let b = format!("{}\n", record);
    f.write_all(b.as_bytes()).unwrap();
    f.sync_data().unwrap();
}

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let arg = |s: &str| args.windows(2).find(|w| w[0] == s).expect(s)[1].clone();
    let trial: usize = arg("--trial").parse().unwrap();
    let n: usize = arg("--n").parse().unwrap();
    let active: usize = arg("--active").parse().unwrap();
    let q_requested: usize = arg("--q").parse().unwrap();
    let requests: usize = arg("--requests").parse().unwrap();
    assert!(active > 0 && active.checked_add(4).unwrap() <= n);
    assert!(q_requested > 0 && requests > 0 && requests % q_requested == 0);
    let cycles = requests / q_requested;
    let depth = (usize::BITS - (n - 1).leading_zeros()) as usize;
    assert!((1..=20).contains(&depth));
    let out = PathBuf::from(arg("--out"));
    fs::create_dir(&out).unwrap();
    let fixture: Value = serde_json::from_slice(&fs::read(arg("--fixture")).unwrap()).unwrap();
    let pool: Vec<Integer> = fixture["fixtures"][trial]["prime_pool_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| Integer::from_str_radix(s.as_str().unwrap(), 16).unwrap())
        .collect();
    assert!(pool.len() >= n.checked_add(cycles).unwrap());
    let unique = pool[..n + cycles].iter().collect::<HashSet<_>>();
    assert_eq!(
        unique.len(),
        n + cycles,
        "fixture must not reuse historical state primes"
    );
    for prime in &pool[..n + cycles] {
        cpsnarks_set::protocols::hrada_membership::validate_prime(prime).unwrap();
    }
    let seed = OsRng.next_u64() >> 2;
    let t = Instant::now();
    let mut users = vec![AuthFixture::new(seed)];
    for i in 1..(active + 4) {
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
    for i in 0..(active + 4) {
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
    for cycle in 0..cycles {
        let u = &mut users[active + cycle % 4];
        u.refresh_state(Fr::from_le_bytes_mod_order(
            &pool[n + cycle].to_digits::<u8>(Order::Lsf),
        ));
        let cs = ConstraintSystem::<Fr>::new_ref();
        u.circuit_for("Q").generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        transitions.push(json!({"slot":active+cycle%4,"new_prime_hex":pool[n+cycle].to_string_radix(16),"state_signature_refreshed":true,"satisfied":true}));
    }
    let transition_credential_ms = ms(t);
    fs::write(out.join("credentials.json"),serde_json::to_vec_pretty(&json!({"seed":seed,"users":credentials,"credential_ms":credential_ms,"transitions":transitions,"transition_credential_ms":transition_credential_ms,"active":active,"signed_users":active+4,"capacity_only_users":n-active-4,"scope":"active+4 real signed distinct users; same RA SR terminal; remaining slots capacity primes only; no Auth proof yet"})).unwrap()).unwrap();
    let t = Instant::now();
    let c = cpu();
    let cp = StateMembership::setup_os().unwrap();
    let cp_setup_ms = ms(t);
    let cp_setup_cpu = cpu() - c;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    let template = PoseidonMerkleState::with_depth(&pool[..n], depth).unwrap();
    let t = Instant::now();
    let c = cpu();
    let mt_params =
        hrada_link::setup(&mut OsRng, ck, template.circuit(&pool[0]).unwrap(), 2).unwrap();
    let mt_setup_ms = ms(t);
    let mt_setup_cpu = cpu() - c;
    let mut descriptor = hrada_poseidon_baseline::parameter_descriptor();
    descriptor.extend((depth as u64).to_le_bytes());
    let digest = hrada_link::parameter_digest(&mt_params, &descriptor).unwrap();
    let parameter_io_start = Instant::now();
    let parameter_io_cpu_start = cpu();
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
    let t = Instant::now();
    let c = cpu();
    let member_serialize_write_ms = ms(parameter_io_start);
    let member_serialize_write_cpu = cpu() - parameter_io_cpu_start;
    let auth_params = hrada_link::setup(&mut OsRng, ck, users[0].circuit_for("Q"), 16).unwrap();
    let auth_setup_ms = ms(t);
    let auth_setup_cpu = cpu() - c;
    let cp_descriptor = cp.canonical_parameters().unwrap();
    let auth_digest = hrada_link::parameter_digest(&auth_params, &cp_descriptor).unwrap();
    let auth_vk_hash = hash(&enc(&auth_params.proving_key.vk));
    let t = Instant::now();
    let c = cpu();
    let mut auth_file = fs::File::create(out.join("shared_auth_pk.uncompressed.bin")).unwrap();
    auth_params
        .proving_key
        .serialize_uncompressed(&mut auth_file)
        .unwrap();
    auth_file.sync_data().unwrap();
    let auth_serialize_write_ms = ms(t);
    let auth_serialize_write_cpu = cpu() - c;
    for u in users.iter_mut().take(active) {
        u.close_issuers();
    }
    let mut header_test = mver(&MHeader::new(template.root(), 0, &auth_digest));
    assert_eq!(
        header_test
            .replace_header(MHeader::new(template.root(), 2, &auth_digest), &auth_digest)
            .unwrap_err(),
        "nonconsecutive_epoch"
    );
    let mut bad_header = MHeader::new(template.root(), 1, &auth_digest);
    bad_header.digest[0] ^= 1;
    assert_eq!(
        header_test
            .replace_header(bad_header, &auth_digest)
            .unwrap_err(),
        "header_digest_mismatch"
    );
    let mut rows = vec![];
    for a in [active] {
        for q in [q_requested] {
            for is_cp in if (trial + a + q) % 2 == 0 {
                [true, false]
            } else {
                [false, true]
            } {
                let strategy = if is_cp { "cp" } else { "mt" };
                let ft = Instant::now();
                let fc = cpu();
                let mut background = (active..active + 4)
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
                    Some(Arc::new(PublicPower::new(252 * n, 12).unwrap()))
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
                let mut primes = pool[..n].to_vec();
                let mut state = power
                    .as_ref()
                    .map(|p| MaintainedState::new_with_power(&primes, Arc::clone(p)).unwrap());
                let mut tree = if is_cp {
                    None
                } else {
                    Some(PoseidonMerkleState::with_depth(&primes, depth).unwrap())
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
                let mut cp_ver = state.as_ref().map(|st| {
                    JointVerifier::new(
                        Header::new(st.state().accumulator.clone(), 0, &auth_digest),
                        auth_digest,
                    )
                });
                let mut mt_ver = tree
                    .as_ref()
                    .map(|st| mver(&MHeader::new(st.root(), 0, &auth_digest)));
                let mp = MParameters {
                    cp: &cp,
                    auth: &auth_params,
                    member: &mt_params,
                    descriptor: descriptor.clone(),
                    member_digest: digest,
                    auth_descriptor: cp_descriptor.clone(),
                    digest: auth_digest,
                };
                let mut resource_file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(out.join(format!("a{}q{}-{}.resources.jsonl", a, q, strategy)))
                    .unwrap();
                let mut updates = vec![];
                let mut shows = vec![];
                let mut journal = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(out.join(format!("a{}q{}-{}.jsonl", a, q, strategy)))
                    .unwrap();
                for cycle in 0..cycles {
                    let cycle_start = Instant::now();
                    let cycle_cpu = cpu();
                    let t = Instant::now();
                    let c = cpu();
                    let previous = state.as_ref().map(|s| s.state().clone());
                    let slot = active + cycle % 4;
                    let old = primes[slot].clone();
                    let new = pool[n + cycle].clone();
                    let sign_t = Instant::now();
                    let sign_c = cpu();
                    background[cycle % 4].refresh_state(Fr::from_le_bytes_mod_order(
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
                    if is_cp {
                        cp_ver
                            .as_mut()
                            .unwrap()
                            .replace_header(Header::new(
                                state.as_ref().unwrap().state().accumulator.clone(),
                                (cycle + 1) as u64,
                                &auth_digest,
                            ))
                            .unwrap();
                    } else {
                        mt_ver
                            .as_mut()
                            .unwrap()
                            .replace_header(
                                MHeader::new(
                                    tree.as_ref().unwrap().root(),
                                    (cycle + 1) as u64,
                                    &auth_digest,
                                ),
                                &auth_digest,
                            )
                            .unwrap();
                    }
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
                        let ack_start = if j == 0 { cycle_start } else { Instant::now() };
                        let ack_cpu_start = if j == 0 { cycle_cpu } else { cpu() };
                        let user = (cycle * q + j) % a;
                        let r = hrada_link::sample_commitment_randomness(&mut OsRng);
                        let nonce = OsRng.next_u64();
                        let mut ac = users[user].circuit_for("Q");
                        let hf = if is_cp {
                            Header::new(
                                state.as_ref().unwrap().state().accumulator.clone(),
                                (cycle + 1) as u64,
                                &auth_digest,
                            )
                            .digest_fields()
                        } else {
                            limbs(&mt_ver.as_ref().unwrap().header.digest)
                        };
                        ac.request.fields[0] = hf[0];
                        ac.request.fields[1] = hf[1];
                        ac.request.fields[2] = Fr::from((cycle + 1) as u64);
                        ac.request.fields[9] = Fr::from(500u64);
                        ac.request.fields[10] = Fr::from(nonce);
                        ac.request.fields[11] = Fr::from(550u64);
                        let fields = ac.public_fields();
                        let ctx = hrada_joint::context(&auth_digest, &fields).unwrap();
                        let t = Instant::now();
                        let c = cpu();
                        let (
                            prove_ms,
                            prove_cpu,
                            auth_ms,
                            auth_cpu,
                            verify_ms,
                            verify_cpu,
                            ack_ms,
                            ack_cpu,
                            bytes,
                            auth_bytes,
                            commitment_bytes,
                            checks,
                            negative_ms,
                            negative_cpu,
                        ) = if is_cp {
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
                            let ap = hrada_link::prove(&mut OsRng, &auth_params, ac, &r).unwrap();
                            let am = ms(t);
                            let auc = cpu() - c;
                            let t = Instant::now();
                            let c = cpu();
                            cp_ver
                                .as_mut()
                                .unwrap()
                                .authorize(
                                    &cp,
                                    &auth_params,
                                    &s,
                                    &p,
                                    &ap,
                                    &fields,
                                    &fields,
                                    500,
                                    550,
                                    || 500,
                                )
                                .unwrap();
                            let vm = ms(t);
                            let vc = cpu() - c;
                            resource(
                                &mut resource_file,
                                &json!({"user":user,"nonce":nonce,"epoch":cycle+1,"operation":"append_authorized_resource_access","synthetic_clock":500}),
                            );
                            let ackm = ms(ack_start);
                            let ackc = cpu() - ack_cpu_start;
                            let t = Instant::now();
                            let c = cpu();
                            let replay = cp_ver
                                .as_mut()
                                .unwrap()
                                .authorize(
                                    &cp,
                                    &auth_params,
                                    &s,
                                    &p,
                                    &ap,
                                    &fields,
                                    &fields,
                                    500,
                                    550,
                                    || 500,
                                )
                                .unwrap_err();
                            assert_eq!(replay, "nonce_already_consumed");
                            let mut stale = JointVerifier::new(
                                Header::new(s.c_p.clone(), (cycle + 2) as u64, &auth_digest),
                                auth_digest,
                            );
                            let stale_error = stale
                                .authorize(
                                    &cp,
                                    &auth_params,
                                    &s,
                                    &p,
                                    &ap,
                                    &fields,
                                    &fields,
                                    500,
                                    550,
                                    || 500,
                                )
                                .unwrap_err();
                            assert_eq!(stale_error, "stale_header");
                            let wrong = cp
                                .commit(&primes[if a == 1 { active } else { (user + 1) % a }], &r)
                                .unwrap();
                            assert!(!hrada_link::verify(
                                &auth_params,
                                ck,
                                &cp_descriptor,
                                &auth_digest,
                                &ap,
                                &fields,
                                &wrong
                            )
                            .unwrap());
                            let checks = json!({"joint_verified":true,"shared_auth_key_user_valid":true,"replay_rejected":true,"old_bundle_next_epoch_rejected":true,"cross_user_commitment_rejected":true});
                            let nm = ms(t);
                            let nc = cpu() - c;
                            fs::write(out.join(format!("a{}q{}-cp-c{}j{}.statement.json",a,q,cycle,j)),serde_json::to_vec(&json!({"context":ctx,"accumulator":Rsa2048::elem_to_bytes(&s.c_p),"commitment":enc(&s.c_e_q),"user":user,"fields":fields.iter().map(enc).collect::<Vec<_>>()})).unwrap()).unwrap();
                            (
                                pm,
                                pc,
                                am,
                                auc,
                                vm,
                                vc,
                                ackm,
                                ackc,
                                cp_components(&p),
                                enc(&ap),
                                enc(&s.c_e_q),
                                checks,
                                nm,
                                nc,
                            )
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
                            let ap = hrada_link::prove(&mut OsRng, &auth_params, ac, &r).unwrap();
                            let am = ms(t);
                            let auc = cpu() - c;
                            let bundle = MBundle {
                                membership: p,
                                auth: ap,
                                commitment,
                                fields: fields.clone(),
                                root: tree.as_ref().unwrap().root_fields(),
                                request_time: 500,
                                permit_until: 550,
                            };
                            let t = Instant::now();
                            let c = cpu();
                            mt_ver
                                .as_mut()
                                .unwrap()
                                .authorize(&mp, &bundle, &fields, 500, 550, || 500)
                                .unwrap();
                            let vm = ms(t);
                            let vc = cpu() - c;
                            resource(
                                &mut resource_file,
                                &json!({"user":user,"nonce":nonce,"epoch":cycle+1,"operation":"append_authorized_resource_access","synthetic_clock":500}),
                            );
                            let ackm = ms(ack_start);
                            let ackc = cpu() - ack_cpu_start;
                            let t = Instant::now();
                            let c = cpu();
                            let replay = mt_ver
                                .as_mut()
                                .unwrap()
                                .authorize(&mp, &bundle, &fields, 500, 550, || 500)
                                .unwrap_err();
                            assert_eq!(replay, "nonce_already_consumed");
                            let mut stale = mver(&MHeader::new(
                                tree.as_ref().unwrap().root(),
                                (cycle + 2) as u64,
                                &auth_digest,
                            ));
                            assert_eq!(
                                stale
                                    .authorize(&mp, &bundle, &fields, 500, 550, || 500)
                                    .unwrap_err(),
                                "stale_header"
                            );
                            let wrong = cp
                                .commit(&primes[if a == 1 { active } else { (user + 1) % a }], &r)
                                .unwrap();
                            assert!(!hrada_link::verify(
                                &auth_params,
                                ck,
                                &cp_descriptor,
                                &auth_digest,
                                &bundle.auth,
                                &fields,
                                &wrong
                            )
                            .unwrap());
                            let checks = json!({"joint_verified":true,"shared_auth_key_user_valid":true,"replay_rejected":true,"old_bundle_next_epoch_rejected":true,"cross_user_commitment_rejected":true});
                            let nm = ms(t);
                            let nc = cpu() - c;
                            fs::write(out.join(format!("a{}q{}-mt-c{}j{}.statement.json",a,q,cycle,j)),serde_json::to_vec(&json!({"root_fields":bundle.root.iter().map(enc).collect::<Vec<_>>(),"commitment":enc(&commitment),"user":user,"fields":fields.iter().map(enc).collect::<Vec<_>>()})).unwrap()).unwrap();
                            (
                                pm,
                                pc,
                                am,
                                auc,
                                vm,
                                vc,
                                ackm,
                                ackc,
                                enc(&bundle.membership),
                                enc(&bundle.auth),
                                enc(&commitment),
                                checks,
                                nm,
                                nc,
                            )
                        };
                        let prefix = format!("a{}q{}-{}-c{}j{}", a, q, strategy, cycle, j);
                        fs::write(out.join(format!("{}.proof.bin", prefix)), &bytes).unwrap();
                        fs::write(out.join(format!("{}.auth.bin", prefix)), &auth_bytes).unwrap();
                        fs::write(
                            out.join(format!("{}.commitment.bin", prefix)),
                            &commitment_bytes,
                        )
                        .unwrap();
                        let post_ack_other_ms = ms(ack_start) - ack_ms - negative_ms;
                        let post_ack_other_cpu = cpu() - ack_cpu_start - ack_cpu - negative_cpu;
                        shows.push(json!({"cycle":cycle,"show":j,"user":user,"nonce":nonce,"prove_ms":prove_ms,"prove_cpu":prove_cpu,"auth_ms":auth_ms,"auth_cpu":auth_cpu,"verify_ms":verify_ms,"verify_cpu":verify_cpu,"ack_ms":ack_ms,"ack_cpu":ack_cpu,"post_ack_artifact_cleanup_ms":post_ack_other_ms,"post_ack_artifact_cleanup_cpu":post_ack_other_cpu,"negative_ms":negative_ms,"negative_cpu":negative_cpu,"proof_bytes":bytes.len(),"auth_bytes":auth_bytes.len(),"commitment_bytes":commitment_bytes.len(),"verified":true,"checks":checks,"auth_vk_hash":auth_vk_hash}));
                        fs::write(
                            out.join("live_shows.json"),
                            serde_json::to_vec_pretty(&shows).unwrap(),
                        )
                        .unwrap();
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
    fs::write(out.join("results.json"),serde_json::to_vec_pretty(&json!({"trial":trial,"n":n,"depth":depth,"active":active,"q":q_requested,"requests_per_cell":requests,"cycles":cycles,"signed_users":active+4,"capacity_only_users":n-active-4,"randomness_distribution":"uniform_BLS12_381_Fr","rows":rows,"member_serialize_write_ms":member_serialize_write_ms,"member_serialize_write_cpu":member_serialize_write_cpu,"auth_setup_ms":auth_setup_ms,"auth_setup_cpu":auth_setup_cpu,"auth_serialize_write_ms":auth_serialize_write_ms,"auth_serialize_write_cpu":auth_serialize_write_cpu,"auth_vk_hash":auth_vk_hash,"cp_setup_ms":cp_setup_ms,"cp_setup_cpu":cp_setup_cpu,"mt_setup_ms":mt_setup_ms,"mt_setup_cpu":mt_setup_cpu,"scope":"full fresh member plus Auth proofs under one shared Auth key for all active users; eager all-active witness refresh; actual local resource ACK; ack includes update+witness on firstshow of interval; synthetic clock500/550 no expiry SLA; parameter setup separately charged; four rotating background slots with fresh state primes; no external distribution"})).unwrap()).unwrap();
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
