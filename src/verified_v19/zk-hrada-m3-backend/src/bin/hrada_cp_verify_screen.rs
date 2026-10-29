//! Isolated CP verification profile and ONE immutable PVK reuse candidate.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_ec::ProjectiveCurve;
use ark_serialize::CanonicalSerialize;
use cpsnarks_set::protocols::hrada_membership::{
    verifier_screen::{profile_uncached, PreparedCpVerifier},
    CpProof, CpStatement, StateMembership, StateSet,
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Instant,
};
struct CountAlloc;
static LIVE: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let p = System.alloc(l);
        if !p.is_null() {
            LIVE.fetch_add(l.size(), Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        System.dealloc(p, l)
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        let q = System.realloc(p, l, n);
        if !q.is_null() {
            LIVE.fetch_add(n, Ordering::Relaxed);
            LIVE.fetch_sub(l.size(), Ordering::Relaxed);
        }
        q
    }
}
#[global_allocator]
static A: CountAlloc = CountAlloc;
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.
}
fn cpu() -> f64 {
    extern "C" {
        fn clock() -> std::os::raw::c_long;
    }
    unsafe { clock() as f64 / 1_000_000. }
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
    let profile_only = args.contains(&"--profile-only".into());
    let fixture: Value = serde_json::from_slice(&fs::read(arg("--fixture")).unwrap()).unwrap();
    let pool: Vec<Integer> = fixture["fixtures"][trial]["prime_pool_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| Integer::from_str_radix(s.as_str().unwrap(), 16).unwrap())
        .collect();
    let t = Instant::now();
    let cp = StateMembership::setup_os().unwrap();
    let setup_ms = ms(t);
    fs::write(
        out.join("cp_parameters.bin"),
        cp.canonical_parameters().unwrap(),
    )
    .unwrap();
    fs::write(
        out.join("range_vk.bin"),
        enc(&cp
            .protocol
            .crs
            .crs_hash_to_prime
            .hash_to_prime_parameters
            .vk),
    )
    .unwrap();
    let mut rows = vec![];
    for mode in if profile_only {
        vec!["profile"]
    } else {
        vec!["same_state", "k1"]
    } {
        let mut primes = pool[..257].to_vec();
        let mut cases = vec![];
        for j in 0..3 {
            if mode == "k1" {
                primes[j + 1] = pool[257 + j].clone();
            }
            let set = StateSet::rebuild(&primes).unwrap();
            let mut rb = [0u8; 30];
            OsRng.fill_bytes(&mut rb);
            let r = Integer::from_digits(&rb, Order::MsfBe);
            let ctx = format!(
                "cp-verifier-screen/trial={}/mode={}/epoch={}/nonce={}",
                trial,
                mode,
                j,
                OsRng.next_u64()
            )
            .into_bytes();
            let (s, p) = cp.prove(&set, &primes[0], &r, &ctx).unwrap();
            fs::write(
                out.join(format!("{}-{}.proof.bin", mode, j)),
                cp_components(&p),
            )
            .unwrap();
            fs::write(out.join(format!("{}-{}.statement.json",mode,j)),serde_json::to_vec_pretty(&json!({"context":ctx,"accumulator_hex":Rsa2048::elem_to_bytes(&s.c_p).iter().map(|b|format!("{:02x}",b)).collect::<String>(),"commitment":enc(&s.c_e_q)})).unwrap()).unwrap();
            cases.push((s, p, ctx));
        }
        if profile_only {
            for (s, p, ctx) in &cases {
                let t = Instant::now();
                cp.verify(s, p, ctx).unwrap();
                let original_ms = ms(t);
                let parts = profile_uncached(&cp, s, p, ctx).unwrap();
                rows.push(json!({"original_ms":original_ms,"profile":parts}));
            }
            continue;
        }
        let mem = LIVE.load(Ordering::Relaxed);
        let c = cpu();
        let t = Instant::now();
        let cached = PreparedCpVerifier::new(&cp);
        let init_ms = ms(t);
        let init_cpu = cpu() - c;
        let heap_bytes = LIVE.load(Ordering::Relaxed) - mem;
        let stack_bytes = cached.stack_bytes();
        let mut samples = vec![];
        let mut checks = vec![];
        for (j, (s, p, ctx)) in cases.iter().enumerate() {
            let mut original_ms = 0.;
            let mut original_cpu = 0.;
            let mut optimized_ms = 0.;
            let mut optimized_cpu = 0.;
            for opt in if (trial + j) % 2 == 0 {
                [false, true]
            } else {
                [true, false]
            } {
                let c = cpu();
                let t = Instant::now();
                if opt {
                    cached.verify(s, p, ctx).unwrap();
                    optimized_ms = ms(t);
                    optimized_cpu = cpu() - c;
                } else {
                    cp.verify(s, p, ctx).unwrap();
                    original_ms = ms(t);
                    original_cpu = cpu() - c;
                }
            }
            samples.push(json!({"show":j,"original_ms":original_ms,"original_cpu":original_cpu,"optimized_ms":optimized_ms,"optimized_cpu":optimized_cpu,"optimized_first":(trial+j)%2!=0}));
        }
        let t = Instant::now();
        let c = cpu();
        drop(cached);
        let drop_ms = ms(t);
        let drop_cpu = cpu() - c;
        // Validation outside timing and outside the charged three-show cache lifetime.
        let cached = PreparedCpVerifier::new(&cp);
        for (j, (s, p, ctx)) in cases.iter().enumerate() {
            let wrong_context = b"wrong-context";
            let bad_commitment = CpStatement {
                c_p: s.c_p.clone(),
                c_e_q: s.c_e_q.double(),
            };
            let bad_state = CpStatement {
                c_p: StateSet::rebuild(&pool[1..258]).unwrap().accumulator,
                c_e_q: s.c_e_q,
            };
            let mut bad_range = p.clone();
            bad_range.proof_hash_to_prime.a = Default::default();
            let mut bad_link = p.clone();
            bad_link.proof_hash_to_prime.link_d = Default::default();
            let mut bad_root = p.clone();
            bad_root.proof_root.message3.s_e += 1;
            let mut bad_modeq = p.clone();
            bad_modeq.proof_modeq.message2.s_e += 1;
            for (name, st, pr, cx) in [
                ("context", s, p, &wrong_context[..]),
                ("commitment", &bad_commitment, p, &ctx[..]),
                ("state", &bad_state, p, &ctx[..]),
                ("range", s, &bad_range, &ctx[..]),
                ("link", s, &bad_link, &ctx[..]),
                ("root", s, &bad_root, &ctx[..]),
                ("modeq", s, &bad_modeq, &ctx[..]),
            ] {
                let a = cp.verify(st, pr, cx).is_err();
                let b = cached.verify(st, pr, cx).is_err();
                assert!(a && b, "{}", name);
                checks.push(
                    json!({"show":j,"case":name,"reference_rejected":a,"optimized_rejected":b}),
                );
            }
        }
        drop(cached);
        rows.push(json!({"mode":mode,"cache_init_ms":init_ms,"cache_init_cpu":init_cpu,"cache_drop_ms":drop_ms,"cache_drop_cpu":drop_cpu,"cache_live_requested_rust_heap_bytes":heap_bytes,"cache_inline_bytes":stack_bytes,"samples":samples,"negative_checks":checks,"state_invalidation_ms":0,"state_invalidation_reason":"cache contains only immutable parameter data, no state or proof; borrow forbids parameter mutation during lifetime"}));
    }
    if !profile_only {
        let t = Instant::now();
        let other = StateMembership::setup_os().unwrap();
        let setup_other = ms(t);
        let mut primes = pool[..257].to_vec();
        let set = StateSet::rebuild(&primes).unwrap();
        let (s, p) = cp
            .prove(
                &set,
                &primes.remove(0),
                &Integer::from(19),
                b"parameter-rotation",
            )
            .unwrap();
        fs::write(out.join("rotation-old.proof.bin"), cp_components(&p)).unwrap();
        let t = Instant::now();
        let cache = PreparedCpVerifier::new(&other);
        let rebuild_ms = ms(t);
        assert!(other.verify(&s, &p, b"parameter-rotation").is_err());
        assert!(cache.verify(&s, &p, b"parameter-rotation").is_err());
        let (s2, p2) = other
            .prove(&set, &pool[0], &Integer::from(21), b"parameter-rotation")
            .unwrap();
        fs::write(out.join("rotation-new.proof.bin"), cp_components(&p2)).unwrap();
        fs::write(
            out.join("rotation-parameters.bin"),
            other.canonical_parameters().unwrap(),
        )
        .unwrap();
        fs::write(
            out.join("rotation-vk.bin"),
            enc(&other
                .protocol
                .crs
                .crs_hash_to_prime
                .hash_to_prime_parameters
                .vk),
        )
        .unwrap();
        for (name, st) in [("old", &s), ("new", &s2)] {
            fs::write(out.join(format!("rotation-{}.statement.json",name)),serde_json::to_vec_pretty(&json!({"context":b"parameter-rotation".to_vec(),"accumulator_hex":Rsa2048::elem_to_bytes(&st.c_p).iter().map(|b|format!("{:02x}",b)).collect::<String>(),"commitment":enc(&st.c_e_q)})).unwrap()).unwrap();
        }
        other.verify(&s2, &p2, b"parameter-rotation").unwrap();
        cache.verify(&s2, &p2, b"parameter-rotation").unwrap();
        fs::write(out.join("rotation.json"),serde_json::to_vec_pretty(&json!({"new_setup_ms":setup_other,"new_cache_build_ms":rebuild_ms,"old_proof_rejected_by_both":true,"new_proof_accepted_by_both":true})).unwrap()).unwrap();
    }
    fs::write(out.join("results.json"),serde_json::to_vec_pretty(&json!({"trial":trial,"profile_only":profile_only,"setup_ms":setup_ms,"rows":rows,"memory_note":"global allocator live requested Rust heap delta across cache construction; excludes allocator metadata, GMP and borrowed existing CP object; inline bytes separately"})).unwrap()).unwrap();
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
