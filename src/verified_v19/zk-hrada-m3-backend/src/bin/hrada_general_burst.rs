#![recursion_limit = "256"]
//! E3 maintained-state update-burst worker (independent of frozen runs). Actual authenticated downloaded keys are used for proofs.
use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381::{Bls12_381, Fr, G1Projective};
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2s, Digest};
use cpsnarks_set::{
    protocols::{
        hrada_auth::{AuthCircuit, AuthFixture},
        hrada_joint::{self, Header, JointVerifier},
        hrada_link::{self, LinkParameters},
        hrada_membership::{
            allocate_prime, CpProof, MaintainedState, PreparedWitness, StateMembership,
        },
        hrada_poseidon_baseline::{
            parameter_descriptor, PoseidonMerkleCircuit, PoseidonMerkleState as MerkleState,
        },
        hrada_public_power::PublicPower,
    },
    utils::integer_to_bigint_mod_q,
};
use rand::{rngs::OsRng, RngCore};
use rug::{integer::Order, Integer};
use serde::Serialize;
use serde_json::{json, Value};
use std::convert::TryFrom;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{BufRead, Read, Write},
    path::PathBuf,
    process::Command,
    sync::Arc,
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

#[derive(Clone, Serialize)]
struct FileMeta {
    id: String,
    name: String,
    bytes: u64,
    blake2s: String,
    #[serde(rename = "type")]
    kind: String,
    depth: Option<usize>,
}
fn digest_file(path: &std::path::Path) -> Result<(u64, String), String> {
    let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = Blake2s::new();
    let mut b = vec![0u8; 1024 * 1024];
    let mut count = 0;
    loop {
        let n = f.read(&mut b).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&b[..n]);
        count += n as u64;
    }
    Ok((count, hex(&h.finalize())))
}
fn persist_key<T: CanonicalSerialize>(
    dir: &std::path::Path,
    id: &str,
    name: &str,
    kind: &str,
    depth: Option<usize>,
    key: &T,
) -> Result<FileMeta, String> {
    let mut f =
        std::io::BufWriter::new(fs::File::create(dir.join(name)).map_err(|e| e.to_string())?);
    key.serialize_uncompressed(&mut f)
        .map_err(|e| format!("serialize:{:?}", e))?;
    f.flush().map_err(|e| e.to_string())?;
    drop(f);
    let (bytes, blake2s) = digest_file(&dir.join(name))?;
    Ok(FileMeta {
        id: id.into(),
        name: name.into(),
        bytes,
        blake2s,
        kind: kind.into(),
        depth,
    })
}
fn persist_bytes(
    dir: &std::path::Path,
    id: &str,
    name: &str,
    kind: &str,
    depth: Option<usize>,
    b: &[u8],
) -> Result<FileMeta, String> {
    fs::write(dir.join(name), b).map_err(|e| e.to_string())?;
    Ok(FileMeta {
        id: id.into(),
        name: name.into(),
        bytes: b.len() as u64,
        blake2s: hex(&hash(b)),
        kind: kind.into(),
        depth,
    })
}
#[derive(Default, Serialize)]
struct LoadStats {
    loaded_bytes: u64,
    hash_ms: f64,
    decode_ms: f64,
    wall_ms: f64,
    loaded_ids: Vec<String>,
    cache_hits: Vec<String>,
}
fn authenticate(
    dir: &std::path::Path,
    file: &FileMeta,
    stats: &mut LoadStats,
) -> Result<PathBuf, String> {
    let path = dir.join(&file.name);
    let t = Instant::now();
    let (n, h) = digest_file(&path)?;
    stats.hash_ms += ms(t);
    if n != file.bytes || h != file.blake2s {
        return Err(format!(
            "downloaded_parameter_authentication_failed:{}",
            file.id
        ));
    }
    stats.loaded_bytes += n;
    stats.loaded_ids.push(file.id.clone());
    Ok(path)
}
fn load_key(
    dir: &std::path::Path,
    file: &FileMeta,
    stats: &mut LoadStats,
) -> Result<legogro16::ProvingKey<Bls12_381>, String> {
    let path = authenticate(dir, file, stats)?;
    let t = Instant::now();
    let mut reader = std::io::BufReader::new(fs::File::open(path).map_err(|e| e.to_string())?);
    // Only trusted-hash-authenticated setup output; cache immutable for this process lifetime.
    let key = legogro16::ProvingKey::<Bls12_381>::deserialize_unchecked(&mut reader)
        .map_err(|e| format!("decode:{:?}", e))?;
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing).map_err(|e| e.to_string())? != 0 {
        return Err("trailing_parameter_bytes".into());
    }
    stats.decode_ms += ms(t);
    Ok(key)
}
fn depth_for(_: &str, _: &str, n: usize) -> usize {
    (usize::BITS - (n - 1).leading_zeros()) as usize
}
struct Loaded {
    group: String,
    cache: PathBuf,
    auth: LinkParameters,
    member: Option<LinkParameters>,
    depth: Option<usize>,
    descriptor: Vec<u8>,
    member_digest: [u8; 32],
    auth_descriptor: Vec<u8>,
    digest: [u8; 32],
}
enum Bundle {
    Cp(CBundle),
    Mt(MBundle),
}
struct Track {
    n: usize,
    next_step: usize,
    epoch: u64,
    primes: Vec<Integer>,
    tree: Option<MerkleState>,
    cp_set: Option<MaintainedState>,
    cp_witness: Option<PreparedWitness>,
    mt_witness: Option<PoseidonMerkleCircuit>,
    cp_verifier: Option<JointVerifier>,
    mt_verifier: Option<MVerifier>,
    witness_epoch: u64,
    previous: Option<Bundle>,
    origin: Instant,
    consumed: HashSet<Vec<u8>>,
}
struct Worker {
    public_power: Arc<PublicPower>,
    n: usize,
    pattern: String,
    dir: PathBuf,
    origin: Instant,
    files: Vec<FileMeta>,
    manifest: Value,
    cp: StateMembership,
    cpbytes: Vec<u8>,
    fixture: AuthFixture,
    primes: Vec<Integer>,
    loaded: Option<Loaded>,
    secondary_loaded: Option<Loaded>,
    tracks: HashMap<String, Track>,
    records: Vec<Value>,
    events: Vec<Value>,
    nonce: u64,
    executions: usize,
}
impl Worker {
    fn save(&self, status: &str, failure: Option<&str>) -> Result<(), String> {
        let v = json!({"status":status,"failure":failure,"manifest":self.manifest,"records":self.records,"events":self.events,"elapsed_ms":ms(self.origin),"resource_executions":self.executions,"scope":"local persistent general-burst worker; each update maintained/committed before one lazy witness refresh; initialization excluded; no WAN/concurrency/SLA"});
        fs::write(
            self.dir.join("results.json.tmp"),
            serde_json::to_vec_pretty(&v).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        fs::rename(
            self.dir.join("results.json.tmp"),
            self.dir.join("results.json"),
        )
        .map_err(|e| e.to_string())
    }
    fn event(&mut self, kind: &str, details: Value) -> Result<(), String> {
        self.events.push(json!({"seq":self.events.len(),"event":kind,"elapsed_ms":ms(self.origin),"details":details}));
        self.save("running", None)
    }
    fn meta(&self, id: &str) -> Result<FileMeta, String> {
        self.files
            .iter()
            .find(|x| x.id == id)
            .cloned()
            .ok_or_else(|| format!("missing_manifest_file:{}", id))
    }
    fn load(
        &mut self,
        strategy: &str,
        trajectory: &str,
        n: usize,
        cache: &std::path::Path,
    ) -> Result<LoadStats, String> {
        let t = Instant::now();
        let mut stats = LoadStats::default();
        let group = format!("{}:{}", strategy, trajectory);
        if self
            .loaded
            .as_ref()
            .map(|x| x.group != group || x.cache != cache)
            .unwrap_or(false)
        {
            self.loaded = None;
        }
        if self.loaded.is_none() {
            let auth = LinkParameters {
                proving_key: load_key(cache, &self.meta("auth")?, &mut stats)?,
                request_fields: 16,
            };
            self.loaded = Some(Loaded {
                group,
                cache: cache.into(),
                auth,
                member: None,
                depth: None,
                descriptor: vec![],
                member_digest: [0; 32],
                auth_descriptor: vec![],
                digest: [0; 32],
            });
        } else {
            stats.cache_hits.push("auth".into());
        }
        if strategy == "cp" {
            if self.loaded.as_ref().unwrap().auth_descriptor.is_empty() {
                let file = self.meta("cp_parameters")?;
                let path = authenticate(cache, &file, &mut stats)?;
                let bytes = fs::read(path).map_err(|e| e.to_string())?;
                if bytes != self.cpbytes {
                    return Err("cp_public_parameter_bytes_differ".into());
                }
                let range = load_key(cache, &self.meta("cp_range")?, &mut stats)?;
                self.cp
                    .protocol
                    .crs
                    .crs_hash_to_prime
                    .hash_to_prime_parameters = range;
                if self.cp.canonical_parameters()? != self.cpbytes {
                    return Err("downloaded_cp_range_vk_mismatch".into());
                }
                let loaded = self.loaded.as_mut().unwrap();
                loaded.auth_descriptor = self.cpbytes.clone();
                loaded.digest = hrada_link::parameter_digest(&loaded.auth, &self.cpbytes)
                    .map_err(|e| format!("{:?}", e))?;
            } else {
                stats
                    .cache_hits
                    .extend(["cp_parameters".into(), "cp_range".into()]);
            }
        } else {
            let depth = depth_for(strategy, trajectory, n);
            if self.loaded.as_ref().unwrap().depth != Some(depth) {
                let member = LinkParameters {
                    proving_key: load_key(
                        cache,
                        &self.meta(&format!("poseidon_{}", depth))?,
                        &mut stats,
                    )?,
                    request_fields: 2,
                };
                let df = self.meta(&format!("descriptor_{}", depth))?;
                let path = authenticate(cache, &df, &mut stats)?;
                let descriptor = fs::read(path).map_err(|e| e.to_string())?;
                let md = hrada_link::parameter_digest(&member, &descriptor)
                    .map_err(|e| format!("{:?}", e))?;
                let mut ad = b"HRADA-CAPACITY-AUTH-V1".to_vec();
                ad.extend(md);
                let l = self.loaded.as_mut().unwrap();
                l.digest =
                    hrada_link::parameter_digest(&l.auth, &ad).map_err(|e| format!("{:?}", e))?;
                l.member = Some(member);
                l.depth = Some(depth);
                l.descriptor = descriptor;
                l.member_digest = md;
                l.auth_descriptor = ad;
            } else {
                stats.cache_hits.extend([
                    format!("poseidon_{}", depth),
                    format!("descriptor_{}", depth),
                ]);
            }
        }
        stats.wall_ms = ms(t);
        Ok(stats)
    }
    fn cache_probe(
        &mut self,
        strategy: &str,
        trajectory: &str,
        n: usize,
        cache: &std::path::Path,
    ) -> Result<Value, String> {
        // Secondary installation must not replace the primary protocol key object.
        let held_range = self
            .cp
            .protocol
            .crs
            .crs_hash_to_prime
            .hash_to_prime_parameters
            .clone();
        let held = self.loaded.take();
        self.loaded = self.secondary_loaded.take();
        let result = self.load(strategy, trajectory, n, cache);
        self.secondary_loaded = self.loaded.take();
        self.loaded = held;
        self.cp
            .protocol
            .crs
            .crs_hash_to_prime
            .hash_to_prime_parameters = held_range;
        let stats = result?;
        let row = json!({"event":"cache_probe","status":"ok","strategy":strategy,"trajectory":trajectory,"n":n,"cache_dir":cache,"metrics":{"load":stats},"full_proof_executed":false});
        self.records.push(row.clone());
        self.save("running", None)?;
        Ok(row)
    }
    fn resource(
        &mut self,
        strategy: &str,
        trajectory: &str,
        step: usize,
        n: usize,
        nonce: u64,
    ) -> Result<f64, String> {
        let t = Instant::now();
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("resource_executions.jsonl"))
            .map_err(|e| e.to_string())?;
        writeln!(f,"{}",json!({"execution":self.executions,"strategy":strategy,"trajectory":trajectory,"step":step,"nonce":nonce,"elapsed_ms":ms(self.origin),"operation":"append_authorized_resource_access"})).map_err(|e|e.to_string())?;
        f.sync_data().map_err(|e| e.to_string())?;
        self.executions += 1;
        let cost = ms(t);
        emit(
            &json!({"event":"RESOURCE","status":"executed","strategy":strategy,"trajectory":trajectory,"step":step,"n":n,"nonce":nonce,"resource_append_sync_ms":cost}),
        )?;
        self.event("resource_executed",json!({"strategy":strategy,"trajectory":trajectory,"step":step,"nonce":nonce,"append_sync_ms":cost}))?;
        Ok(cost)
    }
}

fn require(checks: &mut Vec<Value>, id: &str, ok: bool) -> Result<(), String> {
    checks.push(json!({"id":id,"pass":ok}));
    if ok {
        Ok(())
    } else {
        Err(format!("check_failed:{}", id))
    }
}
impl Worker {
    fn step(
        &mut self,
        strategy: &str,
        trajectory: &str,
        step: usize,
        n: usize,
        k: usize,
        cache: &std::path::Path,
    ) -> Result<Value, String> {
        if n != self.n
            || ![1usize, 10, 100].contains(&k)
            || step > 2
            || trajectory != format!("b{}", k)
        {
            return Err("invalid_update_burst_step".into());
        }
        let initialization = step == 0;
        let cycle = step;
        let replace = !initialization;
        let updated = true;
        let updates_this_step = if initialization { 0 } else { k };
        let step_cpu = process_cpu_seconds()?;
        let group = format!("{}:{}", strategy, trajectory);
        let started = Instant::now();
        self.event("step_started",json!({"strategy":strategy,"trajectory":trajectory,"step":step,"n":n,"replace":replace}))?;
        // Parameter transport happened in the parent. This interval measures actual local authenticated loading.
        let loads = self.load(strategy, trajectory, n, cache)?;
        let l = self.loaded.take().ok_or("loaded_parameters_missing")?;
        let mut tr = self.tracks.remove(&group).unwrap_or(Track {
            n: 0,
            next_step: 0,
            epoch: 0,
            primes: vec![],
            tree: None,
            cp_set: None,
            cp_witness: None,
            mt_witness: None,
            cp_verifier: None,
            mt_verifier: None,
            witness_epoch: 0,
            previous: None,
            origin: Instant::now(),
            consumed: HashSet::new(),
        });
        if step != tr.next_step {
            return Err("out_of_order_trajectory_step".into());
        }
        let depth = if strategy == "cp" {
            None
        } else {
            Some(depth_for(strategy, trajectory, n))
        };
        let state_cpu = process_cpu_seconds()?;
        let t = Instant::now();
        let grow_ms = 0.0;
        let extend_ms = 0.0;
        let mut replace_ms = 0.0;
        let mut maintenance_cache_hits = 0usize;
        let mut maintenance_cache_misses = 0usize;
        let mut update_commit_ms = 0.0;
        let mut update_commit_cpu_seconds = 0.0;
        let journal_name = format!("{}-{}-state_updates.jsonl", strategy, trajectory);
        if initialization {
            tr.primes = self.primes[..n].to_vec();
            if let Some(d) = depth {
                tr.tree = Some(MerkleState::with_depth(&tr.primes, d)?);
            } else {
                tr.cp_set = Some(MaintainedState::new_with_power(
                    &tr.primes,
                    self.public_power.clone(),
                )?);
            }
        } else {
            if tr.n != n || tr.epoch != ((cycle - 1) * k) as u64 {
                return Err("unexpected_burst_start_state".into());
            }
            let mut journal = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(&journal_name))
                .map_err(|e| e.to_string())?;
            for j in 0..k {
                let prime_index = n + (cycle - 1) * k + j;
                let slot = if self.pattern == "hot" {
                    1
                } else {
                    1 + ((cycle - 1) * k + j) % (n - 1)
                };
                let previous_prime = tr.primes[slot].clone();
                tr.primes[slot] = self.primes[prime_index].clone();
                if tr.primes[slot] == previous_prime || tr.primes[0] != self.primes[0] {
                    return Err("invalid_burst_replacement".into());
                }
                let rt = Instant::now();
                if strategy == "cp" {
                    let hit = tr
                        .cp_set
                        .as_mut()
                        .ok_or("missing_maintained_state")?
                        .replace(slot, tr.primes[slot].clone())?;
                    if hit {
                        maintenance_cache_hits += 1;
                    } else {
                        maintenance_cache_misses += 1;
                    }
                } else {
                    tr.tree
                        .as_mut()
                        .ok_or("missing_burst_tree")?
                        .replace(slot, tr.primes[slot].clone())?;
                }
                replace_ms += ms(rt);
                let commit_cpu = process_cpu_seconds()?;
                let commit_time = Instant::now();
                tr.epoch += 1;
                let (header_digest, public_state) = if strategy == "cp" {
                    let h = Header::new(
                        tr.cp_set.as_ref().unwrap().state().accumulator.clone(),
                        tr.epoch,
                        &l.digest,
                    );
                    let digest = hex(&h.digest);
                    let state =
                        json!({"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&h.accumulator))});
                    tr.cp_verifier
                        .as_mut()
                        .ok_or("missing_burst_cp_verifier")?
                        .replace_header(h)?;
                    (digest, state)
                } else {
                    let h = MHeader::new(tr.tree.as_ref().unwrap().root(), tr.epoch, &l.digest);
                    let verifier = tr.mt_verifier.as_mut().ok_or("missing_burst_mt_verifier")?;
                    if h.epoch != verifier.header.epoch + 1 {
                        return Err("nonconsecutive_burst_epoch".into());
                    }
                    let digest = hex(&h.digest);
                    let state = json!({"root_hex":hex(&h.root),"root_fields":tr.tree.as_ref().unwrap().root_fields().iter().map(|x|hex(&enc(x))).collect::<Vec<_>>()});
                    verifier.header = h;
                    (digest, state)
                };
                writeln!(journal,"{}",json!({"strategy":strategy,"trajectory":trajectory,"k":k,"cycle":cycle,"update_in_cycle":j,"slot":slot,"pattern":self.pattern,"epoch":tr.epoch,"prime_index":prime_index,"new_prime_hex":tr.primes[slot].to_string_radix(16),"previous_prime_hex":previous_prime.to_string_radix(16),"target_prime_hex":tr.primes[0].to_string_radix(16),"header_digest":header_digest,"parameters_digest":hex(&l.digest),"public_state":public_state,"operation":"commit_actual_individual_state_update"})).map_err(|e|e.to_string())?;
                journal.sync_data().map_err(|e| e.to_string())?;
                update_commit_ms += ms(commit_time);
                update_commit_cpu_seconds += process_cpu_seconds()? - commit_cpu;
            }
        }
        let update_ms = ms(t);
        let state_cpu_seconds = process_cpu_seconds()? - state_cpu;
        tr.n = n;
        if tr.epoch != (cycle * k) as u64 {
            return Err("unexpected_burst_final_epoch".into());
        }
        let wc = process_cpu_seconds()?;
        let wt = Instant::now();
        if updated {
            tr.witness_epoch = tr.epoch;
            if strategy == "cp" {
                tr.cp_witness = Some(tr.cp_set.as_ref().unwrap().prepare_witness(&tr.primes[0])?);
            } else {
                tr.mt_witness = Some(tr.tree.as_ref().unwrap().circuit(&tr.primes[0])?);
            }
        }
        let witness_ms = ms(wt);
        let witness_cpu_seconds = process_cpu_seconds()? - wc;
        self.event("state_committed",json!({"strategy":strategy,"trajectory":trajectory,"step":step,"epoch":tr.epoch,"updated":updated,"state_update_ms":update_ms,"depth":depth}))?;
        let mut checks = vec![];
        require(
            &mut checks,
            "cached_witness_epoch_current",
            tr.witness_epoch == tr.epoch,
        )?;
        let execution_before = self.executions;
        require(
            &mut checks,
            "target_prime_unchanged",
            tr.primes[0] == self.primes[0],
        )?;
        let prior_sr = self.fixture.sr_signatures;
        let ids = self
            .fixture
            .all_grants
            .iter()
            .map(|g| g.id())
            .collect::<Vec<_>>();
        let track_origin = tr.origin;
        let now = || 500 + track_origin.elapsed().as_secs();
        let request_time = now();
        let permit_until = request_time + 120;
        if permit_until > 86400 {
            return Err("trajectory_exceeded_signed_grant_time_budget".into());
        }
        self.nonce += 1;
        let nonce = self.nonce;
        self.event("request_submitted",json!({"strategy":strategy,"trajectory":trajectory,"step":step,"nonce":nonce,"request_time":request_time,"permit_until":permit_until,"clock":"500+real monotonic elapsed within strategy/trajectory"}))?;
        let mut c = self.fixture.circuit_for("Q");
        let r = random();
        let t = Instant::now();
        let (header_fields, cp_header, mt_header) = if strategy == "cp" {
            let h = Header::new(
                tr.cp_set.as_ref().unwrap().state().accumulator.clone(),
                tr.epoch,
                &l.digest,
            );
            (h.digest_fields(), Some(h), None)
        } else {
            let h = MHeader::new(tr.tree.as_ref().unwrap().root(), tr.epoch, &l.digest);
            (limbs(&h.digest), None, Some(h))
        };
        c.request.fields[0] = header_fields[0];
        c.request.fields[1] = header_fields[1];
        c.request.fields[2] = Fr::from(tr.epoch);
        c.request.fields[9] = Fr::from(request_time);
        c.request.fields[10] = Fr::from(nonce);
        c.request.fields[11] = Fr::from(permit_until);
        let fields = c.public_fields();
        let prepare_ms = ms(t);
        let prefix = format!("{}-{}-{}", strategy, trajectory, step);
        let member_cpu_seconds;
        let auth_cpu_seconds;
        let verify_cpu_seconds;
        let mut negative_check_ms = 0.0;
        let mut negative_check_cpu_seconds = 0.0;
        let member_ms;
        let auth_ms;
        let verify_ms;
        let append_ms;
        let artifact_ms;
        let artifact_cpu_seconds;
        let member_bytes;
        let auth_bytes;
        let commitment_bytes;
        let proof_hash;
        let bundle;
        if strategy == "cp" {
            let set = tr.cp_set.as_ref().unwrap().state();
            let mut verifier = if initialization {
                JointVerifier::new(cp_header.unwrap(), l.digest)
            } else {
                tr.cp_verifier.take().ok_or("missing_cached_cp_verifier")?
            };
            let neg_cpu = process_cpu_seconds()?;
            let neg = Instant::now();
            if let Some(Bundle::Cp(old)) = tr.previous.as_ref().filter(|_| updated) {
                let e = verifier
                    .authorize(
                        &self.cp,
                        &l.auth,
                        &old.statement,
                        &old.membership,
                        &old.auth,
                        &old.fields,
                        &old.fields,
                        old.request_time,
                        old.permit_until,
                        now,
                    )
                    .err();
                require(
                    &mut checks,
                    "old_bundle_current_header_rejected",
                    e.as_deref() == Some("stale_header"),
                )?;
            }
            negative_check_ms += ms(neg);
            negative_check_cpu_seconds += process_cpu_seconds()? - neg_cpu;
            let context = hrada_joint::context(&l.digest, &fields)?;
            let cpu = process_cpu_seconds()?;
            let t = Instant::now();
            let (statement, membership) = self.cp.prove_prepared(
                set,
                &tr.primes[0],
                tr.cp_witness.as_ref().unwrap(),
                &r,
                &context,
            )?;
            member_ms = ms(t);
            member_cpu_seconds = process_cpu_seconds()? - cpu;
            self.event("membership_proved",json!({"strategy":strategy,"trajectory":trajectory,"step":step,"ms":member_ms,"includes_witness_generation":false}))?;
            let cpu = process_cpu_seconds()?;
            let t = Instant::now();
            let ap = hrada_link::prove(&mut OsRng, &l.auth, c, &r)
                .map_err(|e| format!("auth_prove:{:?}", e))?;
            auth_ms = ms(t);
            auth_cpu_seconds = process_cpu_seconds()? - cpu;
            let cpu = process_cpu_seconds()?;
            let t = Instant::now();
            verifier.authorize(
                &self.cp,
                &l.auth,
                &statement,
                &membership,
                &ap,
                &fields,
                &fields,
                request_time,
                permit_until,
                now,
            )?;
            verify_ms = ms(t);
            verify_cpu_seconds = process_cpu_seconds()? - cpu;
            append_ms = self.resource(strategy, trajectory, step, n, nonce)?;
            let neg_cpu = process_cpu_seconds()?;
            let neg = Instant::now();
            let after = self.executions;
            let e = verifier
                .authorize(
                    &self.cp,
                    &l.auth,
                    &statement,
                    &membership,
                    &ap,
                    &fields,
                    &fields,
                    request_time,
                    permit_until,
                    now,
                )
                .err();
            require(
                &mut checks,
                "replay_rejected",
                e.as_deref() == Some("nonce_already_consumed"),
            )?;
            require(
                &mut checks,
                "replay_no_resource_execution",
                self.executions == after,
            )?;
            negative_check_ms += ms(neg);
            negative_check_cpu_seconds += process_cpu_seconds()? - neg_cpu;
            tr.cp_verifier = Some(verifier);
            let artifact_cpu = process_cpu_seconds()?;
            let artifact = Instant::now();
            let mb = cp_components(&membership);
            let ab = enc(&ap);
            let cb = enc(&statement.c_e_q);
            member_bytes = mb.len();
            auth_bytes = ab.len();
            commitment_bytes = cb.len();
            proof_hash = hex(&hash(&[mb.clone(), ab.clone(), cb.clone()].concat()));
            fs::write(self.dir.join(format!("{}-member.bin", prefix)), mb)
                .map_err(|e| e.to_string())?;
            fs::write(self.dir.join(format!("{}-auth.bin", prefix)), ab)
                .map_err(|e| e.to_string())?;
            fs::write(self.dir.join(format!("{}-commitment.bin", prefix)), cb)
                .map_err(|e| e.to_string())?;
            artifact_ms = ms(artifact);
            artifact_cpu_seconds = process_cpu_seconds()? - artifact_cpu;
            bundle = Bundle::Cp(CBundle {
                statement,
                membership,
                auth: ap,
                fields: fields.clone(),
                request_time,
                permit_until,
            });
        } else {
            let set = tr.tree.as_ref().unwrap();
            let mut verifier = if initialization {
                mver(&mt_header.unwrap())
            } else {
                tr.mt_verifier.take().ok_or("missing_cached_mt_verifier")?
            };
            let neg_cpu = process_cpu_seconds()?;
            let neg = Instant::now();
            if let Some(Bundle::Mt(old)) = tr.previous.as_ref().filter(|_| updated) {
                let e = verifier
                    .authorize(
                        &parameters(&self.cp, &l),
                        old,
                        &old.fields,
                        old.request_time,
                        old.permit_until,
                        now,
                    )
                    .err();
                require(
                    &mut checks,
                    "old_bundle_current_header_rejected",
                    e.as_deref() == Some("stale_header"),
                )?;
            }
            negative_check_ms += ms(neg);
            negative_check_cpu_seconds += process_cpu_seconds()? - neg_cpu;
            let cpu = process_cpu_seconds()?;
            let t = Instant::now();
            let mc = tr.mt_witness.as_ref().unwrap().clone();
            let commitment = self.cp.commit(&tr.primes[0], &r)?;
            let membership = hrada_link::prove(&mut OsRng, l.member.as_ref().unwrap(), mc, &r)
                .map_err(|e| format!("member_prove:{:?}", e))?;
            member_ms = ms(t);
            member_cpu_seconds = process_cpu_seconds()? - cpu;
            let cpu = process_cpu_seconds()?;
            let t = Instant::now();
            let ap = hrada_link::prove(&mut OsRng, &l.auth, c, &r)
                .map_err(|e| format!("auth_prove:{:?}", e))?;
            auth_ms = ms(t);
            auth_cpu_seconds = process_cpu_seconds()? - cpu;
            let b = MBundle {
                membership,
                auth: ap,
                commitment,
                fields: fields.clone(),
                root: set.root_fields(),
                request_time,
                permit_until,
            };
            let cpu = process_cpu_seconds()?;
            let t = Instant::now();
            verifier.authorize(
                &parameters(&self.cp, &l),
                &b,
                &fields,
                request_time,
                permit_until,
                now,
            )?;
            verify_ms = ms(t);
            verify_cpu_seconds = process_cpu_seconds()? - cpu;
            append_ms = self.resource(strategy, trajectory, step, n, nonce)?;
            let neg_cpu = process_cpu_seconds()?;
            let neg = Instant::now();
            let e = verifier
                .authorize(
                    &parameters(&self.cp, &l),
                    &b,
                    &fields,
                    request_time,
                    permit_until,
                    now,
                )
                .err();
            require(
                &mut checks,
                "replay_rejected",
                e.as_deref() == Some("nonce_already_consumed"),
            )?;
            require(
                &mut checks,
                "replay_no_resource_execution",
                self.executions == execution_before + 1,
            )?;
            negative_check_ms += ms(neg);
            negative_check_cpu_seconds += process_cpu_seconds()? - neg_cpu;
            tr.mt_verifier = Some(verifier);
            let artifact_cpu = process_cpu_seconds()?;
            let artifact = Instant::now();
            let mb = enc(&b.membership);
            let ab = enc(&b.auth);
            let cb = enc(&b.commitment);
            member_bytes = mb.len();
            auth_bytes = ab.len();
            commitment_bytes = cb.len();
            proof_hash = hex(&hash(&[mb.clone(), ab.clone(), cb.clone()].concat()));
            fs::write(self.dir.join(format!("{}-member.bin", prefix)), mb)
                .map_err(|e| e.to_string())?;
            fs::write(self.dir.join(format!("{}-auth.bin", prefix)), ab)
                .map_err(|e| e.to_string())?;
            fs::write(self.dir.join(format!("{}-commitment.bin", prefix)), cb)
                .map_err(|e| e.to_string())?;
            artifact_ms = ms(artifact);
            artifact_cpu_seconds = process_cpu_seconds()? - artifact_cpu;
            bundle = Bundle::Mt(b);
        }
        require(
            &mut checks,
            "exactly_one_resource_execution",
            self.executions == execution_before + 1,
        )?;
        require(
            &mut checks,
            "original_grant_signatures_unchanged",
            ids == self
                .fixture
                .all_grants
                .iter()
                .map(|g| g.id())
                .collect::<Vec<_>>(),
        )?;
        require(
            &mut checks,
            "no_authorization_state_resign",
            self.fixture.sr_signatures == prior_sr,
        )?;
        if let Some(old) = tr.previous.as_ref() {
            let old_commitment = match old {
                Bundle::Cp(b) => &b.statement.c_e_q,
                Bundle::Mt(b) => &b.commitment,
            };
            let new_commitment = match &bundle {
                Bundle::Cp(b) => &b.statement.c_e_q,
                Bundle::Mt(b) => &b.commitment,
            };
            require(
                &mut checks,
                "fresh_commitment",
                old_commitment != new_commitment,
            )?;
            let old_fields = match old {
                Bundle::Cp(b) => &b.fields,
                Bundle::Mt(b) => &b.fields,
            };
            require(
                &mut checks,
                "head_changes_iff_update_and_fresh_nonce",
                (fields[..3] != old_fields[..3]) == updated && fields[10] != old_fields[10],
            )?;
        }
        let row = json!({"event":"result","status":"ok","strategy":strategy,"trajectory":trajectory,"step":step,"n":n,"depth":depth,"epoch":tr.epoch,"nonce":nonce,"replace":replace,"k":k,"cycle":cycle,"updates_this_step":updates_this_step,"state_update_journal":if initialization{Value::Null}else{json!(journal_name)},"initialization":initialization,"pattern":self.pattern,"maintenance_cache_hits":maintenance_cache_hits,"maintenance_cache_misses":maintenance_cache_misses,"witness_cache_hit":!updated,"checks":checks,"metrics":{"load":loads,"state_update_ms":update_ms,"update_commit_ms":update_commit_ms,"update_commit_cpu_seconds":update_commit_cpu_seconds,"grow_ms":grow_ms,"extend_ms":extend_ms,"replace_ms":replace_ms,"prepare_ms":prepare_ms,"witness_ms":witness_ms,"witness_note":"lazy witness prepared once after all individually committed burst updates; no intermediate client refresh","membership_ms":member_ms,"auth_ms":auth_ms,"verify_ms":verify_ms,"resource_append_sync_ms":append_ms,"worker_step_ms":ms(started),"worker_step_cpu_seconds":process_cpu_seconds()? - step_cpu,"state_cpu_seconds":state_cpu_seconds,"witness_cpu_seconds":witness_cpu_seconds,"membership_cpu_seconds":member_cpu_seconds,"auth_cpu_seconds":auth_cpu_seconds,"verify_cpu_seconds":verify_cpu_seconds,"artifact_ms":artifact_ms,"artifact_cpu_seconds":artifact_cpu_seconds,"negative_check_ms":negative_check_ms,"negative_check_cpu_seconds":negative_check_cpu_seconds,"proof_component_bytes":member_bytes+auth_bytes+commitment_bytes,"member_bytes":member_bytes,"auth_bytes":auth_bytes,"commitment_bytes":commitment_bytes},"proof_blake2s":proof_hash,"membership_public_state":match &bundle{Bundle::Cp(b)=>json!({"accumulator_hex":hex(&Rsa2048::elem_to_bytes(&b.statement.c_p))}),Bundle::Mt(b)=>json!({"root_fields":b.root.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>()})},"public_fields":fields.iter().map(|x|hex(&enc(x))).collect::<Vec<_>>(),"request_time":request_time,"permit_until":permit_until,"artifacts":[format!("{}-member.bin",prefix),format!("{}-auth.bin",prefix),format!("{}-commitment.bin",prefix)],"auth_vk_blake2s":hex(&hash(&enc(&l.auth.proving_key.vk))),"parameters_digest":hex(&l.digest),"cache_security":"downloaded files hash-authenticated on first load, assumed immutable while resident; trusted setup CP object retained locally"});
        fs::write(
            self.dir.join(format!("{}.json", prefix)),
            serde_json::to_vec_pretty(&row).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        tr.previous = Some(bundle);
        tr.next_step += 1;
        self.tracks.insert(group, tr);
        self.loaded = Some(l);
        self.records.push(row.clone());
        self.save("running", None)?;
        Ok(row)
    }
}

fn parameters<'a>(cp: &'a StateMembership, l: &'a Loaded) -> MParameters<'a> {
    MParameters {
        cp,
        auth: &l.auth,
        member: l.member.as_ref().unwrap(),
        descriptor: l.descriptor.clone(),
        member_digest: l.member_digest,
        auth_descriptor: l.auth_descriptor.clone(),
        digest: l.digest,
    }
}
fn emit(v: &Value) -> Result<(), String> {
    let mut o = std::io::stdout().lock();
    writeln!(o, "{}", v).map_err(|e| e.to_string())?;
    o.flush().map_err(|e| e.to_string())
}
fn process_cpu_seconds() -> Result<f64, String> {
    // POSIX clock(), cumulative process CPU including worker threads; macOS/Linux CLOCKS_PER_SEC=1e6.
    extern "C" {
        fn clock() -> i64;
    }
    let ticks = unsafe { clock() };
    if ticks < 0 {
        return Err("process_cpu_clock_failed".into());
    }
    Ok(ticks as f64 / 1_000_000.0)
}

/// Instantaneous process RSS in KiB, measured outside the table construction timer.
fn rss_snapshot_kib() -> Result<u64, String> {
    let output = Command::new("/bin/ps")
        .args(&["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("RSS snapshot ps failed".into());
    }
    String::from_utf8(output.stdout)
        .map_err(|e| e.to_string())?
        .trim()
        .parse::<u64>()
        .map_err(|e| e.to_string())
}
fn initialize(dir: PathBuf, n: usize, pattern: String) -> Result<Worker, String> {
    let origin = Instant::now();
    let rss_before_kib = rss_snapshot_kib()?;
    let table_cpu_start = process_cpu_seconds()?;
    let table_start = Instant::now();
    let public_power = Arc::new(PublicPower::new(
        n.checked_mul(252).ok_or("capacity overflow")?,
        8,
    )?);
    let table_build_ms = ms(table_start);
    let table_build_cpu_seconds = process_cpu_seconds()? - table_cpu_start;
    let rss_after_build_kib = rss_snapshot_kib()?;
    let stats_cpu_start = process_cpu_seconds()?;
    let stats_start = Instant::now();
    let table_stats = public_power.stats();
    let stats_ms = ms(stats_start);
    let stats_cpu_seconds = process_cpu_seconds()? - stats_cpu_start;
    let public_power_manifest = json!({"stats":table_stats,"build_ms":table_build_ms,"build_cpu_seconds":table_build_cpu_seconds,"stats_ms":stats_ms,"stats_cpu_seconds":stats_cpu_seconds,"rss_before_kib":rss_before_kib,"rss_after_build_kib":rss_after_build_kib,"rss_note":"instantaneous whole-process ps RSS snapshots; not peak RSS; ps excluded from build and stats timers","scope":"once per worker public server-only fixed-base comb h=8; reused across trajectories; client witness remains GMP; capacity growth requires full table reconstruction; no trapdoor"});
    let mut files = vec![];
    let mut setup = vec![];
    eprintln!("general-burst worker: generating trial fixture and public setup");
    let mut primes = Vec::with_capacity(n + 200);
    while primes.len() < n + 200 {
        let p = allocate_prime();
        if !primes.contains(&p) {
            primes.push(p);
        }
    }
    fs::write(
        dir.join("state_prime_pool.json"),
        serde_json::to_vec_pretty(
            &primes
                .iter()
                .map(|p| p.to_string_radix(16))
                .collect::<Vec<_>>(),
        )
        .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut fixture = AuthFixture::new_with_expiry(OsRng.next_u64() >> 1, 86400);
    fixture.refresh_state(fr(&primes[0]));
    fixture.close_issuers();
    let cpu_start = process_cpu_seconds()?;
    let t = Instant::now();
    let cp = StateMembership::setup_os()?;
    let setup_ms = ms(t);
    setup.push(json!({"id":"cp","setup_ms":setup_ms,"setup_cpu_seconds":process_cpu_seconds()? - cpu_start}));
    let cpbytes = cp.canonical_parameters()?;
    let ck = &cp.protocol.crs.crs_modeq.pedersen_commitment_parameters;
    files.push(persist_bytes(
        &dir,
        "cp_parameters",
        "cp_parameters.bin",
        "cp_public_parameters",
        None,
        &cpbytes,
    )?);
    files.push(persist_key(
        &dir,
        "cp_range",
        "cp_range_pk.uncompressed.bin",
        "cp_range_pk",
        None,
        &cp.protocol.crs.crs_hash_to_prime.hash_to_prime_parameters,
    )?);
    eprintln!("general-burst worker: shared authorization setup");
    let cpu_start = process_cpu_seconds()?;
    let t = Instant::now();
    let auth = hrada_link::setup(&mut OsRng, ck, fixture.circuit(), 16)
        .map_err(|e| format!("auth_setup:{:?}", e))?;
    let setup_ms = ms(t);
    setup.push(json!({"id":"auth","setup_ms":setup_ms,"setup_cpu_seconds":process_cpu_seconds()? - cpu_start}));
    let auth_vk = hex(&hash(&enc(&auth.proving_key.vk)));
    files.push(persist_key(
        &dir,
        "auth",
        "shared_auth_pk.uncompressed.bin",
        "auth_pk",
        None,
        &auth.proving_key,
    )?);
    // Do not retain the setup's Auth PK; proofs must use the actual downloaded cache file.
    drop(auth);
    let mut poseidon_files = serde_json::Map::new();
    for depth in [depth_for("reserved", "", n)].iter() {
        eprintln!("general-burst worker: Poseidon depth {} setup", depth);
        let state = MerkleState::with_depth(&primes[..n], *depth)?;
        let cpu_start = process_cpu_seconds()?;
        let t = Instant::now();
        let key = hrada_link::setup(&mut OsRng, ck, state.circuit(&primes[0])?, 2)
            .map_err(|e| format!("member_setup:{:?}", e))?;
        let setup_ms = ms(t);
        setup.push(json!({"id":format!("poseidon_{}",depth),"depth":depth,"setup_ms":setup_ms,"setup_cpu_seconds":process_cpu_seconds()? - cpu_start}));
        let name = format!("poseidon_d{}_pk.uncompressed.bin", depth);
        let dn = format!("poseidon_d{}_descriptor.bin", depth);
        files.push(persist_key(
            &dir,
            &format!("poseidon_{}", depth),
            &name,
            "poseidon_member_pk",
            Some(*depth),
            &key.proving_key,
        )?);
        let mut descriptor = format!("HRADA-CAPACITY-POSEIDON-DEPTH{}-V1", depth).into_bytes();
        descriptor.extend(parameter_descriptor());
        descriptor.extend(enc(&ck.g));
        descriptor.extend(enc(&ck.h));
        files.push(persist_bytes(
            &dir,
            &format!("descriptor_{}", depth),
            &dn,
            "poseidon_descriptor",
            Some(*depth),
            &descriptor,
        )?);
        poseidon_files.insert(depth.to_string(), json!([name, dn]));
    }
    let manifest = json!({"version":1,"scenario":"general_burst","pattern":pattern,"maintenance":"validated product and single cofactor cache; public comb h8 for server cofactor misses only; client witness unchanged","public_power":public_power_manifest,"n":n,"depth":depth_for("reserved", "", n),"state_prime_pool":"state_prime_pool.json","files":files,"setup":setup,"auth_file":"shared_auth_pk.uncompressed.bin","cp_files":["cp_parameters.bin","cp_range_pk.uncompressed.bin"],"poseidon_files":poseidon_files,"auth_vk_blake2s":auth_vk,"setup_total_and_serialization_ms":ms(origin),"serialization":"PK serialize_uncompressed; trusted hash authentication then deserialize_unchecked; immutable resident cache","shared_auth":"one file and VK for cp/reserved within this N trial; actual loaded key used for all proofs","scope":"same-process trusted setup CP object retained; downloaded range PK replaces it; no original issuer service, no WAN/SLA/concurrent arrivals"});
    fs::write(
        dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let worker = Worker {
        public_power,
        n,
        pattern,
        dir,
        origin,
        files,
        manifest,
        cp,
        cpbytes,
        fixture,
        primes,
        loaded: None,
        secondary_loaded: None,
        tracks: HashMap::new(),
        records: vec![],
        events: vec![],
        nonce: 1000,
        executions: 0,
    };
    worker.save("ready", None)?;
    Ok(worker)
}
fn string<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v[k].as_str().ok_or_else(|| format!("missing_string:{}", k))
}
fn integer(v: &Value, k: &str) -> Result<usize, String> {
    v[k].as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| format!("missing_integer:{}", k))
}
fn command(worker: &mut Worker, v: Value) -> Result<bool, String> {
    let cmd = string(&v, "cmd")?;
    if cmd == "manifest" {
        emit(&json!({"event":"manifest","status":"ok","manifest":worker.manifest}))?;
        return Ok(false);
    }
    if cmd == "finish" {
        worker.loaded = None;
        worker.secondary_loaded = None;
        worker.save("complete", None)?;
        emit(
            &json!({"event":"finished","status":"complete","steps":worker.records.iter().filter(|v|v["event"]=="result").count(),"resource_executions":worker.executions}),
        )?;
        return Ok(true);
    }
    let strategy = string(&v, "strategy")?;
    let trajectory = string(&v, "trajectory")?;
    let n = integer(&v, "n")?;
    if !["cp", "reserved"].contains(&strategy) || n != worker.n || !trajectory.starts_with("b") {
        return Err("invalid_strategy_trajectory_population".into());
    }
    let cache = PathBuf::from(string(&v, "cache_dir")?);
    if !cache.is_absolute() {
        return Err("cache_dir_must_be_absolute".into());
    }
    let result = match cmd {
        "step" => worker.step(
            strategy,
            trajectory,
            integer(&v, "step")?,
            n,
            integer(&v, "k")?,
            &cache,
        )?,
        "cache_probe" => worker.cache_probe(strategy, trajectory, n, &cache)?,
        _ => return Err("unknown_command".into()),
    };
    emit(&result)?;
    Ok(false)
}
fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let n = args
        .windows(2)
        .find(|w| w[0] == "--n")
        .and_then(|w| w[1].parse::<usize>().ok());
    let n = match n {
        Some(n) if [17usize, 65, 257].contains(&n) => n,
        _ => {
            eprintln!("required --n 17|65|257");
            std::process::exit(2);
        }
    };
    let pattern = args
        .windows(2)
        .find(|w| w[0] == "--pattern")
        .map(|w| w[1].clone())
        .unwrap_or_default();
    if !["hot", "rotating"].contains(&pattern.as_str()) {
        eprintln!("required --pattern hot|rotating");
        std::process::exit(2);
    }
    let dir = args
        .windows(2)
        .find(|w| w[0] == "--output-dir")
        .map(|w| PathBuf::from(&w[1]));
    let dir = match dir {
        Some(x) => x,
        None => {
            eprintln!("required --output-dir NEW_DIR");
            std::process::exit(2)
        }
    };
    if dir.exists() {
        eprintln!("refusing existing output directory");
        std::process::exit(2);
    }
    fs::create_dir_all(&dir).unwrap();
    let mut worker = match initialize(dir.clone(), n, pattern) {
        Ok(w) => w,
        Err(e) => {
            let _ = fs::write(
                dir.join("results.json"),
                json!({"status":"failed","failure":e}).to_string(),
            );
            let _ = emit(&json!({"status":"failed","failure":e}));
            std::process::exit(1)
        }
    };
    emit(&json!({"event":"READY","status":"ready","manifest":worker.manifest})).unwrap();
    for line in std::io::stdin().lock().lines() {
        let result = line
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str(&s).map_err(|e| e.to_string()))
            .and_then(|v| command(&mut worker, v));
        match result {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => {
                let _ = worker.save("failed", Some(&e));
                let _ = emit(&json!({"event":"result","status":"failed","failure":e}));
                std::process::exit(1);
            }
        }
    }
    let e = "stdin_closed_without_finish";
    let _ = worker.save("failed", Some(e));
    let _ = emit(&json!({"status":"failed","failure":e}));
    std::process::exit(1);
}
