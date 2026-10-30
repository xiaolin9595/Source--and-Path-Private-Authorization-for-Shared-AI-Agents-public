use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::synthesis_patch::Mode;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use plan_a_joint_circuit::{
    fixture::{fixed, public_inputs},
    phase_groth16::prove_with_randomness_mode,
};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, BufRead},
    path::Path,
    time::Instant,
};
#[derive(Deserialize)]
struct Request {
    command: String,
    session: usize,
    block: i64,
    length: usize,
    label: String,
    nonce: u64,
    measured: bool,
}
fn digest(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn setup(out: &Path) {
    assert!(!out.exists(), "setup output exists");
    fs::create_dir(out).unwrap();
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bls12_381>::setup(fixed::<3>(3, 0, 20, 20, 32), &mut OsRng).unwrap();
    let (mut pb, mut vb) = (vec![], vec![]);
    pk.serialize_compressed(&mut pb).unwrap();
    vk.serialize_compressed(&mut vb).unwrap();
    fs::write(out.join("pk.compressed"), &pb).unwrap();
    fs::write(out.join("vk.compressed"), &vb).unwrap();
    println!(
        "{}",
        json!({"event":"setup","relation":"original-canonical-zero","backend":"native","setup_ms":t.elapsed().as_secs_f64()*1000.,"pk_sha256":digest(&pb),"vk_sha256":digest(&vb),"pk_bytes":pb.len(),"vk_bytes":vb.len()})
    );
}
fn serve(pk_path: &Path, relation_sha: &str) {
    let pb = fs::read(pk_path).unwrap();
    let pk = ProvingKey::<Bls12_381>::deserialize_compressed(&pb[..]).unwrap();
    let binary_sha = digest(&fs::read(env::current_exe().unwrap()).unwrap());
    let templates = [
        fixed::<3>(1, 0, 20, 20, 32),
        fixed::<3>(2, 0, 20, 20, 32),
        fixed::<3>(3, 0, 20, 20, 32),
    ];
    println!(
        "{}",
        json!({"event":"ready","relation":"original-canonical-zero","backend":"native","pk_sha256":digest(&pb),"binary_sha256":binary_sha,"relation_sha256":relation_sha})
    );
    for line in io::stdin().lock().lines() {
        let q: Request = serde_json::from_str(&line.unwrap()).unwrap();
        assert_eq!(q.command, "request");
        assert!((1..=3).contains(&q.length));
        assert!(matches!(q.label.as_str(), "o" | "gate"));
        let total = Instant::now();
        let mut c = templates[q.length - 1].clone();
        c.request.nonce = Fr::from(q.nonce);
        c.request.canonical_request_lo = Fr::from(123 + q.nonce);
        let padding_prepare_ms = total.elapsed().as_secs_f64() * 1000.;
        let pt = Instant::now();
        let r = Fr::rand(&mut OsRng);
        let s = Fr::rand(&mut OsRng);
        let (proof, _) = prove_with_randomness_mode(&pk, c.clone(), r, s, Mode::Native).unwrap();
        let prove_ms = pt.elapsed().as_secs_f64() * 1000.;
        let st = Instant::now();
        let mut enc = vec![];
        proof.serialize_compressed(&mut enc).unwrap();
        let serialize_ms = st.elapsed().as_secs_f64() * 1000.;
        let online_total_ms = total.elapsed().as_secs_f64() * 1000.;
        let inputs = public_inputs(&c);
        let verified = Groth16::<Bls12_381>::verify(&pk.vk, &inputs, &proof).unwrap();
        let rejected = (0..inputs.len()).all(|index| {
            let mut bad = inputs.clone();
            bad[index] += Fr::from(1);
            !Groth16::<Bls12_381>::verify(&pk.vk, &bad, &proof).unwrap()
        });
        assert!(verified && rejected);
        println!(
            "{}",
            json!({"event":if q.measured{"measurement"}else{"gate"},"relation":"original-canonical-zero","backend":"native","session":q.session,"block":q.block,"length":q.length,"label":q.label,"nonce":q.nonce,"padding_prepare_ms":padding_prepare_ms,"prove_ms":prove_ms,"serialize_ms":serialize_ms,"online_total_ms":online_total_ms,"verified":verified,"mutated_public_rejected":rejected,"proof_sha256":digest(&enc),"binary_sha256":binary_sha,"relation_sha256":relation_sha,"pk_sha256":digest(&pb)})
        );
    }
}
fn main() {
    let a = env::args().collect::<Vec<_>>();
    match a.get(1).map(String::as_str) {
        Some("setup") if a.len() == 3 => setup(Path::new(&a[2])),
        Some("serve") if a.len() == 4 => serve(Path::new(&a[2]), &a[3]),
        _ => panic!("usage: setup OUT | serve PK RELATION_SHA256"),
    }
}
