//! Loader benchmark ONLY for hash-authenticated local uncompressed PK caches.
//! Never use unchecked decoding on an untrusted or merely self-labelled key.
use ark_bls12_381::Bls12_381;
use ark_serialize::CanonicalDeserialize;
use blake2::{Blake2s, Digest};
use serde_json::json;
use std::{fs, time::Instant};
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}
fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    assert!(
        !args.is_empty() && args.len() % 2 == 0,
        "arguments: trusted-cache-path trusted-blake2s [path hash ...]"
    );
    let total = Instant::now();
    let mut retained = vec![];
    let mut rows = vec![];
    for pair in args.chunks(2) {
        let t = Instant::now();
        let data = fs::read(&pair[0]).expect("read cache");
        let read_ms = ms(t);
        let t = Instant::now();
        let actual = hex(&Blake2s::digest(&data));
        assert_eq!(actual, pair[1], "authenticated cache hash mismatch");
        let hash_ms = ms(t);
        let t = Instant::now();
        let mut input = &data[..];
        let pk = legogro16::ProvingKey::<Bls12_381>::deserialize_unchecked(&mut input)
            .expect("decode authenticated uncompressed cache");
        assert!(input.is_empty(), "unexpected trailing data");
        let decode_ms = ms(t);
        rows.push(json!({"path":pair[0],"cache_bytes":data.len(),"read_ms":read_ms,"hash_ms":hash_ms,"decode_ms":decode_ms,"link_bases":pk.vk.link_bases.len(),"hash_matches":true}));
        retained.push(pk);
    }
    println!(
        "{}",
        json!({"status":"complete","mode":"hash-authenticated-uncompressed-local-cache","process":"fresh; OS cache uncontrolled; no purge","total_load_ms":ms(total),"keys_retained":retained.len(),"files":rows})
    );
}
