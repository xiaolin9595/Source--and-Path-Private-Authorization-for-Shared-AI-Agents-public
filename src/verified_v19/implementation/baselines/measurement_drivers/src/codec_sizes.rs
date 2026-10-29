use ark_bls12_381::Bls12_381;
use ark_groth16::{Proof,ProvingKey,VerifyingKey};
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize,Compress};
use serde_json::json;
use std::{env,fs::File,io::{BufReader,Read},time::Instant};
fn sizes<T:CanonicalSerialize>(x:&T)->serde_json::Value{json!({"compressed_bytes":x.serialized_size(Compress::Yes),"uncompressed_bytes":x.serialized_size(Compress::No)})}
fn main(){
 let a:Vec<String>=env::args().collect();assert!(a.len()>=5,"codec_sizes PK VK PROOF PUBLIC [cold_repeats]");let repeats:usize=a.get(5).and_then(|x|x.parse().ok()).unwrap_or(3);
 let pk=ProvingKey::<Bls12_381>::deserialize_compressed(BufReader::new(File::open(&a[1]).unwrap())).unwrap();
 let vk=VerifyingKey::<Bls12_381>::deserialize_compressed(BufReader::new(File::open(&a[2]).unwrap())).unwrap();
 let proof=Proof::<Bls12_381>::deserialize_compressed(BufReader::new(File::open(&a[3]).unwrap())).unwrap();let public_bytes=std::fs::metadata(&a[4]).unwrap().len();
 let mut encoded=Vec::new();pk.serialize_compressed(&mut encoded).unwrap();let mut load_ms=Vec::new();
 for _ in 0..repeats{let t=Instant::now();let z=ProvingKey::<Bls12_381>::deserialize_compressed(&encoded[..]).unwrap();std::hint::black_box(z);load_ms.push(t.elapsed().as_secs_f64()*1000.0)}
 println!("{}",json!({"schema":"plan-a-codec-size-v1","pk":sizes(&pk),"vk":sizes(&vk),"proof":sizes(&proof),"public_framed_compressed_bytes":public_bytes,"public_note":"field elements have the same canonical width; framing is the proof CLI format","pk_deserialize_ms":load_ms,"pk_load_n":repeats}));
}
