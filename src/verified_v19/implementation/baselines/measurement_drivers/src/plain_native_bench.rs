use ark_serialize::{CanonicalSerialize, Compress};
use plan_a_joint_circuit::{fixture, plain::verify_plain};
use serde_json::json;
use std::{env, hint::black_box, time::Instant};

fn chain_bytes(c: &plan_a_joint_circuit::joint::JointCircuit<3>) -> usize {
    let mut n=0usize;
    for s in c.grants.iter().filter(|s| s.enabled) {
        n += 1; // enabled framing
        n += s.grant.issuer.0.serialized_size(Compress::Yes);
        n += s.grant.subject.0.serialized_size(Compress::Yes);
        n += s.grant.resource.serialized_size(Compress::Yes);
        n += 2+8+8+8+8+1; // mask, intervals, clocks, depth
        n += s.grant.serial.serialized_size(Compress::Yes);
        n += s.grant.parent_digest.serialized_size(Compress::Yes);
        n += s.grant.signature.r.serialized_size(Compress::Yes);
        n += s.grant.signature.s.serialized_size(Compress::Yes);
        n += 4+s.grant_path.siblings.len()*32+s.grant_path.directions.len();
        n += 4+s.revocation.path.siblings.len()*32+s.revocation.path.directions.len()+4+32+4+32;
    }
    n
}
fn main(){
    let a:Vec<String>=env::args().collect();let trials:usize=a.get(1).and_then(|x|x.parse().ok()).unwrap_or(30);
    let mut rows=Vec::new();
    for active in 1..=3 { for rep in 0..trials {
        let c=fixture::fixed::<3>(active,10_000+(active*trials+rep) as u64,20,20,32);
        let t=Instant::now();let ok=verify_plain(&c.snapshot,&c.request,&c.entitlement,&c.state,c.registration_salt,&c.grants).is_ok();
        let ns=t.elapsed().as_nanos();black_box(ok);assert!(ok);
        rows.push(json!({"active":active,"repetition":rep,"verify_ns":ns,"signed_chain_framed_compressed_bytes":chain_bytes(&c)}));
    }}
    println!("{}",serde_json::to_string_pretty(&json!({"schema":"plan-a-native-plaintext-baseline-v1","label":"native plaintext signed-chain business verification; not JWT/UCAN conformant; not a privacy lower bound","trials_per_length":trials,"rows":rows})).unwrap());
}
