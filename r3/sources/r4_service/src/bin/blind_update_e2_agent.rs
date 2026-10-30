use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_ff::{PrimeField, UniformRand};
use ark_groth16::{checked::check, Groth16};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use base64::{engine::general_purpose::STANDARD, Engine};
use plan_a_joint_circuit::{
    blind_update::{authorization_digest, state_leaf, BlindUpdateCircuit, BlindUpdateStatement, StateOpening},
    blind_update_sr::proof_sha256_limbs,
    poseidon::{canonical_le_bytes, descriptor, parameter_fingerprint},
    signature::{encode_signature, public_key, sign, SecretKey},
    state_registry::owner_commitment,
};
use rand::{rngs::OsRng, RngCore};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, io::{self, BufRead, Write}, path::{Path, PathBuf}, time::Instant};

fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }
fn hex_field(value: Fr) -> String { let mut b=canonical_le_bytes(value);b.reverse();hex::encode(b) }
fn domain_field(tag: &[u8], payload: &[u8]) -> Fr {
    let mut h=Sha256::new();h.update(tag);h.update([0]);h.update(payload);Fr::from_be_bytes_mod_order(&h.finalize())
}
fn matrix_bytes(circuit: BlindUpdateCircuit,mode:SynthesisMode) -> (Vec<u8>,usize,usize,usize) {
    let cs=ConstraintSystem::new_ref();cs.set_mode(mode);circuit.generate_constraints(cs.clone()).unwrap();cs.finalize();
    let constraints=cs.num_constraints();let instances=cs.num_instance_variables();let witnesses=cs.num_witness_variables();
    let m=cs.to_matrices().unwrap();let mut out=Vec::new();
    for matrix in [&m.a,&m.b,&m.c] {out.extend_from_slice(&(matrix.len() as u64).to_le_bytes());for row in matrix {out.extend_from_slice(&(row.len() as u64).to_le_bytes());for (coefficient,index) in row {coefficient.serialize_compressed(&mut out).unwrap();out.extend_from_slice(&(*index as u64).to_le_bytes());}}}
    (out,constraints,instances,witnesses)
}
fn config() -> Fr {
    let material=format!("plan-a-r3-blind-update-config-v1|{}|poseidon-fingerprint={}|public-inputs=config,deployment,circuit,owner,position,cap,admission,old-leaf,new-leaf,old-version,new-version,old-epoch,new-epoch,identity-binding|state-leaf=owner,grant-root,version,epoch,expiry,active,salt,position",descriptor(),parameter_fingerprint());
    domain_field(b"plan-a-r3-config-v1",material.as_bytes())
}
fn config_material() -> String {
    format!("plan-a-r3-blind-update-config-v1|{}|poseidon-fingerprint={}|public-inputs=config,deployment,circuit,owner,position,cap,admission,old-leaf,new-leaf,old-version,new-version,old-epoch,new-epoch,identity-binding|state-leaf=owner,grant-root,version,epoch,expiry,active,salt,position",descriptor(),parameter_fingerprint())
}
fn circuit_for_shape() -> BlindUpdateCircuit {
    let old=StateOpening{grant_root:Fr::from(11u64),expiry:900,active:true,salt:Fr::from(12u64)};
    let new=StateOpening{grant_root:Fr::from(13u64),expiry:900,active:true,salt:Fr::from(14u64)};
    let mut statement=BlindUpdateStatement{config_digest:Fr::from(1u64),deployment:Fr::from(2u64),circuit_id:Fr::from(3u64),owner:Fr::from(4u64),position:5,expiry_cap:1000,admission_version:0,old_leaf:Fr::from(0u64),new_leaf:Fr::from(0u64),old_version:7,new_version:8,old_epoch:9,new_epoch:10};
    statement.old_leaf=state_leaf(statement.owner,statement.old_version,statement.old_epoch,statement.position,&old);
    statement.new_leaf=state_leaf(statement.owner,statement.new_version,statement.new_epoch,statement.position,&new);
    BlindUpdateCircuit{statement,old,new}
}
fn setup(out: &Path) {
    fs::create_dir_all(out).unwrap();let mut random=[0u8;32];OsRng.fill_bytes(&mut random);
    let deployment=domain_field(b"plan-a-deployment-v1",&random);let config_digest=config();let config_material=config_material();
    let opening=StateOpening{grant_root:Fr::from(1u64),expiry:900,active:true,salt:Fr::from(2u64)};
    let mut statement=BlindUpdateStatement{config_digest,deployment,circuit_id:Fr::from(0u64),owner:Fr::from(3u64),position:5,expiry_cap:1000,admission_version:0,old_leaf:Fr::from(0u64),new_leaf:Fr::from(0u64),old_version:0,new_version:1,old_epoch:1,new_epoch:2};
    statement.old_leaf=state_leaf(statement.owner,0,1,5,&opening);statement.new_leaf=state_leaf(statement.owner,1,2,5,&opening);
    let circuit=BlindUpdateCircuit{statement:statement.clone(),old:opening.clone(),new:opening};
    let (matrix,constraints,instances,witnesses)=matrix_bytes(circuit.clone(),SynthesisMode::Setup);let matrix_sha256=sha(&matrix);
    let t=Instant::now();let (pk,material,_)=Groth16::<Bls12_381>::generate_random_parameters_with_reduction_and_material_profiled(circuit,&mut OsRng).unwrap();let setup_ns=t.elapsed().as_nanos() as u64;
    let mut pk_bytes=Vec::new();pk.serialize_compressed(&mut pk_bytes).unwrap();let mut vk_bytes=Vec::new();pk.vk.serialize_compressed(&mut vk_bytes).unwrap();let mut material_bytes=Vec::new();material.serialize_compressed(&mut material_bytes).unwrap();
    let vk_sha256=sha(&vk_bytes);let material=format!("plan-a-r3-blind-update-relation-v1|matrix-sha256={matrix_sha256}|vk-sha256={vk_sha256}");
    let circuit_id=domain_field(b"plan-a-r3-circuit-v1",material.as_bytes());
    fs::write(out.join("pk.bin"),&pk_bytes).unwrap();fs::write(out.join("vk.bin"),&vk_bytes).unwrap();fs::write(out.join("checking.bin"),&material_bytes).unwrap();
    let metadata=json!({"schema":"e2-setup-v1","setup_ns":setup_ns,"constraints":constraints,"instance_variables":instances,"witness_variables":witnesses,"matrix_sha256":matrix_sha256,"pk_sha256":sha(&pk_bytes),"vk_sha256":vk_sha256,"pk_bytes":pk_bytes.len(),"vk_bytes":vk_bytes.len(),"config_sha256":sha(config_material.as_bytes()),"config_digest":hex_field(config_digest),"deployment_id":hex_field(deployment),"circuit_id":hex_field(circuit_id)});
    fs::write(out.join("metadata.json"),serde_json::to_vec(&metadata).unwrap()).unwrap();println!("{metadata}");
}
fn field(s:&str)->Fr {Fr::from_be_bytes_mod_order(&hex::decode(s).unwrap())}
fn serve(dir: &Path) {
    let metadata:Value=serde_json::from_slice(&fs::read(dir.join("metadata.json")).unwrap()).unwrap();
    let t=Instant::now();let pk_bytes=fs::read(dir.join("pk.bin")).unwrap();let vk_bytes=fs::read(dir.join("vk.bin")).unwrap();let material_bytes=fs::read(dir.join("checking.bin")).expect("checked profile requires checking.bin");
    assert_eq!(sha(&vk_bytes),env::var("PLAN_A_BLIND_UPDATE_VK_ID").expect("missing configured blind VK ID"));
    let setup_matrix=matrix_bytes(circuit_for_shape(),SynthesisMode::Setup).0;let prove_matrix=matrix_bytes(circuit_for_shape(),SynthesisMode::Prove{construct_matrices:true}).0;assert_eq!(setup_matrix,prove_matrix,"Setup/Prove matrix mismatch");let setup_prove_matrix_sha256=sha(&setup_matrix);
    let checked=check::<Bls12_381,_>(&pk_bytes,&vk_bytes,&material_bytes,circuit_for_shape()).expect("R4 checked blind bundle");let pk_load_ns=t.elapsed().as_nanos() as u64;let vk_load_prepare_ns=0;
    let sk=SecretKey(Scalar::rand(&mut OsRng));let owner_pk=public_key(&sk).unwrap();let registration_salt=Fr::rand(&mut OsRng);let owner=owner_commitment(owner_pk.0.x,owner_pk.0.y,registration_salt);
    let mut pk_encoded=Vec::new();owner_pk.0.serialize_compressed(&mut pk_encoded).unwrap();
    let mut opening=StateOpening{grant_root:Fr::rand(&mut OsRng),expiry:900,active:true,salt:Fr::rand(&mut OsRng)};let mut version=0u64;let mut epoch=1u64;let position=5u32;let mut leaf=state_leaf(owner,version,epoch,position,&opening);
    let ready=json!({"event":"ready","profile":"r4-checked-v5","checked_receipt_sha256":hex::encode(checked.receipt()),"setup_prove_matrix_sha256":setup_prove_matrix_sha256,"validation_count":1,"pk_load_ns":pk_load_ns,"vk_load_prepare_ns":vk_load_prepare_ns,"owner_public_key":STANDARD.encode(pk_encoded),"registration_salt":hex_field(registration_salt),"owner_commitment":hex_field(owner),"position":position,"expiry_cap":1000,"admission_version":0,"initial_leaf":hex_field(leaf),"initial_version":version,"initial_epoch":epoch,"metadata":metadata});println!("{ready}");io::stdout().flush().unwrap();
    let stdin=io::stdin();let mut pending:Option<(StateOpening,Fr,u64,u64)>=None;
    for line in stdin.lock().lines() {let cmd:Value=serde_json::from_str(&line.unwrap()).unwrap();match cmd["command"].as_str().unwrap_or("") {
        "next" => {assert!(pending.is_none());let t=Instant::now();let next=StateOpening{grant_root:Fr::rand(&mut OsRng),expiry:900,active:true,salt:Fr::rand(&mut OsRng)};let new_version=version.checked_add(1).unwrap();let new_epoch=epoch.checked_add(1).unwrap();let new_leaf=state_leaf(owner,new_version,new_epoch,position,&next);let witness_prepare_ns=t.elapsed().as_nanos() as u64;
            let statement=BlindUpdateStatement{config_digest:field(metadata["config_digest"].as_str().unwrap()),deployment:field(metadata["deployment_id"].as_str().unwrap()),circuit_id:field(metadata["circuit_id"].as_str().unwrap()),owner,position,expiry_cap:1000,admission_version:0,old_leaf:leaf,new_leaf,old_version:version,new_version,old_epoch:epoch,new_epoch};
            let circuit=BlindUpdateCircuit{statement:statement.clone(),old:opening.clone(),new:next.clone()};let t=Instant::now();let proof=checked.prove(circuit,&mut OsRng).unwrap();let proof_generate_loaded_pk_ns=t.elapsed().as_nanos() as u64;
            let t=Instant::now();let mut proof_bytes=Vec::new();proof.serialize_compressed(&mut proof_bytes).unwrap();let mut aux=[0u8;32];OsRng.fill_bytes(&mut aux);let signature=sign(&sk,authorization_digest(&statement,proof_sha256_limbs(&proof).unwrap()),aux).unwrap();let request=json!({"command":"blind-state-update-verify","statement":{"config_digest":metadata["config_digest"],"deployment_id":metadata["deployment_id"],"circuit_id":metadata["circuit_id"],"owner_commitment":hex_field(owner),"position":position,"expiry_cap":1000,"admission_version":0,"old_leaf":hex_field(leaf),"new_leaf":hex_field(new_leaf),"old_version":version,"new_version":new_version,"old_epoch":epoch,"new_epoch":new_epoch},"proof_b64":STANDARD.encode(&proof_bytes),"signature_b64":STANDARD.encode(encode_signature(&signature))});let request_bytes=serde_json::to_vec(&request).unwrap();let owner_sign_serialize_ns=t.elapsed().as_nanos() as u64;
            pending=Some((next,new_leaf,new_version,new_epoch));println!("{}",json!({"event":"update","request":request,"proof_bytes":proof_bytes.len(),"proof_sha256":sha(&proof_bytes),"request_bytes":request_bytes.len(),"request_sha256":sha(&request_bytes),"timings_ns":{"witness_prepare":witness_prepare_ns,"proof_generate_loaded_pk":proof_generate_loaded_pk_ns,"owner_sign_serialize":owner_sign_serialize_ns}}));io::stdout().flush().unwrap();}
        "commit" => {let (o,l,v,e)=pending.take().unwrap();opening=o;leaf=l;version=v;epoch=e;println!("{}",json!({"event":"committed","version":version,"epoch":epoch,"leaf":hex_field(leaf)}));io::stdout().flush().unwrap();}
        "stop" => break,_=>panic!("bad command")}}
}
fn main(){let a=env::args().collect::<Vec<_>>();match a.get(1).map(String::as_str){Some("setup")=>setup(&PathBuf::from(&a[2])),Some("serve")=>serve(&PathBuf::from(&a[2])),_=>panic!("usage: blind_update_e2_agent setup|serve DIR")}}
