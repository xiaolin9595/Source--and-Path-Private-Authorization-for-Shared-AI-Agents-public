use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16, Proof, ProvingKey};
use ark_r1cs_std::synthesis_patch::Mode;
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use plan_a_joint_circuit::{
    fixture::{fixed, public_inputs},
    joint::JointCircuit,
    offline_mask::TokenPool,
    offline_mask_groth16::{prove_from_pool, MaskedProverTimes, PublicAssemblyContext},
    phase_groth16::{prove_with_randomness_mode, PhaseTimes},
};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet}, env, fs,
    path::{Path, PathBuf}, sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const SCHEDULE_HASHES: [&str; 6] = [
    "b5281627b20a93ad1c40750107a056c90a24a9781eed5df8b9f751dc2ed82db1",
    "238fcb9fccd4b373b6746e6c803a1128f6914e3a6490e90e4595d8313e7dcd51",
    "e94d8979f47d6f2397d5013d58390e9696a39cb0aa312b8873ae83bfe8674c78",
    "46e143a5019e5dd9a9848d5a841a45efbd6d3e3e992141f76377e4bb138b0926",
    "b9078011fa4506780321a283abb5c209afa175e43bffd461b875f05d648240f2",
    "88d1f83ac4762c88bf0a48644b00bcb56676e4d39b3fa7a4e0dc5287eaa80261",
];

#[derive(Clone, Deserialize)]
struct Row { row_index: usize, block: usize, length: usize, length_position: usize, label: String, label_position_within_length: usize }
#[derive(Deserialize)]
struct Schedule { schema: String, setup_id: usize, seed: u64, rows: Vec<Row>, preflight: Vec<Prelude>, warmup: Vec<Prelude> }
#[derive(Deserialize)]
struct Prelude { length: usize, label: String }

fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn read_num(path: impl AsRef<Path>) -> Option<u64> { fs::read_to_string(path).ok()?.trim().parse().ok() }
fn read_text(path: impl AsRef<Path>) -> Option<String> { fs::read_to_string(path).ok().map(|s|s.trim().to_owned()) }

fn telemetry(event: &str, setup_id: usize, block: Option<usize>, process_start: Instant) -> Value {
    let mut freqs=BTreeMap::new(); let mut governors=BTreeMap::new();
    for cpu in 0..10 {
        freqs.insert(cpu.to_string(), read_num(format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_cur_freq")));
        governors.insert(cpu.to_string(), read_text(format!("/sys/devices/system/cpu/cpu{cpu}/cpufreq/scaling_governor")));
    }
    let mut temperatures=BTreeMap::new();
    if let Ok(entries)=fs::read_dir("/sys/class/thermal") { for entry in entries.flatten() {
        let path=entry.path(); if !entry.file_name().to_string_lossy().starts_with("thermal_zone") {continue}
        let name=read_text(path.join("type")).unwrap_or_else(||entry.file_name().to_string_lossy().into_owned());
        temperatures.insert(name,read_num(path.join("temp")));
    }}
    let proc_status=fs::read_to_string("/proc/self/status").ok();
    let rss_kib=proc_status.as_deref().and_then(|s|s.lines().find(|l|l.starts_with("VmRSS:"))).and_then(|l|l.split_whitespace().nth(1)).and_then(|v|v.parse::<u64>().ok());
    let mem_available_kib=fs::read_to_string("/proc/meminfo").ok().and_then(|s|s.lines().find(|l|l.starts_with("MemAvailable:")).and_then(|l|l.split_whitespace().nth(1)).and_then(|v|v.parse::<u64>().ok()));
    json!({"event":event,"setup_id":setup_id,"block":block,
        "unix_ns":SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_string(),
        "monotonic_ms":process_start.elapsed().as_secs_f64()*1000.0,
        "loadavg":read_text("/proc/loadavg"),"mem_available_kib":mem_available_kib,"process_rss_kib":rss_kib,
        "cpu_scaling_cur_freq_khz":freqs,"cpu_governor":governors,"thermal_millidegrees_c":temperatures})
}

fn native_phases(p:&PhaseTimes)->(Map<String,Value>,Value){
    let mut m=Map::new();
    m.insert("canonical_token_claim".into(),json!(0.0)); m.insert("canonical_synthesis".into(),json!(p.synthesis_ms));
    m.insert("canonical_finalize".into(),json!(p.finalize_ms)); m.insert("canonical_qap".into(),json!(p.qap_witness_map_ms));
    m.insert("canonical_scalar_mask_conversion".into(),json!(p.h_scalar_conversion_ms+p.l_scalar_conversion_ms+p.assignment_conversion_ms));
    m.insert("canonical_h_msm".into(),json!(p.h_msm_ms));m.insert("canonical_l_msm".into(),json!(p.l_msm_ms));m.insert("canonical_a_msm".into(),json!(p.a_msm_ms));m.insert("canonical_b1_msm".into(),json!(p.b_g1_msm_ms));m.insert("canonical_b2_msm".into(),json!(p.b_g2_msm_ms));
    m.insert("canonical_bridge_correction".into(),json!(0.0));
    m.insert("canonical_randomizer_assembly".into(),json!(p.rs_delta_randomizer_ms+p.a_randomizer_pre_ms+p.a_coeff_fixed_ms+p.a_randomizer_post_ms+p.b_g1_randomizer_pre_ms+p.b_g1_coeff_fixed_ms+p.b_g2_randomizer_pre_ms+p.b_g2_coeff_fixed_ms+p.b_g1_randomizer_post_ms+p.final_c_assembly_ms+p.affine_normalization_ms));
    (m,serde_json::to_value(p).unwrap())
}
fn masked_phases(p:&MaskedProverTimes)->(Map<String,Value>,Value){
    let mut m=Map::new();m.insert("canonical_token_claim".into(),json!(p.token_claim_and_binding_ms));m.insert("canonical_synthesis".into(),json!(p.synthesis_ms));m.insert("canonical_finalize".into(),json!(p.finalize_ms));m.insert("canonical_qap".into(),json!(p.qap_witness_map_ms));
    m.insert("canonical_scalar_mask_conversion".into(),json!(p.queries.h.masking_ms+p.queries.l.masking_ms+p.queries.a.masking_ms+p.queries.b1.masking_ms+p.queries.b2.masking_ms));
    m.insert("canonical_h_msm".into(),json!(p.queries.h.masked_msm_ms));m.insert("canonical_l_msm".into(),json!(p.queries.l.masked_msm_ms));m.insert("canonical_a_msm".into(),json!(p.queries.a.masked_msm_ms));m.insert("canonical_b1_msm".into(),json!(p.queries.b1.masked_msm_ms));m.insert("canonical_b2_msm".into(),json!(p.queries.b2.masked_msm_ms));
    let bridge=[&p.queries.h,&p.queries.l,&p.queries.a,&p.queries.b1,&p.queries.b2].iter().map(|t|t.masked_bridge_ms+t.correction_ms).sum::<f64>();
    m.insert("canonical_bridge_correction".into(),json!(bridge+p.public_output_bridge_ms));m.insert("canonical_randomizer_assembly".into(),json!(p.correction_to_proof_assembly_ms));(m,serde_json::to_value(p).unwrap())
}

/// BA and BB both call this exact function. The label never enters the timed path.
fn run_native(fixture:&JointCircuit<3>,pk:&ProvingKey<Bls12_381>)->(Proof<Bls12_381>,f64,Map<String,Value>,Value){
    let started=Instant::now(); let r=Fr::rand(&mut OsRng); let s=Fr::rand(&mut OsRng); let circuit=fixture.clone();
    let (proof,times)=prove_with_randomness_mode(pk,circuit,r,s,Mode::Native).unwrap();
    let total=started.elapsed().as_secs_f64()*1000.0; let (phases,details)=native_phases(&times); (proof,total,phases,details)
}
fn run_combined(fixture:&JointCircuit<3>,prepared:&PublicAssemblyContext,pool:&TokenPool)->(Proof<Bls12_381>,f64,Map<String,Value>,Value){
    let started=Instant::now(); let r=Fr::rand(&mut OsRng); let s=Fr::rand(&mut OsRng); let circuit=fixture.clone();
    let (proof,times)=prove_from_pool(pool,prepared,circuit,r,s,Mode::FixedWitness).unwrap();
    let total=started.elapsed().as_secs_f64()*1000.0; let (phases,details)=masked_phases(&times); (proof,total,phases,details)
}
fn checked(phase:&str,index:usize,label:&str,length:usize,fixture:&JointCircuit<3>,prepared:&PublicAssemblyContext,pool:&TokenPool,hashes:&mut HashSet<String>)->Value{
    // Dispatch is outside both run_* timers. BA and BB share run_native exactly.
    let (proof,total,phases,details)=match label {"BA"|"BB"=>run_native(fixture,&prepared.pk),"C"=>run_combined(fixture,prepared,pool),_=>panic!("bad label")};
    let inputs=public_inputs(fixture);assert!(Groth16::<Bls12_381>::verify(&prepared.pk.vk,&inputs,&proof).unwrap());let mut bad=inputs;bad[0]+=Fr::from(1u64);assert!(!Groth16::<Bls12_381>::verify(&prepared.pk.vk,&bad,&proof).unwrap());
    let mut bytes=Vec::new();proof.serialize_compressed(&mut bytes).unwrap();let hash=digest(&bytes);assert!(hashes.insert(hash.clone()));
    json!({"event":phase,"index":index,"length":length,"label":label,"status":"ok","total_prove_ms":total,"phases_ms":phases,"phase_details":details,"verified":true,"changed_public_rejected":true,"proof_sha256":hash,"proof_bytes":bytes.len()})
}

fn validate_schedule(setup_id:usize,bytes:&[u8])->Schedule{
    assert_eq!(digest(bytes),SCHEDULE_HASHES[setup_id],"frozen schedule hash mismatch");
    let s:Schedule=serde_json::from_slice(bytes).unwrap();assert_eq!(s.schema,"r11-completion-schedule-v1");assert_eq!(s.setup_id,setup_id);assert_eq!(s.seed,2026102800+setup_id as u64);assert_eq!(s.rows.len(),108);
    let expected=(1..=3).flat_map(|length|["BA","BB","C"].map(|label|json!([length,label]))).collect::<Vec<_>>();
    for prelude in [&s.preflight,&s.warmup] {assert_eq!(prelude.len(),9);assert_eq!(prelude.iter().map(|x|json!([x.length,x.label])).collect::<Vec<_>>(),expected);}
    let mut cells=HashSet::new();let mut blocks=[0usize;12];let mut length_pos=[[0usize;3];3];let mut label_pos=[[[0usize;3];3];3];
    for(i,row)in s.rows.iter().enumerate(){assert_eq!(row.row_index,i);assert!(row.block<12);assert!((1..=3).contains(&row.length));assert!(row.length_position<3);assert!(row.label_position_within_length<3);let li=row.length-1;let ai=match row.label.as_str(){"BA"=>0,"BB"=>1,"C"=>2,_=>panic!("bad label")};assert!(cells.insert((row.block,row.length,row.label.clone())));blocks[row.block]+=1;if row.label_position_within_length==0{length_pos[li][row.length_position]+=1;}label_pos[li][ai][row.label_position_within_length]+=1;}
    assert!(blocks.iter().all(|x|*x==9));assert!(length_pos.iter().flatten().all(|x|*x==4));assert!(label_pos.iter().flatten().flatten().all(|x|*x==4));s
}

fn write_key(path:&Path,what:&impl CanonicalSerialize)->Vec<u8>{let mut bytes=Vec::new();what.serialize_compressed(&mut bytes).unwrap();fs::write(path,&bytes).unwrap();bytes}

fn main(){
    let args=env::args().collect::<Vec<_>>();assert_eq!(args.len(),4,"usage: r11_completion_setup SETUP_ID SCHEDULE_JSON OUTPUT_DIR|--validate-schedule-only");let setup_id=args[1].parse::<usize>().unwrap();assert!(setup_id<6);let schedule_bytes=fs::read(&args[2]).unwrap();let schedule=validate_schedule(setup_id,&schedule_bytes);
    if args[3]=="--validate-schedule-only" {println!("{}",json!({"event":"schedule_valid","setup_id":setup_id,"sha256":digest(&schedule_bytes),"rows":schedule.rows.len()}));return;}
    let output=PathBuf::from(&args[3]);fs::create_dir_all(&output).unwrap();let process_start=Instant::now();println!("{}",telemetry("process_start",setup_id,None,process_start));
    let setup_started=Instant::now();let(pk,vk)=Groth16::<Bls12_381>::setup(fixed::<3>(3,0,20,20,32),&mut OsRng).unwrap();let setup_ms=setup_started.elapsed().as_secs_f64()*1000.0;let pk_bytes=write_key(&output.join("pk.compressed"),&pk);let vk_bytes=write_key(&output.join("vk.compressed"),&vk);
    let prep_started=Instant::now();let prepared=PublicAssemblyContext::new(Arc::new(pk)).unwrap();let key_prepare_ms=prep_started.elapsed().as_secs_f64()*1000.0;
    // Exactly 42 independent materials are generated before any fixture is constructed.
    let token_started=Instant::now();let tokens=(0..42).map(|id|prepared.generate_set((setup_id as u64)*1000+id).unwrap()).collect::<Vec<_>>();let token_precompute_ms=token_started.elapsed().as_secs_f64()*1000.0;let per_token_bytes=(prepared.pk.h_query.len()+prepared.pk.l_query.len()+prepared.pk.a_query.len()-1+prepared.pk.b_g1_query.len()-1+prepared.pk.b_g2_query.len()-1)*32+576;let pool=TokenPool::new(tokens).unwrap();
    println!("{}",json!({"event":"offline","setup_id":setup_id,"setup_ms":setup_ms,"pk_sha256":digest(&pk_bytes),"vk_sha256":digest(&vk_bytes),"pk_bytes":pk_bytes.len(),"vk_bytes":vk_bytes.len(),"key_prepare_ms":key_prepare_ms,"token_count":42,"token_precompute_ms":token_precompute_ms,"per_token_material_bytes":per_token_bytes,"total_material_bytes":per_token_bytes*42,"pool_remaining":pool.remaining(),"pool_consumed":pool.consumed(),"pool_resident":pool.resident()}));
    let mut fixture_ms=Vec::new();let t=Instant::now();let f1=fixed::<3>(1,0,20,20,32);fixture_ms.push(t.elapsed().as_secs_f64()*1000.0);let t=Instant::now();let f2=fixed::<3>(2,0,20,20,32);fixture_ms.push(t.elapsed().as_secs_f64()*1000.0);let t=Instant::now();let f3=fixed::<3>(3,0,20,20,32);fixture_ms.push(t.elapsed().as_secs_f64()*1000.0);let fixtures=[f1,f2,f3];
    let public_started=Instant::now();let reference=public_inputs(&fixtures[0]);assert!(fixtures.iter().all(|c|public_inputs(c)==reference));let mut public_bytes=Vec::new();for value in &reference{value.serialize_compressed(&mut public_bytes).unwrap();}let public_prepare_ms=public_started.elapsed().as_secs_f64()*1000.0;
    println!("{}",json!({"event":"fixture","setup_id":setup_id,"fixture_signing_ms_by_length":fixture_ms,"public_prepare_ms":public_prepare_ms,"public_sha256":digest(&public_bytes),"public_field_elements":reference.len()}));let mut hashes=HashSet::new();
    for (index,row) in schedule.preflight.iter().enumerate(){println!("{}",checked("preflight",index,&row.label,row.length,&fixtures[row.length-1],&prepared,&pool,&mut hashes));}
    for (index,row) in schedule.warmup.iter().enumerate(){println!("{}",checked("warmup",index,&row.label,row.length,&fixtures[row.length-1],&prepared,&pool,&mut hashes));}
    assert_eq!((pool.remaining(),pool.consumed(),pool.resident()),(36,6,42));println!("{}",json!({"event":"measurement_ready","setup_id":setup_id,"pool_remaining":36,"pool_consumed":6,"pool_resident":42}));
    for block in 0..12{println!("{}",telemetry("block_start",setup_id,Some(block),process_start));for row in schedule.rows.iter().filter(|r|r.block==block){let mut v=checked("proof",row.row_index,&row.label,row.length,&fixtures[row.length-1],&prepared,&pool,&mut hashes);let o=v.as_object_mut().unwrap();o.insert("setup_id".into(),json!(setup_id));o.insert("row_index".into(),json!(row.row_index));o.insert("block".into(),json!(row.block));o.insert("length_position".into(),json!(row.length_position));o.insert("label_position_within_length".into(),json!(row.label_position_within_length));println!("{v}");}println!("{}",telemetry("block_end",setup_id,Some(block),process_start));}
    assert_eq!((pool.remaining(),pool.consumed(),pool.resident()),(0,42,42));assert_eq!(hashes.len(),126);println!("{}",json!({"event":"finished","setup_id":setup_id,"preflight":9,"warmup":9,"measured":108,"unique_proofs":126,"pool_remaining":0,"pool_consumed":42,"pool_resident":42,"elapsed_ms":process_start.elapsed().as_secs_f64()*1000.0}));
}
