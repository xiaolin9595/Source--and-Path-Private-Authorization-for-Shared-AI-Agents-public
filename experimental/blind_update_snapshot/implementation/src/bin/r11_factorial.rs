use ark_bls12_381::{Bls12_381,Fr};
use ark_ff::UniformRand;
use ark_groth16::{Groth16,Proof,ProvingKey};
use ark_r1cs_std::synthesis_patch::Mode;
use ark_serialize::{CanonicalDeserialize,CanonicalSerialize};
use ark_snark::SNARK;
use plan_a_joint_circuit::{fixture::{fixed,public_inputs},joint::JointCircuit,offline_mask::TokenPool,
    offline_mask_groth16::{prove_from_pool,MaskedProverTimes,PublicAssemblyContext},
    phase_groth16::{prove_with_randomness_mode,PhaseTimes}};
use rand::rngs::OsRng;
use serde::Deserialize;
use serde_json::{json,Map,Value};
use sha2::{Digest,Sha256};
use std::{collections::HashSet,env,fs,sync::Arc,time::Instant};

#[derive(Clone,Deserialize)] struct Row{row_index:usize,block:usize,group:usize,length:usize,length_position:usize,arm:String,arm_position_within_length:usize}
#[derive(Deserialize)] struct Schedule{schema:String,seed:u64,rows:Vec<Row>}

fn native_phases(p:&PhaseTimes)->(Map<String,Value>,Value){
    let mut m=Map::new();
    m.insert("canonical_token_claim".into(),json!(0.0));
    m.insert("canonical_synthesis".into(),json!(p.synthesis_ms));
    m.insert("canonical_finalize".into(),json!(p.finalize_ms));
    m.insert("canonical_qap".into(),json!(p.qap_witness_map_ms));
    m.insert("canonical_scalar_mask_conversion".into(),json!(p.h_scalar_conversion_ms+p.l_scalar_conversion_ms+p.assignment_conversion_ms));
    m.insert("canonical_h_msm".into(),json!(p.h_msm_ms)); m.insert("canonical_l_msm".into(),json!(p.l_msm_ms));
    m.insert("canonical_a_msm".into(),json!(p.a_msm_ms)); m.insert("canonical_b1_msm".into(),json!(p.b_g1_msm_ms)); m.insert("canonical_b2_msm".into(),json!(p.b_g2_msm_ms));
    m.insert("canonical_bridge_correction".into(),json!(0.0));
    m.insert("canonical_randomizer_assembly".into(),json!(p.rs_delta_randomizer_ms+p.a_randomizer_pre_ms+p.a_coeff_fixed_ms+p.a_randomizer_post_ms+p.b_g1_randomizer_pre_ms+p.b_g1_coeff_fixed_ms+p.b_g2_randomizer_pre_ms+p.b_g2_coeff_fixed_ms+p.b_g1_randomizer_post_ms+p.final_c_assembly_ms+p.affine_normalization_ms));
    (m,serde_json::to_value(p).unwrap())
}
fn masked_phases(p:&MaskedProverTimes)->(Map<String,Value>,Value){
    let mut m=Map::new(); m.insert("canonical_token_claim".into(),json!(p.token_claim_and_binding_ms));
    m.insert("canonical_synthesis".into(),json!(p.synthesis_ms));m.insert("canonical_finalize".into(),json!(p.finalize_ms));m.insert("canonical_qap".into(),json!(p.qap_witness_map_ms));
    m.insert("canonical_scalar_mask_conversion".into(),json!(p.queries.h.masking_ms+p.queries.l.masking_ms+p.queries.a.masking_ms+p.queries.b1.masking_ms+p.queries.b2.masking_ms));
    m.insert("canonical_h_msm".into(),json!(p.queries.h.masked_msm_ms));m.insert("canonical_l_msm".into(),json!(p.queries.l.masked_msm_ms));m.insert("canonical_a_msm".into(),json!(p.queries.a.masked_msm_ms));m.insert("canonical_b1_msm".into(),json!(p.queries.b1.masked_msm_ms));m.insert("canonical_b2_msm".into(),json!(p.queries.b2.masked_msm_ms));
    let bridge=[&p.queries.h,&p.queries.l,&p.queries.a,&p.queries.b1,&p.queries.b2].iter().map(|t|t.masked_bridge_ms+t.correction_ms).sum::<f64>();
    m.insert("canonical_bridge_correction".into(),json!(bridge+p.public_output_bridge_ms));m.insert("canonical_randomizer_assembly".into(),json!(p.correction_to_proof_assembly_ms));(m,serde_json::to_value(p).unwrap())
}
fn run_one(arm:&str,length:usize,fixture:&JointCircuit<3>,pk:&ProvingKey<Bls12_381>,prepared:&PublicAssemblyContext,pool:&TokenPool)->(Proof<Bls12_381>,f64,Map<String,Value>,Value){
    let started=Instant::now(); let r=Fr::rand(&mut OsRng);let s=Fr::rand(&mut OsRng);let c=fixture.clone();
    let (proof,(phases,details))=match arm{
        "B"=>{let(p,t)=prove_with_randomness_mode(pk,c,r,s,Mode::Native).unwrap();(p,native_phases(&t))},
        "S"=>{let(p,t)=prove_with_randomness_mode(pk,c,r,s,Mode::FixedWitness).unwrap();(p,native_phases(&t))},
        "M"=>{let(p,t)=prove_from_pool(pool,prepared,c,r,s,Mode::Native).unwrap();(p,masked_phases(&t))},
        "C"=>{let(p,t)=prove_from_pool(pool,prepared,c,r,s,Mode::FixedWitness).unwrap();(p,masked_phases(&t))},
        _=>panic!("unknown arm {arm}")};
    let total=started.elapsed().as_secs_f64()*1000.0; assert!((1..=3).contains(&length)); (proof,total,phases,details)
}
fn checked(phase:&str,index:usize,arm:&str,length:usize,fixture:&JointCircuit<3>,pk:&ProvingKey<Bls12_381>,prepared:&PublicAssemblyContext,pool:&TokenPool,hashes:&mut HashSet<String>)->Value{
    let(proof,total,phases,details)=run_one(arm,length,fixture,pk,prepared,pool);let inputs=public_inputs(fixture);
    assert!(Groth16::<Bls12_381>::verify(&pk.vk,&inputs,&proof).unwrap());let mut bad=inputs;bad[0]+=Fr::from(1u64);assert!(!Groth16::<Bls12_381>::verify(&pk.vk,&bad,&proof).unwrap());
    let mut bytes=Vec::new();proof.serialize_compressed(&mut bytes).unwrap();let hash=format!("{:x}",Sha256::digest(&bytes));assert!(hashes.insert(hash.clone()));
    json!({"event":phase,"index":index,"length":length,"arm":arm,"status":"ok","total_prove_ms":total,"phases_ms":phases,"phase_details":details,"verified":true,"changed_public_rejected":true,"proof_sha256":hash,"proof_bytes":bytes.len()})
}
fn main(){
    let a=env::args().collect::<Vec<_>>();assert!((3..=4).contains(&a.len()),"usage: r11_factorial PK SCHEDULE [--preflight-only]");
    let preflight_only=a.get(3).map(|s|s.as_str())==Some("--preflight-only");
    let pk_bytes=fs::read(&a[1]).unwrap();assert_eq!(format!("{:x}",Sha256::digest(&pk_bytes)),"c35b69180afd18e44b0c0f890661583435395c7715f69f31ce3a4418f940c72e");
    let pk=ProvingKey::<Bls12_381>::deserialize_compressed(&pk_bytes[..]).unwrap();let prep_started=Instant::now();let prepared=PublicAssemblyContext::new(Arc::new(pk)).unwrap();let key_prepare_ms=prep_started.elapsed().as_secs_f64()*1000.0;
    let count=if preflight_only{6}else{60};let token_started=Instant::now();let tokens=(0..count).map(|id|prepared.generate_set(id as u64).unwrap()).collect::<Vec<_>>();let token_precompute_ms=token_started.elapsed().as_secs_f64()*1000.0;
    let per_token_bytes=(prepared.pk.h_query.len()+prepared.pk.l_query.len()+(prepared.pk.a_query.len()-1)+(prepared.pk.b_g1_query.len()-1)+(prepared.pk.b_g2_query.len()-1))*32+576;let pool=TokenPool::new(tokens).unwrap();
    println!("{}",json!({"event":"offline","key_prepare_ms":key_prepare_ms,"token_count":count,"token_precompute_ms":token_precompute_ms,"per_token_material_bytes":per_token_bytes,"total_material_bytes":per_token_bytes*count,"remaining":pool.remaining()}));
    let schedule_bytes=fs::read(&a[2]).unwrap();assert_eq!(format!("{:x}",Sha256::digest(&schedule_bytes)),"adea0a034a4f4a674f2da0c57cb5cd294146016f8d77cdf7449197a46373f98f");
    let schedule:Schedule=serde_json::from_slice(&schedule_bytes).unwrap();assert_eq!(schedule.schema,"r11-factorial-schedule-v1");assert_eq!(schedule.seed,2026102706);assert_eq!(schedule.rows.len(),96);
    let mut cells=HashSet::new();let mut block_counts=[0usize;8];let mut arm_len=[[[0usize;4];3];1];let mut positions=[[[0usize;4];4];3];
    for (i,row) in schedule.rows.iter().enumerate(){assert_eq!(row.row_index,i);assert!(row.block<8);assert!(row.group<2);assert!((1..=3).contains(&row.length));assert!(row.length_position<3);assert!(row.arm_position_within_length<4);let ai=match row.arm.as_str(){"B"=>0,"S"=>1,"M"=>2,"C"=>3,_=>panic!("bad arm")};assert!(cells.insert((row.block,row.length,row.arm.clone())));block_counts[row.block]+=1;arm_len[0][row.length-1][ai]+=1;positions[row.length-1][ai][row.arm_position_within_length]+=1;}
    assert!(block_counts.iter().all(|x|*x==12));assert!(arm_len[0].iter().flatten().all(|x|*x==8));assert!(positions.iter().flatten().flatten().all(|x|*x==2));
    let fixtures=[fixed::<3>(1,0,20,20,32),fixed::<3>(2,0,20,20,32),fixed::<3>(3,0,20,20,32)];let reference=public_inputs(&fixtures[0]);assert!(fixtures.iter().all(|c|public_inputs(c)==reference));
    let mut hashes=HashSet::new();let mut pre=0;for length in 1..=3{for arm in ["B","S","M","C"]{println!("{}",checked("preflight",pre,arm,length,&fixtures[length-1],&prepared.pk,&prepared,&pool,&mut hashes));pre+=1;}}
    if preflight_only {assert_eq!(pool.remaining(),0);assert_eq!(hashes.len(),12);println!("{}",json!({"event":"preflight_finished","preflight":12,"unique_proofs":12,"remaining_tokens":0}));return;}
    let mut warm=0;for length in 1..=3{for arm in ["B","S","M","C"]{println!("{}",checked("warmup",warm,arm,length,&fixtures[length-1],&prepared.pk,&prepared,&pool,&mut hashes));warm+=1;}}
    for row in &schedule.rows {let mut v=checked("proof",row.row_index,&row.arm,row.length,&fixtures[row.length-1],&prepared.pk,&prepared,&pool,&mut hashes);let o=v.as_object_mut().unwrap();o.insert("row_index".into(),json!(row.row_index));o.insert("block".into(),json!(row.block));println!("{v}");}
    assert_eq!(pool.remaining(),0);assert_eq!(hashes.len(),120);println!("{}",json!({"event":"finished","preflight":12,"warmup":12,"measured":96,"unique_proofs":120,"remaining_tokens":0}));
}
