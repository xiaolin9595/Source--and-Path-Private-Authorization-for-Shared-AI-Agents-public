//! Compile-only authenticated scaling fixtures for the full-F SR comparison.
//! No anonymous credential operation or performance claim is made here.
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, One, PrimeField};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::protocols::{
    hrada_admission::{AdmissionAuthority, BusinessEntitlement, InMemoryEntitlementLedger},
    hrada_auth::AuthFixture,
    hrada_sr_f_compiler::{compile_portfolio, encode_complete_q, CompiledEpoch, TrustedSnapshotRegistry},
};
use serde::Serialize;
use std::{env, fs, path::PathBuf, time::Instant};

#[derive(Serialize)]
struct PublicRequest { complete_q_hex:String, current_header_digest_hex:String, terminal_public_key_hex:String, context_digest_hex:String, verifier_nonce:u64, tq:u64, te:u64 }
#[derive(Serialize)]
struct Cell { cell_id: &'static str, compile_scan_validation_dominance_ns: u128, stats: cpsnarks_set::protocols::hrada_sr_f_compiler::CompileStats, public_issuance_bytes: usize, private_dependency_bytes: usize, target_terminal_k: usize, intervals: Vec<(u64,u64)>, issuance: cpsnarks_set::protocols::hrada_sr_f_compiler::CredentialIssuanceBatch, request:Option<PublicRequest>, notes: &'static str }
#[derive(Serialize)]
struct Output { format: &'static str, benchmark_seed: u64, cells: Vec<Cell>, accepted: bool }

fn ledger(fixtures: &[AuthFixture], actions: u16) -> InMemoryEntitlementLedger {
    InMemoryEntitlementLedger { records: fixtures.iter().map(|f| BusinessEntitlement { user_commitment:f.base.user_commitment(), system:1, resource:42, action_mask:actions, not_before:0, not_after:2000, active:true, max_delegation_depth:2 }).collect() }
}
fn authority(f: &AuthFixture) -> AdmissionAuthority { AdmissionAuthority::new(f.base.params.clone(),f.base.ra_pk,f.base.sr_pk,1,1) }
fn terminal(f: &AuthFixture)->Vec<u8>{ let mut b=vec![]; f.keys[5].0.serialize(&mut b).unwrap(); b }
fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{:02x}",b)).collect()}
fn public_request(fixtures:&[AuthFixture], cell_id:&str, nonce:u64, tq:u64, te:u64)->Result<PublicRequest,String>{
    let mut header=[0u8;32];
    for (index, field) in fixtures[0].base.request.fields[..2].iter().enumerate(){
        let bytes=field.into_repr().to_bytes_le();
        if bytes.iter().skip(16).any(|byte|*byte!=0){return Err("fixture header limb exceeds 128 bits".into())}
        header[index*16..index*16+bytes.len().min(16)].copy_from_slice(&bytes[..bytes.len().min(16)]);
    }
    let mut context_hasher=Blake2s::new(); context_hasher.update(b"HRADA-SR-F-SCALING-CONTEXT-V1"); context_hasher.update(cell_id.as_bytes());
    let context=context_hasher.finalize();
    let header_limbs=[fixtures[0].base.request.fields[0],fixtures[0].base.request.fields[1]];
    let context_limbs=[Fr::from_le_bytes_mod_order(&context[..16]),Fr::from_le_bytes_mod_order(&context[16..])];
    let agent=fixtures[0].keys[5].0;
    let epoch=fixtures[0].base.request.fields[2];
    let q=[header_limbs[0],header_limbs[1],epoch,Fr::from(1u64),Fr::from(1u64),Fr::from(17u64),Fr::from(18u64),Fr::from(42u64),Fr::from(1u64),Fr::from(tq),Fr::from(nonce),Fr::from(te),context_limbs[0],context_limbs[1],agent.x,agent.y];
    Ok(PublicRequest{complete_q_hex:hex(&encode_complete_q(&q)?),current_header_digest_hex:hex(&header),terminal_public_key_hex:hex(&terminal(&fixtures[0])),context_digest_hex:hex(&context),verifier_nonce:nonce,tq,te})
}

fn rewrite(f: &mut AuthFixture, lower:u64, upper:u64, actions:u16) {
    let map=[(None,0usize),(Some(0usize),1),(Some(1),2),(Some(1),2),(None,0),(Some(4),3),(Some(5),4),(Some(4),3)];
    for (i,(parent,issuer)) in map.iter().enumerate() {
        f.all_grants[i].fields[8]=Fr::from(actions as u64); f.all_grants[i].fields[9]=Fr::from(lower); f.all_grants[i].fields[10]=Fr::from(upper);
        f.all_grants[i].parent=parent.map(|p|f.all_grants[p].id()).unwrap_or_else(||f.base.reg_hash());
        let core=f.all_grants[i].core(); f.all_grants[i].signature=f.issuer_sign(*issuer,core).unwrap();
    }
    f.refresh_state(f.base.prime);
}
fn portfolio(seed:u64,n:usize)->Vec<AuthFixture>{ let first=AuthFixture::new(seed); let mut v=vec![first.clone()]; for i in 1..n {v.push(first.second_user(seed+i as u64));} v }
fn compile(fixtures:&[AuthFixture], actions:u16)->Result<CompiledEpoch,String>{
    let sources=fixtures.iter().map(|f|(&f.base,f.all_grants.as_slice())).collect::<Vec<_>>();
    let registry=TrustedSnapshotRegistry::install_under(fixtures[0].base.request.fields[2].into_repr().as_ref()[0], [fixtures[0].base.request.fields[0],fixtures[0].base.request.fields[1]],&sources)?;
    compile_portfolio(&authority(&fixtures[0]),&ledger(fixtures,actions),&registry,500)
}
fn cell(id:&'static str, fixtures:&[AuthFixture], actions:u16, request:Option<PublicRequest>, note:&'static str)->Result<Cell,String>{
    let target=terminal(&fixtures[0]); let start=Instant::now(); let full=compile(fixtures,actions)?; let elapsed=start.elapsed().as_nanos(); let selected=full.select_terminal(&target);
    let issuance=selected.issuance_batch(); let public=serde_json::to_vec(&issuance).map_err(|e|e.to_string())?; let private_wire=selected.dependencies.iter().map(|(id,supports)|(id.iter().map(|b|format!("{:02x}",b)).collect::<String>(),supports)).collect::<Vec<_>>(); let private=serde_json::to_vec(&private_wire).map_err(|e|e.to_string())?;
    let intervals=selected.credentials.iter().map(|c|(c.not_before,u64::MAX-c.not_after_complement)).collect();
    Ok(Cell{cell_id:id,compile_scan_validation_dominance_ns:elapsed,stats:selected.stats.clone(),public_issuance_bytes:public.len(),private_dependency_bytes:private.len(),target_terminal_k:selected.credentials.len(),intervals,issuance,request,notes:note})
}
fn run(path:PathBuf)->Result<(),String>{
    let seed=env::var("BENCHMARK_SEED").ok().and_then(|v|v.parse().ok()).unwrap_or(0)+2026102400;
    let mut duplicate=portfolio(seed,8); for f in &mut duplicate {rewrite(f,100,1000,1)}
    let mut nested=portfolio(seed+100,8); for (i,f) in nested.iter_mut().enumerate(){rewrite(f,100+i as u64*10,1000-i as u64*10,1)}
    let nested_before=cell("containment_dedup",&nested,1,None,"eight nested authenticated supports; widest present")?;
    for i in [2usize,6,7] { nested[0].all_grants[i].active=false; } nested[0].base.state_version+=1; nested[0].base.request.fields[2]+=Fr::one();
    // The global epoch advances independently of each source's signed state
    // version. Q[2] is the unsigned public global-header carrier, so every
    // source under the successor registry must carry the same new epoch even
    // though only the revoked source changes its signed state snapshot.
    for fixture in nested.iter_mut().skip(1){fixture.base.request.fields[2]+=Fr::one();}
    let next_prime=nested[0].base.prime+Fr::one(); nested[0].refresh_state(next_prime);
    let nested_after=cell("containment_after_widest_revocation",&nested,1,None,"widest target support removed; next maximal interval recovers")?;
    let mut overlap=portfolio(seed+200,8); for(i,f)in overlap.iter_mut().enumerate(){rewrite(f,100+i as u64*10,900+i as u64*10,1)}
    let overlap_request=public_request(&overlap,"overlap_fragmentation",4001,500,550)?;
    let mut permissions=portfolio(seed+300,1); rewrite(&mut permissions[0],100,1000,0xff);
    let mut scan_baseline=portfolio(seed+400,3); for f in scan_baseline.iter_mut().skip(1){f.all_grants.clear();f.refresh_state(f.base.prime);}
    let mut invalid=portfolio(seed+400,3); for f in invalid.iter_mut().skip(1){for grant in &mut f.all_grants{grant.active=false;}f.refresh_state(f.base.prime);}
    let cells=vec![cell("exact_duplicate_dedup",&duplicate,1,None,"eight sources, identical target-terminal supports")?,nested_before,nested_after,
                   cell("overlap_fragmentation",&overlap,1,Some(overlap_request),"eight noncontained overlapping intervals, all covering request time")?,cell("permission_scaling",&permissions,0xff,None,"eight one-hot atoms under one group and interval")?,
                   cell("invalid_candidate_baseline",&scan_baseline,3,None,"one valid source plus two legal empty current snapshots")?,
                   cell("invalid_candidate_scan",&invalid,3,None,"same valid source plus two legal current snapshots whose inactive records add sixteen invalid candidates")?];
    let accepted=cells[0].target_terminal_k==1 && cells[0].stats.path_atom_supports>=8
        && cells[1].target_terminal_k==1 && cells[1].intervals.contains(&(100,1000))
        && cells[2].target_terminal_k==1 && cells[2].intervals.contains(&(110,990))
        && cells[3].target_terminal_k==8 && cells[3].intervals.len()==8
        && cells[4].target_terminal_k==8 && cells[4].stats.permission_count>=8
        && cells[5].stats.valid_paths==cells[6].stats.valid_paths
        && cells[5].stats.path_atom_supports==cells[6].stats.path_atom_supports
        && cells[5].intervals==cells[6].intervals
        && cells[5].target_terminal_k==cells[6].target_terminal_k
        && cells[6].stats.invalid_candidates>=cells[5].stats.invalid_candidates+16;
    let out=Output{format:"HRADA-SR-F-COMPILE-SCALING-V1",benchmark_seed:seed,cells,accepted}; if let Some(p)=path.parent(){fs::create_dir_all(p).map_err(|e|e.to_string())?} fs::write(path,serde_json::to_vec_pretty(&out).unwrap()).map_err(|e|e.to_string())?; if !accepted{return Err("scaling_fixture_gate_failed".into())} Ok(())
}
fn main(){let path=env::args_os().nth(1).map(PathBuf::from).unwrap_or_else(||PathBuf::from("sr_scaling.json"));if let Err(e)=run(path){eprintln!("{e}");std::process::exit(1)}}
