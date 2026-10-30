use ark_bls12_381::{Bls12_381, Fq, Fr, G1Affine, G1Projective, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{One, UniformRand, Zero};
use ark_groth16::{checked::{check, check_then_prove}, CheckingMaterial, Groth16, ProvingKey, VerifyingKey};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalSerialize;
use ark_std::{rand::{rngs::StdRng, SeedableRng}, test_rng};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct ProductCircuit { x: Option<Fr>, a: Option<Fr>, b: Option<Fr>, extra: bool, wrong_matrix: bool }
impl ConstraintSynthesizer<Fr> for ProductCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let x=cs.new_input_variable(|| self.x.ok_or(SynthesisError::AssignmentMissing))?;
        let a=cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b=cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        if self.wrong_matrix { cs.enforce_constraint(a.into(), a.into(), x.into())?; }
        else { cs.enforce_constraint(a.into(), b.into(), x.into())?; }
        if self.extra { cs.enforce_constraint(a.into(), ark_relations::lc!() + ark_relations::r1cs::Variable::One, a.into())?; }
        Ok(())
    }
}
fn shape() -> ProductCircuit { ProductCircuit{x:None,a:None,b:None,extra:false,wrong_matrix:false} }
fn witness(a:u64,b:u64)->ProductCircuit { ProductCircuit{x:Some(Fr::from(a*b)),a:Some(Fr::from(a)),b:Some(Fr::from(b)),extra:false,wrong_matrix:false} }
#[derive(Clone)]
struct EmptyCircuit;
impl ConstraintSynthesizer<Fr> for EmptyCircuit {
    fn generate_constraints(self, _cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> { Ok(()) }
}
fn bytes<T:CanonicalSerialize>(x:&T)->Vec<u8>{let mut v=Vec::new();x.serialize_compressed(&mut v).unwrap();v}
fn bump1(p:ark_bls12_381::G1Affine)->ark_bls12_381::G1Affine{(p.into_group()+G1Projective::generator()).into_affine()}
fn bump2(p:ark_bls12_381::G2Affine)->ark_bls12_381::G2Affine{(p.into_group()+G2Projective::generator()).into_affine()}
fn non_subgroup_g1(rng:&mut StdRng)->G1Affine { loop { if let Some(p)=G1Affine::get_point_from_x_unchecked(Fq::rand(rng),false) { if !p.is_in_correct_subgroup_assuming_on_curve(){return p;} } } }
fn honest() -> (ProvingKey<Bls12_381>,VerifyingKey<Bls12_381>,CheckingMaterial<Bls12_381>) {
    let mut rng=StdRng::seed_from_u64(7);
    let (pk,m)=Groth16::<Bls12_381>::generate_random_parameters_with_reduction_and_material(shape(),&mut rng).unwrap();
    let vk=pk.vk.clone();(pk,vk,m)
}
fn rejects(pk:&ProvingKey<Bls12_381>,vk:&VerifyingKey<Bls12_381>,m:&CheckingMaterial<Bls12_381>){
    assert!(check::<Bls12_381,_>(&bytes(pk),&bytes(vk),&bytes(m),shape()).is_err());
}

#[test]
fn honest_two_witnesses_and_deterministic_zero_tau() {
    let (pk,vk,m)=honest();
    let checked=check::<Bls12_381,_>(&bytes(&pk),&bytes(&vk),&bytes(&m),shape()).unwrap();
    let mut rng=test_rng();
    for c in [witness(2,3),witness(3,2)] {
        let proof=checked.prove(c,&mut rng).unwrap();
        assert!(Groth16::<Bls12_381>::verify_proof(checked.prepared_vk(),&proof,&[Fr::from(6u64)]).unwrap());
    }
    assert!(checked.prove(ProductCircuit{x:Some(6u64.into()),a:Some(2u64.into()),b:Some(3u64.into()),extra:true,wrong_matrix:false},&mut rng).is_err());
    assert!(checked.prove(ProductCircuit{x:Some(6u64.into()),a:Some(2u64.into()),b:Some(3u64.into()),extra:false,wrong_matrix:true},&mut rng).is_err());
    let alpha=Fr::from(2u64);let beta=Fr::from(3u64);let gamma=Fr::from(5u64);let delta=Fr::from(7u64);
    let (zero_pk,zero_m)=Groth16::<Bls12_381>::generate_parameters_with_qap_and_material(
        shape(),alpha,beta,gamma,delta,G1Projective::generator(),G2Projective::generator(),Some(Fr::zero()),&mut rng).unwrap();
    assert!(zero_m.tau_powers_g1.iter().skip(1).all(|p| p.is_zero()));
    check::<Bls12_381,_>(&bytes(&zero_pk),&bytes(&zero_pk.vk),&bytes(&zero_m),shape()).unwrap();
    let (bad_pk,bad_m)=Groth16::<Bls12_381>::generate_parameters_with_qap_and_material(
        shape(),alpha,beta,gamma,delta,G1Projective::generator(),G2Projective::generator(),Some(Fr::one()),&mut rng).unwrap();
    assert!(check::<Bls12_381,_>(&bytes(&bad_pk),&bytes(&bad_pk.vk),&bytes(&bad_m),shape()).is_err());
    let mut noncanonical_pk=bytes(&zero_pk);let mut zero_encoding=bytes(&G1Affine::zero());assert_eq!(zero_encoding[0],0xc0);
    let at=noncanonical_pk.windows(zero_encoding.len()).position(|w|w==zero_encoding).expect("zero query encoding");
    zero_encoding[1]=1;noncanonical_pk[at..at+zero_encoding.len()].copy_from_slice(&zero_encoding);
    assert!(check::<Bls12_381,_>(&noncanonical_pk,&bytes(&zero_pk.vk),&bytes(&zero_m),shape()).is_err());
}

#[test]
fn every_consumed_family_and_shape_is_bound() {
    let (pk,vk,m)=honest();
    macro_rules! pkmut {($body:expr)=>{{let mut q=pk.clone();$body(&mut q);rejects(&q,&vk,&m);}}}
    pkmut!(|q:&mut ProvingKey<Bls12_381>|q.beta_g1=bump1(q.beta_g1));
    pkmut!(|q:&mut ProvingKey<Bls12_381>|q.delta_g1=bump1(q.delta_g1));
    for family in 0..5 { for last in [false,true] { let mut q=pk.clone();match family {
        0=>{let i=if last{q.a_query.len()-1}else{0};q.a_query[i]=bump1(q.a_query[i])},
        1=>{let i=if last{q.b_g1_query.len()-1}else{0};q.b_g1_query[i]=bump1(q.b_g1_query[i])},
        2=>{let i=if last{q.b_g2_query.len()-1}else{0};q.b_g2_query[i]=bump2(q.b_g2_query[i])},
        3=>{let i=if last{q.h_query.len()-1}else{0};q.h_query[i]=bump1(q.h_query[i])},
        _=>{let i=if last{q.l_query.len()-1}else{0};q.l_query[i]=bump1(q.l_query[i])},};rejects(&q,&vk,&m);}}
    let boundary=[0,1,m.num_instance_variables as usize,pk.a_query.len()-1];
    for family in 0..3 {for &i in &boundary {let mut q=pk.clone();match family {0=>q.a_query[i]=bump1(q.a_query[i]),1=>q.b_g1_query[i]=bump1(q.b_g1_query[i]),_=>q.b_g2_query[i]=bump2(q.b_g2_query[i])};rejects(&q,&vk,&m);}}
    for field in 0..5 {let mut q=pk.clone();match field {
        0=>q.vk.alpha_g1=bump1(q.vk.alpha_g1),1=>q.vk.beta_g2=bump2(q.vk.beta_g2),
        2=>q.vk.gamma_g2=bump2(q.vk.gamma_g2),3=>q.vk.delta_g2=bump2(q.vk.delta_g2),
        _=>q.vk.gamma_abc_g1[0]=bump1(q.vk.gamma_abc_g1[0]),};rejects(&q,&q.vk.clone(),&m);}
    let mut q=pk.clone();let i=q.vk.gamma_abc_g1.len()-1;q.vk.gamma_abc_g1[i]=bump1(q.vk.gamma_abc_g1[i]);rejects(&q,&q.vk.clone(),&m);
    for family in 0..6 {let mut short=pk.clone();match family {0=>{short.a_query.pop();},1=>{short.b_g1_query.pop();},2=>{short.b_g2_query.pop();},3=>{short.h_query.pop();},4=>{short.l_query.pop();},_=>{short.vk.gamma_abc_g1.pop();}}rejects(&short,&short.vk.clone(),&m);}
    for family in 0..6 {let mut long=pk.clone();match family {0=>long.a_query.push(long.a_query[0]),1=>long.b_g1_query.push(long.b_g1_query[0]),2=>long.b_g2_query.push(long.b_g2_query[0]),3=>long.h_query.push(long.h_query[0]),4=>long.l_query.push(long.l_query[0]),_=>long.vk.gamma_abc_g1.push(long.vk.gamma_abc_g1[0])}rejects(&long,&long.vk.clone(),&m);}
    for field in 0..7 { let mut q=pk.clone();match field {0=>q.vk.alpha_g1=Default::default(),1=>q.beta_g1=Default::default(),2=>q.vk.beta_g2=Default::default(),3=>q.vk.gamma_g2=Default::default(),4=>q.delta_g1=Default::default(),5=>q.vk.delta_g2=Default::default(),_=>q.h_query[0]=Default::default()};rejects(&q,&q.vk.clone(),&m); }
    assert!(check::<Bls12_381,_>(&bytes(&pk),&bytes(&vk),&bytes(&m),ProductCircuit{x:None,a:None,b:None,extra:true,wrong_matrix:false}).is_err());
    assert!(check::<Bls12_381,_>(&bytes(&pk),&bytes(&vk),&bytes(&m),ProductCircuit{x:None,a:None,b:None,extra:false,wrong_matrix:true}).is_err());
    let mut other_vk=vk.clone();other_vk.alpha_g1=bump1(other_vk.alpha_g1);
    assert!(check::<Bls12_381,_>(&bytes(&pk),&bytes(&other_vk),&bytes(&m),shape()).is_err());
}

#[test]
fn material_strict_decoding_and_callback_gate() {
    let (pk,vk,m)=honest();
    for family in 0..2 { for last in [false,true] {let mut q=m.clone();match family {
        0=>{let i=if last{q.tau_powers_g1.len()-1}else{0};q.tau_powers_g1[i]=bump1(q.tau_powers_g1[i])},
        _=>{let i=if last{q.tau_powers_g2.len()-1}else{0};q.tau_powers_g2[i]=bump2(q.tau_powers_g2[i])},};rejects(&pk,&vk,&q);}}
    for family in 0..2 {let mut q=m.clone();if family==0 {q.tau_powers_g1.push(q.tau_powers_g1[0]);}else{q.tau_powers_g2.push(q.tau_powers_g2[0]);}rejects(&pk,&vk,&q);}
    for family in 0..2 {let mut q=m.clone();if family==0 {q.tau_powers_g1.pop();}else{q.tau_powers_g2.pop();}rejects(&pk,&vk,&q);}
    let mut wrong=m.clone();wrong.domain_size+=1;rejects(&pk,&vk,&wrong);
    let mut wrong=m.clone();wrong.format_version+=1;rejects(&pk,&vk,&wrong);
    let mut wrong=m.clone();wrong.reduction_id[0]^=1;rejects(&pk,&vk,&wrong);
    let mut wrong=m.clone();wrong.domain_id[0]^=1;rejects(&pk,&vk,&wrong);
    let mut wrong=m.clone();wrong.curve_id[0]^=1;rejects(&pk,&vk,&wrong);
    for field in 0..5 {let mut wrong=m.clone();match field {0=>wrong.requested_domain_size+=1,1=>wrong.num_constraints+=1,2=>wrong.num_instance_variables+=1,3=>wrong.num_witness_variables+=1,_=>{wrong.tau_powers_g1.pop();}}rejects(&pk,&vk,&wrong);}
    let empty_result=std::panic::catch_unwind(||check::<Bls12_381,_>(&bytes(&pk),&bytes(&vk),&bytes(&m),EmptyCircuit));
    assert!(empty_result.is_ok(),"d=1 shape must not panic");assert!(empty_result.unwrap().is_err());
    let mut trailing=bytes(&m);trailing.push(0);assert!(check::<Bls12_381,_>(&bytes(&pk),&bytes(&vk),&trailing,shape()).is_err());
    let mut trailing_pk=bytes(&pk);trailing_pk.push(0);assert!(check::<Bls12_381,_>(&trailing_pk,&bytes(&vk),&bytes(&m),shape()).is_err());
    let mut trailing_vk=bytes(&vk);trailing_vk.push(0);assert!(check::<Bls12_381,_>(&bytes(&pk),&trailing_vk,&bytes(&m),shape()).is_err());
    let mut malformed=bytes(&m);malformed[0]^=0xff;assert!(check::<Bls12_381,_>(&bytes(&pk),&bytes(&vk),&malformed,shape()).is_err());
    let mut subgroup_pk=pk.clone();let mut srng=StdRng::seed_from_u64(99);subgroup_pk.a_query[0]=non_subgroup_g1(&mut srng);
    assert!(check::<Bls12_381,_>(&bytes(&subgroup_pk),&bytes(&vk),&bytes(&m),shape()).is_err());
    let mut bad=pk.clone();bad.a_query[0]=bump1(bad.a_query[0]);
    static CALLED:AtomicUsize=AtomicUsize::new(0);CALLED.store(0,Ordering::SeqCst);
    let mut rng=test_rng();let result=check_then_prove::<Bls12_381,_>(&bytes(&bad),&bytes(&vk),&bytes(&m),shape(),||{CALLED.fetch_add(1,Ordering::SeqCst);witness(2,3)},&mut rng);
    assert!(result.is_err());assert_eq!(CALLED.load(Ordering::SeqCst),0);
}

#[test]
fn b2_query_is_independently_bound_to_b1() {
    let (mut pk,vk,m)=honest();
    pk.b_g2_query[0]=bump2(pk.b_g2_query[0]);
    let error=check::<Bls12_381,_>(&bytes(&pk),&bytes(&vk),&bytes(&m),shape()).err().unwrap();
    assert!(error.0.contains("b_query cross-group 0"),"unexpected error: {error}");
}
