use ark_bls12_381::Bls12_381;
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_std::rand::{rngs::StdRng, SeedableRng};
use plan_a_joint_circuit::{
    fixture::{l3, public_inputs},
    indexed_revocation::IndexedRevocationTree,
    joint::{grant_digest, JointCircuit},
    merkle::{build_tree, leaf_hash, path_for},
    plain::verify_plain,
    poseidon::{hash, Domain},
    signature::{public_key, sign, SecretKey},
    Fr,
};
use std::sync::atomic::{AtomicUsize, Ordering};

fn keys() -> [SecretKey; 4] {
    [11u64, 12, 13, 14].map(|x| SecretKey(Scalar::from(x)))
}
fn rebuild_ra(c: &mut JointCircuit<3>) {
    let e = &c.entitlement;
    let leaf = leaf_hash(
        Domain::RaLeaf,
        &[
            e.owner_commitment,
            e.resource,
            Fr::from(e.action_mask as u64),
            Fr::from(e.interval_lo),
            Fr::from(e.interval_hi),
            Fr::from(e.permit_expiry),
            e.admission_id,
        ],
    );
    let (root, levels) = build_tree(vec![leaf], e.path.siblings.len(), Domain::TreeNode).unwrap();
    c.snapshot.root_ra = root;
    c.entitlement.path = path_for(&levels, 0).unwrap();
}
fn rebuild_state(c: &mut JointCircuit<3>) {
    let s = &c.state;
    let leaf = hash(
        Domain::StateLeaf,
        &[
            s.owner_commitment,
            s.grant_root,
            Fr::from(s.state_version),
            Fr::from(s.state_epoch),
            Fr::from(s.state_expiry),
            Fr::from(s.active as u64),
            s.salt,
            Fr::from(s.position),
        ],
    );
    let depth = s.path.siblings.len();
    let mut leaves = vec![Fr::from(0u64); 1usize << depth];
    leaves[s.position as usize] = leaf;
    let (root, levels) = build_tree(leaves, depth, Domain::TreeNode).unwrap();
    c.snapshot.root_state = root;
    c.state.path = path_for(&levels, s.position as usize).unwrap();
}
fn rebuild_root_grant(c: &mut JointCircuit<3>) {
    let leaf = hash(Domain::GrantLeaf, &[grant_digest(&c.grants[0].grant)]);
    let depth = c.grants[0].grant_path.siblings.len();
    let (root, levels) = build_tree(vec![leaf], depth, Domain::TreeNode).unwrap();
    c.state.grant_root = root;
    c.grants[0].grant_path = path_for(&levels, 0).unwrap();
    rebuild_state(c);
}
fn resign(c: &mut JointCircuit<3>) {
    let ks = keys();
    let mut parent = Fr::from(0u64);
    for i in 0..c.grants.iter().take_while(|x| x.enabled).count() {
        c.grants[i].grant.parent_digest = parent;
        let d = grant_digest(&c.grants[i].grant);
        c.grants[i].grant.signature = sign(&ks[i], d, [90 + i as u8; 32]).unwrap();
        parent = d;
    }
    rebuild_root_grant(c);
}
fn both_reject(c: JointCircuit<3>) {
    static CASE: AtomicUsize = AtomicUsize::new(0);
    let case = CASE.fetch_add(1, Ordering::SeqCst) + 1;
    assert!(verify_plain(
        &c.snapshot,
        &c.request,
        &c.entitlement,
        &c.state,
        c.registration_salt,
        &c.grants
    )
    .is_err());
    let cs = ConstraintSystem::new_ref();
    c.generate_constraints(cs.clone()).unwrap();
    assert!(!cs.is_satisfied().unwrap());
    eprintln!("{{\"suite\":\"presentation_mutations\",\"case\":{case},\"status\":\"rejected\"}}");
}

#[test]
fn targeted_business_negatives_native_and_r1cs_agree() {
    let mut c = l3(2, 101);
    c.entitlement.action_mask = 0b1110;
    rebuild_ra(&mut c);
    both_reject(c);
    let mut c = l3(2, 102);
    c.grants[0].grant.action_mask = 0b0011;
    c.grants[1].grant.action_mask = 0b0101;
    resign(&mut c);
    both_reject(c);
    let mut c = l3(2, 103);
    c.grants[0].grant.expiry = 250;
    c.grants[1].grant.expiry = 260;
    resign(&mut c);
    both_reject(c);
    let mut c = l3(2, 104);
    c.grants[0].grant.not_before = 120;
    c.grants[1].grant.not_before = 110;
    resign(&mut c);
    both_reject(c);
    let mut c = l3(2, 105);
    c.grants[1].grant.depth_remaining = 1;
    resign(&mut c);
    both_reject(c);
    let mut c = l3(2, 106);
    resign(&mut c);
    c.grants[1].grant.parent_digest = Fr::from(999u64);
    c.grants[1].grant.signature =
        sign(&keys()[1], grant_digest(&c.grants[1].grant), [6; 32]).unwrap();
    both_reject(c);
    let mut c = l3(2, 107);
    let wrong_issuer = SecretKey(Scalar::from(99u64));
    c.grants[1].grant.issuer = public_key(&wrong_issuer).unwrap();
    c.grants[1].grant.signature =
        sign(&wrong_issuer, grant_digest(&c.grants[1].grant), [7; 32]).unwrap();
    both_reject(c);
    let mut c = l3(2, 108);
    c.grants[1].grant.resource = Fr::from(701u64);
    resign(&mut c);
    both_reject(c);
    let mut c = l3(3, 109);
    c.grants[1].enabled = false;
    both_reject(c);
    let mut c = l3(1, 110);
    c.grants[1].grant.resource = Fr::from(1u64);
    both_reject(c);
    let mut c = l3(2, 111);
    c.state.active = false;
    rebuild_state(&mut c);
    both_reject(c);
    let mut c = l3(2, 112);
    c.state.state_expiry = 199;
    rebuild_state(&mut c);
    both_reject(c);
    let mut c = l3(2, 113);
    c.entitlement.permit_expiry = 199;
    rebuild_ra(&mut c);
    both_reject(c);
    let mut c = l3(2, 114);
    c.grants[1].revocation.predecessor = Fr::from(5000u64);
    both_reject(c);
    let mut c = l3(2, 115);
    let mut revoked =
        IndexedRevocationTree::new(c.grants[0].revocation.path.siblings.len()).unwrap();
    revoked.insert(c.grants[1].grant.serial).unwrap();
    c.snapshot.root_rev = revoked.root();
    both_reject(c);
    let mut c = l3(2, 116);
    c.request.terminal = public_key(&keys()[0]).unwrap();
    both_reject(c);
}

#[test]
fn every_public_input_is_proof_bound() {
    let c = l3(2, 201);
    let mut rng = StdRng::seed_from_u64(0x5031_4149);
    let (pk, vk) = Groth16::<Bls12_381>::setup(c.clone(), &mut rng).unwrap();
    let proof = Groth16::<Bls12_381>::prove(&pk, c.clone(), &mut rng).unwrap();
    let inputs = public_inputs(&c);
    assert!(Groth16::<Bls12_381>::verify(&vk, &inputs, &proof).unwrap());
    for i in 0..inputs.len() {
        let mut changed = inputs.clone();
        changed[i] += Fr::from(1u64);
        assert!(
            !Groth16::<Bls12_381>::verify(&vk, &changed, &proof).unwrap(),
            "public input {i} was not bound"
        );
        eprintln!(
            "{{\"suite\":\"public_fields\",\"case\":{},\"status\":\"rejected\"}}",
            i + 1
        );
    }
}

#[test]
fn twenty_one_request_categories() {
    let mut rng = StdRng::seed_from_u64(0x5233_3231);
    let base = l3(2, 301);
    let (pk, vk) = Groth16::<Bls12_381>::setup(base.clone(), &mut rng).unwrap();
    for length in 1..=3 {
        let c = l3(length, 300 + length as u64);
        let proof = Groth16::<Bls12_381>::prove(&pk, c.clone(), &mut rng).unwrap();
        assert!(Groth16::<Bls12_381>::verify(&vk, &public_inputs(&c), &proof).unwrap());
        eprintln!("{{\"suite\":\"request_categories\",\"case\":{length},\"status\":\"accepted\"}}");
    }
    let proof = Groth16::<Bls12_381>::prove(&pk, base.clone(), &mut rng).unwrap();
    let inputs = public_inputs(&base);
    for (offset, index) in (8usize..=22).enumerate() {
        let mut changed = inputs.clone();
        changed[index] += Fr::from(1u64);
        assert!(!Groth16::<Bls12_381>::verify(&vk, &changed, &proof).unwrap());
        eprintln!(
            "{{\"suite\":\"request_categories\",\"case\":{},\"status\":\"rejected\"}}",
            offset + 4
        );
    }
    for (case, mut c) in [l3(2, 401), l3(2, 402), l3(2, 403)].into_iter().enumerate() {
        match case {
            0 => c.request.action_onehot = 0,
            1 => c.request.interval_lo = 201,
            _ => c.request.interval_hi = 101,
        }
        let cs = ConstraintSystem::new_ref();
        c.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
        eprintln!(
            "{{\"suite\":\"request_categories\",\"case\":{},\"status\":\"rejected\"}}",
            case + 19
        );
    }
}
