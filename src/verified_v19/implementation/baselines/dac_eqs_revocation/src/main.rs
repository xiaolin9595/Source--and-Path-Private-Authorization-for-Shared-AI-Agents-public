use ark_bls12_381::{Bls12_381, Fr};
use ark_ec::pairing::Pairing;
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use blake2::{Blake2b512, Digest};
use delegatable_credentials::{
    accumulator::{Accumulator, NonMembershipWitness, PreparedPublicKey as PreparedAccumulatorPublicKey, PublicKey as AccumulatorPublicKey, SecretKey as AccumulatorSecretKey},
    msbm::{
        issuance::Credential,
        keys::{PreparedRootIssuerPublicKey, RootIssuerPublicKey, RootIssuerSecretKey, UserPublicKey, UserSecretKey},
        show::CredentialShowProtocol,
    },
    set_commitment::{PreparedSetCommitmentSRS, SetCommitmentSRS},
};
use schnorr_pok::compute_random_oracle_challenge;
use std::{env, time::Instant};

type E = Bls12_381;

fn field_from_label(label: &[u8]) -> Fr {
    let digest = Blake2b512::digest(label);
    Fr::from_le_bytes_mod_order(&digest)
}

fn challenge(request: &[u8], public_context: &[u8], contribution: &[u8], root_epoch: u64) -> Fr {
    let mut transcript = Vec::new();
    transcript.extend_from_slice(b"plan-a-b2-dac-eqs-v1");
    transcript.extend_from_slice(&(request.len() as u64).to_le_bytes());
    transcript.extend_from_slice(request);
    transcript.extend_from_slice(&(public_context.len() as u64).to_le_bytes());
    transcript.extend_from_slice(public_context);
    transcript.extend_from_slice(&root_epoch.to_le_bytes());
    transcript.extend_from_slice(contribution);
    compute_random_oracle_challenge::<Fr, Blake2b512>(&transcript)
}

fn serialized_size<T: CanonicalSerialize>(value: &T) -> usize {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).unwrap();
    bytes.len()
}

fn trials_arg() -> usize {
    let args: Vec<_> = env::args().collect();
    args.windows(2)
        .find(|w| w[0] == "--trials")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(10)
}

fn main() {
    let trials = trials_arg();
    let mut rng = StdRng::seed_from_u64(0x504c_414e_4132);
    let max_attributes = 8u32;
    let (srs, trapdoor) = SetCommitmentSRS::<E>::generate_with_random_trapdoor::<StdRng, Blake2b512>(
        &mut rng,
        max_attributes + 20,
        Some(b"plan-a-b2-dac-eqs-v1"),
    );
    let issuer_sk = RootIssuerSecretKey::<E>::new::<StdRng>(&mut rng, max_attributes).unwrap();
    let issuer_pk = RootIssuerPublicKey::new(&issuer_sk, srs.get_P1(), srs.get_P2());
    let prepared_issuer = PreparedRootIssuerPublicKey::from(issuer_pk.clone());
    let prepared_srs = PreparedSetCommitmentSRS::from(srs.clone());

    let user_sk = UserSecretKey::<E>::new::<StdRng>(&mut rng);
    let user_pk = UserPublicKey::new(&user_sk, srs.get_P1());
    let agent_sk = UserSecretKey::<E>::new::<StdRng>(&mut rng);
    let agent_pk = UserPublicKey::new(&agent_sk, srs.get_P1());

    let resource = field_from_label(b"resource:files");
    let read_action = field_from_label(b"action:read");
    let agent_binding = field_from_label(b"agent:terminal-1");
    let serial = Fr::rand(&mut rng);
    let root_attrs = vec![resource, read_action];
    let delegated_attrs = vec![resource, read_action, agent_binding, serial];

    let (root, update_key) = Credential::issue_root(
        &mut rng,
        vec![root_attrs],
        &user_pk,
        Some(2),
        &issuer_sk,
        max_attributes,
        &srs,
    ).unwrap();
    let (root, user_nym, update_key) = root.process_received_from_root(
        &mut rng,
        update_key.as_ref(),
        &user_pk,
        &user_sk,
        prepared_issuer.clone(),
        &srs,
    ).unwrap();
    let (delegated, delegated_update_key) = root.delegate_with_new_attributes(
        &mut rng,
        delegated_attrs.clone(),
        &user_nym.secret,
        &issuer_pk.X_0,
        Some(2),
        &update_key.unwrap(),
        &srs,
    ).unwrap();
    let (delegated, agent_nym, _) = delegated.process_received_delegated(
        &mut rng,
        delegated_update_key.as_ref(),
        &agent_pk,
        &agent_sk,
        prepared_issuer.clone(),
        &srs,
    ).unwrap();

    let accumulator_sk = AccumulatorSecretKey::<E>::new(&mut rng);
    let accumulator_pk = AccumulatorPublicKey::new(&accumulator_sk, srs.get_P2());
    let prepared_accumulator_pk = PreparedAccumulatorPublicKey::from(accumulator_pk.clone());
    // The Dock accumulator polynomial helper treats the empty root polynomial as
    // a zero polynomial. Keep a domain-separated permanent sentinel so the set is non-empty.
    let revocation_sentinel = field_from_label(b"plan-a-b2-revocation-sentinel-v1");
    assert_ne!(serial, revocation_sentinel);
    let revoked: Vec<Fr> = vec![revocation_sentinel];
    let (mut accumulator, _) = Accumulator::<E>::new_using_trapdoor(&revoked, &trapdoor, &accumulator_sk, srs.get_P1());
    let witness = NonMembershipWitness::<E>::from_members_using_trapdoor(&serial, &revoked, &trapdoor, srs.get_P2()).unwrap();
    let mut public_context = Vec::new();
    issuer_pk.serialize_compressed(&mut public_context).unwrap();
    accumulator_pk.serialize_compressed(&mut public_context).unwrap();
    accumulator.accumulated().serialize_compressed(&mut public_context).unwrap();
    let mut srs_bytes = Vec::new(); srs.serialize_compressed(&mut srs_bytes).unwrap();
    public_context.extend_from_slice(&Blake2b512::digest(&srs_bytes));

    println!("trial,show_ns,verify_ns,show_bytes,nonmembership_bytes,accepted");
    for trial in 0..trials {
        let request = format!("POST\n/mcp\ntools/call\nread\nnonce={trial}").into_bytes();
        let disclosed = vec![vec![], delegated_attrs.clone()];
        let started = Instant::now();
        let protocol = CredentialShowProtocol::init::<_, Blake2b512>(
            &mut rng,
            delegated.clone(),
            disclosed.clone(),
            &agent_nym.secret,
            &agent_nym.nym,
            &issuer_pk.X_0,
            &srs,
        ).unwrap();
        let mut contribution = Vec::new();
        protocol.challenge_contribution(srs.get_P1(), &mut contribution).unwrap();
        let c = challenge(&request, &public_context, &contribution, 0);
        let show = protocol.gen_show(&c);
        let show_ns = started.elapsed().as_nanos();

        let started = Instant::now();
        let mut verifier_contribution = Vec::new();
        show.challenge_contribution(srs.get_P1(), &mut verifier_contribution).unwrap();
        let verifier_c = challenge(&request, &public_context, &verifier_contribution, 0);
        let dac_ok = show.verify::<Blake2b512>(disclosed, &verifier_c, prepared_issuer.clone(), prepared_srs.clone()).is_ok();
        let rev_ok = witness.verify(&serial, accumulator.accumulated(), prepared_accumulator_pk.clone(), srs.get_s_P1(), srs.get_P1(), srs.get_P2());
        let verify_ns = started.elapsed().as_nanos();
        // CredentialShow has no aggregate CanonicalSerialize impl. Account for an explicit
        // component-framed wire format (u64 length before each of its 5 public components).
        let show_bytes = 5 * 8
            + serialized_size(&show.commitments)
            + serialized_size(&show.signature)
            + serialized_size(&show.disclosed_attributes_witness)
            + serialized_size(&show.pseudonym)
            + serialized_size(&show.schnorr);
        println!("{trial},{show_ns},{verify_ns},{},{},{}", show_bytes, serialized_size(&witness), dac_ok && rev_ok);
    }

    // Negative: request mutation changes the Fiat-Shamir challenge.
    let disclosed = vec![vec![], delegated_attrs.clone()];
    let protocol = CredentialShowProtocol::init::<_, Blake2b512>(&mut rng, delegated.clone(), disclosed.clone(), &agent_nym.secret, &agent_nym.nym, &issuer_pk.X_0, &srs).unwrap();
    let mut contribution = Vec::new();
    protocol.challenge_contribution(srs.get_P1(), &mut contribution).unwrap();
    let good_c = challenge(b"GET\n/mcp\nnonce=negative", &public_context, &contribution, 0);
    let show = protocol.gen_show(&good_c);
    let mut verifier_contribution = Vec::new(); show.challenge_contribution(srs.get_P1(), &mut verifier_contribution).unwrap();
    let bad_c = challenge(b"POST\n/mcp\nnonce=negative", &public_context, &verifier_contribution, 0);
    assert!(show.verify::<Blake2b512>(disclosed, &bad_c, prepared_issuer.clone(), prepared_srs.clone()).is_err());

    // Negative: the serial's witness cannot be relabeled as a different serial.
    let wrong_serial = serial + Fr::from(1u64);
    assert!(!witness.verify(&wrong_serial, accumulator.accumulated(), prepared_accumulator_pk.clone(), srs.get_s_P1(), srs.get_P1(), srs.get_P2()));

    // Negative: installing the serial invalidates the old non-membership witness.
    accumulator.add_using_trapdoor(&[serial], &trapdoor);
    assert!(!witness.verify(&serial, accumulator.accumulated(), prepared_accumulator_pk.clone(), srs.get_s_P1(), srs.get_P1(), srs.get_P2()));

    // Negative: the registry cannot create a fresh non-membership witness for a revoked member.
    assert!(NonMembershipWitness::<E>::from_members_using_trapdoor(
        &serial,
        &[revocation_sentinel, serial],
        &trapdoor,
        srs.get_P2(),
    ).is_err());
}
