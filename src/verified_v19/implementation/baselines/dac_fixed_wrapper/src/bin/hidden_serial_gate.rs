use ark_bls12_377::{Bls12_377, Fr, G1Affine};
use ark_std::{
    collections::BTreeSet,
    rand::{rngs::StdRng, SeedableRng},
    UniformRand,
};
use blake2::Blake2b512;
use delegatable_credentials::{
    msbm::{
        issuance::Credential,
        keys::{
            PreparedRootIssuerPublicKey, RootIssuerPublicKey, RootIssuerSecretKey, UserPublicKey,
            UserSecretKey,
        },
        show::CredentialShow,
    },
    set_commitment::{
        AggregateSubsetWitness, PreparedSetCommitmentSRS, SetCommitment, SetCommitmentSRS,
    },
};
use plan_a_dac_fixed_wrapper::hidden_serial::HiddenSerialProtocol;
use schnorr_pok::{compute_random_oracle_challenge, discrete_log::PokDiscreteLogProtocol};
use serde::Serialize;
use std::time::Instant;
use vb_accumulator::{
    persistence::{InitialElementsStore, State, UniversalAccumulatorState},
    positive::Accumulator,
    setup::{
        Keypair, NonMembershipProvingKey, PreparedPublicKey, PreparedSetupParams, SetupParams,
    },
    universal::UniversalAccumulator,
};

const PUBLIC_CONTEXT: &[u8] =
    b"plan-a/dac-hidden-serial/v1|deployment=1|header=7|request=read:[10,20]";

#[derive(Clone, Default)]
struct InitialStore(BTreeSet<Fr>);

impl InitialElementsStore<Fr> for InitialStore {
    fn add(&mut self, element: Fr) {
        self.0.insert(element);
    }

    fn has(&self, element: &Fr) -> bool {
        self.0.contains(element)
    }
}

#[derive(Clone, Default)]
struct AccumulatorState(BTreeSet<Fr>);

impl State<Fr> for AccumulatorState {
    fn add(&mut self, element: Fr) {
        self.0.insert(element);
    }

    fn remove(&mut self, element: &Fr) {
        self.0.remove(element);
    }

    fn has(&self, element: &Fr) -> bool {
        self.0.contains(element)
    }

    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

impl<'a> UniversalAccumulatorState<'a, Fr> for AccumulatorState {
    type ElementIterator = std::collections::btree_set::Iter<'a, Fr>;

    fn elements(&'a self) -> Self::ElementIterator {
        self.0.iter()
    }
}

#[derive(Serialize)]
struct GateResult {
    relation: &'static str,
    dac_show_accepted: bool,
    linked_hidden_non_membership_accepted: bool,
    wrong_commitment_rejected: bool,
    mutated_public_context_rejected: bool,
    successor_revocation_rejected: bool,
    prove_ms: f64,
    verify_ms: f64,
    serial_public: bool,
    scope_complete: bool,
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    let mut rng = StdRng::seed_from_u64(0x4849_4444_454e_4e4d);

    // A real randomized Mir-DAC show with no disclosed attributes.
    let max_attributes = 8u32;
    let (set_srs, _) = SetCommitmentSRS::<Bls12_377>::generate_with_random_trapdoor::<
        StdRng,
        Blake2b512,
    >(&mut rng, max_attributes, Some(b"plan-a-hidden-serial-v1"));
    let issuer_sk = RootIssuerSecretKey::<Bls12_377>::new(&mut rng, 2).unwrap();
    let issuer_pk = RootIssuerPublicKey::new(&issuer_sk, set_srs.get_P1(), set_srs.get_P2());
    let holder_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let holder_pk = UserPublicKey::new(&holder_sk, set_srs.get_P1());
    let resource = Fr::from(0x5245_534f_5552_4345u64);
    let serial = Fr::rand(&mut rng);
    let attributes = vec![resource, serial];
    let full_set = attributes.iter().copied().collect::<BTreeSet<_>>();

    let (credential, _) = Credential::issue_root(
        &mut rng,
        vec![attributes],
        &holder_pk,
        None,
        &issuer_sk,
        max_attributes,
        &set_srs,
    )
    .unwrap();

    let presentation_randomizer = Fr::rand(&mut rng);
    let (randomized_credential, pseudonym, psi, chi) = credential
        .randomize_for_show(
            &mut rng,
            &presentation_randomizer,
            &holder_pk,
            &issuer_pk.X_0,
            &set_srs,
        )
        .unwrap();
    let pseudonym_secret = holder_sk.randomize(&psi, &chi);

    let empty_subset = BTreeSet::new();
    let empty_witness = randomized_credential.commitments[0]
        .open_subset_unchecked(
            &randomized_credential.openings[0],
            empty_subset.clone(),
            full_set.clone(),
            &set_srs,
        )
        .unwrap();
    let aggregate_empty_witness = AggregateSubsetWitness::new::<Blake2b512>(
        randomized_credential.commitments.clone(),
        vec![empty_subset],
        vec![empty_witness],
    )
    .unwrap();

    // Dynamic accumulator containing revoked serials. The credential serial is
    // initially absent and therefore has a non-membership witness.
    let accumulator_params = SetupParams::<Bls12_377>::generate_using_rng(&mut rng);
    let accumulator_keys = Keypair::<Bls12_377>::generate_using_rng(&mut rng, &accumulator_params);
    let accumulator_proving_key = NonMembershipProvingKey::generate_using_rng(&mut rng);
    let mut initial_store = InitialStore::default();
    let accumulator = UniversalAccumulator::<G1Affine>::initialize_with_all_random(
        &mut rng,
        &accumulator_params,
        64,
        &accumulator_keys.secret_key,
        &mut initial_store,
    );
    let mut accumulator_state = AccumulatorState::default();
    let already_revoked = Fr::rand(&mut rng);
    let accumulator = accumulator
        .add(
            already_revoked,
            &accumulator_keys.secret_key,
            &initial_store,
            &mut accumulator_state,
        )
        .unwrap();
    let non_membership_witness = accumulator
        .get_non_membership_witness(
            &serial,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();

    let started = Instant::now();
    let holder_blinding = Fr::rand(&mut rng);
    let holder_protocol =
        PokDiscreteLogProtocol::init(pseudonym_secret.0, holder_blinding, set_srs.get_P1());
    let linked_protocol = HiddenSerialProtocol::init(
        &mut rng,
        &randomized_credential.commitments[0],
        &randomized_credential.openings[0],
        full_set.clone(),
        serial,
        &non_membership_witness,
        &accumulator_keys.public_key,
        &accumulator_params,
        &accumulator_proving_key,
        &set_srs,
    )
    .unwrap();
    let mut prover_transcript = vec![];
    holder_protocol
        .challenge_contribution(set_srs.get_P1(), &pseudonym.0, &mut prover_transcript)
        .unwrap();
    linked_protocol
        .challenge_contribution(
            PUBLIC_CONTEXT,
            &randomized_credential.commitments[0],
            accumulator.value(),
            &accumulator_keys.public_key,
            &accumulator_params,
            &accumulator_proving_key,
            &mut prover_transcript,
        )
        .unwrap();
    let challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&prover_transcript);
    let holder_proof = holder_protocol.gen_proof(&challenge);
    let linked_proof = linked_protocol.gen_proof(&challenge).unwrap();
    let prove_ms = elapsed_ms(started);

    let show = CredentialShow {
        commitments: randomized_credential.commitments.clone(),
        signature: randomized_credential.signature,
        disclosed_attributes_witness: aggregate_empty_witness,
        pseudonym,
        schnorr: holder_proof,
    };

    let started = Instant::now();
    let mut verifier_transcript = vec![];
    show.challenge_contribution(set_srs.get_P1(), &mut verifier_transcript)
        .unwrap();
    linked_proof
        .challenge_contribution(
            PUBLIC_CONTEXT,
            &show.commitments[0],
            accumulator.value(),
            &accumulator_keys.public_key,
            &accumulator_params,
            &accumulator_proving_key,
            &mut verifier_transcript,
        )
        .unwrap();
    let verifier_challenge =
        compute_random_oracle_challenge::<Fr, Blake2b512>(&verifier_transcript);
    assert_eq!(challenge, verifier_challenge);

    let dac_show_accepted = show
        .verify::<Blake2b512>(
            vec![vec![]],
            &verifier_challenge,
            PreparedRootIssuerPublicKey::from(issuer_pk.clone()),
            PreparedSetCommitmentSRS::from(set_srs.clone()),
        )
        .is_ok();
    let linked_hidden_non_membership_accepted = linked_proof
        .verify(
            &show.commitments[0],
            accumulator.value(),
            &verifier_challenge,
            PreparedPublicKey::from(accumulator_keys.public_key.clone()),
            PreparedSetupParams::from(accumulator_params.clone()),
            &accumulator_proving_key,
            &set_srs,
        )
        .is_ok();
    let verify_ms = elapsed_ms(started);

    let (wrong_commitment, _) = SetCommitment::new(&mut rng, full_set, &set_srs).unwrap();
    let wrong_commitment_rejected = linked_proof
        .verify(
            &wrong_commitment,
            accumulator.value(),
            &verifier_challenge,
            PreparedPublicKey::from(accumulator_keys.public_key.clone()),
            PreparedSetupParams::from(accumulator_params.clone()),
            &accumulator_proving_key,
            &set_srs,
        )
        .is_err();

    let mut mutated_transcript = vec![];
    show.challenge_contribution(set_srs.get_P1(), &mut mutated_transcript)
        .unwrap();
    linked_proof
        .challenge_contribution(
            b"plan-a/dac-hidden-serial/v1|deployment=1|header=8|request=read:[10,20]",
            &show.commitments[0],
            accumulator.value(),
            &accumulator_keys.public_key,
            &accumulator_params,
            &accumulator_proving_key,
            &mut mutated_transcript,
        )
        .unwrap();
    let mutated_challenge = compute_random_oracle_challenge::<Fr, Blake2b512>(&mutated_transcript);
    let mutated_public_context_rejected = linked_proof
        .verify(
            &show.commitments[0],
            accumulator.value(),
            &mutated_challenge,
            PreparedPublicKey::from(accumulator_keys.public_key.clone()),
            PreparedSetupParams::from(accumulator_params.clone()),
            &accumulator_proving_key,
            &set_srs,
        )
        .is_err();

    let successor_accumulator = accumulator
        .add(
            serial,
            &accumulator_keys.secret_key,
            &initial_store,
            &mut accumulator_state,
        )
        .unwrap();
    let successor_revocation_rejected = linked_proof
        .verify(
            &show.commitments[0],
            successor_accumulator.value(),
            &verifier_challenge,
            PreparedPublicKey::from(accumulator_keys.public_key.clone()),
            PreparedSetupParams::from(accumulator_params),
            &accumulator_proving_key,
            &set_srs,
        )
        .is_err();

    let result = GateResult {
        relation: "randomized_mir_dac_show_hidden_serial_linked_vb_nonmembership_v1",
        dac_show_accepted,
        linked_hidden_non_membership_accepted,
        wrong_commitment_rejected,
        mutated_public_context_rejected,
        successor_revocation_rejected,
        prove_ms,
        verify_ms,
        serial_public: false,
        scope_complete: false,
    };
    assert!(result.dac_show_accepted);
    assert!(result.linked_hidden_non_membership_accepted);
    assert!(result.wrong_commitment_rejected);
    assert!(result.mutated_public_context_rejected);
    assert!(result.successor_revocation_rejected);
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
