use ark_bls12_377::{Bls12_377, Fq, Fr, G1Affine};
use ark_bw6_761::BW6_761;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::{SNARK,CircuitSpecificSetupSNARK};
use ark_std::collections::BTreeSet;
use blake2::{Blake2b512, Blake2s256, Digest};
use delegatable_credentials::{
    msbm::{
        issuance::Credential,
        keys::{
            PreparedRootIssuerPublicKey, RootIssuerPublicKey, RootIssuerSecretKey, UserPublicKey,
            UserSecretKey,
        },
    },
    set_commitment::{SetCommitmentOpening, SetCommitmentSRS},
};
use plan_a_dac_fixed_wrapper::fixed_policy::{
    compute_header_digest, compute_request_digest, encode_record, entitlement_leaf, merkle_root,
    owner_commitment, poseidon_alpha_is_permutation_over_commitment_fr,
    poseidon_alpha_is_permutation_over_hash_fq, poseidon_parameter_fingerprint, public_inputs,
    record_digest, root_grant_leaf, split_record_digest, state_leaf, tree_node_hash,
    DacEntitlementWitness, DacMerklePath, DacStateWitness, FixedPolicyCircuit,
    FixedPolicyDeployment, FixedPolicySlotWitness, FixedPolicyStatement, FixedPolicyWitness,
    GrantRecord,
};
use plan_a_dac_fixed_wrapper::service_adapter::{
    sign_header, sign_terminal, AdapterError, DeltaZeroAdapter,
};
use plan_a_dac_fixed_wrapper::semantic_schema::{manifest_sha256, SemanticManifest};
use rand::{rngs::OsRng, Rng};
use serde::Serialize;
use std::time::Instant;
use vb_accumulator::{
    persistence::{InitialElementsStore, State, UniversalAccumulatorState},
    positive::Accumulator,
    setup::{Keypair, SetupParams},
    universal::UniversalAccumulator,
};

const L_MAX: usize = 3;
const RA_DEPTH: usize = 20;
const STATE_DEPTH: usize = 20;
const GRANT_DEPTH: usize = 3;
const RELATION_VERSION: u64 = 2;
const DEPLOYMENT_ID: u64 = 0x4441_4302;
const MAPPING_VERSION: u64 = 1;
const OWNER: u64 = 11;
const OWNER_ALT: u64 = 12;
const DELEGATE: u64 = 22;
const DELEGATE_B: u64 = 44;
const DELEGATE_ALT: u64 = 55;
const TERMINAL: u64 = 33;
const RESOURCE: u64 = 0x5245_534f_5552_4345;
const READ: u64 = 1;
const POLICY_VERSION: u64 = 3;
const SCHEMA_VERSION: u64 = 4;

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
    l_max: usize,
    constraints: usize,
    canonical_matrix_blake2s: String,
    public_input_order_blake2s: String,
    setup_ms: f64,
    prove_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
    proving_key_bytes: usize,
    verifying_key_bytes: usize,
    dac_srs_bytes: usize,
    dac_srs_trapdoor_bytes_destroy_after_ceremony: usize,
    dac_issuer_secret_key_bytes: usize,
    dac_issuer_public_key_bytes: usize,
    issuer_key_verifier_visible: bool,
    accumulator_public_parameters_bytes: usize,
    accumulator_manager_secret_key_bytes: usize,
    public_parameters_blake2s: String,
    poseidon_parameters_blake2s: String,
    poseidon_alpha5_permutation_over_hash_fq: bool,
    poseidon_alpha5_permutation_over_commitment_fr: bool,
    setup_rng: &'static str,
    trust_roles: &'static str,
    accepted: bool,
    same_pk_b_before_accepted: bool,
    same_pk_depth_one_c_accepted: bool,
    same_pk_alternate_owner_d_accepted: bool,
    same_pk_request_variant_accepted: bool,
    mutated_request_rejected: bool,
    successor_revocation_rejected: bool,
    successor_relation_rejected: bool,
    hidden_field_mutation_rejected: bool,
    non_prefix_rejected: bool,
    depth_rule_rejected: bool,
    noncanonical_time_rejected: bool,
    inverted_request_interval_rejected: bool,
    request_clock_outside_interval_rejected: bool,
    state_expiry_cap_rejected: bool,
    future_state_epoch_rejected: bool,
    noncanonical_entitlement_interval_rejected: bool,
    action_width_rejected: bool,
    request_past_expiry_rejected: bool,
    parent_digest_mutation_rejected: bool,
    ra_source_mutation_rejected: bool,
    inactive_state_rejected: bool,
    root_grant_membership_rejected: bool,
    mutated_ra_root_rejected: bool,
    mutated_state_root_rejected: bool,
    native_r1cs_parent_hash_matched: bool,
    padded_depth_one_relation_accepted: bool,
    alternate_owner_relation_accepted: bool,
    padding_authority_mutation_rejected: bool,
    independent_b_before_accepted: bool,
    removed_a_relation_rejected: bool,
    independent_b_after_accepted: bool,
    independent_b_signature_unchanged: bool,
    stale_header_digest_rejected: bool,
    stale_request_digest_rejected: bool,
    terminal_signature_accepted: bool,
    bad_terminal_signature_rejected: bool,
    noncanonical_proof_bytes_rejected: bool,
    nonmonotonic_header_rejected: bool,
    nonce_replay_rejected: bool,
    delta0_old_header_rejected: bool,
    successor_b_atomic_commit_accepted: bool,
    terminal_signature_bytes: usize,
    serial_public: bool,
    verifier_view_actual_depth_public: bool,
    scope_complete: bool,
    remaining_obligations: &'static str,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct SynthesisSummary {
 witnesses:usize,instances:usize,domain:usize,pk_upper:usize,
    constraints: usize,
    canonical_matrix_blake2s: String,
}

const PUBLIC_INPUT_ORDER: [&str; 34] = [
    "deployment_id",
    "tuple_version",
    "ra_root",
    "state_root",
    "state_epoch",
    "revocation_epoch",
    "issued_at",
    "mapping_version",
    "header_digest",
    "canonical_request_lo[0]",
    "canonical_request_lo[1]",
    "canonical_request_hi[0]",
    "canonical_request_hi[1]",
    "circuit_id",
    "verifier_id",
    "pep_id",
    "nonce",
    "context",
    "request_digest",
    "terminal",
    "resource",
    "one_hot_action",
    "request_lo",
    "request_hi",
    "now",
    "policy_version",
    "schema_version",
    "relation_version",
    "terminal_key.x",
    "terminal_key.y",
    "terminal_key.z=1",
    "accumulator_value.x",
    "accumulator_value.y",
    "accumulator_value.z=1",
];

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn compressed_size<T: CanonicalSerialize>(value: &T) -> usize {
    let mut bytes = Vec::new();
    value.serialize_compressed(&mut bytes).expect("vec writer");
    bytes.len()
}

fn relation_rejects(circuit: FixedPolicyCircuit) -> bool {
    let cs = ConstraintSystem::<Fq>::new_ref();
    match circuit.generate_constraints(cs.clone()) {
        Ok(()) => !cs.is_satisfied().unwrap(),
        Err(_) => true,
    }
}

fn append_usize(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(&(value as u64).to_le_bytes());
}

fn hash_usize(hasher: &mut Blake2s256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}

fn hash_matrix(hasher: &mut Blake2s256, label: u8, matrix: &[Vec<(Fq, usize)>]) {
    hasher.update([label]);
    hash_usize(hasher, matrix.len());
    let mut coefficient_bytes = Vec::new();
    for (row_index, row) in matrix.iter().enumerate() {
        hash_usize(hasher, row_index);
        hash_usize(hasher, row.len());
        for (entry_index, (coefficient, column_index)) in row.iter().enumerate() {
            hash_usize(hasher, entry_index);
            hash_usize(hasher, *column_index);
            coefficient_bytes.clear();
            coefficient
                .serialize_compressed(&mut coefficient_bytes)
                .expect("canonical matrix coefficient serialization");
            hasher.update(&coefficient_bytes);
        }
    }
}

fn blake2s_hex(bytes: impl AsRef<[u8]>) -> String {
    Blake2s256::digest(bytes.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn public_input_order_blake2s() -> String {
    let mut bytes = b"plan-a-dac-fixed-wrapper-public-input-order-v1".to_vec();
    append_usize(&mut bytes, PUBLIC_INPUT_ORDER.len());
    for (index, name) in PUBLIC_INPUT_ORDER.iter().enumerate() {
        append_usize(&mut bytes, index);
        append_usize(&mut bytes, name.len());
        bytes.extend_from_slice(name.as_bytes());
    }
    blake2s_hex(bytes)
}

fn assert_positive_synthesis(circuit: &FixedPolicyCircuit) -> SynthesisSummary {
    let cs = ConstraintSystem::<Fq>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .expect("positive relation synthesizes");
    assert!(cs.is_satisfied().expect("positive relation satisfaction"));
    let expected = public_inputs(&circuit.statement, circuit.deployment.relation_version);
    let actual = {
        let borrowed = cs.borrow().expect("constraint system is present");
        borrowed.instance_assignment[1..].to_vec()
    };
    assert_eq!(
        expected, actual,
        "public input encoder must match R1CS allocation"
    );
    assert_eq!(expected.len(), PUBLIC_INPUT_ORDER.len());
    cs.finalize();
    let matrices = cs.to_matrices().expect("constraint matrices are enabled");
    drop(cs);
    let mut canonical = Blake2s256::new();
    canonical.update(b"plan-a-dac-fixed-wrapper-r1cs-matrices-v1");
    for value in [
        matrices.num_instance_variables,
        matrices.num_witness_variables,
        matrices.num_constraints,
        matrices.a_num_non_zero,
        matrices.b_num_non_zero,
        matrices.c_num_non_zero,
    ] {
        hash_usize(&mut canonical, value);
    }
    // Preserve ark-relations' finalized row order and each row's entry order.
    // Each entry commits to both its column index and canonical field bytes.
    hash_matrix(&mut canonical, b'A', &matrices.a);
    hash_matrix(&mut canonical, b'B', &matrices.b);
    hash_matrix(&mut canonical, b'C', &matrices.c);
    SynthesisSummary {
        witnesses:matrices.num_witness_variables,instances:matrices.num_instance_variables,domain:(matrices.num_constraints+matrices.num_instance_variables).next_power_of_two(),
        pk_upper:(matrices.num_witness_variables+matrices.num_instance_variables)*(3*96+192)+(matrices.num_constraints+matrices.num_instance_variables).next_power_of_two()*96+4096,
        constraints: matrices.num_constraints,
        canonical_matrix_blake2s: canonical
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    }
}

fn serial_scalar(lo: u64, hi: u64) -> Fr {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&lo.to_le_bytes());
    bytes[8..].copy_from_slice(&hi.to_le_bytes());
    Fr::from_le_bytes_mod_order(&bytes)
}

fn sparse_path(position: u64, depth: usize) -> DacMerklePath {
    DacMerklePath {
        siblings: vec![Fq::from(0u64); depth],
        directions: (0..depth)
            .map(|level| ((position >> level) & 1) == 1)
            .collect(),
    }
}

fn tree_root_and_path(mut leaves: Vec<Fq>, depth: usize, mut index: usize) -> (Fq, DacMerklePath) {
    leaves.resize(1usize << depth, Fq::from(0u64));
    let mut levels = vec![leaves];
    for _ in 0..depth {
        let next = levels
            .last()
            .unwrap()
            .chunks_exact(2)
            .map(|pair| tree_node_hash(pair[0], pair[1]))
            .collect::<Vec<_>>();
        levels.push(next);
    }
    let root = levels[depth][0];
    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    for level in &levels[..depth] {
        directions.push(index & 1 == 1);
        siblings.push(level[index ^ 1]);
        index >>= 1;
    }
    (
        root,
        DacMerklePath {
            siblings,
            directions,
        },
    )
}

fn field_witnesses(
    credential: &Credential<Bls12_377>,
    slot: usize,
    set_srs: &SetCommitmentSRS<Bls12_377>,
) -> Vec<G1Affine> {
    let full_set = credential.attributes[slot]
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    let mut prefix = BTreeSet::new();
    credential.attributes[slot]
        .iter()
        .map(|member| {
            prefix.insert(*member);
            credential.commitments[slot]
                .open_subset(
                    &credential.openings[slot],
                    prefix.clone(),
                    full_set.clone(),
                    set_srs,
                )
                .unwrap()
                .0
        })
        .collect()
}

fn opening_randomness(credential: &Credential<Bls12_377>, slot: usize) -> Fr {
    match &credential.openings[slot] {
        SetCommitmentOpening::SetWithoutTrapdoor(r) => *r,
        SetCommitmentOpening::SetWithTrapdoor(_, _) => {
            panic!("fixture unexpectedly contains the set-commitment trapdoor")
        }
    }
}

fn main() {
    let mut rng = OsRng;
    let manifest: SemanticManifest = serde_json::from_slice(&std::fs::read(std::env::var("MATCHED_MANIFEST_PATH").expect("MATCHED_MANIFEST_PATH")).expect("read manifest")).expect("parse manifest");
    assert_eq!((manifest.profile.l_max, manifest.profile.ra_depth, manifest.profile.state_depth, manifest.profile.grant_depth), (L_MAX, RA_DEPTH, STATE_DEPTH, GRANT_DEPTH));
    let by_id = manifest.grants.iter().map(|g|(g.id.as_str(),g)).collect::<std::collections::BTreeMap<_,_>>();
    let rb=by_id["root-b"]; let cb=by_id["child-b"]; let tb=by_id["tail-b"]; let rc=by_id["root-c"];
    let [serial0_lo,serial0_hi]=rb.serial;
    let [serial1_lo,serial1_hi]=cb.serial;
    let serial_b0_lo=serial0_lo; let serial_b0_hi=serial0_hi;
    let serial_b1_lo=serial1_lo; let serial_b1_hi=serial1_hi;
    let [serial_c0_lo,serial_c0_hi]=rc.serial;
    let serial_d0_lo = rng.gen::<u64>();
    let serial_d0_hi = rng.gen::<u64>();
    let serial_d1_lo = rng.gen::<u64>();
    let serial_d1_hi = rng.gen::<u64>();
    let [registration_salt_lo,registration_salt_hi] = manifest.entitlement.registration_salt_u128_le_limbs;
    let registration_salt_alt_lo = rng.gen::<u64>();
    let registration_salt_alt_hi = rng.gen::<u64>();
    let [state_salt_lo,state_salt_hi] = manifest.state.state_salt_u128_le_limbs;
    let state_salt_alt_lo = rng.gen::<u64>();
    let state_salt_alt_hi = rng.gen::<u64>();

    let root_record = GrantRecord {
        enabled: true,
        issuer: OWNER,
        subject: DELEGATE,
        resource: RESOURCE,
        actions: READ | 2,
        lo: 0,
        hi: 100,
        not_before: 0,
        expiry: 100,
        remaining_depth: 2,
        serial_lo: serial0_lo,
        serial_hi: serial0_hi,
        parent_digest_lo: [0; 3],
        parent_digest_hi: [0; 3],
        schema_version: SCHEMA_VERSION,
        policy_version: POLICY_VERSION,
    };
    let (parent_digest_lo, parent_digest_hi) = split_record_digest(record_digest(&root_record, 0));
    let terminal_record = GrantRecord {
        enabled: true,
        issuer: DELEGATE,
        subject: TERMINAL,
        resource: RESOURCE,
        actions: READ,
        lo: 20,
        hi: 80,
        not_before: 20,
        expiry: 80,
        remaining_depth: 1,
        serial_lo: serial1_lo,
        serial_hi: serial1_hi,
        parent_digest_lo,
        parent_digest_hi,
        schema_version: SCHEMA_VERSION,
        policy_version: POLICY_VERSION,
    };
    let root_record_b = root_record.clone();
    let (parent_digest_b_lo, parent_digest_b_hi) =
        split_record_digest(record_digest(&root_record_b, 0));
    let mut terminal_record_b = terminal_record.clone();
    terminal_record_b.parent_digest_lo=parent_digest_b_lo;
    terminal_record_b.parent_digest_hi=parent_digest_b_hi;
    let root_record_c = GrantRecord {
        enabled: true,
        issuer: OWNER,
        subject: TERMINAL,
        resource: RESOURCE,
        actions: READ,
        lo: 20,
        hi: 80,
        not_before: 20,
        expiry: 80,
        remaining_depth: 1,
        serial_lo: serial_c0_lo,
        serial_hi: serial_c0_hi,
        parent_digest_lo: [0; 3],
        parent_digest_hi: [0; 3],
        schema_version: SCHEMA_VERSION,
        policy_version: POLICY_VERSION,
    };
    let (parent_digest_c_lo, parent_digest_c_hi) =
        split_record_digest(record_digest(&root_record_c, 0));
    let padding_record_c = GrantRecord {
        enabled: false,
        issuer: TERMINAL,
        subject: TERMINAL,
        resource: RESOURCE,
        actions: READ,
        lo: 20,
        hi: 80,
        not_before: 20,
        expiry: 80,
        remaining_depth: 1,
        serial_lo: 0,
        serial_hi: 0,
        parent_digest_lo: parent_digest_c_lo,
        parent_digest_hi: parent_digest_c_hi,
        schema_version: SCHEMA_VERSION,
        policy_version: POLICY_VERSION,
    };
    let root_record_d = GrantRecord {
        enabled: true,
        issuer: OWNER_ALT,
        subject: DELEGATE_ALT,
        resource: RESOURCE,
        actions: READ | 2,
        lo: 0,
        hi: 100,
        not_before: 0,
        expiry: 100,
        remaining_depth: 1,
        serial_lo: serial_d0_lo,
        serial_hi: serial_d0_hi,
        parent_digest_lo: [0; 3],
        parent_digest_hi: [0; 3],
        schema_version: SCHEMA_VERSION,
        policy_version: POLICY_VERSION,
    };
    let (parent_digest_d_lo, parent_digest_d_hi) =
        split_record_digest(record_digest(&root_record_d, 0));
    let terminal_record_d = GrantRecord {
        enabled: true,
        issuer: DELEGATE_ALT,
        subject: TERMINAL,
        resource: RESOURCE,
        actions: READ,
        lo: 20,
        hi: 80,
        not_before: 20,
        expiry: 80,
        remaining_depth: 0,
        serial_lo: serial_d1_lo,
        serial_hi: serial_d1_hi,
        parent_digest_lo: parent_digest_d_lo,
        parent_digest_hi: parent_digest_d_hi,
        schema_version: SCHEMA_VERSION,
        policy_version: POLICY_VERSION,
    };

    let mut third_record = terminal_record.clone();
    third_record.issuer = TERMINAL;
    third_record.subject = TERMINAL;
    let (lo,hi) = split_record_digest(record_digest(&terminal_record,1));
    third_record.parent_digest_lo=lo; third_record.parent_digest_hi=hi;
    third_record.remaining_depth=0; third_record.serial_lo=tb.serial[0]; third_record.serial_hi=tb.serial[1];
    let mut third_record_b = terminal_record_b.clone();
    third_record_b.issuer = TERMINAL;
    third_record_b.subject = TERMINAL;
    let (lo,hi) = split_record_digest(record_digest(&terminal_record_b,1));
    third_record_b.parent_digest_lo=lo; third_record_b.parent_digest_hi=hi;
    third_record_b.enabled=false;third_record_b.serial_lo=0;third_record_b.serial_hi=0;
    let mut third_record_c = padding_record_c.clone();
    third_record_c.issuer = TERMINAL;
    third_record_c.subject = TERMINAL;
    let (lo,hi) = split_record_digest(record_digest(&padding_record_c,1));
    third_record_c.parent_digest_lo=lo; third_record_c.parent_digest_hi=hi;
    third_record_c.enabled=false;third_record_c.serial_lo=0;third_record_c.serial_hi=0;
    let mut third_record_d = terminal_record_d.clone();
    third_record_d.issuer = TERMINAL;
    third_record_d.subject = TERMINAL;
    let (lo,hi) = split_record_digest(record_digest(&terminal_record_d,1));
    third_record_d.parent_digest_lo=lo; third_record_d.parent_digest_hi=hi;
    third_record_d.enabled=false;third_record_d.serial_lo=0;third_record_d.serial_hi=0;
    let record_member_count = encode_record(&root_record, 0).len() as u32;
    // The pinned Dock update key stores `max_attributes_per_commitment` SRS
    // powers, while eval of an n-member characteristic polynomial consumes
    // n+1 powers. Its effective API boundary therefore needs one spare power.
    let max_attributes_per_commitment = record_member_count
        .checked_add(1)
        .expect("fixed record width fits u32");
    let (set_srs, set_srs_trapdoor) =
        SetCommitmentSRS::<Bls12_377>::generate_with_random_trapdoor::<OsRng, Blake2b512>(
            &mut rng,
            max_attributes_per_commitment,
            Some(b"plan-a-fixed-policy-v2"),
        );
    assert!(set_srs.P1.len() >= max_attributes_per_commitment as usize);
    assert!(set_srs.P2.len() >= max_attributes_per_commitment as usize);
    let issuer_sk = RootIssuerSecretKey::<Bls12_377>::new(&mut rng, L_MAX as u32).unwrap();
    let issuer_pk = RootIssuerPublicKey::new(&issuer_sk, set_srs.get_P1(), set_srs.get_P2());
    let issuer_sk_alt = RootIssuerSecretKey::<Bls12_377>::new(&mut rng, L_MAX as u32).unwrap();
    let issuer_pk_alt =
        RootIssuerPublicKey::new(&issuer_sk_alt, set_srs.get_P1(), set_srs.get_P2());
    let delegate_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let delegate_pk = UserPublicKey::new(&delegate_sk, set_srs.get_P1());
    let delegate_b_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let delegate_b_pk = UserPublicKey::new(&delegate_b_sk, set_srs.get_P1());
    let delegate_alt_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let delegate_alt_pk = UserPublicKey::new(&delegate_alt_sk, set_srs.get_P1());
    let terminal_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let terminal_pk = UserPublicKey::new(&terminal_sk, set_srs.get_P1());
    let registry_sk = UserSecretKey::<Bls12_377>::new(&mut rng);
    let registry_pk = UserPublicKey::new(&registry_sk, set_srs.get_P1());

    let (credential, update_key) = Credential::issue_root(
        &mut rng,
        vec![encode_record(&root_record, 0)],
        &delegate_pk,
        Some((L_MAX - 1) as u32),
        &issuer_sk,
        max_attributes_per_commitment,
        &set_srs,
    )
    .unwrap();
    let (mut credential_prefix, third_update) = credential
        .delegate_with_new_attributes(
            &mut rng,
            encode_record(&terminal_record, 1),
            &delegate_sk,
            &issuer_pk.X_0,
            Some(2),
            &update_key.unwrap(),
            &set_srs,
        )
        .unwrap();
    credential_prefix.convert_orphan_signature(&terminal_sk,&issuer_pk.X_0);
    let third_update=third_update.unwrap();
    let (mut credential, _) = credential_prefix.clone().delegate_with_new_attributes(&mut rng,encode_record(&third_record,2),&terminal_sk,&issuer_pk.X_0,None,&third_update,&set_srs).unwrap();
    credential.convert_orphan_signature(&terminal_sk, &issuer_pk.X_0);
    credential
        .verify(
            None,
            &terminal_pk,
            PreparedRootIssuerPublicKey::from(issuer_pk.clone()),
            &set_srs,
        )
        .unwrap();
    let (mut credential_b, _) = credential_prefix.delegate_with_new_attributes(&mut rng,encode_record(&third_record_b,2),&terminal_sk,&issuer_pk.X_0,None,&third_update,&set_srs).unwrap();
    credential_b.convert_orphan_signature(&terminal_sk, &issuer_pk.X_0);
    credential_b
        .verify(
            None,
            &terminal_pk,
            PreparedRootIssuerPublicKey::from(issuer_pk.clone()),
            &set_srs,
        )
        .unwrap();
    let (credential_c, update_key_c) = Credential::issue_root(
        &mut rng,
        vec![encode_record(&root_record_c, 0)],
        &terminal_pk,
        Some((L_MAX - 1) as u32),
        &issuer_sk,
        max_attributes_per_commitment,
        &set_srs,
    )
    .unwrap();
    let (mut credential_c, third_update_c) = credential_c
        .delegate_with_new_attributes(
            &mut rng,
            encode_record(&padding_record_c, 1),
            &terminal_sk,
            &issuer_pk.X_0,
            Some(2),
            &update_key_c.unwrap(),
            &set_srs,
        )
        .unwrap();
    credential_c.convert_orphan_signature(&terminal_sk,&issuer_pk.X_0);
    let (mut credential_c, _) = credential_c.delegate_with_new_attributes(&mut rng,encode_record(&third_record_c,2),&terminal_sk,&issuer_pk.X_0,None,&third_update_c.unwrap(),&set_srs).unwrap();
    credential_c.convert_orphan_signature(&terminal_sk, &issuer_pk.X_0);
    credential_c
        .verify(
            None,
            &terminal_pk,
            PreparedRootIssuerPublicKey::from(issuer_pk.clone()),
            &set_srs,
        )
        .unwrap();
    let (credential_d, update_key_d) = Credential::issue_root(
        &mut rng,
        vec![encode_record(&root_record_d, 0)],
        &delegate_alt_pk,
        Some((L_MAX - 1) as u32),
        &issuer_sk_alt,
        max_attributes_per_commitment,
        &set_srs,
    )
    .unwrap();
    let (mut credential_d, third_update_d) = credential_d
        .delegate_with_new_attributes(
            &mut rng,
            encode_record(&terminal_record_d, 1),
            &delegate_alt_sk,
            &issuer_pk_alt.X_0,
            Some(2),
            &update_key_d.unwrap(),
            &set_srs,
        )
        .unwrap();
    credential_d.convert_orphan_signature(&terminal_sk,&issuer_pk_alt.X_0);
    let (mut credential_d, _) = credential_d.delegate_with_new_attributes(&mut rng,encode_record(&third_record_d,2),&terminal_sk,&issuer_pk_alt.X_0,None,&third_update_d.unwrap(),&set_srs).unwrap();
    credential_d.convert_orphan_signature(&terminal_sk, &issuer_pk_alt.X_0);
    credential_d
        .verify(
            None,
            &terminal_pk,
            PreparedRootIssuerPublicKey::from(issuer_pk_alt.clone()),
            &set_srs,
        )
        .unwrap();

    let accumulator_params = SetupParams::<Bls12_377>::generate_using_rng(&mut rng);
    let accumulator_keys = Keypair::<Bls12_377>::generate_using_rng(&mut rng, &accumulator_params);
    let mut initial_store = InitialStore::default();
    let accumulator = UniversalAccumulator::<G1Affine>::initialize_with_all_random(
        &mut rng,
        &accumulator_params,
        64,
        &accumulator_keys.secret_key,
        &mut initial_store,
    );
    let mut accumulator_state = AccumulatorState::default();
    let accumulator = accumulator
        .add(
            Fr::from(0xdead_beefu64),
            &accumulator_keys.secret_key,
            &initial_store,
            &mut accumulator_state,
        )
        .unwrap();
    let serial0 = serial_scalar(serial0_lo, serial0_hi);
    let serial1 = serial_scalar(serial1_lo, serial1_hi);
    let nm0 = accumulator
        .get_non_membership_witness(
            &serial0,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();
    let nm1 = accumulator
        .get_non_membership_witness(
            &serial1,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();
    let serial_b0 = serial_scalar(serial_b0_lo, serial_b0_hi);
    let serial_b1 = serial_scalar(serial_b1_lo, serial_b1_hi);
    let nm_b0 = accumulator
        .get_non_membership_witness(
            &serial_b0,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();
    let nm_b1 = accumulator
        .get_non_membership_witness(
            &serial_b1,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();
    let serial_c0 = serial_scalar(serial_c0_lo, serial_c0_hi);
    let nm_c0 = accumulator
        .get_non_membership_witness(
            &serial_c0,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();
    let serial_d0 = serial_scalar(serial_d0_lo, serial_d0_hi);
    let serial_d1 = serial_scalar(serial_d1_lo, serial_d1_hi);
    let nm_d0 = accumulator
        .get_non_membership_witness(
            &serial_d0,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();
    let nm_d1 = accumulator
        .get_non_membership_witness(
            &serial_d1,
            &accumulator_keys.secret_key,
            &accumulator_state,
            &accumulator_params,
        )
        .unwrap();

    let nm2 = accumulator.get_non_membership_witness(&serial_scalar(third_record.serial_lo,third_record.serial_hi),&accumulator_keys.secret_key,&accumulator_state,&accumulator_params).unwrap();
    let entitlement = DacEntitlementWitness {
        logical_owner: OWNER,
        registration_salt_lo,
        registration_salt_hi,
        resource: RESOURCE,
        action_mask: READ | 2,
        interval_lo: 0,
        interval_hi: 100,
        permit_expiry: 100,
        admission_id_lo: 44,
        admission_id_hi: 0,
        position: 2,
        path: sparse_path(2, RA_DEPTH),
    };
    let root_grant_leaf_a = root_grant_leaf(&root_record, &credential.commitments[0]);
    let root_grant_leaf_b = root_grant_leaf(&root_record_b, &credential_b.commitments[0]);
    let mut root_commitment_a=Vec::new(); credential.commitments[0].serialize_compressed(&mut root_commitment_a).unwrap();
    let mut root_commitment_b=Vec::new(); credential_b.commitments[0].serialize_compressed(&mut root_commitment_b).unwrap();
    assert_eq!(root_commitment_a, root_commitment_b, "actual2/3 must share one native root-b commitment");
    assert_eq!(root_grant_leaf_a, root_grant_leaf_b, "actual2/3 must share one root-b leaf");
    let root_grant_leaf_c = root_grant_leaf(&root_record_c, &credential_c.commitments[0]);
    let grant_leaves = vec![root_grant_leaf_a, root_grant_leaf_c];
    let (grant_root, root_grant_path) = tree_root_and_path(grant_leaves.clone(), GRANT_DEPTH, 0);
    let (grant_root_b, root_grant_path_b) =
        tree_root_and_path(grant_leaves.clone(), GRANT_DEPTH, 0);
    let (grant_root_c, root_grant_path_c) = tree_root_and_path(grant_leaves, GRANT_DEPTH, 1);
    assert_eq!(grant_root, grant_root_b);
    assert_eq!(grant_root, grant_root_c);
    let state = DacStateWitness {
        logical_owner: OWNER,
        owner_commitment: owner_commitment(
            OWNER,
            MAPPING_VERSION,
            registration_salt_lo,
            registration_salt_hi,
            &issuer_pk,
        ),
        grant_root,
        root_grant_position: 0,
        root_grant_path,
        state_version: 0,
        state_epoch: 55,
        state_expiry: 90,
        active: true,
        salt_lo: state_salt_lo,
        salt_hi: state_salt_hi,
        position: 3,
        path: sparse_path(3, STATE_DEPTH),
    };
    let deployment_id = Fq::from(DEPLOYMENT_ID);
    let ra_root = merkle_root(
        entitlement_leaf(
            deployment_id,
            MAPPING_VERSION,
            SCHEMA_VERSION,
            POLICY_VERSION,
            &issuer_pk,
            &entitlement,
        ),
        &entitlement.path,
    )
    .unwrap();
    let state_root = merkle_root(
        state_leaf(
            deployment_id,
            MAPPING_VERSION,
            SCHEMA_VERSION,
            POLICY_VERSION,
            &state,
        ),
        &state.path,
    )
    .unwrap();
    let entitlement_alt = DacEntitlementWitness {
        logical_owner: OWNER_ALT,
        registration_salt_lo: registration_salt_alt_lo,
        registration_salt_hi: registration_salt_alt_hi,
        resource: RESOURCE,
        action_mask: READ | 2,
        interval_lo: 0,
        interval_hi: 100,
        permit_expiry: 100,
        admission_id_lo: 45,
        admission_id_hi: 0,
        position: 4,
        path: sparse_path(4, RA_DEPTH),
    };
    let root_grant_leaf_d = root_grant_leaf(&root_record_d, &credential_d.commitments[0]);
    let (grant_root_alt, root_grant_path_alt) =
        tree_root_and_path(vec![root_grant_leaf_d], GRANT_DEPTH, 0);
    let state_alt = DacStateWitness {
        logical_owner: OWNER_ALT,
        owner_commitment: owner_commitment(
            OWNER_ALT,
            MAPPING_VERSION,
            registration_salt_alt_lo,
            registration_salt_alt_hi,
            &issuer_pk_alt,
        ),
        grant_root: grant_root_alt,
        root_grant_position: 0,
        root_grant_path: root_grant_path_alt,
        state_version: 0,
        state_epoch: 55,
        state_expiry: 90,
        active: true,
        salt_lo: state_salt_alt_lo,
        salt_hi: state_salt_alt_hi,
        position: 5,
        path: sparse_path(5, STATE_DEPTH),
    };
    let ra_root_alt = merkle_root(
        entitlement_leaf(
            deployment_id,
            MAPPING_VERSION,
            SCHEMA_VERSION,
            POLICY_VERSION,
            &issuer_pk_alt,
            &entitlement_alt,
        ),
        &entitlement_alt.path,
    )
    .unwrap();
    let state_root_alt = merkle_root(
        state_leaf(
            deployment_id,
            MAPPING_VERSION,
            SCHEMA_VERSION,
            POLICY_VERSION,
            &state_alt,
        ),
        &state_alt.path,
    )
    .unwrap();

    let deployment = FixedPolicyDeployment {
        relation_version: RELATION_VERSION,
        l_max: L_MAX,
        ra_depth: RA_DEPTH,
        state_depth: STATE_DEPTH,
        grant_depth: GRANT_DEPTH,
        p1: *set_srs.get_P1(),
        p2: *set_srs.get_P2(),
        s_p2: *set_srs.get_s_P2(),
        accumulator_p: accumulator_params.P,
        accumulator_p_tilde: accumulator_params.P_tilde,
        accumulator_pk: accumulator_keys.public_key.clone(),
    };
    let mut statement = FixedPolicyStatement {
        deployment_id,
        tuple_version: 1,
        ra_root,
        state_root,
        state_epoch: 55,
        revocation_epoch: 9,
        issued_at: 1_792_700_000,
        mapping_version: MAPPING_VERSION,
        header_digest: Fq::from(0u64),
        canonical_request_lo: [0x0102_0304_0506_0708, 0x1112_1314_1516_1718],
        canonical_request_hi: [0x2122_2324_2526_2728, 0x3132_3334_3536_3738],
        circuit_id: Fq::from(0x4349_5243_5549_5403u64),
        verifier_id: Fq::from(0x5645_5249_4649_4552u64),
        pep_id: Fq::from(0x5045_5003u64),
        nonce: Fq::from(manifest.request.nonce_u64),
        context: Fq::from(0x434f_4e54_4558_5403u64),
        request_digest: Fq::from(0u64),
        terminal: TERMINAL,
        terminal_key: terminal_pk.0,
        resource: RESOURCE,
        one_hot_action: READ,
        request_lo: 40,
        request_hi: 60,
        now: 50,
        policy_version: POLICY_VERSION,
        schema_version: SCHEMA_VERSION,
        accumulator_value: *accumulator.value(),
    };
    statement.header_digest = compute_header_digest(&statement);
    statement.request_digest = compute_request_digest(&statement);
    let mut witness = FixedPolicyWitness {
        issuer_pk: issuer_pk.clone(),
        entitlement: entitlement.clone(),
        state: state.clone(),
        slots: vec![
            FixedPolicySlotWitness {
                record: root_record.clone(),
                commitment: credential.commitments[0].clone(),
                exact_opening_quotients: field_witnesses(&credential, 0, &set_srs),
                opening_randomness: opening_randomness(&credential, 0),
                non_membership_witness: nm0,
            },
            FixedPolicySlotWitness {
                record: terminal_record.clone(),
                commitment: credential.commitments[1].clone(),
                exact_opening_quotients: field_witnesses(&credential, 1, &set_srs),
                opening_randomness: opening_randomness(&credential, 1),
                non_membership_witness: nm1,
            },
        ],
        signature: credential.signature.clone(),
    };
    witness.slots.push(FixedPolicySlotWitness{record:third_record,commitment:credential.commitments[2].clone(),exact_opening_quotients:field_witnesses(&credential,2,&set_srs),opening_randomness:opening_randomness(&credential,2),non_membership_witness:nm2});
    let circuit = FixedPolicyCircuit {
        deployment: deployment.clone(),
        statement: statement.clone(),
        witness,
    };
    let mut state_b = state;
    state_b.root_grant_position = 0;
    state_b.root_grant_path = root_grant_path_b;
    let mut witness_b = FixedPolicyWitness {
        issuer_pk: issuer_pk.clone(),
        entitlement,
        state: state_b,
        slots: vec![
            FixedPolicySlotWitness {
                record: root_record_b.clone(),
                commitment: credential_b.commitments[0].clone(),
                exact_opening_quotients: field_witnesses(&credential_b, 0, &set_srs),
                opening_randomness: opening_randomness(&credential_b, 0),
                non_membership_witness: nm_b0,
            },
            FixedPolicySlotWitness {
                record: terminal_record_b.clone(),
                commitment: credential_b.commitments[1].clone(),
                exact_opening_quotients: field_witnesses(&credential_b, 1, &set_srs),
                opening_randomness: opening_randomness(&credential_b, 1),
                non_membership_witness: nm_b1.clone(),
            },
        ],
        signature: credential_b.signature.clone(),
    };
    witness_b.slots.push(FixedPolicySlotWitness{record:third_record_b,commitment:credential_b.commitments[2].clone(),exact_opening_quotients:field_witnesses(&credential_b,2,&set_srs),opening_randomness:opening_randomness(&credential_b,2),non_membership_witness:nm_b1});
    let circuit_b = FixedPolicyCircuit {
        deployment: deployment.clone(),
        statement: statement.clone(),
        witness: witness_b,
    };
    let mut state_c = circuit_b.witness.state.clone();
    state_c.root_grant_position = 1;
    state_c.root_grant_path = root_grant_path_c;
    let mut witness_c = FixedPolicyWitness {
        issuer_pk: issuer_pk.clone(),
        entitlement: circuit.witness.entitlement.clone(),
        state: state_c,
        slots: vec![
            FixedPolicySlotWitness {
                record: root_record_c,
                commitment: credential_c.commitments[0].clone(),
                exact_opening_quotients: field_witnesses(&credential_c, 0, &set_srs),
                opening_randomness: opening_randomness(&credential_c, 0),
                non_membership_witness: nm_c0.clone(),
            },
            FixedPolicySlotWitness {
                record: padding_record_c,
                commitment: credential_c.commitments[1].clone(),
                exact_opening_quotients: field_witnesses(&credential_c, 1, &set_srs),
                opening_randomness: opening_randomness(&credential_c, 1),
                non_membership_witness: nm_c0.clone(),
            },
        ],
        signature: credential_c.signature.clone(),
    };
    witness_c.slots.push(FixedPolicySlotWitness{record:third_record_c,commitment:credential_c.commitments[2].clone(),exact_opening_quotients:field_witnesses(&credential_c,2,&set_srs),opening_randomness:opening_randomness(&credential_c,2),non_membership_witness:nm_c0});
    let circuit_c = FixedPolicyCircuit {
        deployment: deployment.clone(),
        statement: statement.clone(),
        witness: witness_c,
    };
    let mut statement_d = statement.clone();
    statement_d.ra_root = ra_root_alt;
    statement_d.state_root = state_root_alt;
    statement_d.header_digest = compute_header_digest(&statement_d);
    statement_d.request_digest = compute_request_digest(&statement_d);
    let mut circuit_d = FixedPolicyCircuit {
        deployment: deployment.clone(),
        statement: statement_d,
        witness: FixedPolicyWitness {
            issuer_pk: issuer_pk_alt,
            entitlement: entitlement_alt,
            state: state_alt,
            slots: vec![
                FixedPolicySlotWitness {
                    record: root_record_d,
                    commitment: credential_d.commitments[0].clone(),
                    exact_opening_quotients: field_witnesses(&credential_d, 0, &set_srs),
                    opening_randomness: opening_randomness(&credential_d, 0),
                    non_membership_witness: nm_d0,
                },
                FixedPolicySlotWitness {
                    record: terminal_record_d,
                    commitment: credential_d.commitments[1].clone(),
                    exact_opening_quotients: field_witnesses(&credential_d, 1, &set_srs),
                    opening_randomness: opening_randomness(&credential_d, 1),
                    non_membership_witness: nm_d1.clone(),
                },
            ],
            signature: credential_d.signature.clone(),
        },
    };

    circuit_d.witness.slots.push(FixedPolicySlotWitness{record:third_record_d,commitment:credential_d.commitments[2].clone(),exact_opening_quotients:field_witnesses(&credential_d,2,&set_srs),opening_randomness:opening_randomness(&credential_d,2),non_membership_witness:nm_d1});
    if std::env::var("R5_COUNT_ONLY").as_deref()==Ok("1") {
        let cs=ConstraintSystem::<Fq>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("R5 isolated synthesis");
        assert!(cs.is_satisfied().expect("R5 satisfaction check"));
        println!("{}",serde_json::json!({"phase":"r5_count_only","constraints":cs.num_constraints(),"satisfied":true,"setup_or_proof_executed":false}));
        return;
    }
    if std::env::var("MATCHED_PROJECTION_ONLY").as_deref()==Ok("1") {
        let mut c3=Vec::new(); credential.commitments[0].serialize_compressed(&mut c3).unwrap();
        let mut c2=Vec::new(); credential_b.commitments[0].serialize_compressed(&mut c2).unwrap();
        let mut child3=Vec::new(); credential.commitments[1].serialize_compressed(&mut child3).unwrap();
        let mut child2=Vec::new(); credential_b.commitments[1].serialize_compressed(&mut child2).unwrap();
        println!("{}",serde_json::json!({"phase":"matched_dac_projection_gate","semantic_input_sha256":manifest_sha256(&manifest),"root_b_commitment_actual3_blake2s":blake2s_hex(&c3),"root_b_commitment_actual2_blake2s":blake2s_hex(&c2),"child_b_commitment_actual3_blake2s":blake2s_hex(&child3),"child_b_commitment_actual2_blake2s":blake2s_hex(&child2),"same_native_root_b_commitment":c3==c2,"same_native_child_b_commitment":child3==child2,"same_root_b_leaf":root_grant_leaf_a==root_grant_leaf_b,"same_root_b_membership_position":circuit.witness.state.root_grant_position==circuit_b.witness.state.root_grant_position,"root_b_position":circuit.witness.state.root_grant_position,"root_c_position":circuit_c.witness.state.root_grant_position,"native_credentials_verified":true,"actual3_prefix_records_equal_actual2":[encode_record(&circuit.witness.slots[0].record,0)==encode_record(&circuit_b.witness.slots[0].record,0),encode_record(&circuit.witness.slots[1].record,1)==encode_record(&circuit_b.witness.slots[1].record,1)]}));
        return;
    }
    if std::env::var("MATCHED_WITHDRAWAL_GATE").as_deref()==Ok("1") {
        let (withdrawn_root,withdrawn_root_c_path)=tree_root_and_path(vec![Fq::from(0u64),root_grant_leaf_c],GRANT_DEPTH,1);
        let mut survivor=circuit_c.clone();
        survivor.witness.state.grant_root=withdrawn_root;
        survivor.witness.state.root_grant_path=withdrawn_root_c_path;
        survivor.statement.state_root=merkle_root(state_leaf(Fq::from(DEPLOYMENT_ID),MAPPING_VERSION,SCHEMA_VERSION,POLICY_VERSION,&survivor.witness.state),&survivor.witness.state.path).unwrap();
        survivor.statement.header_digest=compute_header_digest(&survivor.statement);
        survivor.statement.request_digest=compute_request_digest(&survivor.statement);
        let survivor_audit=assert_positive_synthesis(&survivor);
        let mut withdrawn2=circuit_b.clone(); withdrawn2.statement=survivor.statement.clone();
        let mut withdrawn3=circuit.clone(); withdrawn3.statement=survivor.statement.clone();
        let len2_rejected=relation_rejects(withdrawn2); let len3_rejected=relation_rejects(withdrawn3);
        assert!(len2_rejected && len3_rejected);
        println!("{}",serde_json::json!({"phase":"matched_dac_root_b_withdrawal_gate","semantic_input_sha256":manifest_sha256(&manifest),"root_b_withdrawn":true,"length2_rejected":len2_rejected,"length3_rejected":len3_rejected,"root_c_length1_survives":true,"survivor_audit":survivor_audit,"setup_or_proof_executed":false}));
        return;
    }
    if std::env::var("MATCHED_PREFLIGHT").as_deref()==Ok("1") {
        let audits=[assert_positive_synthesis(&circuit),assert_positive_synthesis(&circuit_b),assert_positive_synthesis(&circuit_c)];
        assert!(audits.iter().all(|a|a.canonical_matrix_blake2s==audits[0].canonical_matrix_blake2s));
        assert_eq!(public_inputs(&circuit.statement,RELATION_VERSION),public_inputs(&circuit_b.statement,RELATION_VERSION));
        assert_eq!(public_inputs(&circuit.statement,RELATION_VERSION),public_inputs(&circuit_c.statement,RELATION_VERSION));
        println!("{}",serde_json::json!({"phase":"matched_dac_preflight","semantic_input_sha256":manifest_sha256(&manifest),"all_three_satisfied":true,"canonical_matrix_equal_same_key":true,"public_statement_equal_all_lengths":true,"native_credentials_verified":true,"audits":audits}));
        return;
    }
    let pilot_start=Instant::now();
    let out=std::env::args().nth(1).expect("output directory");
    let setup_start=Instant::now();
    let (pk,vk)=Groth16::<BW6_761>::setup(circuit.clone(),&mut rng).expect("fresh setup");
    let setup_ms=elapsed_ms(setup_start); eprintln!("setup completed in {setup_ms} ms");
    let mut proof_rows=Vec::new(); let mut full3_ms=0.0;
    let order=std::env::var("MATCHED_LENGTH_ORDER").unwrap_or_else(|_|"3,2,1".into()).split(',').map(|x|x.parse::<u64>().expect("length order integer")).collect::<Vec<_>>();
    assert_eq!(order.iter().copied().collect::<BTreeSet<_>>(),[1u64,2,3].into_iter().collect());
    for active in order { let c=match active {3=>circuit.clone(),2=>circuit_b.clone(),1=>circuit_c.clone(),_=>unreachable!()};
        let inputs=public_inputs(&c.statement,RELATION_VERSION);
        let started=Instant::now();let proof=Groth16::<BW6_761>::prove(&pk,c,&mut rng).expect("prove");let prove_ms=elapsed_ms(started);if active==3{full3_ms=prove_ms;}
        let started=Instant::now();assert!(Groth16::<BW6_761>::verify(&vk,&inputs,&proof).expect("verify"));let verify_ms=elapsed_ms(started);
        let mut bad=inputs.clone();bad[0]+=Fq::from(1u64);assert!(!Groth16::<BW6_761>::verify(&vk,&bad,&proof).expect("negative verify"));
        let mut bytes=Vec::new();proof.serialize_compressed(&mut bytes).unwrap();std::fs::write(format!("{out}/proof-active{active}.bin"),&bytes).unwrap();
        let mut public=Vec::new();inputs.serialize_compressed(&mut public).unwrap();std::fs::write(format!("{out}/public-active{active}.bin"),public).unwrap();
        let row=serde_json::json!({"active":active,"prove_ms":prove_ms,"verify_ms":verify_ms,"verified":true,"mutated_public_rejected":true,"proof_bytes":bytes.len(),"proof_blake2s":blake2s_hex(&bytes),"peak_rss_kib":peak_rss_kib()});eprintln!("proof completed: {row}");proof_rows.push(row);
    }
    let started=Instant::now();let file=std::fs::File::create(format!("{out}/pk.bin")).unwrap();pk.serialize_compressed(std::io::BufWriter::new(file)).unwrap();let mut vkb=Vec::new();vk.serialize_compressed(&mut vkb).unwrap();std::fs::write(format!("{out}/vk.bin"),vkb).unwrap();let serialization_ms=elapsed_ms(started);
    println!("{}",serde_json::json!({"phase":"main_profile_matched_formal","formal":true,"matched_performance_trial":true,"shared_host":true,"semantic_input_sha256":manifest_sha256(&manifest),"l_max":L_MAX,"ra_depth":RA_DEPTH,"state_depth":STATE_DEPTH,"grant_depth":GRANT_DEPTH,"revocation_backend":"hidden serial universal accumulator","setup_ms":setup_ms,"setup_os_rng":true,"proofs":proof_rows,"pk_bytes":std::fs::metadata(format!("{out}/pk.bin")).unwrap().len(),"key_serialization_ms":serialization_ms,"total_after_fixture_ms":elapsed_ms(pilot_start),"peak_rss_kib":peak_rss_kib(),"full_13_case_lifecycle_not_run":true,"third_slot":"enabled terminal self-delegation with depth decrement; not a distinct intermediate"}));
}
fn peak_rss_kib()->u64{std::fs::read_to_string("/proc/self/status").unwrap().lines().find(|l|l.starts_with("VmHWM:")).and_then(|l|l.split_whitespace().nth(1)).unwrap().parse().unwrap()}
