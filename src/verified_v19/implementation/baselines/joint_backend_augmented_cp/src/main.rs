use accumulator::group::{ElemToBytes, Rsa2048};
use ark_bls12_381_current::{Bls12_381, Fr};
use ark_ec_current::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::Fr as MappingScalar;
use ark_ff_current::Zero;
use ark_groth16_current::Groth16;
use ark_relations_current::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize_current::CanonicalSerialize;
use ark_serialize_old::CanonicalSerialize as OldCanonicalSerialize;
use ark_snark_current::{CircuitSpecificSetupSNARK, SNARK};
use cpsnarks_set::protocols::hrada_membership::CpProof;
use joint_backend_augmented_cp::{
    binding_context, prime_integer, prove as prove_cp, setup as setup_cp, validate_bridge,
    verify as verify_cp, verify_with_inputs as verify_cp_inputs, CpLinkedProof, CpStateLifecycle,
};
use joint_backend_matched::{
    augmented_core_public_inputs, augmented_membership_public_inputs,
    certified_map::{generate_prime_252, CertifiedStateMap, MappingError, MappingRecord},
    inline_augmented_from_joint, prove_augmented, setup_augmented, state_leaf, verify_augmented,
    verify_augmented_with_inputs,
};
use plan_a_joint_circuit::signature::PublicKey;
use plan_a_joint_circuit::{
    fixture::fixed,
    joint::JointCircuit,
    merkle::{node_hash, MerklePath},
    poseidon::Domain,
    signature::{encode_signature, SecretKey},
};
use rand_current::rngs::OsRng;
use rug::{integer::Order, Integer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf, time::Instant};

fn milliseconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

fn require(condition: bool, label: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("gate failed: {label}"))
    }
}

#[derive(Clone, Copy)]
enum Backend {
    Inline,
    PoseidonSplit,
    CpRsaSplit,
}

impl Backend {
    fn label(self) -> &'static str {
        match self {
            Self::Inline => "inline",
            Self::PoseidonSplit => "poseidon_split",
            Self::CpRsaSplit => "cp_rsa_split",
        }
    }
}

// Six-period schedule: every backend occupies every position twice in each
// complete cycle. Formal timing uses two cycles (12 fresh setups).
fn backend_order(repetition: usize) -> [Backend; 3] {
    use Backend::{CpRsaSplit as C, Inline as I, PoseidonSplit as P};
    match repetition % 6 {
        0 => [I, P, C],
        1 => [I, C, P],
        2 => [P, I, C],
        3 => [P, C, I],
        4 => [C, I, P],
        _ => [C, P, I],
    }
}

fn encoded<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn bridge_parameter_bytes(
    parameters: &joint_backend_augmented_cp::CpLinkedParameters,
) -> Result<Vec<u8>, String> {
    let mut output = b"plan-a/e8/cp-current-bridge/v1".to_vec();
    for point in [parameters.commitment_g, parameters.commitment_h] {
        let bytes = encoded(&point)?;
        output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        output.extend(bytes);
    }
    let link_g1 = encoded(&parameters.core.vk.link_pp.g1)?;
    output.extend_from_slice(&(link_g1.len() as u32).to_le_bytes());
    output.extend(link_g1);
    let link_g2 = encoded(&parameters.core.vk.link_pp.g2)?;
    output.extend_from_slice(&(link_g2.len() as u32).to_le_bytes());
    output.extend(link_g2);
    Ok(output)
}

fn mapping_certificate_bytes(
    certificate: &joint_backend_matched::certified_map::MappingCertificate,
) -> Vec<u8> {
    let record = &certificate.record;
    let mut bytes = b"plan-a/e8/mapping-certificate/v1".to_vec();
    for field in [
        record.deployment_id,
        record.owner_commitment,
        record.state_leaf,
    ] {
        bytes.extend(plan_a_joint_circuit::poseidon::canonical_le_bytes(field));
    }
    bytes.extend(record.position.to_le_bytes());
    bytes.extend(record.state_version.to_le_bytes());
    bytes.extend(record.state_epoch.to_le_bytes());
    bytes.extend(plan_a_joint_circuit::poseidon::canonical_le_bytes(
        record.prime,
    ));
    bytes.extend(record.mapping_version.to_le_bytes());
    bytes.extend(encode_signature(&certificate.signature));
    bytes
}

fn old_encoded<T: OldCanonicalSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .serialize(&mut bytes)
        .map_err(|error| format!("{error:?}"))?;
    Ok(bytes)
}

// Measured component encoding used by the retained CP baseline. It is an
// experiment bundle encoding, not a claim about a production wire format.
fn cp_proof_components(proof: &CpProof) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut put = |bytes: Vec<u8>| {
        output.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        output.extend(bytes);
    };
    for element in [
        &proof.c_e,
        &proof.proof_root.message1.c_w,
        &proof.proof_root.message1.c_r,
        &proof.proof_root.message2.alpha1,
        &proof.proof_root.message2.alpha2,
        &proof.proof_root.message2.alpha3,
        &proof.proof_root.message2.alpha4,
        &proof.proof_modeq.message1.alpha1,
    ] {
        put(Rsa2048::elem_to_bytes(element));
    }
    let root = &proof.proof_root.message3;
    let modeq = &proof.proof_modeq.message2;
    for integer in [
        &root.s_e,
        &root.s_r,
        &root.s_r_2,
        &root.s_r_3,
        &root.s_beta,
        &root.s_delta,
        &modeq.s_e,
        &modeq.s_r,
    ] {
        let mut bytes = vec![if integer < &Integer::from(0) { 1 } else { 0 }];
        bytes.extend((*integer).clone().abs().to_digits::<u8>(Order::MsfBe));
        put(bytes);
    }
    put(old_encoded(&proof.proof_modeq.message1.alpha2)?);
    put(old_encoded(&modeq.s_r_q)?);
    put(old_encoded(&proof.proof_hash_to_prime)?);
    Ok(output)
}

fn relation_metrics<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<Value, String> {
    let cs = ConstraintSystem::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|error| format!("{error:?}"))?;
    require(
        cs.is_satisfied().map_err(|error| error.to_string())?,
        "satisfied relation",
    )?;
    cs.finalize();
    let matrices = cs.to_matrices().ok_or("missing matrices")?;
    Ok(json!({
        "constraints": matrices.num_constraints,
        "instances": matrices.num_instance_variables,
        "witnesses": matrices.num_witness_variables,
        "a_nnz": matrices.a_num_non_zero,
        "b_nnz": matrices.b_num_non_zero,
        "c_nnz": matrices.c_num_non_zero,
    }))
}

fn sparse_state_path(leaf: Fr, mut position: u32, depth: usize) -> (Fr, MerklePath) {
    let mut defaults = vec![Fr::zero()];
    for level in 0..depth {
        defaults.push(node_hash(
            Domain::TreeNode,
            defaults[level],
            defaults[level],
        ));
    }
    let mut current = leaf;
    let mut siblings = Vec::with_capacity(depth);
    let mut directions = Vec::with_capacity(depth);
    for level in 0..depth {
        let right = position & 1 == 1;
        siblings.push(defaults[level]);
        directions.push(right);
        current = if right {
            node_hash(Domain::TreeNode, defaults[level], current)
        } else {
            node_hash(Domain::TreeNode, current, defaults[level])
        };
        position >>= 1;
    }
    (
        current,
        MerklePath {
            siblings,
            directions,
        },
    )
}

fn successor<const L: usize>(current: &JointCircuit<L>) -> JointCircuit<L> {
    let mut next = current.clone();
    next.state.state_version += 1;
    next.state.state_epoch += 1;
    next.snapshot.state_epoch = next.state.state_epoch;
    next.snapshot.issued_at += 1;
    let leaf = state_leaf(&next.state);
    let (root, path) = sparse_state_path(leaf, next.state.position, next.state.path.siblings.len());
    next.state.path = path;
    next.snapshot.root_state = root;
    next
}

fn mapping_template<const L: usize>(joint: &JointCircuit<L>) -> MappingRecord {
    MappingRecord {
        deployment_id: Fr::from(0x4538_0001u64),
        owner_commitment: joint.state.owner_commitment,
        state_leaf: state_leaf(&joint.state),
        position: joint.state.position,
        state_version: joint.state.state_version,
        state_epoch: joint.state.state_epoch,
        prime: Fr::zero(),
        mapping_version: 1,
    }
}

fn initial_state(
    fixture: &JointCircuit<3>,
    repetition: usize,
) -> Result<
    (
        CertifiedStateMap,
        Vec<joint_backend_matched::certified_map::MappingCertificate>,
        CpStateLifecycle,
    ),
    String,
> {
    let mut map = CertifiedStateMap::new(SecretKey(MappingScalar::from(
        0x4538u64 + repetition as u64,
    )))
    .map_err(|error| error.to_string())?;
    let target = map
        .generate_and_issue(
            mapping_template(fixture),
            [11u8.wrapping_add(repetition as u8); 32],
            [12u8.wrapping_add(repetition as u8); 32],
        )
        .map_err(|error| error.to_string())?;
    let mut certificates = vec![target];
    for index in 1..8u32 {
        let template = MappingRecord {
            deployment_id: Fr::from(0x4538_0001u64),
            owner_commitment: Fr::from(10_000u64 + index as u64),
            state_leaf: Fr::from(20_000u64 + index as u64),
            position: index,
            state_version: 0,
            state_epoch: fixture.state.state_epoch,
            prime: Fr::zero(),
            mapping_version: 1,
        };
        certificates.push(
            map.generate_and_issue(
                template,
                [31u8.wrapping_add(index as u8); 32],
                [63u8.wrapping_add(index as u8); 32],
            )
            .map_err(|error| error.to_string())?,
        );
    }
    let primes = certificates
        .iter()
        .map(|certificate| prime_integer(certificate.record.prime))
        .collect();
    let lifecycle = CpStateLifecycle::new(primes)?;
    Ok((map, certificates, lifecycle))
}

fn run_repetition(repetition: usize, output: &PathBuf) -> Result<Value, String> {
    let fixture = fixed::<3>(3, 1000 + repetition as u64, 20, 20, 32);
    let started = Instant::now();
    let (mut map, certificates, mut cp_state) = initial_state(&fixture, repetition)?;
    let initial_mapping_and_accumulator_ms = milliseconds(started);
    let mapping = certificates[0].clone();
    let mapping_pk: PublicKey = map.public_key.clone();
    require(map.is_live(&mapping), "initial mapping is live")?;
    require(
        cp_state.contains(mapping.record.prime),
        "initial CP member admitted",
    )?;

    let (augmented_core, augmented_member) =
        joint_backend_matched::split_augmented_from_joint(&fixture, &mapping, &mapping_pk);
    let relation = json!({
        "augmented_inline": relation_metrics(inline_augmented_from_joint(&fixture, &mapping, &mapping_pk))?,
        "augmented_core": relation_metrics(augmented_core)?,
        "poseidon_membership": relation_metrics(augmented_member)?,
        "cp_membership": "native CP-RSA proof; constraints live in retained legacy setup and are measured through its proof/setup artifacts",
    });

    let mut rng = OsRng;
    let order = backend_order(repetition);
    let mut inline_parameters = None;
    let mut poseidon_parameters = None;
    let mut cp_parameters = None;
    let mut inline_setup_ms = None;
    let mut poseidon_setup_ms = None;
    let mut cp_setup_ms = None;
    for backend in order {
        let started = Instant::now();
        match backend {
            Backend::Inline => {
                inline_parameters = Some(
                    Groth16::<Bls12_381>::setup(
                        inline_augmented_from_joint(&fixture, &mapping, &mapping_pk),
                        &mut rng,
                    )
                    .map_err(|error| format!("inline setup: {error}"))?,
                );
                inline_setup_ms = Some(milliseconds(started));
            }
            Backend::PoseidonSplit => {
                poseidon_parameters =
                    Some(setup_augmented(&fixture, &mapping, &mapping_pk, &mut rng)?);
                poseidon_setup_ms = Some(milliseconds(started));
            }
            Backend::CpRsaSplit => {
                cp_parameters = Some(setup_cp(&fixture, &mapping, &mapping_pk, &mut rng)?);
                cp_setup_ms = Some(milliseconds(started));
            }
        }
    }
    let (inline_pk, inline_vk) = inline_parameters.ok_or("inline setup did not run")?;
    let poseidon_parameters = poseidon_parameters.ok_or("Poseidon setup did not run")?;
    let mut cp_parameters = cp_parameters.ok_or("CP/RSA setup did not run")?;
    let inline_setup_ms = inline_setup_ms.ok_or("inline setup timing missing")?;
    let poseidon_setup_ms = poseidon_setup_ms.ok_or("Poseidon setup timing missing")?;
    let cp_setup_ms = cp_setup_ms.ok_or("CP/RSA setup timing missing")?;
    validate_bridge(&cp_parameters)?;
    cp_parameters.core.vk.link_bases.swap(0, 1);
    require(
        validate_bridge(&cp_parameters).is_err(),
        "swapped CP bases rejected",
    )?;
    cp_parameters.core.vk.link_bases.swap(0, 1);
    let saved_g = cp_parameters.core.vk.link_bases[0];
    cp_parameters.core.vk.link_bases[0] = cp_parameters.commitment_h;
    require(
        validate_bridge(&cp_parameters).is_err(),
        "wrong CP g rejected",
    )?;
    cp_parameters.core.vk.link_bases[0] = saved_g;
    let saved_h = cp_parameters.core.vk.link_bases[1];
    cp_parameters.core.vk.link_bases[1] = cp_parameters.commitment_g;
    require(
        validate_bridge(&cp_parameters).is_err(),
        "wrong CP h rejected",
    )?;
    cp_parameters.core.vk.link_bases[1] = saved_h;
    let saved_declared_h = cp_parameters.commitment_h;
    cp_parameters.commitment_h = cp_parameters.commitment_g;
    require(
        validate_bridge(&cp_parameters).is_err(),
        "wrong declared CP h rejected",
    )?;
    cp_parameters.commitment_h = saved_declared_h;
    validate_bridge(&cp_parameters)?;

    let public_inputs = augmented_core_public_inputs(&fixture, &mapping, &mapping_pk);
    let member_inputs = augmented_membership_public_inputs(&fixture);

    let mut inline_proof = None;
    let mut poseidon_proof = None;
    let mut cp_proof = None;
    let mut inline_prove_ms = None;
    let mut inline_verify_ms = None;
    let mut poseidon_prove_ms = None;
    let mut poseidon_verify_ms = None;
    let mut cp_prove_ms = None;
    let mut cp_verify_ms = None;
    for backend in order {
        match backend {
            Backend::Inline => {
                let started = Instant::now();
                let proof = Groth16::<Bls12_381>::prove(
                    &inline_pk,
                    inline_augmented_from_joint(&fixture, &mapping, &mapping_pk),
                    &mut rng,
                )
                .map_err(|error| format!("inline prove: {error}"))?;
                inline_prove_ms = Some(milliseconds(started));
                let started = Instant::now();
                require(
                    Groth16::<Bls12_381>::verify(&inline_vk, &public_inputs, &proof)
                        .map_err(|error| error.to_string())?,
                    "augmented inline proof",
                )?;
                inline_verify_ms = Some(milliseconds(started));
                inline_proof = Some(proof);
            }
            Backend::PoseidonSplit => {
                let started = Instant::now();
                let proof = prove_augmented(
                    &poseidon_parameters,
                    &fixture,
                    &mapping,
                    &mapping_pk,
                    &mut rng,
                )?;
                poseidon_prove_ms = Some(milliseconds(started));
                let started = Instant::now();
                verify_augmented(
                    &poseidon_parameters,
                    &fixture,
                    &mapping,
                    &mapping_pk,
                    &proof,
                )?;
                poseidon_verify_ms = Some(milliseconds(started));
                poseidon_proof = Some(proof);
            }
            Backend::CpRsaSplit => {
                let started = Instant::now();
                let proof = prove_cp(
                    &cp_parameters,
                    cp_state.set(),
                    &fixture,
                    &mapping,
                    &mapping_pk,
                    &mut rng,
                )?;
                cp_prove_ms = Some(milliseconds(started));
                let started = Instant::now();
                verify_cp(
                    &cp_parameters,
                    cp_state.set(),
                    &fixture,
                    &mapping,
                    &mapping_pk,
                    &proof,
                )?;
                cp_verify_ms = Some(milliseconds(started));
                cp_proof = Some(proof);
            }
        }
    }
    let inline_proof = inline_proof.ok_or("inline proof did not run")?;
    let poseidon_proof = poseidon_proof.ok_or("Poseidon proof did not run")?;
    let cp_proof = cp_proof.ok_or("CP/RSA proof did not run")?;
    let inline_prove_ms = inline_prove_ms.ok_or("inline prove timing missing")?;
    let inline_verify_ms = inline_verify_ms.ok_or("inline verify timing missing")?;
    let poseidon_prove_ms = poseidon_prove_ms.ok_or("Poseidon prove timing missing")?;
    let poseidon_verify_ms = poseidon_verify_ms.ok_or("Poseidon verify timing missing")?;
    let cp_prove_ms = cp_prove_ms.ok_or("CP/RSA prove timing missing")?;
    let cp_verify_ms = cp_verify_ms.ok_or("CP/RSA verify timing missing")?;

    let mut wrong_position = mapping.clone();
    wrong_position.record.position ^= 1;
    require(
        prove_cp(
            &cp_parameters,
            cp_state.set(),
            &fixture,
            &wrong_position,
            &mapping_pk,
            &mut rng,
        )
        .is_err(),
        "mapping position mutation rejected",
    )?;

    // This certificate has a valid signature under the configured mapping
    // key and its prime is present in a temporary CP accumulator.  Rejection
    // therefore comes from the Joint record/position binding, rather than
    // from signature verification or CP membership.
    let mut wrong_position_issuer = CertifiedStateMap::new(SecretKey(MappingScalar::from(
        0x4538u64 + repetition as u64,
    )))
    .map_err(|error| error.to_string())?;
    let mut signed_wrong_position_record = mapping.record.clone();
    signed_wrong_position_record.position ^= 1;
    signed_wrong_position_record.prime = Fr::zero();
    let signed_wrong_position = wrong_position_issuer
        .generate_and_issue(
            signed_wrong_position_record,
            [111u8.wrapping_add(repetition as u8); 32],
            [112u8.wrapping_add(repetition as u8); 32],
        )
        .map_err(|error| error.to_string())?;
    let mut negative_primes = certificates
        .iter()
        .map(|certificate| prime_integer(certificate.record.prime))
        .collect::<Vec<_>>();
    negative_primes.push(prime_integer(signed_wrong_position.record.prime));
    let wrong_position_state = CpStateLifecycle::new(negative_primes)?;
    let signed_wrong_position_rejected = match prove_cp(
        &cp_parameters,
        wrong_position_state.set(),
        &fixture,
        &signed_wrong_position,
        &mapping_pk,
        &mut rng,
    ) {
        Err(_) => true,
        Ok(proof) => verify_cp(
            &cp_parameters,
            wrong_position_state.set(),
            &fixture,
            &signed_wrong_position,
            &mapping_pk,
            &proof,
        )
        .is_err(),
    };
    require(
        signed_wrong_position_rejected,
        "validly signed wrong-position certificate rejected",
    )?;

    let mut duplicate_generation_record = mapping.record.clone();
    duplicate_generation_record.prime = generate_prime_252(
        &duplicate_generation_record,
        [113u8.wrapping_add(repetition as u8); 32],
    )
    .map_err(|error| error.to_string())?;
    require(
        map.issue(
            duplicate_generation_record,
            [114u8.wrapping_add(repetition as u8); 32],
        ) == Err(MappingError::DuplicateGeneration),
        "alternate prime for a live generation rejected",
    )?;
    let mut wrong_prime = mapping.clone();
    wrong_prime.record.prime = certificates[1].record.prime;
    require(
        prove_cp(
            &cp_parameters,
            cp_state.set(),
            &fixture,
            &wrong_prime,
            &mapping_pk,
            &mut rng,
        )
        .is_err(),
        "mapping prime mutation rejected",
    )?;

    // Tamper only with the current-stack linked commitment of an otherwise
    // valid proof.  This is distinct from the cross-prime splice below: the
    // CP statement and membership proof still refer to the certified prime.
    let mut wrong_commitment = prove_cp(
        &cp_parameters,
        cp_state.set(),
        &fixture,
        &mapping,
        &mapping_pk,
        &mut rng,
    )?;
    wrong_commitment.core.link_d = (wrong_commitment.core.link_d.into_group()
        + cp_parameters.commitment_g.into_group())
    .into_affine();
    require(
        verify_cp(
            &cp_parameters,
            cp_state.set(),
            &fixture,
            &mapping,
            &mapping_pk,
            &wrong_commitment,
        )
        .is_err(),
        "wrong linked commitment rejected",
    )?;

    // Build a valid CP membership proof for a different live prime, then
    // splice it beside the original Joint-core proof.  Both components are
    // individually well formed, but their hidden prime/opening link differs.
    let wrong_opening = Integer::from(1);
    let wrong_context = binding_context(&cp_parameters, &public_inputs)?;
    let (wrong_statement, wrong_membership) = cp_parameters.cp.prove(
        cp_state.set(),
        &prime_integer(certificates[1].record.prime),
        &wrong_opening,
        &wrong_context,
    )?;
    cp_parameters
        .cp
        .verify(&wrong_statement, &wrong_membership, &wrong_context)?;
    let forged_commitment = CpLinkedProof {
        statement: wrong_statement,
        membership: wrong_membership,
        core: cp_proof.core.clone(),
    };
    require(
        verify_cp(
            &cp_parameters,
            cp_state.set(),
            &fixture,
            &mapping,
            &mapping_pk,
            &forged_commitment,
        )
        .is_err(),
        "cross-prime commitment splice rejected",
    )?;

    let mut rejected = [0usize; 3];
    for index in 0..public_inputs.len() {
        let mut changed = public_inputs.clone();
        changed[index] += Fr::from(1u64);
        if !Groth16::<Bls12_381>::verify(&inline_vk, &changed, &inline_proof)
            .map_err(|error| error.to_string())?
        {
            rejected[0] += 1;
        }
        if verify_augmented_with_inputs(
            &poseidon_parameters,
            &changed,
            &member_inputs,
            &poseidon_proof,
        )
        .is_err()
        {
            rejected[1] += 1;
        }
        if verify_cp_inputs(&cp_parameters, cp_state.set(), &changed, &cp_proof).is_err() {
            rejected[2] += 1;
        }
    }
    require(
        rejected == [27, 27, 27],
        "all public-field mutations rejected",
    )?;

    if repetition == 0 {
        for active in 1..=3 {
            let other = fixed::<3>(active, 7000 + active as u64, 20, 20, 32);
            require(
                state_leaf(&other.state) == mapping.record.state_leaf
                    && other.state.position == mapping.record.position,
                "enabled-length fixtures share certified state",
            )?;
            let other_inputs = augmented_core_public_inputs(&other, &mapping, &mapping_pk);
            let inline = Groth16::<Bls12_381>::prove(
                &inline_pk,
                inline_augmented_from_joint(&other, &mapping, &mapping_pk),
                &mut rng,
            )
            .map_err(|error| error.to_string())?;
            require(
                Groth16::<Bls12_381>::verify(&inline_vk, &other_inputs, &inline)
                    .map_err(|error| error.to_string())?,
                "same inline CRS across enabled lengths",
            )?;
            let poseidon = prove_augmented(
                &poseidon_parameters,
                &other,
                &mapping,
                &mapping_pk,
                &mut rng,
            )?;
            verify_augmented(
                &poseidon_parameters,
                &other,
                &mapping,
                &mapping_pk,
                &poseidon,
            )?;
            let cp = prove_cp(
                &cp_parameters,
                cp_state.set(),
                &other,
                &mapping,
                &mapping_pk,
                &mut rng,
            )?;
            verify_cp(
                &cp_parameters,
                cp_state.set(),
                &other,
                &mapping,
                &mapping_pk,
                &cp,
            )?;
        }
    }

    let next_fixture = successor(&fixture);
    let mut next_record = mapping_template(&next_fixture);
    let started = Instant::now();
    next_record.prime = generate_prime_252(&next_record, [91u8.wrapping_add(repetition as u8); 32])
        .map_err(|error| error.to_string())?;
    let successor_prime_generation_ms = milliseconds(started);
    let independent_prime = certificates[1].record.prime;
    let started = Instant::now();
    let next_mapping = map
        .replace_with_accumulator(
            &mapping.record,
            next_record,
            [92u8.wrapping_add(repetition as u8); 32],
            &mut cp_state,
        )
        .map_err(|error| error.to_string())?;
    let replace_and_confirm_ms = milliseconds(started);
    require(!map.is_live(&mapping), "retired mapping is not live")?;
    require(map.is_live(&next_mapping), "successor mapping is live")?;
    require(
        !cp_state.contains(mapping.record.prime),
        "old prime removed",
    )?;
    require(
        cp_state.contains(next_mapping.record.prime),
        "successor prime admitted",
    )?;
    require(
        cp_state.contains(independent_prime),
        "independent member survives",
    )?;

    let reused = MappingRecord {
        owner_commitment: Fr::from(0xdead_u64),
        position: 31,
        state_epoch: next_mapping.record.state_epoch + 1,
        prime: mapping.record.prime,
        ..next_mapping.record.clone()
    };
    require(
        map.issue(reused, [93; 32]) == Err(MappingError::DuplicatePrime),
        "retired prime never reused",
    )?;

    let successor_inputs = augmented_core_public_inputs(&next_fixture, &next_mapping, &mapping_pk);
    let successor_member_inputs = augmented_membership_public_inputs(&next_fixture);
    require(
        !Groth16::<Bls12_381>::verify(&inline_vk, &successor_inputs, &inline_proof)
            .map_err(|error| error.to_string())?,
        "old inline proof rejected after replacement",
    )?;
    require(
        verify_augmented_with_inputs(
            &poseidon_parameters,
            &successor_inputs,
            &successor_member_inputs,
            &poseidon_proof,
        )
        .is_err(),
        "old Poseidon proof rejected after replacement",
    )?;
    require(
        verify_cp(
            &cp_parameters,
            cp_state.set(),
            &next_fixture,
            &next_mapping,
            &mapping_pk,
            &cp_proof,
        )
        .is_err(),
        "old CP proof rejected against successor accumulator",
    )?;

    let next_inline = Groth16::<Bls12_381>::prove(
        &inline_pk,
        inline_augmented_from_joint(&next_fixture, &next_mapping, &mapping_pk),
        &mut rng,
    )
    .map_err(|error| error.to_string())?;
    require(
        Groth16::<Bls12_381>::verify(&inline_vk, &successor_inputs, &next_inline)
            .map_err(|error| error.to_string())?,
        "successor inline proof under same CRS",
    )?;
    let next_poseidon = prove_augmented(
        &poseidon_parameters,
        &next_fixture,
        &next_mapping,
        &mapping_pk,
        &mut rng,
    )?;
    verify_augmented(
        &poseidon_parameters,
        &next_fixture,
        &next_mapping,
        &mapping_pk,
        &next_poseidon,
    )?;
    let next_cp = prove_cp(
        &cp_parameters,
        cp_state.set(),
        &next_fixture,
        &next_mapping,
        &mapping_pk,
        &mut rng,
    )?;
    verify_cp(
        &cp_parameters,
        cp_state.set(),
        &next_fixture,
        &next_mapping,
        &mapping_pk,
        &next_cp,
    )?;

    let prefix = output.join(format!("rep-{repetition}"));
    fs::create_dir_all(&prefix).map_err(|error| error.to_string())?;
    let cp_membership_bytes = cp_proof_components(&cp_proof.membership)?;
    let cp_statement_bytes = {
        let mut bytes = Rsa2048::elem_to_bytes(&cp_proof.statement.c_p);
        bytes.extend(old_encoded(&cp_proof.statement.c_e_q)?);
        bytes
    };
    let bridge_bytes = bridge_parameter_bytes(&cp_parameters)?;
    let bridge_sha256 = sha256_hex(&bridge_bytes);
    let artifacts = [
        ("inline-pk.bin", encoded(&inline_pk)?),
        ("inline-vk.bin", encoded(&inline_vk)?),
        ("inline-proof.bin", encoded(&inline_proof)?),
        ("poseidon-core-pk.bin", encoded(&poseidon_parameters.core)?),
        (
            "poseidon-core-vk.bin",
            encoded(&poseidon_parameters.core.vk)?,
        ),
        (
            "poseidon-member-pk.bin",
            encoded(&poseidon_parameters.membership)?,
        ),
        (
            "poseidon-member-vk.bin",
            encoded(&poseidon_parameters.membership.vk)?,
        ),
        ("poseidon-core-proof.bin", encoded(&poseidon_proof.core)?),
        (
            "poseidon-member-proof.bin",
            encoded(&poseidon_proof.membership)?,
        ),
        ("cp-core-pk.bin", encoded(&cp_parameters.core)?),
        ("cp-core-vk.bin", encoded(&cp_parameters.core.vk)?),
        ("cp-core-proof.bin", encoded(&cp_proof.core)?),
        ("cp-membership-proof.bin", cp_membership_bytes),
        ("cp-statement.bin", cp_statement_bytes),
        (
            "cp-parameters.bin",
            cp_parameters.cp_parameter_bytes.clone(),
        ),
        ("cp-current-bridge-parameters.bin", bridge_bytes),
        (
            "mapping-certificate.bin",
            mapping_certificate_bytes(&mapping),
        ),
        ("mapping-public-key.bin", encoded(&mapping_pk.0)?),
    ];
    let mut sizes = serde_json::Map::new();
    for (name, bytes) in artifacts {
        sizes.insert(name.into(), json!(bytes.len()));
        fs::write(prefix.join(name), bytes).map_err(|error| error.to_string())?;
    }

    Ok(json!({
        "repetition": repetition,
        "backend_order": order.map(Backend::label),
        "relation_metrics": relation,
        "same_canonical_semantics": {
            "joint_fixture": true,
            "mapping_record": true,
            "hidden_prime_leaf_position": true,
            "public_core_inputs": 27,
            "backend_state_commitment_bytes_may_differ": true,
        },
        "full_proof_verify": {
            "inline": true,
            "poseidon_split": true,
            "cp_rsa_split": true,
        },
        "inline": {
            "setup_ms": inline_setup_ms,
            "prove_ms": inline_prove_ms,
            "verify_ms": inline_verify_ms,
            "pk_bytes": sizes["inline-pk.bin"],
            "vk_bytes": sizes["inline-vk.bin"],
            "proof_bytes": sizes["inline-proof.bin"],
            "proof_plus_mapping_certificate_bytes": sizes["inline-proof.bin"].as_u64().unwrap()
                + sizes["mapping-certificate.bin"].as_u64().unwrap(),
        },
        "poseidon_split": {
            "setup_ms": poseidon_setup_ms,
            "prove_ms": poseidon_prove_ms,
            "verify_ms": poseidon_verify_ms,
            "core_pk_bytes": sizes["poseidon-core-pk.bin"],
            "membership_pk_bytes": sizes["poseidon-member-pk.bin"],
            "core_vk_bytes": sizes["poseidon-core-vk.bin"],
            "membership_vk_bytes": sizes["poseidon-member-vk.bin"],
            "proof_bundle_bytes": sizes["poseidon-core-proof.bin"].as_u64().unwrap()
                + sizes["poseidon-member-proof.bin"].as_u64().unwrap(),
            "proof_bundle_plus_mapping_certificate_bytes": sizes["poseidon-core-proof.bin"].as_u64().unwrap()
                + sizes["poseidon-member-proof.bin"].as_u64().unwrap()
                + sizes["mapping-certificate.bin"].as_u64().unwrap(),
        },
        "cp_rsa_split": {
            "setup_ms": cp_setup_ms,
            "prove_ms": cp_prove_ms,
            "verify_ms": cp_verify_ms,
            "core_pk_bytes": sizes["cp-core-pk.bin"],
            "core_vk_bytes": sizes["cp-core-vk.bin"],
            "proof_bundle_bytes": sizes["cp-core-proof.bin"].as_u64().unwrap()
                + sizes["cp-membership-proof.bin"].as_u64().unwrap()
                + sizes["cp-statement.bin"].as_u64().unwrap(),
            "proof_bundle_plus_mapping_certificate_bytes": sizes["cp-core-proof.bin"].as_u64().unwrap()
                + sizes["cp-membership-proof.bin"].as_u64().unwrap()
                + sizes["cp-statement.bin"].as_u64().unwrap()
                + sizes["mapping-certificate.bin"].as_u64().unwrap(),
            "cp_parameter_bytes": sizes["cp-parameters.bin"],
            "cp_parameter_sha256": sha256_hex(&cp_parameters.cp_parameter_bytes),
            "bridge_parameter_bytes": sizes["cp-current-bridge-parameters.bin"],
            "bridge_parameter_sha256": bridge_sha256,
            "mapping_certificate_bytes": sizes["mapping-certificate.bin"],
            "mapping_public_key_bytes": sizes["mapping-public-key.bin"],
        },
        "lifecycle": {
            "member_count": cp_state.member_count(),
            "initial_mapping_and_accumulator_ms": initial_mapping_and_accumulator_ms,
            "successor_prime_generation_ms": successor_prime_generation_ms,
            "replace_and_confirm_ms": replace_and_confirm_ms,
            "old_prime_absent": true,
            "successor_prime_present": true,
            "independent_member_survives": true,
            "old_mapping_not_live": true,
            "retired_prime_reuse_rejected": true,
            "wrong_g_rejected": true,
            "wrong_h_rejected": true,
            "wrong_declared_h_rejected": true,
            "swapped_g_h_rejected": true,
            "wrong_commitment_rejected": true,
            "cross_prime_commitment_splice_rejected": true,
            "wrong_position_rejected": true,
            "validly_signed_wrong_position_rejected": true,
            "different_prime_rejected": true,
            "alternate_prime_for_live_generation_rejected": true,
            "canonical_point_roundtrip_and_scalar_modulus_checked": true,
            "base_field_modulus_checked": true,
            "legacy_to_current_coordinate_roundtrip_checked": true,
            "current_curve_and_subgroup_checked": true,
            "ordered_nonidentity_distinct_g_h_checked": true,
            "same_crs_enabled_lengths_checked": repetition == 0,
            "same_crs_enabled_lengths": if repetition == 0 { json!([1, 2, 3]) } else { Value::Null },
            "fresh_successor_all_three_backends": true,
            "retired_proof_all_three_backends_rejected": true,
        },
        "public_mutations_rejected": {
            "inline": rejected[0],
            "poseidon_split": rejected[1],
            "cp_rsa_split": rejected[2],
        },
    }))
}

fn run() -> Result<(), String> {
    let output = env::var_os("E8_AUGMENTED_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("results"));
    fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    let repetitions = env::var("E8_AUGMENTED_REPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1);
    require(repetitions > 0, "positive repetition count")?;
    let mut samples = Vec::with_capacity(repetitions);
    for repetition in 0..repetitions {
        samples.push(run_repetition(repetition, &output)?);
    }
    let result = json!({
        "schema": "plan-a-e8-certified-state-map-three-backend-v1",
        "status": "success",
        "relation": "augmented Joint authorization plus signed generation-bound state-to-prime mapping; inline and Poseidon variants also carry the certificate so all three discharge the same added SR responsibility",
        "comparison_boundary": "same canonical records, request, policy, mapping generation and accept/reject behavior; Poseidon roots and RSA accumulator bytes are backend-specific",
        "setup_boundary": "fresh local experimental setup per repetition; not a production MPC ceremony",
        "security_boundary": "certificate circuit proves signature and 252-bit range; issuer and verifier perform native 64-round derived-base probable-prime validation with the documented random-oracle and union-loss qualification",
        "cp_security_boundary": "the retained RSA-2048 CP accumulator carries its Strong-RSA-style and modulus/setup assumptions; it is not labeled 128-bit-equivalent to the pairing backends",
        "additional_trust_and_setup_duties": "the augmented relation additionally requires the mapping issuer to generate and validate generation-unique primes, sign certificates, maintain lifetime non-reuse state, update the accumulator, and distribute the circuit-specific CRS and backend parameters",
        "fresh_setup_repetitions": repetitions,
        "order_control": {
            "schedule": "six backend permutations in repetition-index order",
            "period": 6,
            "formal_minimum_repetitions": 12,
        },
        "samples": samples,
    });
    fs::write(
        output.join("results.json"),
        serde_json::to_vec_pretty(&result).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    println!(
        "{}",
        json!({"ok": true, "output": output, "repetitions": repetitions})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
