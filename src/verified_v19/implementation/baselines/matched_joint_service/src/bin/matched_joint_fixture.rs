//! Fresh-setup producer for the matched Joint actual-1/actual-2 envelopes.
use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::Fr as Scalar;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use plan_a_dac_fixed_wrapper::semantic_schema::{
    canonical_http_sha256, manifest_sha256, CanonicalHttpRequest, SemanticManifest,
};
use plan_a_joint_circuit::{
    contract::terminal_transcript,
    fixture::public_inputs,
    poseidon::{hash, Domain},
    signature::{encode_signature, public_key, sign, SecretKey},
};
use plan_a_matched_joint_service::{
    build_joint_a_actual2_bound_nonce, build_joint_actual1_bound, build_joint_actual1_bound_nonce,
    build_joint_actuals_bound, build_joint_actuals_bound_nonce,
};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, path::PathBuf, time::Instant};

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}
fn sha_domain(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update([0]);
    h.update(bytes);
    h.finalize().into()
}
fn limbs(d: [u8; 32]) -> [u64; 4] {
    std::array::from_fn(|i| u64::from_le_bytes(d[i * 8..(i + 1) * 8].try_into().unwrap()))
}
fn encode<T: CanonicalSerialize>(v: &T) -> String {
    let mut b = vec![];
    v.serialize_compressed(&mut b).unwrap();
    hex::encode(b)
}
fn public_inputs_fingerprint(
    circuit: &plan_a_joint_circuit::joint::JointCircuit<2>,
) -> (Vec<String>, String) {
    let values = public_inputs(circuit).iter().map(encode).collect::<Vec<_>>();
    let digest = hex::encode(Sha256::digest(canonical(&json!(values))));
    (values, digest)
}
fn hash_usize(hasher: &mut Sha256, value: usize) {
    hasher.update((value as u64).to_le_bytes());
}
fn hash_matrix(hasher: &mut Sha256, label: u8, matrix: &[Vec<(Fr, usize)>]) {
    hasher.update([label]);
    hash_usize(hasher, matrix.len());
    for (row_index, row) in matrix.iter().enumerate() {
        hash_usize(hasher, row_index);
        hash_usize(hasher, row.len());
        for (entry_index, (coefficient, column_index)) in row.iter().enumerate() {
            hash_usize(hasher, entry_index);
            hash_usize(hasher, *column_index);
            let mut bytes = Vec::new();
            coefficient.serialize_compressed(&mut bytes).unwrap();
            hasher.update(bytes);
        }
    }
}
fn synthesis_audit(
    circuit: &plan_a_joint_circuit::joint::JointCircuit<2>,
) -> Result<Value, String> {
    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit
        .clone()
        .generate_constraints(cs.clone())
        .map_err(|e| e.to_string())?;
    let satisfied = cs.is_satisfied().map_err(|e| e.to_string())?;
    let unsatisfied_constraint = cs.which_is_unsatisfied().map_err(|e| e.to_string())?;
    let expected = public_inputs(circuit);
    let actual = cs
        .borrow()
        .ok_or("missing-constraint-system")?
        .instance_assignment[1..]
        .to_vec();
    cs.finalize();
    let matrices = cs.to_matrices().ok_or("missing-constraint-matrices")?;
    let mut digest = Sha256::new();
    digest.update(b"plan-a-matched-joint-r1cs-matrices-v1");
    for value in [
        matrices.num_instance_variables,
        matrices.num_witness_variables,
        matrices.num_constraints,
        matrices.a_num_non_zero,
        matrices.b_num_non_zero,
        matrices.c_num_non_zero,
    ] {
        hash_usize(&mut digest, value);
    }
    hash_matrix(&mut digest, b'A', &matrices.a);
    hash_matrix(&mut digest, b'B', &matrices.b);
    hash_matrix(&mut digest, b'C', &matrices.c);
    Ok(json!({
        "satisfied": satisfied,
        "unsatisfied_constraint": unsatisfied_constraint,
        "public_inputs_equal_instance_assignment": expected == actual,
        "num_instance_variables": matrices.num_instance_variables,
        "num_witness_variables": matrices.num_witness_variables,
        "num_constraints": matrices.num_constraints,
        "a_num_non_zero": matrices.a_num_non_zero,
        "b_num_non_zero": matrices.b_num_non_zero,
        "c_num_non_zero": matrices.c_num_non_zero,
        "canonical_matrix_sha256": hex::encode(digest.finalize()),
        "canonical_matrix_encoding": "metadata(instance,witness,constraints,A/B/C nonzero); finalized A/B/C row order; entries=(entry_index,column_index,canonical_compressed_Fr)",
    }))
}
fn header_message(header: &Value) -> Fr {
    let d = sha_domain(b"plan-a-matched-header-v1", &canonical(header));
    let a = Fr::from(u128::from_be_bytes(d[..16].try_into().unwrap()));
    let b = Fr::from(u128::from_be_bytes(d[16..].try_into().unwrap()));
    hash(Domain::Terminal, &[a, b])
}
fn main() {
    let result = (|| -> Result<Value, String> {
        let manifest_path =
            PathBuf::from(env::var("MATCHED_MANIFEST_PATH").map_err(|_| "missing-manifest-path")?);
        let manifest: SemanticManifest =
            serde_json::from_slice(&std::fs::read(manifest_path).map_err(|e| e.to_string())?)
                .map_err(|_| "bad-manifest")?;
        let update = env::var("MATCHED_UPDATE_INDEX")
            .unwrap_or_else(|_| "1".into())
            .parse::<usize>()
            .map_err(|_| "bad-update-index")?;
        let http: CanonicalHttpRequest = serde_json::from_slice(
            &std::fs::read(env::var("MATCHED_HTTP_JSON_PATH").map_err(|_| "missing-http-path")?)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|_| "bad-http-json")?;
        let http_sha: [u8; 32] = hex::decode(canonical_http_sha256(&http).map_err(str::to_owned)?)
            .map_err(|_| "bad-http-sha")?
            .try_into()
            .map_err(|_| "bad-http-sha")?;
        if env::var("MATCHED_JOINT_PUBLIC_INPUT_AUDIT").as_deref() == Ok("1") {
            let mut phases = Vec::new();
            for phase in [0usize, 1usize] {
                let nonce = manifest.request.nonce_u64;
                let bound = limbs(http_sha);
                let a = build_joint_a_actual2_bound_nonce(&manifest, phase, bound, nonce)
                    .map_err(|e| e.to_string())?;
                let bc = build_joint_actuals_bound_nonce(&manifest, phase, bound, nonce)
                    .map_err(|e| e.to_string())?;
                let vectors = [("a", &a), ("b", &bc.actual2), ("c", &bc.actual1)]
                    .into_iter()
                    .map(|(name, circuit)| {
                        let (values, digest) = public_inputs_fingerprint(circuit);
                        (name, circuit, values, digest)
                    })
                    .collect::<Vec<_>>();
                let reference = &vectors[2].2;
                let comparisons = vectors
                    .iter()
                    .map(|(name, circuit, values, digest)| {
                        let differing_indices = values
                            .iter()
                            .zip(reference)
                            .enumerate()
                            .filter_map(|(index, (left, right))| (left != right).then_some(index))
                            .collect::<Vec<_>>();
                        Ok::<Value, String>(json!({"chain":name,"public_inputs":values,
                               "public_inputs_sha256":digest,"differing_indices_from_c":differing_indices,
                               "expected_positive": phase == 0 || *name != "a",
                               "synthesis":synthesis_audit(circuit)?}))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                phases.push(json!({"update_index":phase,"nonce_u64":nonce,
                                   "canonical_http_sha256":hex::encode(http_sha),"candidates":comparisons}));
            }
            let template = build_joint_actuals_bound_nonce(
                &manifest,
                update,
                limbs(http_sha),
                manifest.request.nonce_u64,
            )
            .map_err(|e| e.to_string())?
            .actual2;
            return Ok(json!({"valid":true,"diagnostic_only":true,
                             "semantic_input_sha256":manifest_sha256(&manifest),
                             "setup_template":{"update_index":update,"chain":"b","synthesis":synthesis_audit(&template)?},
                             "phases":phases}));
        }
        let fixtures = build_joint_actuals_bound(&manifest, update, limbs(http_sha))
            .map_err(|e| e.to_string())?;
        let mut rng = OsRng;
        let t = Instant::now();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(fixtures.actual2.clone(), &mut rng)
                .map_err(|e| e.to_string())?;
        let setup_ms = t.elapsed().as_secs_f64() * 1000.0;
        let vk_bytes = {
            let mut b = vec![];
            vk.serialize_compressed(&mut b).map_err(|e| e.to_string())?;
            b
        };
        let vk_sha = hex::encode(Sha256::digest(&vk_bytes));
        let pk_bytes = {
            let mut b = vec![];
            pk.serialize_compressed(&mut b).map_err(|e| e.to_string())?;
            b
        };
        let pk_sha = hex::encode(Sha256::digest(&pk_bytes));
        std::fs::write(
            env::var("MATCHED_JOINT_VK_OUT").map_err(|_| "missing-vk-out")?,
            &vk_bytes,
        )
        .map_err(|e| e.to_string())?;
        let semantic_sha = manifest_sha256(&manifest);
        let snapshot = &fixtures.actual2.snapshot;
        let header = json!({"issued_at":snapshot.issued_at,"ra_root":encode(&snapshot.root_ra),"revocation_epoch":snapshot.revocation_epoch,"revocation_root":encode(&snapshot.root_rev),"semantic_input_sha256":semantic_sha,"state_epoch":snapshot.state_epoch,"state_root":encode(&snapshot.root_state),"tuple_version":snapshot.tuple_version});
        let registry_sk = SecretKey(Scalar::from(
            env::var("MATCHED_REGISTRY_SK_U64")
                .map_err(|_| "missing-registry-sk")?
                .parse::<u64>()
                .map_err(|_| "bad-registry-sk")?,
        ));
        let registry_pk = public_key(&registry_sk).map_err(|e| e.to_string())?;
        let header_sig =
            sign(&registry_sk, header_message(&header), [0x71; 32]).map_err(|e| e.to_string())?;
        let terminal_sk = SecretKey(Scalar::from(manifest.request.terminal));
        let terminal_pk = public_key(&terminal_sk).map_err(|e| e.to_string())?;
        let circuit_id = env::var("MATCHED_JOINT_CIRCUIT_ID").map_err(|_| "missing-circuit-id")?;
        let header_sha = sha_domain(b"plan-a-matched-header-v1", &canonical(&header));
        let mut rows = vec![];
        for (actual, circuit) in [(1, fixtures.actual1), (2, fixtures.actual2)] {
            let t = Instant::now();
            let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng)
                .map_err(|e| e.to_string())?;
            let prove_ms = t.elapsed().as_secs_f64() * 1000.0;
            let mut proof_bytes = vec![];
            proof
                .serialize_compressed(&mut proof_bytes)
                .map_err(|e| e.to_string())?;
            let t = Instant::now();
            let verified = Groth16::<Bls12_381>::verify(&vk, &public_inputs(&circuit), &proof)
                .map_err(|e| e.to_string())?;
            let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
            if !verified {
                return Err("self-verification-failed".into());
            }
            let terminal_sig = sign(
                &terminal_sk,
                terminal_transcript(http_sha, header_sha, &circuit_id, &proof_bytes),
                [actual as u8; 32],
            )
            .map_err(|e| e.to_string())?;
            rows.push(json!({"actual":actual,"envelope":{"proof":hex::encode(&proof_bytes),"semantic_input_sha256":semantic_sha,"terminal_signature":hex::encode(encode_signature(&terminal_sig)),"update_index":update},"prove_ms":prove_ms,"verify_ms":verify_ms}));
        }
        if let Ok(path) = env::var("MATCHED_PHASE_BUNDLE_OUT") {
            let mut phases = vec![];
            let mut cases = serde_json::Map::new();
            for phase in 0..3 {
                let base = manifest.request.nonce_u64;
                let names: Vec<(&str, &str, u64)> = match phase {
                    0 => vec![
                        ("t0_a", "a", 0),
                        ("t0_b", "b", 1),
                        ("t0_c", "c", 2),
                        ("negative_body", "c", 100),
                        ("negative_proof", "c", 101),
                        ("negative_terminal", "c", 102),
                        ("old_ticket", "c", 104),
                        ("removed_a", "a", 105),
                    ],
                    1 => vec![("t1_b", "b", 3), ("t1_c", "c", 4), ("revoked_b", "b", 106)],
                    _ => vec![("t2_c", "c", 5), ("expired", "c", 103)],
                };
                let header_c = build_joint_actual1_bound(&manifest, phase, limbs(http_sha))
                    .map_err(|e| e.to_string())?
                    .1;
                let snap = &header_c.snapshot;
                let phase_header = json!({"issued_at":snap.issued_at,"ra_root":encode(&snap.root_ra),"revocation_epoch":snap.revocation_epoch,"revocation_root":encode(&snap.root_rev),"semantic_input_sha256":semantic_sha,"state_epoch":snap.state_epoch,"state_root":encode(&snap.root_state),"tuple_version":snap.tuple_version});
                let phase_header_sha =
                    sha_domain(b"plan-a-matched-header-v1", &canonical(&phase_header));
                for (name_index, (case_name, chain, offset)) in names.into_iter().enumerate() {
                    let nonce = base.checked_add(offset).ok_or("nonce overflow")?;
                    let body = json!({"nonce_u64":nonce,"operation":"read"});
                    let body_bytes = canonical(&body);
                    let mut case_http = http.clone();
                    case_http.body_sha256 = hex::encode(Sha256::digest(&body_bytes));
                    let case_sha: [u8; 32] =
                        hex::decode(canonical_http_sha256(&case_http).map_err(str::to_owned)?)
                            .unwrap()
                            .try_into()
                            .unwrap();
                    let circuit = match chain {
                        "c" => {
                            build_joint_actual1_bound_nonce(
                                &manifest,
                                phase,
                                limbs(case_sha),
                                nonce,
                            )
                            .map_err(|e| e.to_string())?
                            .1
                        }
                        "b" => {
                            build_joint_actuals_bound_nonce(
                                &manifest,
                                phase,
                                limbs(case_sha),
                                nonce,
                            )
                            .map_err(|e| e.to_string())?
                            .actual2
                        }
                        "a" => build_joint_a_actual2_bound_nonce(
                            &manifest,
                            phase,
                            limbs(case_sha),
                            nonce,
                        )
                        .map_err(|e| e.to_string())?,
                        _ => unreachable!(),
                    };
                    let proof = Groth16::<Bls12_381>::prove(&pk, circuit.clone(), &mut rng)
                        .map_err(|e| e.to_string())?;
                    let self_verified =
                        Groth16::<Bls12_381>::verify(&vk, &public_inputs(&circuit), &proof)
                            .map_err(|e| e.to_string())?;
                    if !self_verified {
                        return Err(format!("lifecycle-self-verification-failed-{case_name}"));
                    }
                    let (_, public_inputs_sha256) = public_inputs_fingerprint(&circuit);
                    let mut bytes = vec![];
                    proof
                        .serialize_compressed(&mut bytes)
                        .map_err(|e| e.to_string())?;
                    let sig = sign(
                        &terminal_sk,
                        terminal_transcript(case_sha, phase_header_sha, &circuit_id, &bytes),
                        [(phase * 11 + name_index + 1) as u8; 32],
                    )
                    .map_err(|e| e.to_string())?;
                    let proof_sha256 = hex::encode(Sha256::digest(&bytes));
                    let envelope = json!({"proof":hex::encode(bytes),"semantic_input_sha256":semantic_sha,"terminal_signature":hex::encode(encode_signature(&sig)),"update_index":phase});
                    cases.insert(
                        case_name.into(),
                        json!({"body":body,"envelope":envelope,
                               "proof_sha256":proof_sha256,
                               "public_inputs_sha256":public_inputs_sha256,
                               "self_verified":self_verified,"update_index":phase,
                               "vk_sha256":vk_sha}),
                    );
                }
                let hs = sign(
                    &registry_sk,
                    header_message(&phase_header),
                    [0x72 + phase as u8; 32],
                )
                .map_err(|e| e.to_string())?;
                phases.push(json!({"header_envelope":{"header":phase_header,"registry_signature":hex::encode(encode_signature(&hs))},"update_index":phase}));
            }
            let case_plan_sha256 = hex::encode(Sha256::digest(include_bytes!(
                "../../../../service/matched_case_plan_v1.json"
            )));
            let bundle = json!({"case_plan_sha256":case_plan_sha256,"cases":cases,"phases":phases,"registry_public_key":encode(&registry_pk.0),"semantic_input_sha256":semantic_sha,"terminal_public_key":encode(&terminal_pk.0),"vk_path":env::var("MATCHED_JOINT_VK_OUT").unwrap(),"vk_sha256":vk_sha});
            std::fs::write(path, serde_json::to_vec_pretty(&bundle).unwrap())
                .map_err(|e| e.to_string())?;
        }
        Ok(
            json!({"header_envelope":{"header":header,"registry_signature":hex::encode(encode_signature(&header_sig))},"http_sha256":hex::encode(http_sha),"pk_bytes":pk_bytes.len(),"pk_sha256":pk_sha,"registry_public_key":encode(&registry_pk.0),"terminal_public_key":encode(&terminal_pk.0),"rows":rows,"semantic_input_sha256":semantic_sha,"setup_ms":setup_ms,"vk_bytes":vk_bytes.len(),"vk_sha256":vk_sha}),
        )
    })();
    println!(
        "{}",
        match result {
            Ok(v) => v,
            Err(e) => json!({"valid":false,"error":e}),
        }
    )
}
