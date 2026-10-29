use ark_bls12_381::{Bls12_381, Fr};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::CanonicalSerialize;
use ark_snark::{CircuitSpecificSetupSNARK, SNARK};
use joint_backend_matched::{
    core_public_inputs, membership_public_inputs, prove_linked, setup_linked, split_from_joint,
    verify_linked, verify_linked_inputs, LinkedProof,
};
use plan_a_joint_circuit::fixture::{fixed, public_inputs};
use rand::rngs::OsRng;
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf, time::Instant};

fn milliseconds(start: Instant) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0
}

fn encoded<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn metrics<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<Value, String> {
    let cs = ConstraintSystem::new_ref();
    circuit
        .generate_constraints(cs.clone())
        .map_err(|error| error.to_string())?;
    if !cs.is_satisfied().map_err(|error| error.to_string())? {
        return Err("circuit is unsatisfied".into());
    }
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

fn require(condition: bool, label: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(format!("gate failed: {label}"))
    }
}

fn run() -> Result<(), String> {
    let output = env::var_os("E8_JOINT_OUTPUT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("results"));
    fs::create_dir_all(&output).map_err(|error| error.to_string())?;
    let repetitions = env::var("E8_JOINT_REPS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(3);
    require(repetitions > 0, "positive repetition count")?;

    let mut samples = Vec::new();
    let mut checks = Vec::new();
    for repetition in 0..repetitions {
        let fixture = fixed::<3>(3, 1000 + repetition as u64, 20, 20, 32);
        let (core_circuit, membership_circuit) = split_from_joint(&fixture);
        let relation_metrics = json!({
            "native_inline": metrics(fixture.clone())?,
            "linked_core": metrics(core_circuit)?,
            "linked_state_membership": metrics(membership_circuit)?,
        });
        let mut rng = OsRng;

        let started = Instant::now();
        let (inline_pk, inline_vk) = Groth16::<Bls12_381>::setup(fixture.clone(), &mut rng)
            .map_err(|error| format!("inline setup: {error}"))?;
        let inline_setup_ms = milliseconds(started);
        let started = Instant::now();
        let linked_parameters = setup_linked(&fixture, &mut rng)?;
        let linked_setup_ms = milliseconds(started);

        let started = Instant::now();
        let inline_proof = Groth16::<Bls12_381>::prove(&inline_pk, fixture.clone(), &mut rng)
            .map_err(|error| format!("inline prove: {error}"))?;
        let inline_prove_ms = milliseconds(started);
        let inline_inputs = public_inputs(&fixture);
        let started = Instant::now();
        let inline_valid = Groth16::<Bls12_381>::verify(&inline_vk, &inline_inputs, &inline_proof)
            .map_err(|error| format!("inline verify: {error}"))?;
        let inline_verify_ms = milliseconds(started);
        require(inline_valid, "inline valid proof")?;

        let started = Instant::now();
        let linked_proof = prove_linked(&linked_parameters, &fixture, &mut rng)?;
        let linked_prove_ms = milliseconds(started);
        let started = Instant::now();
        verify_linked(&linked_parameters, &fixture, &linked_proof)?;
        let linked_verify_ms = milliseconds(started);

        let mut inline_mutations_rejected = 0usize;
        let mut linked_mutations_rejected = 0usize;
        let core_inputs = core_public_inputs(&fixture);
        let membership_inputs = membership_public_inputs(&fixture);
        for index in 0..inline_inputs.len() {
            let mut changed = inline_inputs.clone();
            changed[index] += Fr::from(1u64);
            if !Groth16::<Bls12_381>::verify(&inline_vk, &changed, &inline_proof)
                .map_err(|error| error.to_string())?
            {
                inline_mutations_rejected += 1;
            }
            if verify_linked_inputs(
                &linked_parameters,
                &changed,
                &membership_inputs,
                &linked_proof,
            )
            .is_err()
            {
                linked_mutations_rejected += 1;
            }
        }
        require(
            inline_mutations_rejected == inline_inputs.len(),
            "all inline public mutations rejected",
        )?;
        require(
            linked_mutations_rejected == core_inputs.len(),
            "all linked core public mutations rejected",
        )?;
        let changed_membership = vec![membership_inputs[0] + Fr::from(1u64)];
        require(
            verify_linked_inputs(
                &linked_parameters,
                &core_inputs,
                &changed_membership,
                &linked_proof,
            )
            .is_err(),
            "linked state root mutation rejected",
        )?;

        let second_linked = prove_linked(&linked_parameters, &fixture, &mut rng)?;
        let spliced = LinkedProof {
            core: linked_proof.core.clone(),
            membership: second_linked.membership,
        };
        require(
            verify_linked(&linked_parameters, &fixture, &spliced).is_err(),
            "cross-presentation commitment splice rejected",
        )?;

        let prefix = output.join(format!("rep-{repetition}"));
        fs::create_dir_all(&prefix).map_err(|error| error.to_string())?;
        let artifacts = [
            ("inline-pk.bin", encoded(&inline_pk)?),
            ("inline-vk.bin", encoded(&inline_vk)?),
            ("inline-proof.bin", encoded(&inline_proof)?),
            ("linked-core-pk.bin", encoded(&linked_parameters.core)?),
            (
                "linked-membership-pk.bin",
                encoded(&linked_parameters.membership)?,
            ),
            ("linked-core-proof.bin", encoded(&linked_proof.core)?),
            (
                "linked-membership-proof.bin",
                encoded(&linked_proof.membership)?,
            ),
        ];
        let mut sizes = serde_json::Map::new();
        for (name, bytes) in artifacts {
            sizes.insert(name.into(), json!(bytes.len()));
            fs::write(prefix.join(name), bytes).map_err(|error| error.to_string())?;
        }
        let linked_proof_bytes = sizes["linked-core-proof.bin"].as_u64().unwrap()
            + sizes["linked-membership-proof.bin"].as_u64().unwrap();
        samples.push(json!({
            "repetition": repetition,
            "relation_metrics": relation_metrics,
            "inline": {
                "setup_ms": inline_setup_ms,
                "prove_ms": inline_prove_ms,
                "verify_ms": inline_verify_ms,
                "proof_bytes": sizes["inline-proof.bin"],
                "pk_bytes": sizes["inline-pk.bin"],
                "vk_bytes": sizes["inline-vk.bin"],
            },
            "poseidon_state_split_legogroth16": {
                "setup_ms_total": linked_setup_ms,
                "prove_ms_total": linked_prove_ms,
                "verify_ms_total": linked_verify_ms,
                "proof_bundle_bytes": linked_proof_bytes,
                "core_pk_bytes": sizes["linked-core-pk.bin"],
                "membership_pk_bytes": sizes["linked-membership-pk.bin"],
            },
        }));
        checks.push(json!({
            "repetition": repetition,
            "inline_public_mutations_rejected": inline_mutations_rejected,
            "linked_core_public_mutations_rejected": linked_mutations_rejected,
            "linked_root_mutation_rejected": true,
            "cross_presentation_splice_rejected": true,
        }));

        if repetition == 0 {
            for active in 1..=3 {
                let other = fixed::<3>(active, 2000 + active as u64, 20, 20, 32);
                let inline = Groth16::<Bls12_381>::prove(&inline_pk, other.clone(), &mut rng)
                    .map_err(|error| error.to_string())?;
                require(
                    Groth16::<Bls12_381>::verify(&inline_vk, &public_inputs(&other), &inline)
                        .map_err(|error| error.to_string())?,
                    "inline same CRS across enabled lengths",
                )?;
                let linked = prove_linked(&linked_parameters, &other, &mut rng)?;
                verify_linked(&linked_parameters, &other, &linked)?;
            }
            checks.push(json!({"same_crs_enabled_lengths":[1,2,3],"pass":true}));
        }
    }

    let result = json!({
        "schema": "plan-a-e8-current-joint-two-backend-v1",
        "status": "success",
        "scope": "native 23-field Joint reference versus full logical Joint split into core and Poseidon state membership, linked on hidden (state_leaf,position) with current-stack LegoGroth16",
        "not_in_scope": [
            "CP/RSA backend",
            "certified-state-map augmented three-backend relation",
            "production setup ceremony",
            "publication-grade conclusion before retained review"
        ],
        "fresh_setup_repetitions": repetitions,
        "checks": checks,
        "samples": samples,
    });
    fs::write(
        output.join("results.json"),
        serde_json::to_vec_pretty(&result).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    println!(
        "{}",
        json!({"ok":true,"output":output,"repetitions":repetitions})
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
