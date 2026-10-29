//! Reproducible, raw-observation benchmark for the minimal HRADA M3 backend.
//!
//! Protocol setup is performed exactly once and reported separately. Each
//! online sample records preparation, component and end-to-end stages. Warmups and failed
//! samples are retained in the CSV; the process exits unsuccessfully only
//! after both artifacts have been written.

use accumulator::{
    group::{ElemToBytes, Group, Rsa2048, UnknownOrderGroup},
    Accumulator, AccumulatorWithoutHashToPrime,
};
use ark_bls12_381::{Bls12_381, G1Projective};
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2s, Digest};
use cpsnarks_set::{
    commitments::Commitment,
    parameters::Parameters,
    protocols::{
        abac_link::{self, AbacPolicy, AbacProverInput, AbacRequest, M3HashParameters},
        hash_to_prime::snark_hash::Protocol as HashProtocol,
        membership::{
            transcript::{TranscriptProverChannel, TranscriptVerifierChannel},
            Proof as MembershipProofGeneric, Protocol as MembershipProtocol,
            Statement as MembershipStatement, Witness as MembershipWitness, CRS as MembershipCrs,
        },
    },
    utils::integer_to_bytes,
};
use merlin::Transcript;
use rand::{rngs::StdRng, SeedableRng};
use rug::{rand::RandState, Integer};
use serde::Serialize;
use serde_json::json;
use std::{
    cell::RefCell,
    convert::{TryFrom, TryInto},
    env,
    error::Error,
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const TRANSCRIPT_LABEL: &[u8] = b"hrada-m3-membership-v1";
const CP_ENCODING: &str = "hrada-cp-experimental-v1";
const LEGO_ENCODING: &str = "ark-canonical-serialize-v1";

type Hp = HashProtocol<Bls12_381, M3HashParameters>;
type Membership = MembershipProtocol<Rsa2048, G1Projective, Hp>;
type MembershipProof = MembershipProofGeneric<Rsa2048, G1Projective, Hp>;
type MembershipCr = MembershipCrs<Rsa2048, G1Projective, Hp>;
type LegoProof = legogro16::Proof<Bls12_381>;
type RsaElem = <Rsa2048 as Group>::Elem;

#[derive(Debug)]
struct Config {
    runs: usize,
    warmups: usize,
    tail_runs: usize,
    tail_warmups: usize,
    policy_variants: usize,
    seed: u64,
    output: PathBuf,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Observation {
    schema_version: u32,
    run_id: usize,
    sample_id: String,
    is_warmup: bool,
    policy_variant: usize,
    policy_resource: u16,
    policy_action: u16,
    policy_epoch: u32,
    policy_agent_id: u32,
    authorization_population: usize,
    stage: String,
    elapsed_ns: u64,
    accepted: bool,
    error: String,
    proof_bytes: u64,
    cp_proof_bytes: u64,
    lego_proof_bytes: u64,
    total_proof_bytes: u64,
    setup_included: bool,
    seed: u64,
    params_hash: String,
    link_params_hash: String,
    params_hash_scope: String,
    source_hash: String,
    proof_encoding: String,
}

#[derive(Clone)]
struct PolicyContext {
    variant_id: usize,
    policy: AbacPolicy,
    message: Integer,
    prime: Integer,
    hash_to_prime_index: u64,
    accumulator_value: RsaElem,
    membership_witness: RsaElem,
    accumulator_state_hash: String,
}

struct Timed<T> {
    value: Result<T, String>,
    elapsed_ns: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("m3-min benchmark failed: {}", error);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = parse_args(env::args().skip(1))?;
    ensure_output_parent(&config.output)?;
    let environment_path = environment_path(&config.output);
    let manifest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_files = [
        "src/protocols/abac_link.rs",
        "src/bin/m3_min_benchmark.rs",
        "Cargo.toml",
        "Cargo.lock",
    ];
    let source_hashes = source_files
        .iter()
        .map(|relative| {
            let hash = hash_file(&manifest_root.join(relative))?;
            Ok((relative.to_string(), hash))
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let source_hash = aggregate_source_hash(&source_hashes);

    let system_parameters = Parameters::from_security_level(128)
        .map_err(|error| format!("system parameters: {:?}", error))?;
    let mut setup_rng1 = seeded_rug(config.seed, b"setup-rug");
    let mut setup_rng2 = seeded_std(config.seed, b"setup-rust");
    let setup_started = Instant::now();
    let cp_setup_started = Instant::now();
    let membership = Membership::setup(&system_parameters, &mut setup_rng1, &mut setup_rng2)
        .map_err(|error| format!("CP-RSA setup: {:?}", error))?;
    let cp_setup_elapsed_ns = elapsed_ns(cp_setup_started);
    let cp_pedersen = &membership.crs.crs_modeq.pedersen_commitment_parameters;
    let abac_setup_started = Instant::now();
    let abac_parameters = abac_link::setup(
        &mut setup_rng2,
        cp_pedersen,
        system_parameters.security_level,
        system_parameters.hash_to_prime_bits,
    )
    .map_err(|error| format!("ABAC setup: {:?}", error))?;
    let abac_setup_elapsed_ns = elapsed_ns(abac_setup_started);
    let setup_elapsed_ns = elapsed_ns(setup_started);
    let parameter_digest = abac_link::parameter_digest(&abac_parameters, cp_pedersen)
        .map_err(|error| format!("parameter digest: {:?}", error))?;
    let link_params_hash = hex(&parameter_digest);
    let rsa_modulus_hash =
        hash_integer(&Rsa2048::rsa_modulus().map_err(|error| format!("RSA modulus: {:?}", error))?);
    let cp_crs_hash = cp_crs_hash(&membership)?;
    let params_hash = hash_named_values(&[
        ("domain", "HRADA-M3-FULL-PROTOCOL-PARAMETERS-V1"),
        ("rsaModulus", &rsa_modulus_hash),
        ("cpCrs", &cp_crs_hash),
        ("abacLink", &link_params_hash),
        ("accumulatorMode", "Rsa2048/AccumulatorWithoutHashToPrime"),
    ]);

    // Prepare several semantically distinct policies before online timing.
    // Each variant has its own valid hidden member and accumulator statement;
    // setup/issuance is deliberately excluded from the online microbenchmark.
    let mut policy_contexts = Vec::with_capacity(config.policy_variants);
    for variant_id in 0..config.policy_variants {
        let variant = u32::try_from(variant_id).map_err(|_| "policy variant overflow")?;
        let policy = AbacPolicy {
            resource: u16::try_from(7 + variant * 13).map_err(|_| "policy resource overflow")?,
            action: u16::try_from(3 + variant * 7).map_err(|_| "policy action overflow")?,
            epoch: 42 + variant,
            agent_id: 9_001 + variant * 17,
            serial: 11 + variant,
        };
        let message = policy.packed_message();
        let (prime, hash_to_prime_index) = membership
            .hash_to_prime(&message)
            .map_err(|error| format!("hash to prime for variant {}: {:?}", variant_id, error))?;
        let accumulator_member =
            Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty()
                .add(&[Integer::from(65_537), Integer::from(65_539)])
                .add_with_proof(&[prime.clone()]);
        let accumulator_value = accumulator_member.0.value;
        let membership_witness = accumulator_member.1.witness.0.value;
        let accumulator_state_hash = hex(&Blake2s::digest(
            &<Rsa2048 as ElemToBytes>::elem_to_bytes(&accumulator_value),
        ));
        policy_contexts.push(PolicyContext {
            variant_id,
            policy,
            message,
            prime,
            hash_to_prime_index,
            accumulator_value,
            membership_witness,
            accumulator_state_hash,
        });
    }

    let total_samples = config.warmups + config.runs;
    let mut observations =
        Vec::with_capacity(total_samples * 7 + config.tail_runs + config.tail_warmups);
    let mut failed_samples = 0usize;
    let mut successful_samples = 0usize;
    let mut tail_failed_samples = 0usize;
    let mut tail_successful_samples = 0usize;

    for run_id in 0..total_samples {
        let policy_context = &policy_contexts[run_id % policy_contexts.len()];
        let policy = policy_context.policy;
        let is_warmup = run_id < config.warmups;
        let sample_id = if is_warmup {
            format!("W{:04}", run_id)
        } else {
            format!("R{:04}", run_id - config.warmups)
        };
        let sample_seed = derive_u64(config.seed, sample_id.as_bytes());
        let request = AbacRequest {
            resource: policy.resource,
            action: policy.action,
            epoch: policy.epoch,
            agent_id: policy.agent_id,
            nonce: derive_u64(sample_seed, b"nonce"),
        };

        // A fresh Pedersen opening per request is mandatory: reusing rho would
        // make C_p linkable even though p remains hidden.
        let statement_prepare_timed = timed(|| {
            let commitment_randomness =
                deterministic_integer(sample_seed, b"commitment-randomness");
            let member_commitment = cp_pedersen
                .commit(&policy_context.prime, &commitment_randomness)
                .map_err(|error| format!("member commitment: {:?}", error))?;
            Ok((
                commitment_randomness,
                MembershipStatement {
                    c_p: policy_context.accumulator_value.clone(),
                    c_e_q: member_commitment,
                },
            ))
        });

        let mut cp_rng1 = seeded_rug(sample_seed, b"cp-rug");
        let mut cp_rng2 = seeded_std(sample_seed, b"cp-rust");
        let joint_prove_started = Instant::now();
        let cp_timed = timed(|| match &statement_prepare_timed.value {
            Ok((commitment_randomness, statement)) => create_membership_proof(
                &membership,
                &mut cp_rng1,
                &mut cp_rng2,
                statement,
                policy_context.message.clone(),
                commitment_randomness.clone(),
                policy_context.membership_witness.clone(),
            ),
            Err(error) => Err(format!("statement unavailable: {}", error)),
        });

        let mut lego_rng = seeded_std(sample_seed, b"lego-rust");
        let lego_timed = timed(|| match &statement_prepare_timed.value {
            Ok((commitment_randomness, _)) => abac_link::prove(
                &mut lego_rng,
                &abac_parameters,
                AbacProverInput {
                    security_level: system_parameters.security_level,
                    required_prime_bits: system_parameters.hash_to_prime_bits,
                    prime: &policy_context.prime,
                    commitment_randomness,
                    hash_to_prime_index: policy_context.hash_to_prime_index,
                    request,
                    policy,
                },
            )
            .map_err(|error| format!("{:?}", error)),
            Err(error) => Err(format!("statement unavailable: {}", error)),
        });
        let joint_prove_elapsed_ns = elapsed_ns(joint_prove_started);

        let cp_verify_timed = timed(|| match (&cp_timed.value, &statement_prepare_timed.value) {
            (Ok(proof), Ok((_, statement))) => {
                Ok(verify_membership(&membership.crs, proof, statement))
            }
            (Err(error), _) => Err(format!("CP proof unavailable: {}", error)),
            (_, Err(error)) => Err(format!("statement unavailable: {}", error)),
        });
        let abac_link_verify_timed =
            timed(
                || match (&lego_timed.value, &statement_prepare_timed.value) {
                    (Ok(proof), Ok((_, statement))) => abac_link::verify(
                        &abac_parameters,
                        proof,
                        request,
                        &statement.c_e_q,
                        cp_pedersen,
                        &parameter_digest,
                    )
                    .map_err(|error| format!("{:?}", error)),
                    (Err(error), _) => Err(format!("Lego proof unavailable: {}", error)),
                    (_, Err(error)) => Err(format!("statement unavailable: {}", error)),
                },
            );
        // This is a real end-to-end verifier invocation, not a sum of the two
        // component measurements above.
        let joint_verify_timed = timed(|| {
            match (
                &cp_timed.value,
                &lego_timed.value,
                &statement_prepare_timed.value,
            ) {
                (Ok(cp_proof), Ok(lego_proof), Ok((_, statement))) => {
                    let cp_accepted = verify_membership(&membership.crs, cp_proof, statement);
                    let link_accepted = abac_link::verify(
                        &abac_parameters,
                        lego_proof,
                        request,
                        &statement.c_e_q,
                        cp_pedersen,
                        &parameter_digest,
                    )
                    .map_err(|error| format!("{:?}", error))?;
                    Ok(cp_accepted && link_accepted)
                }
                (Err(error), _, _) => Err(format!("CP proof unavailable: {}", error)),
                (_, Err(error), _) => Err(format!("Lego proof unavailable: {}", error)),
                (_, _, Err(error)) => Err(format!("statement unavailable: {}", error)),
            }
        });

        let cp_encoding = cp_timed
            .value
            .as_ref()
            .map_err(Clone::clone)
            .and_then(encode_cp_proof);
        let lego_encoding = lego_timed
            .value
            .as_ref()
            .map_err(Clone::clone)
            .and_then(encode_lego_proof);
        let cp_bytes = cp_encoding
            .as_ref()
            .map(|bytes| bytes.len() as u64)
            .unwrap_or(0);
        let lego_bytes = lego_encoding
            .as_ref()
            .map(|bytes| bytes.len() as u64)
            .unwrap_or(0);
        let total_bytes = cp_bytes.saturating_add(lego_bytes);

        let cp_prove_status = combine_prove_status(&cp_timed.value, &cp_encoding);
        let lego_prove_status = combine_prove_status(&lego_timed.value, &lego_encoding);
        let statement_status = result_status(&statement_prepare_timed.value);
        let joint_prove_status = combine_statuses(&cp_prove_status, &lego_prove_status);
        let stage_results = [
            (
                "statement_prepare",
                statement_prepare_timed.elapsed_ns,
                statement_status,
                0,
            ),
            (
                "cp_rsa_prove",
                cp_timed.elapsed_ns,
                cp_prove_status,
                cp_bytes,
            ),
            (
                "lego_abac_prove",
                lego_timed.elapsed_ns,
                lego_prove_status,
                lego_bytes,
            ),
            (
                "joint_prove",
                joint_prove_elapsed_ns,
                joint_prove_status,
                total_bytes,
            ),
            (
                "cp_rsa_verify",
                cp_verify_timed.elapsed_ns,
                bool_status(&cp_verify_timed.value),
                cp_bytes,
            ),
            (
                "abac_link_verify",
                abac_link_verify_timed.elapsed_ns,
                bool_status(&abac_link_verify_timed.value),
                total_bytes,
            ),
            (
                "joint_verify",
                joint_verify_timed.elapsed_ns,
                bool_status(&joint_verify_timed.value),
                total_bytes,
            ),
        ];
        let sample_accepted = stage_results
            .iter()
            .all(|(_, _, (accepted, _), _)| *accepted);
        if sample_accepted {
            successful_samples += 1;
        } else {
            failed_samples += 1;
        }
        for (stage, stage_elapsed_ns, (accepted, error), proof_bytes) in stage_results {
            observations.push(Observation {
                schema_version: 1,
                run_id,
                sample_id: sample_id.clone(),
                is_warmup,
                policy_variant: policy_context.variant_id,
                policy_resource: policy.resource,
                policy_action: policy.action,
                policy_epoch: policy.epoch,
                policy_agent_id: policy.agent_id,
                authorization_population: 3,
                stage: stage.to_string(),
                elapsed_ns: stage_elapsed_ns,
                accepted,
                error,
                proof_bytes,
                cp_proof_bytes: cp_bytes,
                lego_proof_bytes: lego_bytes,
                total_proof_bytes: total_bytes,
                setup_included: false,
                seed: sample_seed,
                params_hash: params_hash.clone(),
                link_params_hash: link_params_hash.clone(),
                params_hash_scope: "RSA modulus + complete distinct CP CRS fields + ABAC link parameters + accumulator mode".to_string(),
                source_hash: source_hash.clone(),
                proof_encoding: format!("cp={};lego={}", CP_ENCODING, LEGO_ENCODING),
            });
        }
    }

    // Tail-latency suite: precompute one valid proof, then time verifier-only
    // invocations. This deliberately excludes proof generation and mirrors a
    // service that repeatedly verifies already received authorization proofs.
    let tail_total = config.tail_warmups + config.tail_runs;
    if tail_total > 0 {
        let policy_context = &policy_contexts[0];
        let policy = policy_context.policy;
        let tail_proof_seed = derive_u64(config.seed, b"tail-proof");
        let request = AbacRequest {
            resource: policy.resource,
            action: policy.action,
            epoch: policy.epoch,
            agent_id: policy.agent_id,
            nonce: derive_u64(tail_proof_seed, b"nonce"),
        };
        let commitment_randomness =
            deterministic_integer(tail_proof_seed, b"commitment-randomness");
        let member_commitment = cp_pedersen
            .commit(&policy_context.prime, &commitment_randomness)
            .map_err(|error| format!("tail member commitment: {:?}", error))?;
        let statement = MembershipStatement {
            c_p: policy_context.accumulator_value.clone(),
            c_e_q: member_commitment,
        };
        let mut cp_rng1 = seeded_rug(tail_proof_seed, b"cp-rug");
        let mut cp_rng2 = seeded_std(tail_proof_seed, b"cp-rust");
        let cp_proof = create_membership_proof(
            &membership,
            &mut cp_rng1,
            &mut cp_rng2,
            &statement,
            policy_context.message.clone(),
            commitment_randomness.clone(),
            policy_context.membership_witness.clone(),
        )?;
        let mut lego_rng = seeded_std(tail_proof_seed, b"lego-rust");
        let lego_proof = abac_link::prove(
            &mut lego_rng,
            &abac_parameters,
            AbacProverInput {
                security_level: system_parameters.security_level,
                required_prime_bits: system_parameters.hash_to_prime_bits,
                prime: &policy_context.prime,
                commitment_randomness: &commitment_randomness,
                hash_to_prime_index: policy_context.hash_to_prime_index,
                request,
                policy,
            },
        )
        .map_err(|error| format!("tail Lego proof: {:?}", error))?;
        let cp_bytes = encode_cp_proof(&cp_proof)?.len() as u64;
        let lego_bytes = encode_lego_proof(&lego_proof)?.len() as u64;
        let total_bytes = cp_bytes.saturating_add(lego_bytes);

        for tail_id in 0..tail_total {
            let is_warmup = tail_id < config.tail_warmups;
            let sample_id = if is_warmup {
                format!("TW{:04}", tail_id)
            } else {
                format!("T{:04}", tail_id - config.tail_warmups)
            };
            let measured = timed(|| {
                let cp_accepted = verify_membership(&membership.crs, &cp_proof, &statement);
                let link_accepted = abac_link::verify(
                    &abac_parameters,
                    &lego_proof,
                    request,
                    &statement.c_e_q,
                    cp_pedersen,
                    &parameter_digest,
                )
                .map_err(|error| format!("{:?}", error))?;
                Ok(cp_accepted && link_accepted)
            });
            let (accepted, error) = bool_status(&measured.value);
            if accepted {
                tail_successful_samples += 1;
            } else {
                tail_failed_samples += 1;
            }
            observations.push(Observation {
                schema_version: 1,
                run_id: total_samples + tail_id,
                sample_id,
                is_warmup,
                policy_variant: policy_context.variant_id,
                policy_resource: policy.resource,
                policy_action: policy.action,
                policy_epoch: policy.epoch,
                policy_agent_id: policy.agent_id,
                authorization_population: 3,
                stage: "joint_verify_tail".to_string(),
                elapsed_ns: measured.elapsed_ns,
                accepted,
                error,
                proof_bytes: total_bytes,
                cp_proof_bytes: cp_bytes,
                lego_proof_bytes: lego_bytes,
                total_proof_bytes: total_bytes,
                setup_included: false,
                seed: tail_proof_seed,
                params_hash: params_hash.clone(),
                link_params_hash: link_params_hash.clone(),
                params_hash_scope: "RSA modulus + complete distinct CP CRS fields + ABAC link parameters + accumulator mode".to_string(),
                source_hash: source_hash.clone(),
                proof_encoding: format!("cp={};lego={}", CP_ENCODING, LEGO_ENCODING),
            });
        }
    }

    write_csv(&config.output, &observations)?;
    let csv_hash = hash_file(&config.output)?;
    let artifact = json!({
        "schemaVersion": 1,
        "recordedAtUnixMs": u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()).unwrap_or(u64::MAX),
        "benchmark": "HRADA-M3-min-joint-proof",
        "config": {
            "runs": config.runs,
            "warmups": config.warmups,
            "tailRuns": config.tail_runs,
            "tailWarmups": config.tail_warmups,
            "tailProofPrecomputed": true,
            "policyVariants": config.policy_variants,
            "seed": config.seed,
            "setupPerInvocation": 1,
            "setupIncludedInOnlineStages": false
        },
        "environment": {
            "os": env::consts::OS,
            "arch": env::consts::ARCH,
            "rustc": command_output("rustc", &["--version", "--verbose"]),
            "cargo": command_output("cargo", &["--version"]),
            "uname": command_output("uname", &["-a"]),
            "gitCommit": command_output("git", &["rev-parse", "HEAD"]),
            "gitStatusShort": command_output("git", &["status", "--short"])
        },
        "setup": {
            "elapsedNs": setup_elapsed_ns,
            "cpSetupElapsedNs": cp_setup_elapsed_ns,
            "abacSetupElapsedNs": abac_setup_elapsed_ns,
            "securityLevel": system_parameters.security_level,
            "hashToPrimeBits": system_parameters.hash_to_prime_bits,
            "paramsHash": params_hash,
            "paramsHashScope": "RSA modulus + complete distinct CP CRS fields + ABAC link parameters + accumulator mode",
            "linkParamsHash": link_params_hash,
            "linkParamsHashScope": "CP Pedersen bases + complete ABAC Lego verification key",
            "rsaModulusHash": rsa_modulus_hash,
            "cpCrsHash": cp_crs_hash,
            "cpCrsHashScope": "security scalar parameters + integer commitment bases + Pedersen bases + complete CP hash-to-prime Lego proving key",
            "accumulatorMode": "Rsa2048/AccumulatorWithoutHashToPrime",
            "authorizationPopulationPerVariant": 3,
            "accumulatorStateHashes": policy_contexts.iter().map(|context| json!({
                "policyVariant": context.variant_id,
                "blake2s256": context.accumulator_state_hash,
            })).collect::<Vec<_>>()
        },
        "encoding": {
            "cpProof": CP_ENCODING,
            "cpProofNotes": "Deterministic experimental wire encoding: domain tag; fixed field order; u64-le length-prefixed values; signed big-endian GMP integers; Rsa2048 ElemToBytes; ark CanonicalSerialize for curve, scalar, and embedded Lego proof.",
            "legoProof": LEGO_ENCODING,
            "proofBytesDefinition": "cpProofBytes and legoProofBytes count encoded proof objects only; totalProofBytes is their sum and excludes statements, CRS, accumulator state, CSV framing, and setup artifacts."
        },
        "sources": {
            "aggregateAlgorithm": "Blake2s-256(domain || path || fileHash)",
            "aggregateHash": source_hash,
            "files": source_hashes.iter().map(|(path, hash)| json!({"path": path, "blake2s256": hash})).collect::<Vec<_>>()
        },
        "artifacts": {
            "observationsCsv": config.output.to_string_lossy(),
            "observationsCsvBlake2s256": csv_hash,
            "rows": observations.len(),
            "onlineSamples": total_samples,
            "successfulOnlineSamples": successful_samples,
            "failedOnlineSamples": failed_samples,
            "tailVerificationSamples": tail_total,
            "successfulTailVerificationSamples": tail_successful_samples,
            "failedTailVerificationSamples": tail_failed_samples,
            "failureRowsRetained": true
        },
        "dependencies": {
            "cargoLocked": true,
            "cargoLockBlake2s256": source_hashes.iter().find(|(path, _)| path == "Cargo.lock").map(|(_, hash)| hash)
        }
    });
    fs::write(&environment_path, serde_json::to_vec_pretty(&artifact)?)?;

    println!("observations={}", config.output.display());
    println!("environment={}", environment_path.display());
    println!(
        "rows={} successful_online={} failed_online={} successful_tail={} failed_tail={}",
        observations.len(),
        successful_samples,
        failed_samples,
        tail_successful_samples,
        tail_failed_samples
    );
    if failed_samples > 0 || tail_failed_samples > 0 {
        return Err(format!(
            "{} online and {} tail sample(s) failed; artifacts were retained",
            failed_samples, tail_failed_samples
        )
        .into());
    }
    Ok(())
}

fn parse_args<I>(mut args: I) -> Result<Config, String>
where
    I: Iterator<Item = String>,
{
    let mut config = Config {
        runs: 10,
        warmups: 3,
        tail_runs: 0,
        tail_warmups: 0,
        policy_variants: 1,
        seed: 20_260_805,
        output: PathBuf::from("results/raw/m3_min_observations.csv"),
    };
    while let Some(argument) = args.next() {
        if argument == "--help" || argument == "-h" {
            println!(
                "usage: m3_min_benchmark [--runs N] [--warmups N] [--tail-runs N] [--tail-warmups N] [--policy-variants N] [--seed U64] [--output FILE.csv]"
            );
            std::process::exit(0);
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {}", argument))?;
        match argument.as_str() {
            "--runs" => config.runs = parse_value(&argument, &value)?,
            "--warmups" => config.warmups = parse_value(&argument, &value)?,
            "--tail-runs" => config.tail_runs = parse_value(&argument, &value)?,
            "--tail-warmups" => config.tail_warmups = parse_value(&argument, &value)?,
            "--policy-variants" => config.policy_variants = parse_value(&argument, &value)?,
            "--seed" => config.seed = parse_value(&argument, &value)?,
            "--output" => config.output = PathBuf::from(value),
            _ => return Err(format!("unknown argument: {}", argument)),
        }
    }
    if config.runs == 0 {
        return Err("--runs must be greater than zero".to_string());
    }
    if config.policy_variants == 0 || config.policy_variants > 1_024 {
        return Err("--policy-variants must be in 1..=1024".to_string());
    }
    if config.output.extension().and_then(|value| value.to_str()) != Some("csv") {
        return Err("--output must name a .csv file".to_string());
    }
    Ok(config)
}

fn parse_value<T: std::str::FromStr>(name: &str, value: &str) -> Result<T, String> {
    value
        .parse()
        .map_err(|_| format!("invalid value for {}: {}", name, value))
}

fn ensure_output_parent(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    Ok(())
}

fn environment_path(csv: &Path) -> PathBuf {
    let stem = csv
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("m3_min_observations");
    csv.with_file_name(format!("{}.environment.json", stem))
}

fn timed<T, F>(operation: F) -> Timed<T>
where
    F: FnOnce() -> Result<T, String>,
{
    let started = Instant::now();
    let value = operation();
    Timed {
        value,
        elapsed_ns: elapsed_ns(started),
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn create_membership_proof(
    protocol: &Membership,
    rng1: &mut RandState,
    rng2: &mut StdRng,
    statement: &MembershipStatement<Rsa2048, G1Projective>,
    message: Integer,
    randomness: Integer,
    witness: <Rsa2048 as Group>::Elem,
) -> Result<MembershipProof, String> {
    let transcript = RefCell::new(Transcript::new(TRANSCRIPT_LABEL));
    let mut channel = TranscriptVerifierChannel::new(&protocol.crs, &transcript);
    protocol
        .prove(
            &mut channel,
            rng1,
            rng2,
            statement,
            &MembershipWitness {
                e: message,
                r_q: randomness,
                w: witness,
            },
        )
        .map_err(|error| format!("{:?}", error))?;
    channel.proof().map_err(|error| format!("{:?}", error))
}

fn verify_membership(
    crs: &MembershipCr,
    proof: &MembershipProof,
    statement: &MembershipStatement<Rsa2048, G1Projective>,
) -> bool {
    let transcript = RefCell::new(Transcript::new(TRANSCRIPT_LABEL));
    let mut channel = TranscriptProverChannel::new(crs, &transcript, proof);
    Membership::from_crs(crs)
        .verify(&mut channel, statement)
        .is_ok()
}

fn bool_status(result: &Result<bool, String>) -> (bool, String) {
    match result {
        Ok(true) => (true, String::new()),
        Ok(false) => (false, "verification returned false".to_string()),
        Err(error) => (false, error.clone()),
    }
}

fn result_status<T>(result: &Result<T, String>) -> (bool, String) {
    match result {
        Ok(_) => (true, String::new()),
        Err(error) => (false, error.clone()),
    }
}

fn combine_statuses(left: &(bool, String), right: &(bool, String)) -> (bool, String) {
    if left.0 && right.0 {
        return (true, String::new());
    }
    let errors = [&left.1, &right.1]
        .iter()
        .filter(|error| !error.is_empty())
        .map(|error| error.as_str())
        .collect::<Vec<_>>()
        .join("; ");
    (false, errors)
}

fn combine_prove_status<T>(
    proof: &Result<T, String>,
    encoding: &Result<Vec<u8>, String>,
) -> (bool, String) {
    match (proof, encoding) {
        (Err(error), _) => (false, error.clone()),
        (Ok(_), Err(error)) => (false, format!("proof serialization: {}", error)),
        (Ok(_), Ok(_)) => (true, String::new()),
    }
}

fn encode_cp_proof(proof: &MembershipProof) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    append_bytes(&mut output, CP_ENCODING.as_bytes());
    append_rsa(&mut output, &proof.c_e);
    append_rsa(&mut output, &proof.proof_root.message1.c_w);
    append_rsa(&mut output, &proof.proof_root.message1.c_r);
    append_rsa(&mut output, &proof.proof_root.message2.alpha1);
    append_rsa(&mut output, &proof.proof_root.message2.alpha2);
    append_rsa(&mut output, &proof.proof_root.message2.alpha3);
    append_rsa(&mut output, &proof.proof_root.message2.alpha4);
    append_integer(&mut output, &proof.proof_root.message3.s_e);
    append_integer(&mut output, &proof.proof_root.message3.s_r);
    append_integer(&mut output, &proof.proof_root.message3.s_r_2);
    append_integer(&mut output, &proof.proof_root.message3.s_r_3);
    append_integer(&mut output, &proof.proof_root.message3.s_beta);
    append_integer(&mut output, &proof.proof_root.message3.s_delta);
    append_rsa(&mut output, &proof.proof_modeq.message1.alpha1);
    append_canonical(&mut output, &proof.proof_modeq.message1.alpha2)?;
    append_integer(&mut output, &proof.proof_modeq.message2.s_e);
    append_integer(&mut output, &proof.proof_modeq.message2.s_r);
    append_canonical(&mut output, &proof.proof_modeq.message2.s_r_q)?;
    append_canonical(&mut output, &proof.proof_hash_to_prime)?;
    Ok(output)
}

fn encode_lego_proof(proof: &LegoProof) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    append_canonical(&mut output, proof)?;
    Ok(output)
}

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

fn append_rsa(output: &mut Vec<u8>, value: &<Rsa2048 as Group>::Elem) {
    append_bytes(output, &<Rsa2048 as ElemToBytes>::elem_to_bytes(value));
}

fn append_integer(output: &mut Vec<u8>, value: &Integer) {
    let sign = if value == &0 {
        0u8
    } else if value < &0 {
        2u8
    } else {
        1u8
    };
    let magnitude = value.clone().abs();
    output.push(sign);
    append_bytes(output, &integer_to_bytes(&magnitude));
}

fn append_canonical<T: CanonicalSerialize>(output: &mut Vec<u8>, value: &T) -> Result<(), String> {
    let mut encoded = Vec::new();
    value
        .serialize(&mut encoded)
        .map_err(|error| format!("{:?}", error))?;
    append_bytes(output, &encoded);
    Ok(())
}

fn seeded_std(seed: u64, domain: &[u8]) -> StdRng {
    StdRng::from_seed(derive_digest(seed, domain))
}

fn seeded_rug(seed: u64, domain: &[u8]) -> RandState<'static> {
    let digest = derive_digest(seed, domain);
    let mut rng = RandState::new();
    rng.seed(&Integer::from_digits(&digest, rug::integer::Order::MsfBe));
    rng
}

fn deterministic_integer(seed: u64, domain: &[u8]) -> Integer {
    let mut digest = derive_digest(seed, domain);
    digest[0] &= 0x3f;
    digest[0] |= 0x20;
    Integer::from_digits(&digest, rug::integer::Order::MsfBe)
}

fn derive_u64(seed: u64, domain: &[u8]) -> u64 {
    let digest = derive_digest(seed, domain);
    u64::from_le_bytes(digest[..8].try_into().expect("fixed digest width"))
}

fn derive_digest(seed: u64, domain: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s::new();
    hasher.update(b"HRADA-M3-BENCH-SEED-V1");
    hasher.update(&seed.to_le_bytes());
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn write_csv(path: &Path, observations: &[Observation]) -> Result<(), Box<dyn Error>> {
    let file = File::create(path)?;
    let mut writer = csv::WriterBuilder::new()
        .has_headers(true)
        .from_writer(file);
    for observation in observations {
        writer.serialize(observation)?;
    }
    writer.flush()?;
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, std::io::Error> {
    let contents = fs::read(path)?;
    Ok(hex(&Blake2s::digest(&contents)))
}

fn hash_integer(value: &Integer) -> String {
    hex(&Blake2s::digest(&integer_to_bytes(value)))
}

fn cp_crs_hash(membership: &Membership) -> Result<String, String> {
    let crs = &membership.crs;
    let mut encoded = Vec::new();
    append_bytes(&mut encoded, b"HRADA-M3-CP-CRS-V1");
    for value in [
        crs.parameters.security_level,
        crs.parameters.security_zk,
        crs.parameters.security_soundness,
        crs.parameters.hash_to_prime_bits,
        crs.parameters.field_size_bits,
    ] {
        encoded.extend_from_slice(&value.to_le_bytes());
    }
    append_rsa(&mut encoded, &crs.crs_root.integer_commitment_parameters.g);
    append_rsa(&mut encoded, &crs.crs_root.integer_commitment_parameters.h);
    append_canonical(
        &mut encoded,
        &crs.crs_modeq.pedersen_commitment_parameters.g,
    )?;
    append_canonical(
        &mut encoded,
        &crs.crs_modeq.pedersen_commitment_parameters.h,
    )?;
    append_canonical(
        &mut encoded,
        &crs.crs_hash_to_prime.hash_to_prime_parameters,
    )?;
    Ok(hex(&Blake2s::digest(&encoded)))
}

fn hash_named_values(values: &[(&str, &str)]) -> String {
    let mut hasher = Blake2s::new();
    for (name, value) in values {
        hasher.update(&(name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update(&(value.len() as u64).to_le_bytes());
        hasher.update(value.as_bytes());
    }
    hex(&hasher.finalize())
}

fn aggregate_source_hash(source_hashes: &[(String, String)]) -> String {
    let mut hasher = Blake2s::new();
    hasher.update(b"HRADA-M3-SOURCE-SET-V1");
    for (path, hash) in source_hashes {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(hash.as_bytes());
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
}

fn command_output(program: &str, arguments: &[&str]) -> String {
    match Command::new(program)
        .args(arguments)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
    {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        Ok(output) => format!(
            "unavailable (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => format!("unavailable: {}", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argument_validation_and_environment_name_are_stable() {
        let config = parse_args(
            [
                "--runs",
                "2",
                "--warmups",
                "1",
                "--seed",
                "9",
                "--output",
                "out/raw.csv",
            ]
            .iter()
            .map(|value| value.to_string()),
        )
        .unwrap();
        assert_eq!(config.runs, 2);
        assert_eq!(config.warmups, 1);
        assert_eq!(config.seed, 9);
        assert_eq!(
            environment_path(&config.output),
            PathBuf::from("out/raw.environment.json")
        );
        assert!(parse_args(["--runs", "0"].iter().map(|value| value.to_string())).is_err());
    }

    #[test]
    fn signed_integer_encoding_is_deterministic_and_unambiguous() {
        let mut positive = Vec::new();
        let mut negative = Vec::new();
        let mut positive_again = Vec::new();
        append_integer(&mut positive, &Integer::from(65_537));
        append_integer(&mut negative, &Integer::from(-65_537));
        append_integer(&mut positive_again, &Integer::from(65_537));
        assert_eq!(positive, positive_again);
        assert_ne!(positive, negative);
        assert_eq!(positive[0], 1);
        assert_eq!(negative[0], 2);
    }
}
