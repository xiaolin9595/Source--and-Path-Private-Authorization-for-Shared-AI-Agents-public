//! Same-machine capability baseline inspired by A-PoA's anonymous membership goal.
//!
//! This is deliberately named `A-PoA-style`, not an A-PoA reproduction: it
//! uses this repository's CP-RSA hidden-membership protocol rather than the
//! NI-ZKPoKE construction evaluated in the A-PoA paper.  It proves only that a
//! hidden 128-bit authorization identifier maps to an RSA-accumulator member;
//! it does not bind resource, action, epoch, agent id, or nonce.

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
        abac_link::M3HashParameters,
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
const BASELINE_NAME: &str = "A-PoA-style CP-RSA membership-only capability baseline";

type Hp = HashProtocol<Bls12_381, M3HashParameters>;
type Membership = MembershipProtocol<Rsa2048, G1Projective, Hp>;
type MembershipProof = MembershipProofGeneric<Rsa2048, G1Projective, Hp>;
type MembershipCr = MembershipCrs<Rsa2048, G1Projective, Hp>;
type RsaElem = <Rsa2048 as Group>::Elem;

#[derive(Debug)]
struct Config {
    runs: usize,
    warmups: usize,
    tail_runs: usize,
    tail_warmups: usize,
    population: usize,
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
    authorization_population: usize,
    stage: String,
    elapsed_ns: u64,
    accepted: bool,
    error: String,
    proof_bytes: u64,
    setup_included: bool,
    seed: u64,
    params_hash: String,
    source_hash: String,
    proof_encoding: String,
}

struct AuthorizationContext {
    identifier: Integer,
    prime: Integer,
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
        eprintln!("A-PoA-style benchmark failed: {}", error);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = parse_args(env::args().skip(1))?;
    ensure_output_parent(&config.output)?;
    let environment_path = environment_path(&config.output);
    let manifest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_files = [
        "src/bin/apoa_style_benchmark.rs",
        "src/protocols/membership/mod.rs",
        "src/protocols/hash_to_prime/snark_hash.rs",
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
    let cp_setup_started = Instant::now();
    let membership = Membership::setup(&system_parameters, &mut setup_rng1, &mut setup_rng2)
        .map_err(|error| format!("CP-RSA setup: {:?}", error))?;
    let cp_setup_elapsed_ns = elapsed_ns(cp_setup_started);

    // Issuance is measured separately and excluded from every online stage.
    // Every accumulator element is a 254-bit prime obtained with the same
    // 128-bit identifier-to-prime mapping used by the proof relation.
    let issuance_started = Instant::now();
    let mut identifiers = Vec::with_capacity(config.population);
    let mut primes = Vec::with_capacity(config.population);
    for member_index in 0..config.population {
        let identifier = deterministic_identifier(config.seed, member_index);
        let (prime, _) = membership
            .hash_to_prime(&identifier)
            .map_err(|error| format!("hash to prime for member {}: {:?}", member_index, error))?;
        identifiers.push(identifier);
        primes.push(prime);
    }
    let target_identifier = identifiers
        .last()
        .ok_or("authorization population unexpectedly empty")?
        .clone();
    let target_prime = primes
        .last()
        .ok_or("authorization prime population unexpectedly empty")?
        .clone();
    let filler_primes = &primes[..primes.len() - 1];
    let accumulator_without_target =
        Accumulator::<Rsa2048, Integer, AccumulatorWithoutHashToPrime>::empty().add(filler_primes);
    let wrong_accumulator_value = accumulator_without_target.value.clone();
    let accumulator_member = accumulator_without_target.add_with_proof(&[target_prime.clone()]);
    let context = AuthorizationContext {
        identifier: target_identifier,
        prime: target_prime,
        accumulator_value: accumulator_member.0.value,
        membership_witness: accumulator_member.1.witness.0.value,
        accumulator_state_hash: String::new(),
    };
    let issuance_elapsed_ns = elapsed_ns(issuance_started);
    let context = AuthorizationContext {
        accumulator_state_hash: hex(&Blake2s::digest(&<Rsa2048 as ElemToBytes>::elem_to_bytes(
            &context.accumulator_value,
        ))),
        ..context
    };

    let rsa_modulus_hash =
        hash_integer(&Rsa2048::rsa_modulus().map_err(|error| format!("RSA modulus: {:?}", error))?);
    let cp_crs_hash = cp_crs_hash(&membership)?;
    let params_hash = hash_named_values(&[
        ("domain", "HRADA-APOA-STYLE-CP-MEMBERSHIP-V1"),
        ("rsaModulus", &rsa_modulus_hash),
        ("cpCrs", &cp_crs_hash),
        ("accumulatorMode", "Rsa2048/AccumulatorWithoutHashToPrime"),
    ]);

    let correctness =
        correctness_gate(&membership, &context, &wrong_accumulator_value, config.seed)?;
    if !correctness.valid_proof_accepted
        || !correctness.wrong_accumulator_rejected
        || !correctness.wrong_commitment_rejected
    {
        return Err("correctness gate failed before timing".into());
    }

    let total_samples = config.warmups + config.runs;
    let tail_total = config.tail_warmups + config.tail_runs;
    let mut observations = Vec::with_capacity(total_samples * 4 + tail_total);
    let mut failed_samples = 0usize;
    let mut successful_samples = 0usize;

    let cp_pedersen = &membership.crs.crs_modeq.pedersen_commitment_parameters;
    for run_id in 0..total_samples {
        let is_warmup = run_id < config.warmups;
        let sample_id = if is_warmup {
            format!("W{:04}", run_id)
        } else {
            format!("R{:04}", run_id - config.warmups)
        };
        let sample_seed = derive_u64(config.seed, sample_id.as_bytes());
        let statement_prepare = timed(|| {
            let randomness = deterministic_randomness(sample_seed, b"commitment-randomness");
            let commitment = cp_pedersen
                .commit(&context.prime, &randomness)
                .map_err(|error| format!("member commitment: {:?}", error))?;
            Ok((
                randomness,
                MembershipStatement {
                    c_p: context.accumulator_value.clone(),
                    c_e_q: commitment,
                },
            ))
        });

        let mut proof_rng1 = seeded_rug(sample_seed, b"cp-rug");
        let mut proof_rng2 = seeded_std(sample_seed, b"cp-rust");
        let authenticate_started = Instant::now();
        let prove = timed(|| match &statement_prepare.value {
            Ok((randomness, statement)) => create_membership_proof(
                &membership,
                &mut proof_rng1,
                &mut proof_rng2,
                statement,
                context.identifier.clone(),
                randomness.clone(),
                context.membership_witness.clone(),
            ),
            Err(error) => Err(format!("statement unavailable: {}", error)),
        });
        let verify = timed(|| match (&prove.value, &statement_prepare.value) {
            (Ok(proof), Ok((_, statement))) => {
                Ok(verify_membership(&membership.crs, proof, statement))
            }
            (Err(error), _) => Err(format!("proof unavailable: {}", error)),
            (_, Err(error)) => Err(format!("statement unavailable: {}", error)),
        });
        let authenticate_elapsed_ns = elapsed_ns(authenticate_started);

        let encoding = prove
            .value
            .as_ref()
            .map_err(Clone::clone)
            .and_then(encode_cp_proof);
        let proof_bytes = encoding
            .as_ref()
            .map(|bytes| bytes.len() as u64)
            .unwrap_or(0);
        let prepare_status = result_status(&statement_prepare.value);
        let prove_status = combine_prove_status(&prove.value, &encoding);
        let verify_status = bool_status(&verify.value);
        let authenticate_status = combine_statuses(&prove_status, &verify_status);
        let stage_results = [
            (
                "statement_prepare",
                statement_prepare.elapsed_ns,
                prepare_status,
                0,
            ),
            (
                "membership_prove",
                prove.elapsed_ns,
                prove_status,
                proof_bytes,
            ),
            (
                "membership_verify",
                verify.elapsed_ns,
                verify_status,
                proof_bytes,
            ),
            (
                "membership_authenticate",
                authenticate_elapsed_ns,
                authenticate_status,
                proof_bytes,
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
        for (stage, stage_elapsed_ns, (accepted, error), stage_proof_bytes) in stage_results {
            observations.push(Observation {
                schema_version: 1,
                run_id,
                sample_id: sample_id.clone(),
                is_warmup,
                authorization_population: config.population,
                stage: stage.to_string(),
                elapsed_ns: stage_elapsed_ns,
                accepted,
                error,
                proof_bytes: stage_proof_bytes,
                setup_included: false,
                seed: sample_seed,
                params_hash: params_hash.clone(),
                source_hash: source_hash.clone(),
                proof_encoding: CP_ENCODING.to_string(),
            });
        }
    }

    let mut tail_failed_samples = 0usize;
    let mut tail_successful_samples = 0usize;
    if tail_total > 0 {
        let tail_seed = derive_u64(config.seed, b"tail-proof");
        let randomness = deterministic_randomness(tail_seed, b"commitment-randomness");
        let commitment = cp_pedersen
            .commit(&context.prime, &randomness)
            .map_err(|error| format!("tail member commitment: {:?}", error))?;
        let statement = MembershipStatement {
            c_p: context.accumulator_value.clone(),
            c_e_q: commitment,
        };
        let mut proof_rng1 = seeded_rug(tail_seed, b"cp-rug");
        let mut proof_rng2 = seeded_std(tail_seed, b"cp-rust");
        let proof = create_membership_proof(
            &membership,
            &mut proof_rng1,
            &mut proof_rng2,
            &statement,
            context.identifier.clone(),
            randomness,
            context.membership_witness.clone(),
        )?;
        let proof_bytes = encode_cp_proof(&proof)?.len() as u64;
        for tail_id in 0..tail_total {
            let is_warmup = tail_id < config.tail_warmups;
            let sample_id = if is_warmup {
                format!("TW{:04}", tail_id)
            } else {
                format!("T{:04}", tail_id - config.tail_warmups)
            };
            let measured = timed(|| Ok(verify_membership(&membership.crs, &proof, &statement)));
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
                authorization_population: config.population,
                stage: "membership_verify_tail".to_string(),
                elapsed_ns: measured.elapsed_ns,
                accepted,
                error,
                proof_bytes,
                setup_included: false,
                seed: tail_seed,
                params_hash: params_hash.clone(),
                source_hash: source_hash.clone(),
                proof_encoding: CP_ENCODING.to_string(),
            });
        }
    }

    write_csv(&config.output, &observations)?;
    let csv_hash = hash_file(&config.output)?;
    let artifact = json!({
        "schemaVersion": 1,
        "recordedAtUnixMs": u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()).unwrap_or(u64::MAX),
        "benchmark": BASELINE_NAME,
        "comparability": {
            "isFaithfulAPoAReproduction": false,
            "implementedRelation": "CP-RSA zero-knowledge hidden membership of one 128-bit authorization identifier in an RSA-2048 accumulator",
            "excludedRelations": ["resource", "action", "epoch", "agentId", "nonce", "delegation monotonicity"],
            "apoaDifference": "A-PoA evaluates an NI-ZKPoKE construction; this binary reuses HRADA's CP-RSA membership backend and is therefore a capability ablation, not A-PoA implementation data."
        },
        "config": {
            "runs": config.runs,
            "warmups": config.warmups,
            "tailRuns": config.tail_runs,
            "tailWarmups": config.tail_warmups,
            "tailProofPrecomputed": true,
            "authorizationPopulation": config.population,
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
            "cpSetupElapsedNs": cp_setup_elapsed_ns,
            "issuanceElapsedNs": issuance_elapsed_ns,
            "issuanceIncludes": "identifier-to-prime mapping for all members, accumulator construction, and target witness generation",
            "securityLevel": system_parameters.security_level,
            "hashToPrimeBits": system_parameters.hash_to_prime_bits,
            "paramsHash": params_hash,
            "paramsHashScope": "RSA modulus + complete CP CRS fields + accumulator mode",
            "rsaModulusHash": rsa_modulus_hash,
            "cpCrsHash": cp_crs_hash,
            "accumulatorMode": "Rsa2048/AccumulatorWithoutHashToPrime",
            "accumulatorStateBlake2s256": context.accumulator_state_hash
        },
        "correctnessGate": {
            "validProofAccepted": correctness.valid_proof_accepted,
            "wrongAccumulatorRejected": correctness.wrong_accumulator_rejected,
            "wrongCommitmentRejected": correctness.wrong_commitment_rejected
        },
        "encoding": {
            "proof": CP_ENCODING,
            "proofNotes": "Deterministic experimental wire encoding shared with m3_min_benchmark.",
            "proofBytesDefinition": "Encoded proof object only; excludes statement, CRS, accumulator state, CSV framing, and setup artifacts."
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CorrectnessGate {
    valid_proof_accepted: bool,
    wrong_accumulator_rejected: bool,
    wrong_commitment_rejected: bool,
}

fn correctness_gate(
    membership: &Membership,
    context: &AuthorizationContext,
    wrong_accumulator_value: &RsaElem,
    seed: u64,
) -> Result<CorrectnessGate, String> {
    let gate_seed = derive_u64(seed, b"correctness-gate");
    let randomness = deterministic_randomness(gate_seed, b"commitment-randomness");
    let cp_pedersen = &membership.crs.crs_modeq.pedersen_commitment_parameters;
    let commitment = cp_pedersen
        .commit(&context.prime, &randomness)
        .map_err(|error| format!("correctness commitment: {:?}", error))?;
    let statement = MembershipStatement {
        c_p: context.accumulator_value.clone(),
        c_e_q: commitment,
    };
    let mut proof_rng1 = seeded_rug(gate_seed, b"cp-rug");
    let mut proof_rng2 = seeded_std(gate_seed, b"cp-rust");
    let proof = create_membership_proof(
        membership,
        &mut proof_rng1,
        &mut proof_rng2,
        &statement,
        context.identifier.clone(),
        randomness.clone(),
        context.membership_witness.clone(),
    )?;
    let valid_proof_accepted = verify_membership(&membership.crs, &proof, &statement);
    let wrong_accumulator_statement = MembershipStatement {
        c_p: wrong_accumulator_value.clone(),
        c_e_q: statement.c_e_q.clone(),
    };
    let wrong_accumulator_rejected =
        !verify_membership(&membership.crs, &proof, &wrong_accumulator_statement);
    let wrong_randomness = randomness + 1;
    let wrong_commitment = cp_pedersen
        .commit(&context.prime, &wrong_randomness)
        .map_err(|error| format!("wrong correctness commitment: {:?}", error))?;
    let wrong_commitment_statement = MembershipStatement {
        c_p: statement.c_p.clone(),
        c_e_q: wrong_commitment,
    };
    let wrong_commitment_rejected =
        !verify_membership(&membership.crs, &proof, &wrong_commitment_statement);
    Ok(CorrectnessGate {
        valid_proof_accepted,
        wrong_accumulator_rejected,
        wrong_commitment_rejected,
    })
}

fn parse_args<I>(mut args: I) -> Result<Config, String>
where
    I: Iterator<Item = String>,
{
    let mut config = Config {
        runs: 100,
        warmups: 10,
        tail_runs: 1_000,
        tail_warmups: 100,
        population: 50,
        seed: 20_260_805,
        output: PathBuf::from("results/raw/apoa_style_membership_observations.csv"),
    };
    while let Some(argument) = args.next() {
        if argument == "--help" || argument == "-h" {
            println!(
                "usage: apoa_style_benchmark [--runs N] [--warmups N] [--tail-runs N] [--tail-warmups N] [--population N] [--seed U64] [--output FILE.csv]"
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
            "--population" => config.population = parse_value(&argument, &value)?,
            "--seed" => config.seed = parse_value(&argument, &value)?,
            "--output" => config.output = PathBuf::from(value),
            _ => return Err(format!("unknown argument: {}", argument)),
        }
    }
    if config.runs == 0 {
        return Err("--runs must be greater than zero".to_string());
    }
    if config.population == 0 || config.population > 100_000 {
        return Err("--population must be in 1..=100000".to_string());
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

fn create_membership_proof(
    protocol: &Membership,
    rng1: &mut RandState,
    rng2: &mut StdRng,
    statement: &MembershipStatement<Rsa2048, G1Projective>,
    identifier: Integer,
    randomness: Integer,
    witness: RsaElem,
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
                e: identifier,
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

fn result_status<T>(result: &Result<T, String>) -> (bool, String) {
    match result {
        Ok(_) => (true, String::new()),
        Err(error) => (false, error.clone()),
    }
}

fn bool_status(result: &Result<bool, String>) -> (bool, String) {
    match result {
        Ok(true) => (true, String::new()),
        Ok(false) => (false, "verification returned false".to_string()),
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

fn append_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    output.extend_from_slice(bytes);
}

fn append_rsa(output: &mut Vec<u8>, value: &RsaElem) {
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
    output.push(sign);
    append_bytes(output, &integer_to_bytes(&value.clone().abs()));
}

fn append_canonical<T: CanonicalSerialize>(output: &mut Vec<u8>, value: &T) -> Result<(), String> {
    let mut encoded = Vec::new();
    value
        .serialize(&mut encoded)
        .map_err(|error| format!("{:?}", error))?;
    append_bytes(output, &encoded);
    Ok(())
}

fn deterministic_identifier(seed: u64, member_index: usize) -> Integer {
    let digest = derive_digest(seed, format!("member-{}", member_index).as_bytes());
    Integer::from_digits(&digest[..16], rug::integer::Order::MsfBe)
}

fn deterministic_randomness(seed: u64, domain: &[u8]) -> Integer {
    let mut digest = derive_digest(seed, domain);
    digest[0] &= 0x3f;
    digest[0] |= 0x20;
    Integer::from_digits(&digest, rug::integer::Order::MsfBe)
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

fn derive_u64(seed: u64, domain: &[u8]) -> u64 {
    let digest = derive_digest(seed, domain);
    u64::from_le_bytes(digest[..8].try_into().expect("fixed digest width"))
}

fn derive_digest(seed: u64, domain: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s::new();
    hasher.update(b"HRADA-APOA-STYLE-BENCH-SEED-V1");
    hasher.update(&seed.to_le_bytes());
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
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
        .unwrap_or("apoa_style_membership_observations");
    csv.with_file_name(format!("{}.environment.json", stem))
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
    Ok(hex(&Blake2s::digest(&fs::read(path)?)))
}

fn hash_integer(value: &Integer) -> String {
    hex(&Blake2s::digest(&integer_to_bytes(value)))
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
    hasher.update(b"HRADA-APOA-STYLE-SOURCE-SET-V1");
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
    fn defaults_and_argument_validation_are_stable() {
        let config = parse_args(
            [
                "--runs",
                "2",
                "--warmups",
                "1",
                "--population",
                "50",
                "--output",
                "out/raw.csv",
            ]
            .iter()
            .map(|value| value.to_string()),
        )
        .unwrap();
        assert_eq!(config.runs, 2);
        assert_eq!(config.warmups, 1);
        assert_eq!(config.population, 50);
        assert_eq!(
            environment_path(&config.output),
            PathBuf::from("out/raw.environment.json")
        );
        assert!(parse_args(["--runs", "0"].iter().map(|value| value.to_string())).is_err());
        assert!(parse_args(["--population", "0"].iter().map(|value| value.to_string())).is_err());
    }

    #[test]
    fn identifiers_are_128_bit_and_domain_separated() {
        let first = deterministic_identifier(7, 0);
        let second = deterministic_identifier(7, 1);
        assert_ne!(first, second);
        assert!(first.significant_bits() <= 128);
        assert!(second.significant_bits() <= 128);
    }
}
