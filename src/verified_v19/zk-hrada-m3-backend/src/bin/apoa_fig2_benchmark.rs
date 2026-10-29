//! A same-machine paper-spec reimplementation of the NI-ZKPoKE transcript in
//! Fig. 2 of A-PoA.
//!
//! This is not an official reproduction: the paper does not publish its source
//! code or fully specify group-base generation, the bound B, transcript byte
//! encoding, or hash-to-prime details.  Those choices are fixed and hashed by
//! this binary.  The implemented relation is membership-only:
//!     public (u, v), private x, with u^x = v in the RSA-2048 group.
//! The public membership witness u is part of the authentication payload.

use accumulator::group::{ElemFrom, ElemToBytes, Group, Rsa2048, UnknownOrderGroup};
use blake2::{Blake2s, Digest};
use cpsnarks_set::utils::{integer_to_bytes, random_symmetric_range};
use rug::{integer::IsPrime, rand::RandState, Integer};
use serde::Serialize;
use serde_json::json;
use std::{
    collections::HashSet,
    convert::TryFrom,
    env,
    error::Error,
    fs::{self, File},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

const BENCHMARK_NAME: &str = "A-PoA-Fig2-Rust paper-spec reimplementation (membership-only)";
const PROTOCOL_DOMAIN: &[u8] = b"APOA-FIG2-RUST-NIZKPOKE-V1";
const ENCODING_DOMAIN: &[u8] = b"APOA-FIG2-RUST-PROOF-V1";
const SECURITY_BITS: u32 = 128;
const GROUP_BYTES: usize = 256;
const SCALAR_BYTES: usize = 16;
const LOGICAL_PROOF_BYTES: u64 = (3 * GROUP_BYTES + 3 * SCALAR_BYTES) as u64;

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
    logical_proof_bytes: u64,
    encoded_proof_bytes: u64,
    authentication_payload_bytes: u64,
    setup_included: bool,
    seed: u64,
    params_hash: String,
    source_hash: String,
    proof_encoding: String,
}

#[derive(Clone)]
struct ApoaParameters {
    g: RsaElem,
    h: RsaElem,
    randomness_bound: Integer,
    transcript_prefix: Vec<u8>,
    params_hash: String,
}

#[derive(Clone)]
struct AuthorizationFixture {
    x: Integer,
    u: RsaElem,
    v: RsaElem,
    state_hash: String,
}

#[derive(Clone)]
struct ApoaProof {
    ell: Integer,
    z: RsaElem,
    q_g: RsaElem,
    q_u: RsaElem,
    r_x: Integer,
    r_rho: Integer,
}

struct ProveOutput {
    proof: ApoaProof,
    hprime_elapsed_ns: u64,
    hprime_index: u64,
}

struct VerifyOutput {
    accepted: bool,
    hprime_elapsed_ns: u64,
}

struct Timed<T> {
    value: Result<T, String>,
    elapsed_ns: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CorrectnessCheck {
    name: String,
    passed: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("A-PoA Fig. 2 benchmark failed: {}", error);
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = parse_args(env::args().skip(1))?;
    ensure_output_parent(&config.output)?;
    let environment_path = environment_path(&config.output);
    let manifest_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let source_files = ["src/bin/apoa_fig2_benchmark.rs", "Cargo.toml", "Cargo.lock"];
    let source_hashes = source_files
        .iter()
        .map(|relative| {
            let hash = hash_file(&manifest_root.join(relative))?;
            Ok((relative.to_string(), hash))
        })
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    let source_hash = aggregate_source_hash(&source_hashes);

    let parameter_setup_started = Instant::now();
    let parameters = setup_parameters()?;
    let parameter_setup_elapsed_ns = elapsed_ns(parameter_setup_started);
    let issuance_started = Instant::now();
    let fixture = issue_fixture(config.seed, config.population)?;
    let issuance_elapsed_ns = elapsed_ns(issuance_started);

    let correctness_checks = correctness_gate(&parameters, &fixture, config.seed)?;
    if correctness_checks.iter().any(|check| !check.passed) {
        return Err("A-PoA Fig. 2 correctness gate failed before timing".into());
    }

    let total_online = config.warmups + config.runs;
    let total_tail = config.tail_warmups + config.tail_runs;
    let mut observations = Vec::with_capacity(total_online * 5 + total_tail * 2);
    let mut online_successes = 0usize;
    let mut online_failures = 0usize;
    let mut tail_successes = 0usize;
    let mut tail_failures = 0usize;
    let mut hprime_indices = Vec::with_capacity(total_online);

    for run_id in 0..total_online {
        let is_warmup = run_id < config.warmups;
        let sample_id = if is_warmup {
            format!("W{:04}", run_id)
        } else {
            format!("R{:04}", run_id - config.warmups)
        };
        let sample_seed = derive_u64(config.seed, sample_id.as_bytes());
        let mut proof_rng = seeded_rug(sample_seed, b"proof-rng");
        let prove = timed(|| prove(&parameters, &fixture, &mut proof_rng));
        let serialize = timed(|| match &prove.value {
            Ok(output) => encode_proof(&output.proof),
            Err(error) => Err(format!("proof unavailable: {}", error)),
        });
        let verify = timed(|| match &prove.value {
            Ok(output) => verify(&parameters, &fixture.u, &fixture.v, &output.proof),
            Err(error) => Err(format!("proof unavailable: {}", error)),
        });

        if let Ok(output) = &prove.value {
            hprime_indices.push(output.hprime_index);
        }
        let encoded_proof_bytes = serialize
            .value
            .as_ref()
            .map(|bytes| bytes.len() as u64)
            .unwrap_or(0);
        let authentication_payload_bytes = encoded_proof_bytes + GROUP_BYTES as u64;
        let prove_status = result_status(&prove.value);
        let serialize_status = result_status(&serialize.value);
        let verify_status = verify_status(&verify.value);
        let hprime_prove_ns = prove
            .value
            .as_ref()
            .map(|output| output.hprime_elapsed_ns)
            .unwrap_or(0);
        let hprime_verify_ns = verify
            .value
            .as_ref()
            .map(|output| output.hprime_elapsed_ns)
            .unwrap_or(0);
        let hprime_prove_status = if hprime_prove_ns > 0 {
            prove_status.clone()
        } else {
            (false, "Hprime prove timing unavailable".to_string())
        };
        let hprime_verify_status = if hprime_verify_ns > 0 {
            verify_status.clone()
        } else {
            (false, "Hprime verify timing unavailable".to_string())
        };
        let stage_results = [
            ("apoa_prove_total", prove.elapsed_ns, prove_status),
            ("apoa_hprime_prove", hprime_prove_ns, hprime_prove_status),
            ("apoa_verify_total", verify.elapsed_ns, verify_status),
            ("apoa_hprime_verify", hprime_verify_ns, hprime_verify_status),
            ("apoa_serialize", serialize.elapsed_ns, serialize_status),
        ];
        let sample_accepted = stage_results.iter().all(|(_, _, (accepted, _))| *accepted);
        if sample_accepted {
            online_successes += 1;
        } else {
            online_failures += 1;
        }
        for (stage, stage_elapsed_ns, (accepted, error)) in stage_results {
            observations.push(observation(
                run_id,
                sample_id.clone(),
                is_warmup,
                config.population,
                stage,
                stage_elapsed_ns,
                accepted,
                error,
                encoded_proof_bytes,
                authentication_payload_bytes,
                sample_seed,
                &parameters.params_hash,
                &source_hash,
            ));
        }
    }

    if total_tail > 0 {
        let tail_seed = derive_u64(config.seed, b"tail-proof");
        let mut tail_rng = seeded_rug(tail_seed, b"proof-rng");
        let tail_proof = prove(&parameters, &fixture, &mut tail_rng)?.proof;
        let encoded_proof_bytes = encode_proof(&tail_proof)?.len() as u64;
        let authentication_payload_bytes = encoded_proof_bytes + GROUP_BYTES as u64;
        for tail_id in 0..total_tail {
            let is_warmup = tail_id < config.tail_warmups;
            let sample_id = if is_warmup {
                format!("TW{:04}", tail_id)
            } else {
                format!("T{:04}", tail_id - config.tail_warmups)
            };
            let measured = timed(|| verify(&parameters, &fixture.u, &fixture.v, &tail_proof));
            let status = verify_status(&measured.value);
            let hprime_elapsed_ns = measured
                .value
                .as_ref()
                .map(|output| output.hprime_elapsed_ns)
                .unwrap_or(0);
            let hprime_status = if hprime_elapsed_ns > 0 {
                status.clone()
            } else {
                (false, "Hprime tail timing unavailable".to_string())
            };
            if status.0 && hprime_status.0 {
                tail_successes += 1;
            } else {
                tail_failures += 1;
            }
            for (stage, stage_elapsed_ns, (accepted, error)) in [
                ("apoa_verify_tail", measured.elapsed_ns, status),
                ("apoa_hprime_verify_tail", hprime_elapsed_ns, hprime_status),
            ] {
                observations.push(observation(
                    total_online + tail_id,
                    sample_id.clone(),
                    is_warmup,
                    config.population,
                    stage,
                    stage_elapsed_ns,
                    accepted,
                    error,
                    encoded_proof_bytes,
                    authentication_payload_bytes,
                    tail_seed,
                    &parameters.params_hash,
                    &source_hash,
                ));
            }
        }
    }

    write_csv(&config.output, &observations)?;
    let csv_hash = hash_file(&config.output)?;
    let modulus = Rsa2048::rsa_modulus().map_err(|error| format!("RSA modulus: {:?}", error))?;
    let encoded_proof_bytes = observations
        .iter()
        .find(|row| row.encoded_proof_bytes > 0)
        .map(|row| row.encoded_proof_bytes)
        .unwrap_or(0);
    let authentication_payload_bytes = encoded_proof_bytes + GROUP_BYTES as u64;
    let artifact = json!({
        "schemaVersion": 1,
        "recordedAtUnixMs": u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()).unwrap_or(u64::MAX),
        "benchmark": BENCHMARK_NAME,
        "comparability": {
            "isOfficialAPoAReproduction": false,
            "isPaperSpecReimplementation": true,
            "implementedRelation": "public (u,v), private 128-bit prime x, u^x=v in the RSA-2048 quotient group",
            "publicMembershipWitness": true,
            "excludedRelations": ["resource", "action", "epoch", "agentId", "nonce", "delegation monotonicity"],
            "unspecifiedPaperChoicesFixedHere": ["B", "g/h", "transcript encoding", "domain separation", "hash-to-prime", "wire encoding"]
        },
        "config": {
            "runs": config.runs,
            "warmups": config.warmups,
            "tailRuns": config.tail_runs,
            "tailWarmups": config.tail_warmups,
            "tailProofPrecomputed": true,
            "authorizationPopulation": config.population,
            "seed": config.seed,
            "setupIncludedInOnlineStages": false
        },
        "parameters": {
            "securityBits": SECURITY_BITS,
            "rsaModulusBits": modulus.significant_bits(),
            "rsaModulusBlake2s256": hash_integer(&modulus),
            "groupModel": "Rsa2048 quotient identifying x and -x, inherited from cpsnarks-set accumulator backend",
            "g": "Rsa2048::elem(4)",
            "h": "Rsa2048::elem(9)",
            "randomnessBound": "B=2^(bitlen(N)+2*lambda+1)",
            "randomnessBoundBits": parameters.randomness_bound.significant_bits(),
            "memberBits": SECURITY_BITS,
            "hash": "Blake2s-256 truncated to 128 bits",
            "hashToPrime": "128-bit top-bit-set odd candidate with u64 counter and GMP probable-prime test (30 repetitions)",
            "paramsHash": parameters.params_hash
        },
        "setup": {
            "parameterSetupElapsedNs": parameter_setup_elapsed_ns,
            "issuanceElapsedNs": issuance_elapsed_ns,
            "issuanceIncludes": "population 128-bit prime generation, filler exponent product, accumulator value, and public membership witness",
            "authorizationStateBlake2s256": fixture.state_hash
        },
        "correctnessGate": {
            "allPassed": correctness_checks.iter().all(|check| check.passed),
            "passed": correctness_checks.iter().filter(|check| check.passed).count(),
            "total": correctness_checks.len(),
            "checks": correctness_checks
        },
        "encoding": {
            "logicalProofBytes": LOGICAL_PROOF_BYTES,
            "logicalProofFormula": "3*256-byte RSA elements + 3*16-byte integers = 816 bytes",
            "paperReportedProofBytes": 861,
            "paperInternalSizeNote": "A-PoA reports 861 bytes, while its stated 3*n_size + 3*Hash_size formula gives 816 bytes for RSA-2048/hash-128.",
            "proofEncoding": String::from_utf8_lossy(ENCODING_DOMAIN),
            "encodedProofBytes": encoded_proof_bytes,
            "authenticationPayloadBytes": authentication_payload_bytes,
            "authenticationPayloadDefinition": "encoded proof plus the 256-byte public membership witness u; excludes accumulator v, network framing, registry state, and CRS"
        },
        "hprime": {
            "onlineSearchIndexMin": hprime_indices.iter().min(),
            "onlineSearchIndexMedian": median_u64(&hprime_indices),
            "onlineSearchIndexMax": hprime_indices.iter().max()
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
        "sources": {
            "aggregateAlgorithm": "Blake2s-256(domain || path || fileHash)",
            "aggregateHash": source_hash,
            "files": source_hashes.iter().map(|(path, hash)| json!({"path": path, "blake2s256": hash})).collect::<Vec<_>>()
        },
        "artifacts": {
            "observationsCsv": config.output.to_string_lossy(),
            "observationsCsvBlake2s256": csv_hash,
            "rows": observations.len(),
            "onlineSamples": total_online,
            "successfulOnlineSamples": online_successes,
            "failedOnlineSamples": online_failures,
            "tailVerificationSamples": total_tail,
            "successfulTailVerificationSamples": tail_successes,
            "failedTailVerificationSamples": tail_failures,
            "failureRowsRetained": true
        }
    });
    fs::write(&environment_path, serde_json::to_vec_pretty(&artifact)?)?;

    println!("observations={}", config.output.display());
    println!("environment={}", environment_path.display());
    println!(
        "rows={} correctness={}/{} successful_online={} failed_online={} successful_tail={} failed_tail={}",
        observations.len(),
        correctness_checks.iter().filter(|check| check.passed).count(),
        correctness_checks.len(),
        online_successes,
        online_failures,
        tail_successes,
        tail_failures
    );
    if online_failures > 0 || tail_failures > 0 {
        return Err(format!(
            "{} online and {} tail sample(s) failed; artifacts were retained",
            online_failures, tail_failures
        )
        .into());
    }
    Ok(())
}

fn setup_parameters() -> Result<ApoaParameters, String> {
    let modulus = Rsa2048::rsa_modulus().map_err(|error| format!("RSA modulus: {:?}", error))?;
    let g = Rsa2048::elem(4);
    let h = Rsa2048::elem(9);
    let exponent_bits = modulus.significant_bits() + 2 * SECURITY_BITS + 1;
    let randomness_bound = Integer::from(1) << exponent_bits;
    parameters_from_parts(g, h, randomness_bound)
}

fn parameters_from_parts(
    g: RsaElem,
    h: RsaElem,
    randomness_bound: Integer,
) -> Result<ApoaParameters, String> {
    let modulus = Rsa2048::rsa_modulus().map_err(|error| format!("RSA modulus: {:?}", error))?;
    let mut transcript_prefix = Vec::new();
    append_len_prefixed(&mut transcript_prefix, PROTOCOL_DOMAIN);
    append_len_prefixed(
        &mut transcript_prefix,
        &fixed_integer_bytes(&modulus, GROUP_BYTES)?,
    );
    append_len_prefixed(&mut transcript_prefix, &fixed_group_bytes(&g)?);
    append_len_prefixed(&mut transcript_prefix, &fixed_group_bytes(&h)?);
    append_len_prefixed(
        &mut transcript_prefix,
        b"Hprime=Blake2s128-topbit-odd-counter-probable-prime-30",
    );
    let params_hash = hex(&Blake2s::digest(&transcript_prefix));
    Ok(ApoaParameters {
        g,
        h,
        randomness_bound,
        transcript_prefix,
        params_hash,
    })
}

fn issue_fixture(seed: u64, population: usize) -> Result<AuthorizationFixture, String> {
    let mut primes = Vec::with_capacity(population);
    let mut seen = HashSet::with_capacity(population);
    for index in 0..population {
        let prime = member_prime(seed, index)?;
        if !seen.insert(prime.to_string()) {
            return Err(format!("duplicate member prime at index {}", index));
        }
        primes.push(prime);
    }
    let x = primes
        .last()
        .ok_or("authorization population unexpectedly empty")?
        .clone();
    let mut filler_product = Integer::from(1);
    for prime in primes.iter().take(primes.len() - 1) {
        filler_product *= prime;
    }
    let accumulator_base = Rsa2048::unknown_order_elem();
    let u = Rsa2048::exp(&accumulator_base, &filler_product);
    let v = Rsa2048::exp(&u, &x);
    let mut state_encoding = Vec::new();
    append_len_prefixed(&mut state_encoding, &fixed_group_bytes(&u)?);
    append_len_prefixed(&mut state_encoding, &fixed_group_bytes(&v)?);
    Ok(AuthorizationFixture {
        x,
        u,
        v,
        state_hash: hex(&Blake2s::digest(&state_encoding)),
    })
}

fn prove(
    parameters: &ApoaParameters,
    fixture: &AuthorizationFixture,
    rng: &mut RandState,
) -> Result<ProveOutput, String> {
    let k = random_symmetric_range(rng, &parameters.randomness_bound);
    let rho_x = random_symmetric_range(rng, &parameters.randomness_bound);
    let rho_k = random_symmetric_range(rng, &parameters.randomness_bound);
    let z = Rsa2048::op(
        &Rsa2048::exp(&parameters.g, &fixture.x),
        &Rsa2048::exp(&parameters.h, &rho_x),
    );
    let a_g = Rsa2048::op(
        &Rsa2048::exp(&parameters.g, &k),
        &Rsa2048::exp(&parameters.h, &rho_k),
    );
    let a_u = Rsa2048::exp(&fixture.u, &k);
    let hprime_started = Instant::now();
    let (ell, hprime_index) = transcript_prime(parameters, &fixture.u, &fixture.v, &z, &a_g, &a_u)?;
    let hprime_elapsed_ns = elapsed_ns(hprime_started);
    let c = challenge(&ell)?;
    let numerator_x = k + Integer::from(&c * &fixture.x);
    let numerator_rho = rho_k + Integer::from(&c * &rho_x);
    let (q_x, r_x) = <(Integer, Integer)>::from(numerator_x.div_rem_euc_ref(&ell));
    let (q_rho, r_rho) = <(Integer, Integer)>::from(numerator_rho.div_rem_euc_ref(&ell));
    let q_g = Rsa2048::op(
        &Rsa2048::exp(&parameters.g, &q_x),
        &Rsa2048::exp(&parameters.h, &q_rho),
    );
    let q_u = Rsa2048::exp(&fixture.u, &q_x);
    Ok(ProveOutput {
        proof: ApoaProof {
            ell,
            z,
            q_g,
            q_u,
            r_x,
            r_rho,
        },
        hprime_elapsed_ns,
        hprime_index,
    })
}

fn verify(
    parameters: &ApoaParameters,
    u: &RsaElem,
    v: &RsaElem,
    proof: &ApoaProof,
) -> Result<VerifyOutput, String> {
    if proof.ell.significant_bits() != SECURITY_BITS
        || proof.ell.is_even()
        || proof.ell.is_probably_prime(30) == IsPrime::No
        || proof.r_x < 0
        || proof.r_rho < 0
        || proof.r_x >= proof.ell
        || proof.r_rho >= proof.ell
    {
        return Ok(VerifyOutput {
            accepted: false,
            hprime_elapsed_ns: 1,
        });
    }
    let c = challenge(&proof.ell)?;
    let negative_c = -c;
    let a_g = Rsa2048::op(
        &Rsa2048::op(
            &Rsa2048::op(
                &Rsa2048::exp(&proof.q_g, &proof.ell),
                &Rsa2048::exp(&parameters.g, &proof.r_x),
            ),
            &Rsa2048::exp(&parameters.h, &proof.r_rho),
        ),
        &Rsa2048::exp(&proof.z, &negative_c),
    );
    let a_u = Rsa2048::op(
        &Rsa2048::op(
            &Rsa2048::exp(&proof.q_u, &proof.ell),
            &Rsa2048::exp(u, &proof.r_x),
        ),
        &Rsa2048::exp(v, &negative_c),
    );
    let hprime_started = Instant::now();
    let (expected_ell, _) = transcript_prime(parameters, u, v, &proof.z, &a_g, &a_u)?;
    let hprime_elapsed_ns = elapsed_ns(hprime_started);
    Ok(VerifyOutput {
        accepted: expected_ell == proof.ell,
        hprime_elapsed_ns,
    })
}

fn transcript_prime(
    parameters: &ApoaParameters,
    u: &RsaElem,
    v: &RsaElem,
    z: &RsaElem,
    a_g: &RsaElem,
    a_u: &RsaElem,
) -> Result<(Integer, u64), String> {
    let mut base = parameters.transcript_prefix.clone();
    for element in [u, v, z, a_g, a_u] {
        append_len_prefixed(&mut base, &fixed_group_bytes(element)?);
    }
    for index in 0..1_000_000u64 {
        let mut hasher = Blake2s::new();
        hasher.update(b"APOA-FIG2-HPRIME-V1");
        hasher.update(&base);
        hasher.update(&index.to_le_bytes());
        let digest = hasher.finalize();
        let mut candidate_bytes = [0u8; SCALAR_BYTES];
        candidate_bytes.copy_from_slice(&digest[..SCALAR_BYTES]);
        candidate_bytes[0] |= 0x80;
        candidate_bytes[SCALAR_BYTES - 1] |= 1;
        let candidate = Integer::from_digits(&candidate_bytes, rug::integer::Order::MsfBe);
        if candidate.is_probably_prime(30) != IsPrime::No {
            return Ok((candidate, index));
        }
    }
    Err("Hprime search exceeded one million candidates".to_string())
}

fn challenge(ell: &Integer) -> Result<Integer, String> {
    let mut hasher = Blake2s::new();
    hasher.update(b"APOA-FIG2-CHALLENGE-V1");
    hasher.update(&fixed_integer_bytes(ell, SCALAR_BYTES)?);
    let digest = hasher.finalize();
    Ok(Integer::from_digits(
        &digest[..SCALAR_BYTES],
        rug::integer::Order::MsfBe,
    ))
}

fn member_prime(seed: u64, member_index: usize) -> Result<Integer, String> {
    let mut base = Vec::new();
    base.extend_from_slice(b"APOA-MEMBER-PRIME-V1");
    base.extend_from_slice(&seed.to_le_bytes());
    base.extend_from_slice(&(member_index as u64).to_le_bytes());
    for index in 0..1_000_000u64 {
        let mut hasher = Blake2s::new();
        hasher.update(&base);
        hasher.update(&index.to_le_bytes());
        let digest = hasher.finalize();
        let mut candidate_bytes = [0u8; SCALAR_BYTES];
        candidate_bytes.copy_from_slice(&digest[..SCALAR_BYTES]);
        candidate_bytes[0] |= 0x80;
        candidate_bytes[SCALAR_BYTES - 1] |= 1;
        let candidate = Integer::from_digits(&candidate_bytes, rug::integer::Order::MsfBe);
        if candidate.is_probably_prime(30) != IsPrime::No {
            return Ok(candidate);
        }
    }
    Err(format!(
        "member prime search exceeded one million candidates for {}",
        member_index
    ))
}

fn correctness_gate(
    parameters: &ApoaParameters,
    fixture: &AuthorizationFixture,
    seed: u64,
) -> Result<Vec<CorrectnessCheck>, String> {
    let mut rng1 = seeded_rug(derive_u64(seed, b"correctness-proof-1"), b"proof-rng");
    let mut rng2 = seeded_rug(derive_u64(seed, b"correctness-proof-2"), b"proof-rng");
    let proof1 = prove(parameters, fixture, &mut rng1)?.proof;
    let proof2 = prove(parameters, fixture, &mut rng2)?.proof;
    let valid1 = verify(parameters, &fixture.u, &fixture.v, &proof1)?.accepted;
    let valid2 = verify(parameters, &fixture.u, &fixture.v, &proof2)?.accepted;
    let wrong_u = Rsa2048::op(&fixture.u, &parameters.g);
    let wrong_v = Rsa2048::op(&fixture.v, &parameters.g);
    let mut tampered_ell = proof1.clone();
    tampered_ell.ell = next_128_bit_prime(Integer::from(&tampered_ell.ell + 2))?;
    let mut tampered_z = proof1.clone();
    tampered_z.z = Rsa2048::op(&tampered_z.z, &parameters.g);
    let mut tampered_qg = proof1.clone();
    tampered_qg.q_g = Rsa2048::op(&tampered_qg.q_g, &parameters.g);
    let mut tampered_qu = proof1.clone();
    tampered_qu.q_u = Rsa2048::op(&tampered_qu.q_u, &parameters.g);
    let mut tampered_rx = proof1.clone();
    tampered_rx.r_x += 1;
    let mut tampered_rrho = proof1.clone();
    tampered_rrho.r_rho += 1;
    let mut invalid_rx_range = proof1.clone();
    invalid_rx_range.r_x = invalid_rx_range.ell.clone();
    let mut invalid_rrho_range = proof1.clone();
    invalid_rrho_range.r_rho = invalid_rrho_range.ell.clone();
    let alternate_parameters = parameters_from_parts(
        parameters.h.clone(),
        parameters.g.clone(),
        parameters.randomness_bound.clone(),
    )?;

    let cases = [
        ("valid-proof-1-accepted", valid1),
        ("valid-proof-2-accepted", valid2),
        ("fresh-proofs-randomized-z", proof1.z != proof2.z),
        (
            "wrong-public-witness-rejected",
            !verify(parameters, &wrong_u, &fixture.v, &proof1)?.accepted,
        ),
        (
            "wrong-accumulator-rejected",
            !verify(parameters, &fixture.u, &wrong_v, &proof1)?.accepted,
        ),
        (
            "tampered-ell-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &tampered_ell)?.accepted,
        ),
        (
            "tampered-z-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &tampered_z)?.accepted,
        ),
        (
            "tampered-qg-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &tampered_qg)?.accepted,
        ),
        (
            "tampered-qu-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &tampered_qu)?.accepted,
        ),
        (
            "tampered-rx-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &tampered_rx)?.accepted,
        ),
        (
            "tampered-rrho-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &tampered_rrho)?.accepted,
        ),
        (
            "rx-out-of-range-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &invalid_rx_range)?.accepted,
        ),
        (
            "rrho-out-of-range-rejected",
            !verify(parameters, &fixture.u, &fixture.v, &invalid_rrho_range)?.accepted,
        ),
        (
            "parameter-splice-rejected",
            !verify(&alternate_parameters, &fixture.u, &fixture.v, &proof1)?.accepted,
        ),
    ];
    Ok(cases
        .iter()
        .map(|(name, passed)| CorrectnessCheck {
            name: (*name).to_string(),
            passed: *passed,
        })
        .collect())
}

fn next_128_bit_prime(mut candidate: Integer) -> Result<Integer, String> {
    if candidate.is_even() {
        candidate += 1;
    }
    while candidate.significant_bits() == SECURITY_BITS {
        if candidate.is_probably_prime(30) != IsPrime::No {
            return Ok(candidate);
        }
        candidate += 2;
    }
    Err("next prime crossed the 128-bit boundary".to_string())
}

fn encode_proof(proof: &ApoaProof) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(ENCODING_DOMAIN.len() + LOGICAL_PROOF_BYTES as usize);
    output.extend_from_slice(ENCODING_DOMAIN);
    output.extend_from_slice(&fixed_integer_bytes(&proof.ell, SCALAR_BYTES)?);
    output.extend_from_slice(&fixed_group_bytes(&proof.z)?);
    output.extend_from_slice(&fixed_group_bytes(&proof.q_g)?);
    output.extend_from_slice(&fixed_group_bytes(&proof.q_u)?);
    output.extend_from_slice(&fixed_integer_bytes(&proof.r_x, SCALAR_BYTES)?);
    output.extend_from_slice(&fixed_integer_bytes(&proof.r_rho, SCALAR_BYTES)?);
    Ok(output)
}

fn fixed_group_bytes(element: &RsaElem) -> Result<Vec<u8>, String> {
    left_pad(
        &<Rsa2048 as ElemToBytes>::elem_to_bytes(element),
        GROUP_BYTES,
    )
}

fn fixed_integer_bytes(value: &Integer, width: usize) -> Result<Vec<u8>, String> {
    if value < &0 {
        return Err("cannot fixed-encode a negative integer".to_string());
    }
    left_pad(&integer_to_bytes(value), width)
}

fn left_pad(bytes: &[u8], width: usize) -> Result<Vec<u8>, String> {
    if bytes.len() > width {
        return Err(format!(
            "value requires {} bytes, exceeds fixed width {}",
            bytes.len(),
            width
        ));
    }
    let mut output = vec![0u8; width - bytes.len()];
    output.extend_from_slice(bytes);
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn observation(
    run_id: usize,
    sample_id: String,
    is_warmup: bool,
    population: usize,
    stage: &str,
    elapsed_ns: u64,
    accepted: bool,
    error: String,
    encoded_proof_bytes: u64,
    authentication_payload_bytes: u64,
    seed: u64,
    params_hash: &str,
    source_hash: &str,
) -> Observation {
    Observation {
        schema_version: 1,
        run_id,
        sample_id,
        is_warmup,
        authorization_population: population,
        stage: stage.to_string(),
        elapsed_ns,
        accepted,
        error,
        logical_proof_bytes: LOGICAL_PROOF_BYTES,
        encoded_proof_bytes,
        authentication_payload_bytes,
        setup_included: false,
        seed,
        params_hash: params_hash.to_string(),
        source_hash: source_hash.to_string(),
        proof_encoding: String::from_utf8_lossy(ENCODING_DOMAIN).to_string(),
    }
}

fn result_status<T>(result: &Result<T, String>) -> (bool, String) {
    match result {
        Ok(_) => (true, String::new()),
        Err(error) => (false, error.clone()),
    }
}

fn verify_status(result: &Result<VerifyOutput, String>) -> (bool, String) {
    match result {
        Ok(output) if output.accepted => (true, String::new()),
        Ok(_) => (false, "verification returned false".to_string()),
        Err(error) => (false, error.clone()),
    }
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
        output: PathBuf::from("results/raw/apoa_fig2_observations.csv"),
    };
    while let Some(argument) = args.next() {
        if argument == "--help" || argument == "-h" {
            println!(
                "usage: apoa_fig2_benchmark [--runs N] [--warmups N] [--tail-runs N] [--tail-warmups N] [--population N] [--seed U64] [--output FILE.csv]"
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

fn seeded_rug(seed: u64, domain: &[u8]) -> RandState<'static> {
    let digest = derive_digest(seed, domain);
    let mut rng = RandState::new();
    rng.seed(&Integer::from_digits(&digest, rug::integer::Order::MsfBe));
    rng
}

fn derive_u64(seed: u64, domain: &[u8]) -> u64 {
    let digest = derive_digest(seed, domain);
    u64::from_le_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

fn derive_digest(seed: u64, domain: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s::new();
    hasher.update(b"APOA-FIG2-BENCH-SEED-V1");
    hasher.update(&seed.to_le_bytes());
    hasher.update(&(domain.len() as u64).to_le_bytes());
    hasher.update(domain);
    let digest = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn append_len_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_le_bytes());
    output.extend_from_slice(value);
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
        .unwrap_or("apoa_fig2_observations");
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

fn aggregate_source_hash(source_hashes: &[(String, String)]) -> String {
    let mut hasher = Blake2s::new();
    hasher.update(b"APOA-FIG2-SOURCE-SET-V1");
    for (path, hash) in source_hashes {
        hasher.update(&(path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(hash.as_bytes());
    }
    hex(&hasher.finalize())
}

fn median_u64(values: &[u64]) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    Some(sorted[sorted.len() / 2])
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
    fn proof_size_formula_and_encoding_are_stable() {
        assert_eq!(LOGICAL_PROOF_BYTES, 816);
        let parameters = setup_parameters().unwrap();
        let fixture = issue_fixture(7, 3).unwrap();
        let mut rng = seeded_rug(9, b"proof-rng");
        let proof = prove(&parameters, &fixture, &mut rng).unwrap().proof;
        let encoded = encode_proof(&proof).unwrap();
        assert_eq!(encoded.len(), ENCODING_DOMAIN.len() + 816);
        assert!(
            verify(&parameters, &fixture.u, &fixture.v, &proof)
                .unwrap()
                .accepted
        );
    }

    #[test]
    fn arguments_reject_empty_runs_and_population() {
        assert!(parse_args(["--runs", "0"].iter().map(|value| value.to_string())).is_err());
        assert!(parse_args(["--population", "0"].iter().map(|value| value.to_string())).is_err());
    }
}
