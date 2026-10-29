# Current-profile paired SR gate

Run only on `benchmark-host` (`hostname=benchmark-node`) while holding
`${REMOTE_DATA}/pets2027/results/.experiment.lock`. Use Rust 1.95.0, CPUs 0–9,
`CARGO_BUILD_JOBS=10`, `RAYON_NUM_THREADS=10`, and `OMP_NUM_THREADS=1`.

1. Preserve a fresh result directory and the exact source tree, `Cargo.toml`,
   `Cargo.lock`, stdout, stderr, exit code, `/usr/bin/time -v`, and SHA-256
   manifest. Never overwrite an earlier failure.
2. Run `cargo fmt -- --check`, then `cargo check --release --locked --bin
   current_profile_paired`. Stop and retain the first diagnostic if either
   fails.
3. Run `cargo run --release --locked --bin current_profile_paired -- --out
   RESULT_ARTIFACTS --joint-pk PK --joint-vk VK` once, using the audited current
   Joint Lmax=3/dS=10/dRA=10/dRev=32 key pair. The process must generate one fixed SR parameter set
   and then execute the deterministic shuffled 20-trial schedule: N=16,
   updates=1/8, seeds=1..10.
4. Run `runner_scripts/analyze_sr_current_profile_paired.py` on the server with
   10,000 bootstrap repetitions. The analysis must fail closed unless every
   positive and negative predicate passes, all support files exist, and both
   configurations contain ten distinct workload seeds. It must also require a
   5/5 Joint-first/SR-first order split and report bootstrap confidence
   intervals for signed per-trial Joint-minus-SR component differences.

The workload seeds change synthetic keys, records, paths, witnesses, and proof
randomness. They are not fresh parameter setups and do not imply deployment
generalization. Every trial must materialize sixteen complete signed RA/state
database rows and must apply its own `u=1` or `u=8` RA/state/revocation batch,
plus the target support revocation. The exact successor root materialization,
header signature, and public-version serialization are measured within the
same paired workload and counted once. The synthetic private keys in the
retained support files are nonproduction fixtures. Production network latency
is unknown. These paired component measurements are not an end-to-end
break-even because production delivery and HTTP paths are not measured.
