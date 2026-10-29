# Remote gate request: staged DAC wrapper gates

Run only on `benchmark-host` under the shared experiment lock.

1. Record host-before, repository/source manifest, resolved `Cargo.lock`, and
   the exact Dock source revision.
2. Run `cargo fmt -- --check`.
3. Run locked offline `cargo check --release`; do not change dependency major
   or minor versions to satisfy a cache.
4. Run `cargo run --release` and retain stdout/stderr/exit code.
5. Run `cargo run --release --bin hidden_serial_gate` and retain evidence.
6. Run
   `DAC_FIXED_GATE_PHASE=synthesis cargo run --release --bin fixed_policy_gate`.
   Require both A/B two-level paths and the C one-level-plus-padding path to
   satisfy one fixed relation, plus alternate-owner D, a legal request
   variant, and every emitted negative. Require exact equality of the
   finalized A/B/C sparse matrices (metadata, row order, entry order, column
   indices, and canonical coefficients), not only equal constraint counts;
   retain the emitted matrix digest and public-input order. This phase must
   exit before Groth16 setup/prove.
7. Only after step 6 passes, run the full `fixed_policy_gate`; retain
   setup/prove/verify timing, constraint count, key/proof/signature sizes,
   one-PK successful proofs for A/B/C/D and the legal request variant,
   public-parameter digest, A-delete/B-preserve lifecycle, exact B signature
   equality, canonical proof-byte/terminal-signature negatives, Delta=0 stale
   header behavior, nonce replay, and successor B atomic commit.
   This first full run is an `n=1` smoke artifact and is not a formal timing
   row. Final B2 timing requires at least ten independent fresh setups/trials
   per applicable configuration, paired raw trial rows, and 95% bootstrap
   confidence intervals. Re-run Joint at `L_max=2` with the same actual depth,
   semantic tree capacities, raw records, request, and update sequence; do not
   reuse the existing main-E2 `L_max=3` timing as the paired comparator.
   For the post-v21 matched service gate, set `MATCHED_DAC_PRODUCER_OUT`,
   `MATCHED_DAC_VK_OUT`, and `MATCHED_DAC_TRUSTED_CONFIG_OUT`, then follow
   `SERVICE_WIRE_CONTRACT.md`. Run `MATCHED_DAC_PRODUCER_MODE=lifecycle` once
   for t0 A/B/C, t1 B/C and t2 C correctness. Use `formal-t1` for the ten
   fresh paired actual-one/actual-two trials. The retained v21 full pass does
   not imply that the producer or resident verifier has passed.
8. Run the pinned Poseidon authors' `calc_round_numbers.py` at commit
   `9d80ec0473ad7cde5a12f3aac46439ad0da68c0a` with the exact BLS12-377 `Fq`
   modulus recorded in `POSEIDON_PARAMETERS.md`, `M=128`, `t=3`, `alpha=5`,
   and security margin enabled. Retain the script bytes/digest, invocation,
   stdout/stderr, require the observed recommendation `R_F=8,R_P=55`, and
   independently check that the frozen source uses `R_F=8,R_P=57` (two
   additional partial rounds); otherwise fail without changing the relation.
9. Retain the emitted Poseidon parameter-array Blake2s digest and both alpha
   field guards. Require `Fq=true`, `Fr=false`.
10. Accept the partial stage-1 subrelation only if its JSON has `accepted=true`,
   `mutated_public_attribute_rejected=true`, and `scope_complete=false`.

Do not merge this stage result into the full B2 row.  It is evidence only for
the signature-and-commitment wrapper subrelation.

Do not label `fixed_policy_gate` complete B2 while it emits
`scope_complete=false`. The precise remaining items are the paired raw-record
artifact, official Poseidon calculator evidence, successful full proof and
lifecycle gate, and matched main-service experiment, as tracked in
`B2_COMPLETION_MATRIX.md`.
