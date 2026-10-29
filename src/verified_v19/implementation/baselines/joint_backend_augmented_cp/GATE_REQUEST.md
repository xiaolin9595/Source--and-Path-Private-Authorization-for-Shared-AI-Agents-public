# E8 augmented three-backend gate request

This crate is an isolated experiment. It does not alter the production service
or the retained Joint relation. Run only on benchmark-host under the global experiment
lock.

The gate must establish all of the following before any number is cited:

1. The augmented inline, Poseidon split, and CP/RSA split variants consume the
   same Joint fixture and signed generation-bound mapping record.
2. All 27 augmented public-field mutations are rejected by every variant.
3. The CP/RSA statement and current Joint-core proof use canonically converted,
   subgroup-checked identical Pedersen bases, identical scalar modulus and the
   same hidden opening in the ordered equation `g*prime + h*opening`. Identity,
   equal, swapped, wrong `g`, wrong `h` and mismatched declared parameters are
   rejected. The retained arkworks codec and current IETF-oriented codec are
   not treated as byte-compatible: the bridge uses explicit 48-byte field
   coordinates, checks both field moduli, lossless coordinate round trips,
   current on-curve/subgroup membership and ordered nonidentity bases.
   Canonical current bridge bytes, legacy CP parameters and their digests are
   retained.
4. Replacement removes the retired prime, admits the successor, preserves an
   independent member, retires the old mapping, and prevents lifetime reuse.
5. Old proofs fail against successor state while fresh successor proofs verify
   under the same circuit-specific parameters for all three variants.
6. Setup, proof, verification, transition, parameter, and measured artifact
   costs are reported separately. Native initial mapping plus accumulator
   construction, successor prime generation, and replacement/confirmation are
   separate lifecycle measurements. Local experimental setup is not called a
   production ceremony.
7. Wrong commitment, a cross-prime CP/core commitment splice, wrong private
   position and a different private prime are rejected. The wrong-position
   gate includes a valid mapping signature and CP membership, so it reaches
   the Joint record/position constraint. The service ledger separately rejects
   an alternate prime for one live generation. Mapping-certificate/public-key
   bytes and every backend's complete setup artifacts are reported rather than
   treating the adapter as free.
8. A one-repetition run is a correctness bring-up only. Publication-grade E8
   timing uses twelve paired fresh setup/trials. The driver cycles through all
   six backend permutations twice, so each backend occupies each execution
   position four times. Correctness gates must pass before those timed
   repetitions are scheduled. The retained analysis reports 10,000-resample
   fixed-seed 95% percentile-bootstrap intervals for each backend median and
   for every pairwise signed difference, separately for setup, proving and
   verification.

The circuit proves mapping signature and canonical 252-bit range. Primality is
a native issuer/verifier responsibility: 64 SHA-derived Miller--Rabin bases.
The random-oracle assumption and repeated/adaptive issuance union loss remain
explicit; the gate must not report an unconditional service-wide 128-bit bound.
The retained CP component uses RSA-2048 and carries its Strong-RSA-style and
modulus/setup assumptions; it is not assigned the same security-bit label as
the pairing backends. The signed certified map also adds issuer trust, lifetime
prime-uniqueness state, accumulator maintenance, certificate distribution and
circuit-specific setup artifacts. All are part of the comparison boundary.

## Frozen execution package

The sole server runner executes the following command from this crate after
syncing the frozen source to benchmark-host:

```sh
E8_AUGMENTED_FORMAL_REPS=12 ./run_on_benchmark-host.sh
```

The script is fail closed and orders its dependencies as follows:

1. Verify the physical host and acquire the global experiment lock.
2. Run formatting, offline locked metadata, release check, release tests and
   release build; retain every exit code, stream and resource log.
3. Record the complete source/dependency manifest and exact audited lock hash.
4. Run one full correctness repetition. This includes the three relation
   matrices, complete setup/prove/verify, all 27 public-field mutations for
   every backend, CP/current bridge negatives, signed wrong-position and
   cross-prime-splice negatives, enabled lengths 1/2/3 under the same CRS, and
   the removal/successor/independent-survival/no-reuse lifecycle.
5. Validate the bring-up artifacts with `analyze_e8.py --mode correctness`.
   Formal timing cannot start if any predicate or retained file is missing.
6. Run twelve fresh-setup repetitions with the six backend orders repeated
   twice. Each repetition again performs a real proof and verification for all
   three backends and the fail-closed negative/lifecycle matrix.
7. Run `analyze_e8.py --mode formal` and retain `formal/ANALYSIS.json`, raw
   per-repetition `results.json`, every setup/proof/bridge/certificate artifact,
   the source manifest and the final artifact digest manifest.

## Machine-readable success predicates

`correctness/VALIDATION.json` and `formal/ANALYSIS.json` use schema
`plan-a-e8-certified-state-map-three-backend-analysis-v1`. A formal pass has:

- `validated=true`, `mode="formal"`, and at least 12 fresh setups in complete
  six-order cycles;
- all six `order_counts` equal and each backend position count equal to
  `fresh_setup_repetitions/3`;
- `same_augmented_relation_all_three_backends`,
  `full_proof_verify_all_trials`,
  `all_27_public_mutations_rejected_all_trials`,
  `bridge_negative_matrix_all_trials`, `successor_lifecycle_all_trials`,
  `same_crs_enabled_lengths_checked_once`,
  `all_artifacts_retained_and_nonempty`, and
  `cp_and_bridge_digests_match` all true;
- positive finite setup/prove/verify times for every backend and trial;
- a 10,000-resample fixed-seed percentile-bootstrap interval for every backend
  median and every pairwise signed timing difference; and
- byte accounting that includes the mapping certificate, mapping public key,
  CP parameters, canonical bridge parameters, all circuit-specific setup
  artifacts and complete proof bundles.

Only repetition zero performs the extra active-length 1/2/3 proofs. Later
samples explicitly record that this additional correctness work was skipped;
they do not repeat or imply an unexecuted per-setup claim.

