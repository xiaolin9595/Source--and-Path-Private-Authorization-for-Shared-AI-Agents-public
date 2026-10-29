# E8 remote gate request

## Scope

This crate is ready for the remote compile/correctness/measurement gate. It is
the exploratory **legacy Auth relation-composition ablation** labelled
`legacy_relation_composition_ablation_exploratory_n3`. It is not a new-Joint
full-contract benchmark, an application workflow benchmark, or
publication-grade scaling evidence. Do not substitute the Blake2s
`hrada_merkle_baseline`.

The executable performs three fresh setup repetitions. Within each repetition,
CP--Lego, Poseidon-Merkle--Lego, and Groth16 over `InlineCircuit` use the same
`AuthFixture`, identical 16 Auth public fields, the same allocated state prime,
and the same eight-member state population. The generator validates a 252-bit
prime, while every sample records the actual `significant_bits()` value rather
than relying on that label. The two Lego variants also
share the same freshly generated Auth Lego parameters and CP commitment bases.
The Inline relation allocates the Auth state prime once as a private variable
and passes that exact `FpVar` into the Poseidon membership gadget. Its public
input order is the unchanged Q16 followed by the two canonical Poseidon-root
limbs.

Each repetition records fresh setup, component and total proving times,
verification, proof/parameter byte counts, a measured codec description, state
replacement, and selected-witness refresh. `null` is emitted for Inline stages
that cannot be separated. Correctness gates cover the valid proofs, every one
of the 16 Q-field mutations, a changed CP accumulator, both Poseidon root-limb
mutations, wrong-prime witnesses, and the Lego membership/Auth residual against
the same commitment. The program
retains each repetition's raw proofs and CRS files next to `results.json`.
Those complete raw files remain in the private run directory for audit. The
anonymous release omits `cp-parameters.bin`, `auth-pk.bin`,
`poseidon-member-pk.bin`, and `inline-pk.bin`; it retains their manifest/result
hashes, this regeneration command and source, and each VK, commitment and proof.

## Scheduling boundary

Run only on SSH host `benchmark-host` after E5 has released
`${REMOTE_DATA}/pets2027/results/.experiment.lock` (expected no earlier than
2026-10-23 19:30 CST). The runner uses nonblocking `flock` and exits without
building if the lock is still held. Do not compile, preflight, or measure this
crate on another host.

## Exact command on benchmark-host

After copying the reviewed source delta, use the coordinated source checkout
and the unified task output root explicitly:

```bash
cd ${REMOTE_DATA}/pets2027/M3-min
E8_REPO=${REMOTE_DATA}/pets2027/M3-min \
E8_OUTPUT_ROOT=${REMOTE_DATA}/pets2027/plan_a_20261023/runs \
bash work/plan_a_2026_10_23/implementation/baselines/backend_ablation/run_on_benchmark-host.sh
```

If the coordinator freezes the full repository at another path, set `E8_REPO`
to that path; the script derives both the standalone crate and the
`zk-hrada-m3-backend` path dependency from it. Do not point `E8_REPO` at the
standalone crate alone.

The script uses Rust 1.95.0, CPU 0--9, `RAYON_NUM_THREADS=10`, and
`OMP_NUM_THREADS=1`. Because this standalone crate is delivered without a lock
file, it seeds `Cargo.lock` from the path dependency's reviewed lock, uses
`cargo fetch` to add the standalone package and pinned standard Groth16
revision while retaining the reviewed dependency resolutions, saves the result
with the source manifest, and uses `--locked` for the build. A build or
positive/negative gate failure invalidates that run; retain the complete failed
artifact directory and start a new run directory after fixing source. Never
delete an unfavorable repetition or merge these n=3 samples with older bins.

The static handoff on 2026-10-23 did not run Cargo, the executable, an
experiment, or an analysis while E5 owned the server. Remote compilation is the
first executable validation gate.
