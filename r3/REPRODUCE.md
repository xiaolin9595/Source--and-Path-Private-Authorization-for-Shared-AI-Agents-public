# Reproduction levels

Run commands from the candidate root. Rust commands require a toolchain that can
build the locked 2021-edition crates; this candidate was checked with Rust
1.89.0. All path dependencies are bundled below `sources/`. Registry crates are
locked by the complete Cargo lockfiles; the first build on a new machine needs a
normal Cargo registry cache or one prior `cargo fetch --locked` operation.
This is the anonymous-package verification toolchain. The recorded R3/E2 Linux
measurement build used Rust 1.95.0; the two environments must not be conflated.

The supplied Docker image was actually built from the context identity recorded
in `CONTAINER_VERIFICATION.json`; unified recomputation, the three-gate smoke,
and E3 PDF/SVG generation passed. Documentation-only finalization produces a
new FILELIST and intentionally maps back to that tested context without claiming
a self-referential image rebuild.

## Level 1: cryptographic smoke

This is a real functional smoke, not a syntax check. It generates and verifies
small proofs, exercises signed blind-update admission/CAS, and checks malformed
checked-CRS rejection before a witness callback:

```sh
./scripts/smoke.sh
```

The measured local run completed with `SMOKE_PASS`: one randomized-dummy crypto
gate, one blind-update proof/signature/CAS gate, and one strict checked-key
decoding/callback gate all passed. A clean-target local run took 116.40 seconds
on the preparation machine; this is an observed value, not a runtime promise.

## Level 2: recompute included observations

The candidate includes the authorized, sanitized E1 session records, R2
calibration/formal joined rows, R3/E2 observation rows, R4's ten compact
timing-observation cells, R6's ten component observations, and bounded
historical main-result records. Recompute them and require byte-for-byte
identity:

```sh
python3 scripts/recompute_existing.py
```

Expected digests are:

- E1/R1: `1b9a2845025c1c938693f5be8415a21f6f351dc046d2a4890b1deaef39585773`
- R2: `28ccaa81e7c1c8e5482fd44b56d717470829b4a6001a054be2c9962fa15caea2`
- R3/E2: `a7e8f0e0bc050db5c6bd2a8ff547911117da3a1c5fbe695da7d3689af009e5ad`
- R4 included timing observations: `b77aa2f8740ac0b1868fce479d259d9e24c49ec8ba0fcf14b5d6af27b63c42ef`
- R6 component observations: `5f180c1fd0efe36a2a2934905b788b93917e136e8670452dd35aaa06bd499514`

The command was run during candidate preparation and printed
`UNIFIED_RECOMPUTE_PASS`. E3 includes aggregate results and
official-data retrieval guidance only; private extracts are excluded. The local
earlier three-study recomputation took 6.77 seconds; the current unified
command additionally validates R4, R6, and the bounded historical layer.

Historical entry mapping is: grid200 and depth20-repeat50 under
`results/historical/scaling_grid_200` and `depth20_repeat50`; matched DAC under
`dac_matched`; warm/service/full-request membership under the three
`membership_*` roots; and lifecycle180 under `lifecycle180`. The grid adapter
recomputes raw point statistics and shape only. Its CI endpoints are retained
from the frozen source hash documented in `GRID_CI_PROVENANCE.md`; the original
random-stream derivation was not found and is not reconstructed.

The R4 Level-2 command validates exactly ten cells, fixed relation shapes,
alternating order, proof-verification flags, fresh recorded PK/VK/checking
material identities, all timing fields, pairwise differences, and every
median/minimum/maximum. It then requires byte-for-byte identity with the frozen
analysis. The package deliberately omits the large bundles, so this Level-2
path validates the measurement-time digest records but does **not** rehash or
cryptographically revalidate the omitted PK/checking-material bytes. The
separately named `results/r4/analysis/analyze_r4_formal.py` is unchanged and
continues to require the complete bundle files for a Level-3 run.

Create an isolated, version-pinned plotting environment and regenerate the
public E3 four-panel figure from aggregate rows only:

```sh
./scripts/render_e3_figure.sh /tmp/e3-figure
```

The expected PDF SHA-256 is
`fea45aa7c7df89b6951c43272fae196e14986b14db74ce60434d664814e129fe`.
The exact Python package versions are in `requirements-e3-figure.txt`. PDF bytes
can vary with platform font/backend metadata even when all plotted values and
layout are the same; the expected hash is a strict check for the documented
macOS/Python 3.9.6 environment, not a universal cross-platform promise.

## Level 3: complete experiment entry points

The real drivers are included and exposed by `scripts/run_full.sh`; there is no
placeholder supervisor name. Show each frozen driver interface with:

```sh
./scripts/run_full.sh e1 --help
./scripts/run_full.sh r2 --help
./scripts/run_full.sh e2 --help
```

Build the actual binaries with the bundled source and lockfiles:

```sh
cargo build --locked --release --manifest-path sources/e1_original/Cargo.toml \
  --bin e1_original_native
cargo build --locked --release --manifest-path sources/r1_randomized_dummy/Cargo.toml \
  --bin e1_r1_dummy_native
cargo build --locked --release --manifest-path sources/r2_presentation/Cargo.toml \
  --bin r2_loopback
cargo build --locked --release --manifest-path sources/r3_blind_update/Cargo.toml \
  --bin blind_update_e2_agent --bin plan_a_service_core
```

E1 consists of four independent sessions. For each session, use a new output
directory and the frozen relation identifiers:

```sh
./scripts/run_full.sh e1 \
  --session 1 \
  --original-bin sources/e1_original/target/release/e1_original_native \
  --dummy-bin sources/r1_randomized_dummy/target/release/e1_r1_dummy_native \
  --original-relation-sha aaa275c14c7138470195b6b4b083ddcf4982963c0cd7f24a69bc861e4a3cbf02 \
  --dummy-relation-sha a39da393348b43a537e0c8f52318449edefba94a5961caefbcaa4d24d1bfbe6c \
  --output runs/e1-session01
```

Repeat with sessions 2--4, then analyze all four `records.jsonl` files with
`results/e1/analysis/analyze_e1.py`.

For a complete R2 calibration-to-formal run, the package supplies a one-command
supervisor. It builds the binary, derives source/gate/configuration identities
from the packaged files, rejects reuse of all sixteen packaged E1 setup-key
identities, generates two fresh calibration and four fresh formal setups,
freezes `Tpad`, and writes a run manifest:

```sh
./scripts/run_full.sh r2-complete runs/r2-complete
```

No digest or path placeholder is required. The resulting run manifest explicitly
states that its hashes identify the sanitized anonymous package rather than
claiming byte identity with private-path-bearing historical manifests.

Before committing hours to the full run, exercise the same build, package-hash,
E1-key-collision, fresh-setup, Agent/receiver, gate, and joined-row control flow
with nine gates and three measurements:

```sh
./scripts/run_full.sh r2-complete runs/r2-control --control-test
```

For expert inspection, an individual R2 session can also be invoked directly.
Create a fresh key pair with the real loopback binary, then pass the resulting
key files and computed package identities to the frozen session driver:

```sh
sources/r2_presentation/target/release/r2_loopback setup runs/r2-setup01
./scripts/run_full.sh r2 --phase calibration --session 1 \
  --binary sources/r2_presentation/target/release/r2_loopback \
  --pk runs/r2-setup01/pk.compressed --vk runs/r2-setup01/vk.compressed \
  --output runs/r2-calibration01 --setup-id calibration-01 \
  --config-sha256 "$(sha256sum results/r2/R2_PROTOCOL_FROZEN.md | cut -d' ' -f1)" \
  --gate-manifest-sha256 "$(sha256sum results/r2/R2_GATE_MANIFEST.md | cut -d' ' -f1)" \
  --source-manifest-sha256 "$(sha256sum results/r2/R2_SOURCE_MANIFEST.md | cut -d' ' -f1)"
```

The complete frozen protocol requires two fresh calibration setups, selection
of `Tpad` by the frozen analyzer, and four different fresh formal setups. Formal
sessions pass the frozen positive value with `--tpad-ms`.

R3/E2 generates its fresh setups internally. The full reviewed scale is ten
setups, thirty measured updates, and three independent warmups per setup:

```sh
./scripts/run_full.sh e2 \
  --agent sources/r3_blind_update/target/release/blind_update_e2_agent \
  --core sources/r3_blind_update/target/release/plan_a_service_core \
  --output runs/e2-full --setups 10 --updates 30 --warmups 3 \
  --source-manifest results/r3_e2/SOURCE_MANIFEST.sha256 \
  --protocol results/r3_e2/E2_PROTOCOL_FROZEN.md \
  --analyzer results/r3_e2/analysis/analyze_e2.py \
  --gate-manifest results/r3_e2/GATE_MANIFEST_SANITIZED.sha256
```

The sanitized gate manifest retains the frozen member digests but replaces its
remote absolute path prefixes with logical `gate/` names. Its package hash is
therefore intentionally different from the private-path-bearing source file.

Complete cryptographic reruns require Linux, loopback networking, at least ten
available CPU cores, sufficient RAM, and substantial temporary storage for
fresh Groth16 keys. Use CPU affinity 0--9, `RAYON_NUM_THREADS=10`, and
`OMP_NUM_THREADS=1` as frozen by the protocols. E1/R2 contain thousands of
proofs and take hours; E2 performs 300 measured updates plus warmups. Never
overwrite a run, discard overflow/failure rows, or tune thresholds after seeing
data.

R4's reviewed five-plus-five compact timing collection is included for Level-2
numeric recomputation. A Level-3 R4 rerun creates fresh full bundles and invokes
`results/r4/analysis/analyze_r4_formal.py`, which hashes every PK, VK, and
checking-material file before accepting a cell; this invariant must not be
weakened. The large historical bundles are not distributed in this Git-sized
candidate.

R6 is included as ten compact observations plus its frozen analyzer, runner,
schedule, and package-relative source. Recompute it independently with:

```sh
python3 scripts/recompute_r6.py
```

The expected analysis SHA-256 is
`5f180c1fd0efe36a2a2934905b788b93917e136e8670452dd35aaa06bd499514`.
The original runner remains byte-identical under `frozen/`; the adjacent
wrapper only rebases repository paths. This is full-tree reconstruction, not
incremental throughput, enrollment, or an end-to-end access service.

The package-relative fresh-run entry was exercised at small depth through its
adapter correctness tests. A fresh component trial can be run with:

```sh
cargo build --locked --release --manifest-path sources/r6_tree_maintenance/adapter/Cargo.toml
cargo build --locked --release --manifest-path sources/r3_blind_update/Cargo.toml \
  --bin plan_a_service_core --bin plan_a_mutation_cli
python3 sources/r6_tree_maintenance/run_packaged_trial.py \
  --depth 3 --seed 4243 --output runs/r6-depth3 \
  --adapter sources/r6_tree_maintenance/adapter/target/release/r6-tree-adapter \
  --service-core sources/r3_blind_update/target/release/plan_a_service_core \
  --mutation-cli sources/r3_blind_update/target/release/plan_a_mutation_cli \
  --adapter-source sources/r6_tree_maintenance/adapter/src/main.rs \
  --adapter-lock sources/r6_tree_maintenance/adapter/Cargo.lock
```

The formal depth-16/depth-20 schedule and five fixed seeds per depth are in
`results/r6/SCHEDULE.tsv`; full-scale reruns are costly and are not part of the
smoke command.

To perform the full R4 Level-3 collection from fresh bundles, build both actual
relation drivers and create a source/dependency manifest whose paths are
relative to this candidate:

```sh
cargo build --locked --release --manifest-path sources/r4_service/Cargo.toml \
  --bin r4_checked_blind --bin r4_checked_joint
./scripts/make_r4_source_manifest.sh runs/r4-source-dependency.sha256
results/r4/analysis/run_r4_formal_v5.sh \
  runs/r4-formal-v5 \
  sources/r4_service/target/release/r4_checked_blind \
  sources/r4_service/target/release/r4_checked_joint \
  runs/r4-source-dependency.sha256
python3 results/r4/analysis/analyze_r4_formal.py \
  --run runs/r4-formal-v5 --output runs/r4-formal-v5/ANALYSIS_REPRODUCED.json
```

The manifest must be generated before the run and `sha256sum -c` must succeed
from the same candidate root. The supervisor creates five fresh bundles for
each relation. The final analyzer then reads and rehashes all three bundle files
for every cell; it cannot operate on the compact Level-2 package alone.
