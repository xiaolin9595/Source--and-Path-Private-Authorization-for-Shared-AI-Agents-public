# Artifact appendix

Paper: **Source- and Path-Private Authorization for Shared AI Agents**.

This appendix accompanies the research artifact. Artifact evaluation has not been submitted, and no badge is claimed. The authors intend to seek artifact evaluation after paper acceptance.

The organization follows the [PETS 2027 artifact instructions](https://www.petsymposium.org/artifacts.php) and its [appendix template](https://petsymposium.org/files/ARTIFACT-APPENDIX.md), accessed 2026-10-30. `FILELIST.sha256` identifies the release files; `SOURCE_INDEX.md` and `RESULT_INDEX.md` distinguish the implementation and measurement generations.

## Description

The artifact implements authorization for shared agents, blind state replacement, randomized dummy grants, scheduled presentation release, and deterministic Groth16 parameter validation. It includes the measurements and analysis associated with these constructions, alongside public-record intersection analysis. Historical implementation and experiment versions remain separately identified because the manuscript reports several distinct evaluation configurations.

Original code and analysis scripts use MIT licensing. Bundled dependencies retain their own notices and licenses. Public input datasets are obtained from their original providers; the release supplies retrieval instructions and derived aggregate statistics.

### Security, privacy and ethics

The functional tests use synthetic authorization records and fixture signing keys. Local service tests exchange requests over loopback networking. The artifact requires no production credential, paid service, or participant account. It does not require disabling host protections. Public-trace experiments analyze groupings and do not identify employees or construct employee delegation histories.

## Basic requirements

### Hardware

The measured cryptographic studies used an Intel Xeon w7-3445 server with 40 logical CPUs and 251 GiB of RAM. Their processes were assigned CPUs 0–9, ten Rayon threads and one OpenMP thread, on a shared host. This describes the measurement environment rather than a minimum memory requirement. The reduced cryptographic smoke and analysis of included observations provide smaller entry points. No GPU or specialized cryptographic hardware is required.

The R4 checked process reached a peak below 873 MiB in the measured authorization relation, while its ordinary loader and setup have separately recorded peaks. At the larger R6 population, the measurement process remained below 638 MiB and the largest child-process peak below 1,091 MiB. These are separate process observations, not bounds on container construction or all concurrent artifact processes. `CONTAINER.md` supplies the measured container environment and storage guidance.

### Software

Cargo lockfiles fix Rust registry dependencies, and the release bundles its path dependencies. The preparation environment builds the new package with Rust 1.89.0. The original scaling, randomized-dummy, scheduled-release, blind-update and R4 measurements use Rust 1.95.0; the manuscript separately identifies Rust 1.85.1 arithmetic studies. Rebuilding with another toolchain does not reproduce an identical historical binary.

Python plotting dependencies are fixed in `requirements-e3-figure.txt`. The aggregate figure was regenerated in a new Python 3.9.6 environment with NumPy 1.26.4 and Matplotlib 3.9.4. The Linux container uses an isolated plotting environment. `CONTAINER.md` records the Docker runtime, immutable base-image identity, package inventory and container verification.

### Time and storage

Observed preparation-machine times are 116.40 seconds for a clean-target cryptographic smoke and 6.59 seconds for recomputation of the four included E1/R2/R3/R4 analyses. Creating a clean plotting environment and rendering E3 took 70.37 seconds; rendering with installed dependencies took 1.72 seconds. These observations are not universal runtime guarantees.

The ten R4 formal setups and paired loading measurements occupied 106 minutes 46 seconds on the measurement server. Their retained local evidence occupies approximately 558 MiB, including complete public parameter files. Those large parameters are not copied into the source repository. R6's ten population workloads occupied 56 minutes 29 seconds; only its compact measurements are included in the release, with synthetic populations generated during a rerun. Full E1/R2 runs contain thousands of proofs and require hours. These complete experimental runs are distinct from the much shorter recomputation of recorded observations. Initial dependency downloads also depend on the network and local caches.

## Environment

### Access

The anonymous reviewer entry is https://anonymous.4open.science/r/joint-authorization-2027/ . The revision package is under `r3/`; historical sources remain at their existing locations. Run the following commands from `r3/`. The repository's generation index identifies the corresponding source and result snapshots.

### Setup and functional checks

Within the new revision directory, `REPRODUCE.md` provides native setup commands and `CONTAINER.md` provides the container commands. The current tested native entry points are:

```sh
./scripts/smoke.sh
python3 scripts/recompute_existing.py
./scripts/render_e3_figure.sh /tmp/e3-figure
```

The smoke must report `SMOKE_PASS`, exercising actual cryptographic and rejection behavior. The analysis command must report `UNIFIED_RECOMPUTE_PASS`, with the individual checks described below. E3 rendering consumes the included 80-row aggregate summary. Its reference PDF hash is platform-specific; comparisons on another platform must also inspect the plotted values and layout.

## Evaluation

### Claims and experiments

| Paper result | Evidence and current entry |
|---|---|
| Baseline authorization and selective revocation, §7.2 | Historical reviewed source and functional tests in `../src/verified_v19/`, together with the preserved earlier experimental sources. |
| Baseline scaling and the independent depth-20 repetition, §7.3 | `results/historical/scaling_grid_200/` and `depth20_repeat50/`: 200 and 50 proof records. The grid's deterministic statistics are recomputed; original bootstrap endpoints are retained with provenance, as explained below. The separate 50-proof analysis is reproduced exactly. |
| Delegation and membership comparisons, §§7.4–7.5 | `results/historical/dac_matched/`, `membership_warm/`, `membership_service/` and `membership_full_request/`: matched DAC measurements and three distinct membership timing windows. |
| Blind state replacement, §7.6 and Appendix F | `results/r3_e2/`: ten setups, 300 accepted updates, median proving 174.838 ms and SR proof verification 6.521 ms; full driver is `scripts/run_full.sh e2`. |
| Length-dependent computation and scheduled release, §7.7 and Appendix G | `results/e1/` and `results/r2/`: independent-session comparison and arrival-time analysis. Full entries are `scripts/run_full.sh e1` and `scripts/run_full.sh r2-complete`; the latter also supplies a reduced control test. |
| Repeated-request proxy intersections, §7.7 | `results/e3/` and `sources/e3_analysis/`: the included aggregate figure and complete analysis using data retrieved from the documented providers. |
| Accepted-parameter functionality and costs, §7.3 and Appendix E | `results/r4/`: ten completed compact timing records and retained functional rejection evidence; fresh-bundle drivers generate and validate both actual relations. |
| Earlier lifecycle measurements, §7.6 and Appendix H | `results/historical/lifecycle180/`: 180 retained trials with their frozen analyzer and summaries. |
| Large-population state maintenance, §7.6 and Appendix H | `results/r6/` and `sources/r6_tree_maintenance/`: five seeded workloads at each of 65,536 and 1,048,576 commitments. Maintenance medians are 7.215 s and 126.099 s; receiver verification plus holder refresh medians are 8.190 s and 122.938 s. All ten trials pass all seven correctness checks. |

Full commands and argument definitions are in `REPRODUCE.md`. `scripts/recompute_historical.py` checks the seven historical result groups without rerunning the experiments; the corresponding verification record states exactly which frozen outputs or fields are compared.

### Expected interpretation

Recomputing recorded observations checks the published statistics. Running a fresh experiment also exercises setup, workload generation and measurement. Fresh random keys and shared-host scheduling imply that a new experiment will have different identities and timings. No post-hoc filtering or threshold adjustment is used to obtain agreement.

For R4, the compact analysis checks recorded identities and timing records. The unchanged complete analyzer additionally hashes the actual PK, VK and checking-material bytes. These are distinct checks. The mathematical security arguments are supplied in the manuscript; successful experiments alone do not establish their theorems.

## Reproduction scope

The 200-proof scaling grid retains complete observations, deterministic summaries and the original confidence-interval ledger. The original per-cell/per-metric bootstrap random-stream derivation was not retained. The supplied checker therefore reconstructs point statistics and validates the saved interval metadata, but does not claim to regenerate those interval endpoints. It does not search for a seed that matches them. Other historical checks are enumerated in `results/historical/HISTORICAL_RECOMPUTE_VERIFICATION.json`.

Original public traces remain at their providers. The release contains retrieval instructions and derived aggregates, not private extracts. Large historical parameter bundles are omitted; fresh complete R4 experiments generate new bundles. No live database, terminal environment, generated secret setup scalar or user credential is a release input.

## Reuse

The implementations expose separately recorded authorization, state-transition and parameter-validation relations. Researchers can vary public workload populations, path capacity and tree depths through the documented experiment drivers, generating new parameters when the relation changes. Public-record analysis can accept another dataset only after its identifiers, grouping semantics and candidate interpretation are specified; a manager field alone does not establish a delegation edge.
