# R6: measured large-population state maintenance

2026-10-30. This design follows the source audit in `r6_preparation/R6_SOURCE_MAPPING.md`. The user authorized completion of remaining experiments; no additional approval is needed. Preserve frozen R1–R4 sources.

## Question and implementation identity

Measure the actual current cost of replacing a state leaf, materializing and authenticating its new root, and refreshing a holder path at populations 65,536 and 1,048,576. Both populations occupy every leaf of a state tree of depth 16 or 20, respectively. These are population measurements, not empty-tree capacity tests. The existing implementation performs full sparse root reconstruction and dense holder reconstruction. Do not introduce an incremental-node prototype merely to obtain a favorable throughput number. Do not describe these results as incremental updates or sustained production throughput.

## Workload and measurements

Build an isolated adapter from the audited blind-update implementation. Reuse its Poseidon leaf/node domains, state serialization, transactional state CAS, full sparse materializer, snapshot signing/verification, and dense holder tree/path construction. If a helper is inaccessible, extract the exact routine without altering its logic and retain a diff and equivalence tests. Do not alter the running R4 copy.

Use five recorded deterministic workload seeds per population. Initialize N valid synthetic state rows, with a recorded uniformly selected target index and valid replacement state. Keep unrelated registration/revocation populations fixed and document their values. Initial population construction is outside update latency and reported separately. A workload seed is independent synthetic state, not an independent cryptographic setup.

Measure each stage separately: (1) one accepted transactional leaf CAS with a prevalidated update, (2) database read and state-root reconstruction, (3) canonical snapshot construction and header signing, (4) receiver header verification and holder path reconstruction, (5) serialized public state bytes and path bytes. Record complete maintenance latency spanning stages 1–3 as a separate timer, and full refresh separately. Identify whether each stage includes serialization, process startup, file I/O and database transfer. If using in-process primitives, name the result component measurement rather than HTTP service latency. Do not include Groth16 setup, checked-CRS loading or proving in a tree-maintenance measurement. Proof verification cost is covered by R3; the CAS timer is explicitly conditional on an already validated update.

Use the existing fixture signer and label it synthetic key use. Verify the new header signature and refreshed path against its new root, and test stale-CAS rejection. Assert that the updated leaf differs, the root differs, unchanged rows remain intact, and a path for a distinct unchanged holder still verifies after refresh. At a small depth, compare the sparse materializer with independent dense reconstruction before scaling. Record peak process RSS and stage boundaries; do not infer stage-specific RSS from whole-process peak RSS.

## Pilot, execution and reporting

First conduct a small correctness check and one depth-16 pilot. Preserve pilot logs separately. Assess time and memory before running depth 20; use a bounded timeout and fail-stop on invalid roots, missing stages or resource failure. A failed attempt is retained, never silently replaced. If five depth-20 workloads are infeasible, report the actual count and observations; do not represent a truncated run as five observations. Freeze source, dependencies, workload seeds, measurement windows and runner before formal execution. Run formal R6 after R4 formal measurements to avoid adding self-induced contention to R4. Shared-host conditions remain explicitly recorded; no exclusivity claim.

For each population report five observations, median and min–max. Compute per-trial sequential maintenance rate as one divided by complete maintenance seconds, and summarize those rates; label it reciprocal sequential latency, not sustained/concurrent throughput. No bootstrap CI is justified from five synthetic workloads alone. Retain raw per-stage timings, exit status, environment allowlist, source hashes, root/path correctness results and reproducible analysis. One appendix table and a concise main-text interpretation will be written only after reviewing real results.

## Deliverables

Adapter and meaningful correctness tests; frozen protocol/runner; separate pilot and formal records; reproducible analysis and a compact metrics note; exact measured scope and any omitted stage identified. If actual integration would require a new service protocol, stop that expansion and measure the audited components with accurate labels. Never present an unexecuted stage as measured.
