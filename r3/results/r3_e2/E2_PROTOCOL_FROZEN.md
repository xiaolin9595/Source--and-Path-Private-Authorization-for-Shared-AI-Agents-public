# E2: cost of authenticated blind state replacement

Design date: 2026-10-29. Author authorization: continue R3/E2. This document freezes the experiment design before formal samples. A source-and-tool manifest, successful current-source functional gates, and explicit root release are additionally required before formal collection. Later corrections must be logged, never silently applied to completed samples.

## Research question and scope

Measure the cost of replacing an admitted owner's state commitment without sending the successor opening to the state registry (SR). Report relation size, proof and key sizes, client proof generation, cryptographic verification, and actual HTTP update acceptance. Initial admission and its opening are visible and are prepared outside the update timer. SR also observes the owner, stable position, versions, epochs, public commitments, admission metadata, and request timing/outcomes. This experiment does not estimate anonymity or establish commitment hiding.

The handbook's reference to a thirtieth update is operationalized as thirty successive updates by the same owner. The thirtieth update is not a thirtieth independent user. Large-population tree throughput belongs to the separate optional R6 experiment.

## Functional release gates

Run the current Rust relation tests and real HTTP tests with the actual Rust verifier. Archive stdout, stderr, exit status, toolchain, source hashes and commands. Existing historical reports do not substitute for these records. Check authorized root replacement, owner deactivation and prevention of reactivation; owner/position/cap/admission/configuration/deployment/circuit binding; proof and signature binding, malformed encodings and invalid keys; preceding-state agreement, replay and concurrent compare-and-swap; integer bounds, nonwrapping version increment and increasing epoch. Verify at least two successive proven replacements and publication of their new leaf in a reconstructed snapshot. Verify the full epoch storage/publication path above the signed-64-bit boundary; direct SQL storage alone is not a proof of a valid transition. State precisely whether access-proof refresh is also exercised.

Inspect actual request schemas and persisted successor rows for absence of the new grant root, expiry, active bit and salt. This establishes absence of transmitted openings, not erasure of admission history or all information about these values. Record concrete public-input, witness, constraint and matrix counts; pin configuration, deployment, circuit and verification-key identities. Do not reuse obsolete counts from an earlier relation.

## Sampling design

Use ten independently generated Groth16 setups. For each setup, initialize an independently generated admitted owner and a fresh database, and perform thirty sequential accepted root replacements. There are 300 formal updates in ten setup clusters. Every measured update retains active=true, uses a fresh root and fresh salt, increments version by one and epoch monotonically, and keeps expiry at a predeclared valid constant within the trusted admission cap. Deactivation is covered by functional tests, not confounded with update position thirty. Cryptographic randomness comes from the operating system.

Before the measured chain for each setup, perform three excluded warmup replacements using a separate warmup owner and database under that setup. Retain warmup records with explicit labels. Setup, admission, initial snapshot and service startup are outside the per-update endpoint interval. The measured client's direct preparation-to-response interval must be timed, not reconstructed by adding component medians. Each accepted row's successor commitment/version/epoch must equal the following row's predecessor. Preserve all formal observations, including slow responses and errors; an unexpected error stops the run with its partial data intact.

## Timing and size observations

Use monotonic high-resolution clocks and report units explicitly. Separately record setup generation; checked proving-key loading; verification-key loading/preparation; client witness preparation; proof generation with a loaded proving key; owner signing and serialization; pure proof verification; the complete server verification stage including its actual external-verifier launch and key handling; atomic state replacement; HTTP request-to-committed-response; and direct client preparation-to-response. Some intervals nest: they must not be added as disjoint costs unless instrumentation establishes disjoint boundaries. Record unavailable subcomponents as unavailable, not zero. Retain the existing per-request external verifier architecture rather than substituting a warm in-process verifier for the headline service measurement.

Record compressed proof bytes, compressed proving/verification-key bytes, complete encoded request bytes, relation constraints and allocation counts, matrix digest, and identity derivation. Key loading is a separate deployment cost; setup randomness generation is included in setup time. Record the exact boundaries of every metric in the driver manifest. Post-update snapshot publication is functionally validated but excluded from HTTP update acceptance unless the endpoint actually performs it; report any separately measured publication interval under its own name.

## Host and execution

Use the already authorized shared shared Linux host host, with CPU affinity 0–9, RAYON_NUM_THREADS=10 and OMP_NUM_THREADS=1. Record hostname, CPU, memory, operating system, compiler/library versions, affinity, start/end time and available load observations. Do not describe the host as exclusive. Use a new remote directory for the current source; preserve prior R1/R2 and blind-update artifacts. Resolve tool paths before launch and refuse an existing formal output directory. Archive source, dependency lock, driver, analyzer, binary and configuration hashes before the first formal sample. No concurrent heavy experiment launched by this task.

## Analysis fixed before collection

Report the pooled median of 300 updates for each latency and the ten per-setup medians. Compute descriptive 95% percentile intervals by resampling ten whole setup clusters with replacement, retaining all thirty observations in each selected cluster, for 10,000 bootstrap replicates using seed 20261029. These intervals reflect setup-cluster variation on this shared host, not independent sampling of 300 users or deployment-wide guarantees. Setup costs have ten observations and use a ten-observation bootstrap with the same replicate count.

For within-chain growth, report the median paired difference (update 30 minus update 1) over the ten setups for HTTP and direct client latency, with a paired ten-setup bootstrap interval. Retain the complete position-by-setup data; do not substitute a difference between pooled marginal medians. Report counts, extrema and error outcomes alongside summaries when they affect interpretation. There is no performance pass/fail threshold and no filtering based on speed. Functional correctness and record completeness are requirements for labeling a run complete.

## Paper integration

Main text: describe the transition relation and SR's residual view, then report measured constraint/proof size, proving time and verification time with a compact table. Appendix: exact relation and authorization argument, service observations, complete timing boundaries and setup-cluster methodology. Preserve the existing conditional presentation-privacy theorem; a new commitment-hiding or unconditional coalition theorem is not inferred from update proof zero knowledge. Recompile the actual V21 manuscript and retain the twelve-page main-text limit without changing template typography.
