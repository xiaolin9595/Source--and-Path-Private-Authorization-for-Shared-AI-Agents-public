# R2 independent release-time experiment — design freeze

2026-10-29, Asia/Shanghai. User approved R1+R2 after the completed E1 attempt failed its median-difference screen. This document freezes the design before any R2 calibration or formal measurement. Implementation hashes and a correctness gate must be added before collection. E1 data are not calibration data.

## Relation, request and receiver

Use an isolated copy of the completed R1 valid-dummy relation, production depths 20/20/32, root-grant depth 3, maximum path capacity 3, Native backend. Preserve E1 directories, binaries and observations. A new presentation executable is allowed; the authorization matrix must match the R1 frozen matrix at every length. Keep setup and prepared real authorization templates outside the online interval; clone, challenge-bound request construction, fresh dummy preparation, proving, terminal signing and serialization are online.

Use a separate loopback TCP observer/receiver process. It sends a fresh OS-random 32-byte challenge and records monotonic time immediately before sending the challenge. Define request nonce as Fr::from_le_bytes_mod_order(SHA256(domain || challenge)), with a fixed versioned domain chosen in the implementation manifest. The receiver independently computes it. The complete canonical request and snapshot digests must be reconstructed and checked, not substituted with the E1 diagnostic 123+nonce expression. Bind the terminal signature to the canonical request, snapshot, configured circuit and exact compressed proof using the existing terminal-transcript construction. Reuse existing cryptographic serialization and verification routines where possible.

After receiving the entire challenge, the agent records t_agent and starts the online operation. Transfer the actual compressed proof, canonical public statement and terminal signature, not merely their hashes or a self-verification result. The wire must not include experimental length, arm, block, session, timings or labels. Public request fields and encoding widths must have the same distribution across lengths. Use one fixed, bounded canonical envelope format and fixed size across experimental lengths; document and test the bytes. A dedicated local control channel may carry the scheduled private witness choice; record this separately and keep it outside the receiver-facing wire. No completion notification may reach the observer before the presentation release.

The receiver records t_arrival immediately after reading the complete bounded frame and BEFORE proof or signature verification. Primary observation = t_arrival - t_challenge_send. Subsequently verify the proof, statement/challenge consistency, expected terminal key, signature, request/snapshot/circuit binding and one-use challenge state independently. Invalid or incomplete rows invalidate collection; never omit them silently. Log correctness results outside the timed receive boundary.

## Release algorithm

Let t_ready be the time at which the complete signed serialized presentation buffer is ready. For padded arms use k=max(1,ceil((t_ready-t_agent)/Tpad)) and deadline=t_agent+k*Tpad. Wait against the monotonic clock until that deadline, then call send. Record k, t_ready, deadline, actual send-call time, last-send return time and actual complete receive time. Never release before deadline. Do not adapt Tpad by length, label, elapsed formal results or machine load. A missed deadline due to scheduler wakeup is recorded as overshoot; do not silently change k after wakeup. For the unpadded control, send as soon as the identical buffer is ready.

Record actual waiting as send-call time minus t_ready; report its arithmetic mean, distribution and per-length values. Overflow means k>1. Record overshoot separately from overflow. The connection is established before each measured challenge; use the same connection policy in every arm. Fixed timeout 60 seconds per response; a timeout stops the attempt with its partial data retained.

## Independent calibration

Two new calibration sessions, each with a fresh R1 setup, 100 balanced blocks of three lengths: 600 genuine unpadded online presentations, 200 per length. Nine unmeasured gates per session. A fixed schedule seed and schedule hash are recorded before collection. No E1 or smoke/gate timings enter calibration.

For each length compute the nearest-rank empirical 99th percentile of ready elapsed time t_ready-t_agent, with sorted rank ceil(0.99*n). Fix Tpad to ceil((max of the three percentiles + 100 ms)/50 ms)*50 ms. These margins are predetermined design choices, not estimates of a guaranteed tail bound. Retain all calibration samples and report sample sizes and finite tail resolution; do not claim a measured p99.9. Freeze the chosen Tpad, calibration digest and implementation identity before formal collection. No second candidate is selected from formal outcomes.

## Formal measurement and analysis

Four new setups/sessions, independent of both calibration setups and E1 keys. Each session has 125 balanced blocks. Each block contains lengths 1/2/3 in three arms: u (same R1 presentation, immediate send), pA and pB (identical padded algorithm with diagnostic labels only). Total 4500 formal presentations; nine unmeasured gates per session. Randomize each block with a preregistered schedule seed independent of challenge/proof randomness.

Primary screen pools pA and pB in advance: every pairwise absolute median difference of ACTUAL receiver durations <=15 ms AND nearest-median length-classification accuracy <=45%. Train on sessions 1/3 and test on 2/4, use fixed smallest-length tie breaking. Report the unpadded control, each padded label, A/A label classification by length, paired A/A differences, per-session medians, confusion matrices and 1000 deterministic session/block bootstrap intervals. Labels are joined from the private schedule only after collection, never parsed from wire.

Report overflow counts/rates by length with binomial intervals, actual waiting means/quantiles, send scheduling overshoot, primary end-to-end durations, raw ready durations and per-phase computation. Overflow samples remain in ALL primary statistics. Do not condition success on first-bucket observations. A pass is an empirical result for this loopback observation and workload only; it is not constant-time computation, resistance to all repeated-observation attacks, or Internet-wide privacy.

## Execution and gates

### Statistical and encoding addendum, before collection

Use Python random.Random with schedule seed 2026102960+calibration_session (1 or 2) and 2026102970+formal_session (1 through 4); serialize and hash the entire schedule before the first measurement. Proofs, dummy witnesses and challenges continue to use OS entropy. Record the Python version.

The 1000 bootstrap replicates apply to pooled median differences, actual-wait means and overflow fractions, not to classifier accuracy. Use random.Random(2026102980): sample four sessions with replacement from [1,2,3,4]; for each selected session occurrence independently sample 125 whole blocks with replacement, retaining all nine cells of each block and pairing throughout. Recompute each statistic; use sorted replicate elements 24 and 974 (zero based) for the 95% percentile interval. This resampling does not train a classifier. All reported classifier point estimates use the original fixed training/testing split. Within each length, the A/A classifier uses separate pA and pB training medians and assigns each test duration to its nearest label median, with ties assigned to pA. Report exact correct/total counts. Paired A/A summaries use pA minus pB within the same session/block/length, reporting mean and median over 500 pairs.

Use Wilson 95% binomial intervals (z=1.959963984540054) for overflow counts as nominal descriptive intervals; within-session dependence means these are not an independent-trial guarantee. Also provide the session/block bootstrap overflow intervals above. With only four sessions, neither interval establishes a universal tail bound.

Maximum envelope size is 1 MiB; the measured successful envelope must have one identical byte length across all lengths and arms. With the same challenge, all canonical request, snapshot and public-input bytes must be exactly equal across three path lengths; proof/signature randomness is excluded from that equality assertion. The authorization fixtures retain the R1 synthetic self-delegation pattern and common terminal; this study does not claim a sample of real deployment paths.

Use existing authorized shared Linux host, CPUs 0–9, Rayon 10, OMP 1, the existing pinned compiler/dependencies, shared-host telemetry. Run no other heavy experiment from this task concurrently. Do not rent compute or alter unrelated jobs.

Before calibration: test proof/terminal-signature round trips and receiver-side mutations of nonce/challenge, request, snapshot, signature, proof and circuit identity; replay rejection; malformed/oversize/truncated framing; fixed wire size; all three lengths; matrix identity; release boundaries/overflow/overshoot; independent complete receive timestamp; analyzer rejection of missing/duplicate/wrong-arm/timing-invalid rows. Synthetic timing tests are only software tests and cannot enter measured results. Complete a small real loopback gate with actual proof and signature, including a deliberate overflow, and keep it outside calibration and formal data.

Before each collection phase freeze source/binary/VK/PK/config/schedule/analyzer identities. Refuse existing output directories. A correctness or schema failure stops the attempt and preserves evidence. Changes after collection require a separately named attempt and explanation. This design authorizes implementation and gates now; root review of those gates releases calibration and then the predetermined formal run without further user confirmation.
