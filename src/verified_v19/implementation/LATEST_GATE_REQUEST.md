# Latest integration gate (after E5 releases the benchmark-host lock)

Freeze the entire `implementation` tree after this file. Run only on benchmark-host:

1. Main crate all-target check and release build for `plan_a_agent_cli`, `plan_a_service_core`, `plan_a_mutation_cli`, `plan_a_proof_cli`.
2. Baseline `sr_joint_bbs` all-target check and release build of `joint_lifecycle_artifacts`.
3. Targeted tests: `constraint_observer`, `offline_delegation`, and baseline `joint_revocation_lifecycle`.
4. `service/real_http_trace.py` with agent/core/mutation/lifecycle binaries and the matching L3 PK/VK.
5. `service/resident_http_trace.py` for ten warm requests, recording cold PK load separately.
6. `plan_a_proof_cli e5-interleaved PK 3 500 DS DRA DREV SEED` is the preferred E5 driver for any rerun; proof randomness remains `OsRng`.

Do not rerun T1 primitives, the 16 business negatives, q128, or the 200-cell E2 sweep unless the observer matrix test differs. Core relation code before the observer is byte-identical to v9; the observer must prove complete A/B/C equality on/off.

## Post-audit source delta (do not rerun E2/E5)

- Signature nonce now rejection-samples a canonical nonzero scalar from the full field using SignatureNonce(sk,message,aux limbs,counter); challenge mapping/R1CS matrices are unchanged. Run signature native/R1CS tests plus the full-range boundary test.
- External snapshot/request/terminal inputs now carry trusted `deployment_id`; run same-key cross-deployment header, presentation, and terminal replay negatives.
- Agent and core share `contract::terminal_transcript`; run one-shot and resident HTTP positive/bad-terminal cases.
- Successful update/revoke ACKs must contain `publication_status=pending`; successor installation remains a separate measured event.
- E2/E5 retain their frozen manifests with fixture state_version 7. Current bootstrap fixture version 0 is not their source version.
