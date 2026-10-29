# Offline child and compiler-ingest capability gate

Run only on `benchmark-host` under the sole compilation lock. This is an independent
correctness gate. Do not merge its setup/prove/verify durations into any
retained timing snapshot.

## Why a new gate is required

`results/final_gate_v5/SR_FINAL30_FRESH10.json` reports
`offline_new_terminal_old_compiled_credential_rejected=true`,
`new_delegation_compile_ns=5748085`, and
`new_delegation_issuance_ns=717900`. The retained source really performs an
old-showing/new-public rejection followed by compilation, issuance and a
successful new showing. However, that JSON boolean was emitted as a literal,
the retained SR unit test checks only that the compiled terminal keys differ,
and the separate Joint Groth16 test is not named in the retained test output.
Those artifacts are useful partial evidence but do not establish the complete
three-step capability gate.

## Required run

1. Copy the current `implementation` tree and the existing
   `sr_comparison_2026_10_23` path dependency into a fresh result directory.
   Retain source hashes, `Cargo.lock`, its SHA-256, compiler versions and the
   exact commands.
2. Run `cargo fmt -- --check` in `implementation/baselines/sr_joint_bbs`.
3. Run `cargo check --release --locked --offline --bin offline_compiler_capability_gate`.
4. Run `cargo run --release --locked --offline --bin offline_compiler_capability_gate`
   once, capturing stdout as `RESULT.json`, stderr, exit code and process
   resource record. The program uses fresh `OsRng` for its Joint and SR setup;
   elapsed time is not a reported result.
5. Require schema `plan-a-offline-child-compiler-capability-gate-v1`, exit zero
   and `gate_passed=true`. Require every boolean ending in `_equal`,
   `_changed`, `_matches_request`, `_accepted`, or `_rejected` to be true,
   `initial_active_depth=1`, `child_active_depth=2`, both compiler valid-path
   counts to equal one and both invalid-path counts to equal zero. Retain the
   JSON SHA-256 and all proof/public-field/source hashes.

The rejection sub-gate must isolate the compiled terminal binding. Construct
the canonical current T1 Q16 request for the child terminal first. Then create
a fresh showing from the old credential for that exact Q16, current header,
request interval and verifier nonce. Require the fresh showing to verify
against the old compiled public fields under that request, and require the
same showing and identical request context to fail against the child compiled
public fields with the exact `FullFError::PublicFieldsMismatch` variant. Assert
that the old and child SR public fields are identical in system, circuit
version, epoch, resource and action, and differ only in the terminal key.
Finally, require a new credential issued from the compiler-ingested child to
produce a fresh showing accepted under the same T1 request. A rejection caused
only by replaying an old showing under a changed nonce or context does not pass.

The successful old-public verification is only a primitive control showing
that the fresh proof and unchanged request context are otherwise valid. It is
not a service authorization result. The HTTP verifier does not accept a caller
selected old public tuple: `http_bridge::request_context` decodes
`terminal_agent_pk`, places its coordinates in Q16 slots 14 and 15, and returns
the derived public fields; `sr_http_verifier::sr_verify` passes exactly those
fields to `full_f_bbs::verify`. The service constructs the canonical request
from the received envelope before calling that verifier. Retain the JSON
`old_public_t1_request_control_scope` string so the control cannot be reported
as service `Accept`.

Retain three explicit evidence groups in `RESULT.json`: (1) complete initial
and child snapshot-record hashes plus their equal Joint snapshot digest, and
complete initial and child signed-root hashes; (2) initial/child Joint public
input and proof hashes under the same proving key; (3) T1 Q16/request-context,
nonce, old/new SR public fields, credentials and fresh showing hashes. The
validator must require `sr_public_fields_differ_only_in_terminal=true`,
`t1_current_public_matches_compiler_child=true`,
`old_and_new_showings_use_identical_t1_request_context=true`, and the three SR
accept/reject/accept predicates.

The gate proves only the implemented component boundary: Joint can accept a
new offline child under the same authenticated snapshot and one fixed proving
key; the existing nondelegatable SR credential does not cover the new terminal;
after the compiler ingests the child and the issuer signs the new atom, the new
SR showing verifies. It does not claim that the compiler learned the child
without ingestion, and it does not add an HTTP, delivery or production-network
measurement.
