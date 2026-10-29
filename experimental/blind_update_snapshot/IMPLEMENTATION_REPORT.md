# R3 implementation report

Date: 2026-10-29

## Functional result

Rust integration tests: 4 passed, 0 failed. They cover root replacement, owner deactivation, wrong owner/position/leaf, deployment/cap/admission public-input substitution, version overflow, non-increasing epoch, expiry over cap, inactive recovery, proof mismatch, signature mismatch, illegal identity public key, replay, and two-thread CAS (exactly one success).

The original Python result was a direct application-function integration test, not an HTTP test. It passed with the real verifier and SQLite, but that evidence is now superseded by the independent review fixes below. `test_blind_update_service.py` now starts `ThreadingHTTPServer` on loopback and sends requests through `BaseHTTPRequestHandler`, including concurrent requests, duplicate JSON keys and a wrong route. The updated socket test has not yet been rerun with the Rust fixture because formal E1 currently owns `206160G` and the local Rust runtime is unavailable.

Previously observed in the pre-review functional fixture (not E2 timing; superseded because the identity-binding constraint changed):

- constraints: 10,949 (pre-review only; recount required)
- compressed Groth16 proof: 192 bytes
- compressed verifying key: 1,016 bytes
- canonical JSON request: 1,034 bytes
- Rust: 1.95.0 x86_64 Linux on existing shared `206160G`

No setup/prove/verify latency claim is made here. No 10-setup/30-update E2 run was performed. The post-review Rust build/proof/socket gate remains pending until it can run without overlapping E1.

## Independent-review corrections

- Legacy CAS now rejects `active IS NULL` inside the writer transaction before Boolean conversion. A local regression test covers the exact inactive legacy verification → blind commit → legacy CAS interleaving.
- State versions, state epochs, expiry caps and admission versions use canonical 20-digit unsigned decimal TEXT. Every comparison decodes to a Python integer; SQL string ordering is never used. A one-time migration rebuilds legacy signed-INTEGER tables, preserves rows and makes the active column nullable.
- Local storage tests pass at `2^63-1`, `2^63`, and `2^64-1`; encoding `2^64` is rejected. The circuit's existing `u64::MAX -> 0` overflow rejection remains in the Rust test suite pending rerun.
- The functional fixture no longer uses identities 1/2/3. Config and deployment identities use explicit domain-separated SHA-256-to-field derivation. The circuit identity binds the frozen R1CS matrix SHA-256 and compressed VK SHA-256. A public Poseidon identity-binding input consumes config/deployment/circuit values without making the matrix value-dependent.
- Local lightweight Python checks after the corrections: 14 passed. Four R3-specific checks cover a real loopback `ThreadingHTTPServer`/handler exchange (using a lightweight verifier double only for routing), u64 boundaries, legacy-schema migration, and the inactive blind/legacy race; ten unchanged baseline service-logic tests also pass. The socket test with the real Rust verifier remains pending.

## Actually integrated interfaces

- Rust relation: yes
- In-process SR admission/proof/signature/CAS: yes
- External resident-style JSON verifier command `blind-state-update-verify`: yes
- SQLite service application endpoint `POST /state/blind-update`: yes
- HTTP body opening fields: absent and rejected by exact schema
- service request-body logging: absent (`log_message` disabled and body is never emitted)
- persistence of new opening: absent; post-update active hint is `NULL`
- legacy visible-opening endpoint: retained for pre-blind rows, rejected after the row enters blind mode
- initial enrollment opening/history: still visible baseline behavior
- authority suspension/recovery: not present in baseline and not added

## Claim limits

The circuit proves consistency and monotonic transition rules; it does not prove that the new salt is freshly or randomly generated. SR still sees owner identity/key, fixed position, cap, old/new commitments, version, epoch, ordering/timing, request size, and outcome. This work does not justify “SR sees only update time,” a coalition theorem, malicious-SR integrity, or strengthened paper claims before review.

