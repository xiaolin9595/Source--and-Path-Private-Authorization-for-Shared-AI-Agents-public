# Plan A HTTP service prototype

This service implements the T4 root-window and T8 HTTP enforcement logic around the real Rust proof CLI contract in `PROOF_CLI_CONTRACT.md`.

Properties implemented:

* core-verified signed atomic `(RA root, state epoch/root, revocation epoch/root, tuple version, issue time)` headers whose state and revocation roots are rebuilt from committed registry records under the header transaction lock;
* immutable publication time and duplicate-header rejection, preventing re-publication from extending an old root's lifetime;
* exact tuple lookup, so mixed roots and a different tuple under the same epochs reject;
* current header remains valid until replacement; a retired header is accepted through the inclusive `retired_at + Delta` boundary, and `Delta=0` leaves only the current tuple after retirement;
* canonical request binding of method, path, body, audience, resource, action, nonce, expiry, agent, circuit, VK and snapshot;
* real subprocess calls to both proof and terminal-signature verification;
* SQLite `BEGIN IMMEDIATE` and a uniqueness key on `(audience, terminal agent, nonce)` for exactly-once resource commit under concurrency.

The trusted commit clock is read after `BEGIN IMMEDIATE` acquires the writer lock. Request interval/expiry and tuple retirement are then rechecked, so database lock wait cannot carry a previously valid request across its deadline. This HTTP prototype routes only the exact `/resource/read` path; queries are rejected by the route check rather than included in the canonical business request.

This is accurately an **HTTP prototype**. It does not claim MCP 2026-07-28 compatibility: that version additionally requires its stateless request envelope, per-request `_meta`, MCP method/name headers, OAuth 2.1 bearer handling and protected-resource discovery. A later adapter can map MCP request fields into this service's canonical request without changing the proof boundary.

Normal mode has no mock verifier. Test-only verifier fixtures must never supply cryptographic timing or evidence of authenticated updates. The Rust core verifies registry admissions, owner signatures over deployment/position/version/epoch/the complete opening, revocation capabilities, headers, proofs and terminal signatures. Remote evidence must still distinguish those cryptographic stages, database commit and total HTTP latency.

`POST /admin/enroll` verifies a registry-signed admission and atomically records a unique owner and unique assigned position for the service's configured deployment together with the owner key, registration salt, expiry cap, and initial state. `POST /admin/state-update` accepts no caller-supplied admission facts: it loads those facts and the current epoch/active state from the trusted tables, injects them into the real CLI's `state-update-verify` command, then repeats the lookup and performs a SQLite compare-and-swap while holding the writer lock. `POST /admin/revoke` passes the revocation capability to `revoke-authorize`, then uniquely inserts the returned serial. `/admin/header` reads the trusted clock only after acquiring its writer lock, rebuilds both Poseidon roots from the committed records, rejects even a correctly signed tuple with mismatched roots or state epoch, and writes a transition receipt in the same transaction. The RA root remains supplied by the separately trusted RA publisher and is covered by the complete tuple signature; this prototype does not materialize the RA tree in SQLite.

The SR update boundary must accept a structured state opening rather than an opaque replacement leaf. It looks up the preassigned `(owner_commitment, position)`, authenticates that owner over the deployment, position, expected version, new epoch, and entire opening, then reconstructs the leaf itself. The SR consequently sees `grant_root`, state expiry, active status, salt, version, and epoch, though it need not see grant contents. Admission and transition policy must prevent an owner from copying another owner’s opening or reactivating a source-disabled record. An RA-bound position or an equivalent zero-knowledge update proof would be needed to hide this opening from the SR.


`real_http_trace.py` writes a JSON trace whose `checks` object records bootstrap admissions, header and request mutations, nonce/CAS/revocation races, rejected signed root mismatches, materialized successor roots and linked H0/H1 revocation publication. `resident_http_trace.py` records one cold proving-key load and ten warm Agent proof plus HTTP request measurements. A trace is evidence only with its frozen source manifest and shared Linux host logs.

### Deployment and publication boundary

The process is single deployment. `--deployment-id` is trusted configuration and must match the deployment field in the signed snapshot, canonical request, proof verification statement, and terminal-signature request. Sharing registry/VK keys does not enable cross-deployment replay because the core rejects a mismatched deployment before cryptographic verification.

A successful mutation response carries `publication_status: "pending"`: the database record is committed while the current header is unchanged. A successor becomes enforceable only after `/admin/header` verifies its signature, rematerializes its state and revocation roots from the database, and installs it atomically. Trace timestamps are observations, not a promised publication bound. The RA root remains supplied by the separately trusted RA publisher and is covered by the signed snapshot.
