# Matched Joint/DAC service contract

Status: static integration source awaiting the sole `206160G` runner.  No local
build, correctness, or performance claim is attached to this file.

`matched_service.py` loads one trusted configuration containing the typed
canonical semantic manifest and its Rust-computed `semantic_input_sha256`.
Both resident backend processes must deserialize that manifest into
`semantic_schema::SemanticManifest`, recompute `manifest_sha256`, and reject a
mismatch before materialization, setup, proof verification, or commit.

The caller supplies only `{backend,envelope}`.  It cannot supply an expected
statement.  The service reconstructs expected values from the canonical HTTP
method/path/body digest, trusted audience and backend profile, the installed
header, the canonical manifest request, the trusted logical-terminal key map,
and the clock.  Backend-native roots and terminal keys may differ.  The shared
semantic hash must be identical.

## Resident verifier JSON-lines protocol

Each command and response is one compact JSON object followed by LF.  A
process must retain adapter/ticket state across calls.

* `materialize-and-verify-header` receives the canonical manifest, semantic
  hash, update index, backend profile and signed header envelope.  It rebuilds
  the backend-native roots from typed records and returns exactly
  `{valid:true,header}`.  `header` includes the semantic hash and the four
  ordered update integers plus all backend-native authenticated values.
* `verify-at-read` receives the manifest, service-built expected object and
  proof envelope.  It recomputes the semantic hash, rejects any statement
  mismatch, parses canonical proof/VK/signature bytes without trailing bytes,
  verifies the proof and terminal signature, then returns exactly
  `{valid:true,ticket}`.  A ticket is opaque, unforgeable, single-use and bound
  to the complete envelope and expected request.
* `commit` receives that ticket, the same envelope, and a freshly rebuilt
  expected object.  It rechecks the current header, `Delta=0`, clock interval,
  exact proof bytes, terminal signature and nonce, consumes the ticket, and
  returns exactly `{valid:true}`.

The service invokes `commit` while holding the SQLite `BEGIN IMMEDIATE`
transaction.  It then inserts the nonce and resource effect in that same
transaction.  A header change, failed commit, or duplicate nonce rolls back
without consuming the SQLite nonce.  A backend must discard a failed ticket;
retry uses a fresh proof verification.

Policy validity and signed-header freshness use one trusted underlying clock.
For this synthetic fixture the service derives one immutable epoch offset from
the canonical manifest: `max(updates[].issued_at) - request.now`. Policy checks
use the underlying value and header installation/retirement use that value plus
the offset. Joint and DAC share the same mapping. The service rejects malformed
or nonmonotone manifest issue times before starting residents; the correctness
gate includes a tampered-mapping startup rejection. Its test clock file is an
explicit harness input. Production defaults to the host clock.

## Required Joint fixtures

The Joint builder consumes the same parsed `SemanticManifest` instance as the
DAC builder.  For update index 1 it must construct two real `JointCircuit<2>`
inputs:

* actual depth 2: `root-b -> child-b`;
* actual depth 1: `root-c` followed by the circuit's canonical disabled slot.

Both use the manifest-derived Lmax=2 profile, entitlement and state paths,
request, terminal mapping, update header, and current indexed-revocation
witnesses.  The old L3 fixture is forbidden.  Before setup, each builder emits
its full consumed semantic projection and requires its typed canonical hash to
equal `semantic_input_sha256`.

## Formal runner output

Run `matched_correctness_driver.py` once before timing, against one resident
service and one SQLite database across t0, t1 and t2. Then run ten fresh setups. Each setup
contains both backends, both actual depths, and one proof per backend/depth.
Balance backend and depth order. Preserve each producer's exact stdout, stderr,
parsed JSON and command log immediately inside its setup directory, and update
partial raw-row/setup indexes after every successful request. Report setup,
prove, internal verify, authorization-dictionary assembly, HTTP plus SQLite
commit, and the explicitly labelled sum of measured components separately.
The component sum is not a complete client wall time: it excludes setup,
witness/input construction outside the producer's prove timer, proof
serialization, terminal signing, producer process startup/teardown, service
startup and header installation. Every row records the shared semantic hash,
backend-native root bundle, source and lock digests, runtime versions, and
deployment/matrix/PK/VK digests and PK/VK/proof byte sizes. Produce
10,000-resample paired 95% bootstrap
intervals.  Sidecar native-root evidence remains labelled separately from full
proof and matched-service gates.

“Fresh setup” means fresh backend CRS/native parameters, PK, VK and proofs.
The canonical semantic manifest, logical IDs, deterministically derived
logical grant/terminal keys, and registry test key stay fixed across setups and
are recorded as such. Timed rows are limited to t1. Lifecycle correctness is a
separate untimed gate.

Predeclared summaries report each backend median and the paired median of
`DAC - Joint`, with a 10,000-resample percentile 95% interval for each backend
median and the paired median difference. Resampling uses the same paired setup
indices for both backend estimates and their difference, separately within
each actual-depth cell (n=10); setup is deduplicated to one value per
backend/setup (n=10). This applies to setup, prove, HTTP/SQLite, and the measured
component sum.

