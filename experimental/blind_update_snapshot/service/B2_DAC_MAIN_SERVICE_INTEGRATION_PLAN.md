# B2 DAC main-service integration plan

Status: implementation pending the frozen DAC builder/CLI export.  This file
defines the service boundary that the matched gate must enforce; it is not a
pass claim.

## Trusted reconstruction boundary

The HTTP caller supplies only the authorization envelope and proof bytes.  The
service reads the installed header from its own SQLite registry, parses the
HTTP method/path/body, reads its trusted clock, and builds the expected DAC
statement from:

- trusted deployment, relation, mapping, policy, schema, circuit, verifier,
  and parameter identifiers;
- the current installed header and accumulator value;
- the canonical resource, action, time interval, nonce, terminal identity and
  terminal public key derived from the request; and
- the SHA-256 tagged digest of the service's canonical request JSON.

The verifier CLI receives this service-built statement.  It must not accept a
caller-built statement merely because its internal header/request digests are
self-consistent.  It compares every reconstructed field to the public inputs,
checks canonical proof bytes, runs the BW6-761 Groth16 verifier, and checks the
terminal signature over the exact proof and reconstructed statement.

## Header and root encoding

The service instance pins one backend and one canonical root encoding in its
trusted configuration.  Joint and DAC use different native fields and root
bytes.  The store can hold either encoding as an opaque canonical hex string,
but the active instance rejects the wrong length or noncanonical field value.
No digest truncation or cross-field conversion is permitted.  The public
snapshot digest remains a tagged SHA-256 digest of the full canonical snapshot
JSON.

Header installation calls the selected backend CLI to recompute typed RA,
state, and revocation/accumulator values from the stored canonical records,
then checks the registry signature and monotonic tuple/epoch rules before the
SQLite transaction installs the version.

## Atomic commit and durability

After cryptographic verification, the service starts the same SQLite writer
transaction used by the Joint gate.  Inside that transaction it rereads the
trusted clock and current header, rechecks `Delta=0`, request expiry, the exact
proof ticket, terminal signature, and nonce, then inserts the nonce and the
resource effect atomically.  In-memory `DeltaZeroAdapter` evidence is a
relation/reference gate only; the matched HTTP row does not claim equal
durability until this SQLite path passes for both backends.

Correctness gates cover stale header, mutated method/path/body/resource,
terminal, nonce replay/race, altered proof bytes, altered terminal signature,
and expiry between read and commit.  A failed attempt must not consume the
nonce.

## Resident process and timing

The matched runner keeps each backend verifier resident or, if the current
one-shot service boundary is retained, measures process startup separately and
does not subtract one backend's internal crypto time from the other's command
wall time.  Every row reports:

1. internal setup, proof generation, and proof verification;
2. local proof delivery/pipe time;
3. HTTP loopback and SQLite commit wall time; and
4. total symmetric client cycle, with balanced backend order.

Public header materialization/publication is a shared lifecycle event and is
reported once.  Production network and queueing remain explicit unknown
variables.  The formal matched set uses at least ten fresh setups/trials where
setup applies, keeps raw paired rows and 10,000-resample 95% bootstrap
intervals, and records deployment-constant, matrix, PK, and VK digests for each
fresh setup.  Same-matrix evidence is limited to the multiple legal witnesses
proved under one deployment/CRS.
