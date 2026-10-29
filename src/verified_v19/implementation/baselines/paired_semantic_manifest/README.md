# Paired semantic manifest gate

This independent crate materializes one canonical logical authorization data
set and maps it into the Joint BLS12-381 and DAC BLS12-377 representations. It
does not require identical root bytes. It recomputes each backend's native RA,
state, root-grant and revocation commitments, then records membership outcomes
for the same ordered updates:

1. A, B and C are active;
2. A is removed from the private root-grant tree while B and C remain;
3. B's terminal serial is revoked while C remains usable.

The source semantic object is serialized to canonical compact JSON and then
deserialized once. Both backend derivations consume only that parsed typed
object. Each backend reconstructs the reversible authorization values from
native grants, keys, entitlement/state objects, request objects, and applied
updates. Fields that are compiler/profile metadata rather than reversible
credential members are listed separately and bound into four public request
context fields (`circuit_id`, `verifier_id`, `pep_id`, and `context`) as the
four little-endian limbs of their SHA-256 digest. The canonical request limbs
independently bind an actual service request:
`SHA-256("plan-a-matched-http-v1\\0" || compact
JSON({audience,body_sha256,method,path}))`. The body digest is computed over
the exact compact request body. This digest is carried through the circuit
request digest and terminal signature transcript.
The output does not describe metadata
as native reverse projection. Each mixed projection is hashed independently. The
validator independently reserializes the embedded object
and both projections, recomputes all three hashes, derives the expected
membership, revocation, and request outcomes, and requires exact projection
equality. Joint B/C signed grant
bytes and Dock B/C credential bytes are snapshotted before the updates and
compared afterward.

Without producer environment variables the driver is an artifact consistency
gate. With `MATCHED_DAC_PRODUCER_OUT`, it additionally builds actual-one and
actual-two DAC circuits from the parsed object, performs fresh `OsRng` setup,
proves both with one key, verifies them, and writes resident proof envelopes
that omit the verifying key and setup parameters. Resident service acceptance
and formal paired timing remain separate gates. The deterministic manifest RNG
is not a deployable issuer or accumulator setup; proof setup uses `OsRng`.

Only the sole benchmark-host runner may compile or execute it. Retain the source,
resolved lock, dependency provenance, stdout/stderr, exit codes, and hashes.
