# Scheme A executable contract (frozen 2026-10-23)

This crate implements one authorization atom: one resource, one 16-bit action
mask and one closed interval. Multiple entitlements are represented as distinct
RA leaves; the paper must not describe this implementation as proving arbitrary
sets in one leaf.

The public statement authenticates a single indivisible snapshot
`(root_ra, root_state, root_rev, version, issued_at)`. The verifier selects a
signed snapshot from its window as a unit; roots from different snapshots may
never be combined. Re-publishing an old tuple does not refresh `issued_at`.

Registration alone grants no business permission. The root grant opening must
match an RA-tree entitlement opening for owner commitment, resource, allowed
actions, interval and permit expiry. SR admission is assumed to validate the
business source before inserting that leaf; a negative admission fixture is
mandatory.

Each enabled grant preserves resource, narrows the 16-bit action mask and
closed interval, has non-increasing expiry and a depth value exactly one below
its parent. The request time is at most the RA permit expiry and every enabled
grant expiry. Verifier, PEP and audience are bound by the request transcript but
are deliberately not persistent per-grant fields in this matched contract.

The revocation serial is a canonical nonzero 252-bit integer. Zero is reserved
for disabled-slot padding. Uniform 252-bit serials provide about 126-bit birthday
collision resistance. A revocation capability is `(rk[32], counter:u32)`.
The implementation absorbs the little-endian field reductions of the two
16-byte halves of `rk` and the counter under `RevocationSerial`, takes the low
252 bits of the Poseidon result, and rejects zero and the reserved upper
sentinel. Issuers advance the counter if a reserved value occurs. The indexed tree enforces
unique ordered occupied entries, permanent lower/upper sentinels and monotonic
insertions. A tail pointer of zero never serves as a free-form successor.

All disabled slots are a suffix and every disabled field, point and path value
is canonical padding. Native and circuit signature verification reject identity,
non-subgroup points and non-canonical scalar encodings. The terminal signature
is an external commit step over the canonical public request, full authenticated
snapshot, nonce, circuit identifier and complete serialized Groth16 proof.

State updates require authenticated owner identity, the assigned leaf position,
an expected-version compare-and-swap and a strictly increasing epoch. The state
leaf repeats the RA owner commitment. SR therefore knows the owner-to-position
mapping. Fixed positions, updates and revealed serials have the linkability
described in the threat model; this implementation does not claim SR blindness,
hidden update events or post-corruption forward privacy.


## Signature nonce sampling

Signing hashes `(secret_scalar, message, aux_lo128, aux_hi128, counter)` in the SignatureNonce domain and rejects outputs that are zero or not canonical scalars. It retries the counter, also retrying if the response scalar is zero. This uses the full scalar range without reduction bias. The verification challenge remains the low `Scalar::MODULUS_BIT_SIZE-1` bits because that mapping is the fixed R1CS verification relation.
