# Plan A proof CLI contract v1

Transport is one JSON object on stdin and one JSON object on stdout. Success exits `0`; malformed input or internal failure exits nonzero. A cryptographically invalid proof/signature is a successful command evaluation with `{"valid":false}` and exit `0`.

## Canonical encodings

The service uses a protocol-specific restricted canonical JSON: UTF-8 objects with ASCII schema keys, strings with defined field-level length/format limits, booleans, and nonnegative integers; keys are sorted, whitespace omitted, floats/NaN/infinities and duplicate keys rejected. This is **not** claimed to implement RFC 8785. The Python encoding is `json.dumps(sort_keys=True,separators=(",",":"),ensure_ascii=False)` after strict parsing/schema checks.

`snapshot_digest = SHA-256("plan-a-snapshot-v1\0" || canonical_json(snapshot))`.

`canonical_request_sha256 = SHA-256("plan-a-request-v1\0" || canonical_json(request_fields))`. `relation_request_digest` is the canonical BLS12-381 field encoding recomputed by core with the circuit's Poseidon request relation; the service does not implement Poseidon.

Snapshot is one indivisible tuple:

```json
{"deployment_id":"64 lowercase canonical field hex","tuple_version":1,"ra_root":"64 lowercase hex","state_epoch":7,"state_root":"64 lowercase hex","revocation_epoch":9,"revocation_root":"64 lowercase hex","issued_at":1792700000}
```

The service maintains trusted monotonic publication history. The current tuple remains valid until replacement (subject to any separately enforced state expiry). Replacement atomically records server-observed `retired_at` on the predecessor. A retired tuple is accepted iff `now <= retired_at + Delta`; `Delta=0` therefore accepts only the current tuple after retirement. Republishing an old tuple cannot change `retired_at`.

Request fields are:

```json
{
  "protocol_version":"plan-a-http-v1",
  "deployment_id":"64 lowercase canonical field hex",
  "method":"POST",
  "path":"/resource/read",
  "body_sha256":"64 lowercase hex",
  "audience":"https://service.example",
  "resource":"files",
  "action_onehot":1,
  "nonce":"base64url without padding, 16..64 decoded bytes",
  "request_time":1792700001,
  "expires_at":1792700100,
  "terminal_agent_pk":"implementation-defined canonical string",
  "circuit_id":"plan-a-joint-v1",
  "vk_id":"manifest identifier",
  "snapshot_digest":"64 lowercase hex"
}
```

The base business request above contains no derived relation digest, proof or signature. The service hashes only those base fields. The envelope carries `relation_request_digest` separately. Core maps `canonical_request_sha256` into two unsigned 128-bit limbs (fixed big-endian order), incorporates those plus the circuit semantic fields into the Poseidon request relation, recomputes `relation_request_digest`, and compares it with the public input. This ordering avoids a digest cycle.

`action_onehot` is a public unsigned 16-bit value with exactly one bit set. Grants do not contain audience; the request digest does.

## Verify proof

Input:

```json
{"command":"verify","vk_id":"...","public_statement":{"snapshot":{},"request":{},"canonical_request_sha256":"...","relation_request_digest":"..."},"proof_b64":"..."}
```

Output: `{"valid":true}` or `{"valid":false,"error":"stable-code"}`. Core recomputes the Poseidon relation digest from semantic fields and constrains it as the public input. SHA-256 remains outside the circuit. Core also checks request expiry against permit/grant expiry.

## Verify signed header tuple

Input `{"command":"header-verify","snapshot":{...},"signature_b64":"..."}`. The trusted registry signature covers the entire canonical snapshot object, including RA root, both mutable roots/epochs, tuple version and `issued_at`. Output uses the standard `valid` shape. E7 may not use the service's unit-test HMAC substitute.

## Revoke by capability preimage

Input `{"command":"revoke-authorize","rk_b64":"32 random bytes","counter":N,"sn":"canonical low-252 field encoding"}`. Core recomputes `sn = low252(Poseidon(RevocationSerial,[rk_lo128,rk_hi128,counter]))`, rejects zero/reserved sentinels, and atomically performs a unique monotonic indexed-tree insertion. It does not require `grant_context` or issue-time registration: knowledge of `(rk,counter)` is the revocation capability. Issuance must reject an `sn` already present in the current revocation tree. Public revocation exposes `rk`, counter and `sn`; service rate limits are operational DoS control.

## Trusted enrollment and owner CAS update

`admission-verify` verifies a registry signature over the deployment identifier,
owner commitment, unique position, admitted owner public key and registration
salt, maximum state expiry, and the complete initial state opening. Initial
version must be zero. The service stores this admission under uniqueness
constraints for both `(deployment, owner)` and `(deployment, position)`.

The external `state-update-verify` request contains only the deployment, owner,
position, expected version, new epoch, complete new opening and owner signature.
The service looks up the admitted public key, registration salt, expiry cap and
current state, adds those trusted values to the core request, and rechecks them
inside the SQLite writer transaction. The signed digest binds deployment,
owner, position, expected version, new epoch and every opening field. Owners
cannot extend beyond the admitted expiry or reactivate an inactive state.

Before the first header, the registry installs every initial state through
`admission-verify`; there is no implicit empty or caller supplied state leaf.
At header commit, the service holds the SQLite writer lock, reads all admitted
state leaves and capability authorized revocations, asks the core to rebuild
the sparse Poseidon state tree and indexed revocation tree, and requires both
roots and the maximum state epoch to equal the signed tuple. It stores a
transition receipt with the materialized roots and record counts in the same
transaction. Failed updates and failed revocations therefore cannot affect a
published root. The RA root remains an input from the separately trusted RA
publisher and is covered by the registry signature; this prototype does not
materialize the RA admission tree in SQLite.

## Verify terminal signature

Input:

```json
{"command":"terminal-verify","deployment_id":"...","terminal_agent_pk":"...","canonical_request_sha256":"...","snapshot_digest":"...","circuit_id":"...","proof_b64":"...","signature_b64":"..."}
```

The core first rejects any deployment other than its trusted `PLAN_A_DEPLOYMENT_ID`. The signed transcript is the Terminal-domain Poseidon hash of the two big-endian u128 limbs of each request and snapshot SHA-256 digest, both big-endian u128 limbs of SHA-256(full circuit id), the proof byte length, and consecutive 31-byte little-endian proof chunks. The Agent and verifier call the same library helper. Output uses the same `valid` shape. The signature covers proof bytes so a valid request signature cannot be moved to another proof.

## Prover-side commands

The core may additionally implement:

* `setup {l_max,state_depth,revocation_depth,circuit_id}`;
* `prove {public_statement,witness}`;
* `terminal-sign {agent_sk_ref,canonical_request_sha256,snapshot_digest,circuit_id,proof_b64}`.

The HTTP service never receives `agent_sk_ref` or witness material.



## Mutation publication boundary

A successful state update or revocation returns `publication_status:"pending"`. This means the mutation is durably recorded but the current header is unchanged. Enforcement begins only after a registry-signed successor whose materialized state/revocation roots match the database is atomically installed. Traces record mutation acknowledgement and successor installation times as observations; this prototype asserts no automatic publication deadline.
