# Required input contract for the matched proof/service driver

`PAIRED_MANIFEST.json` is an input artifact, not a substitute for matched
proofs. The runtime-owned matched driver must deserialize the exact
`canonical_raw_manifest` object and pass that one in-memory value to both
backend builders:

```text
raw_bytes = canonical compact JSON(canonical_raw_manifest)
semantic_input_sha256 = SHA256(raw_bytes)
joint_fixture = build_joint381(raw_manifest, fresh_joint_setup)
dac_fixture   = build_dac377(raw_manifest, fresh_dac_setup)
```

Neither builder may import the old Joint fixture constants or independently
construct another DAC record set. Backend-specific code may derive keys,
parent digests, commitments, salts-as-field-elements, authenticated roots,
Merkle paths, accumulator witnesses, signatures, padding, and proof encodings
from the shared raw value. These derived bytes are expected to differ.

Before setup/prove, each builder must emit a projection containing every raw
logical field it consumed. Canonicalize and hash both projections; require
both hashes equal `canonical_raw_manifest_sha256`. Fail before timing on any
field omission or mismatch. At minimum the projection covers entitlement,
state, all five grants and parent record IDs, serial limbs, request, terminal,
tree capacities, policy/schema/mapping versions, and all three ordered updates.

Every Joint and DAC proof/service result row must carry the same
`semantic_input_sha256`, plus its backend root bundle and key-map digest. The
service request is a separate `CanonicalHttpRequest` whose exact compact body
hash, method, path and audience are bound as the four little-endian limbs of
`SHA-256("plan-a-matched-http-v1\0" || canonical_http_json)`. Both circuits
and terminal transcripts must use those limbs; copying a digest from an
untrusted envelope into the service's expected request is invalid. The
driver must prove and service-verify these shared scenarios with fresh setup:

- tuple 1: A, B, and C accepted;
- tuple 2: A rejected after deletion; B and C accepted with their original
  credential/signature bytes unchanged;
- tuple 3: B rejected after revocation; C accepted with its original bytes;
- the same logical request and terminal in the paired row, with backend-native
  terminal keys linked by the versioned logical-ID mapping.

The service path must use the DAC adapter call sequence in
`ADAPTER_CALL_CONTRACT.md`. The output must label the sidecar root-only gate,
the full proof gate, and matched service gate separately. Passing the sidecar
alone must leave B2 completion false.
