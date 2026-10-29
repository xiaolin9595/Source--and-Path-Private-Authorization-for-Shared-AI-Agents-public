# R3 identity derivation

Status: derivation frozen in source; concrete post-review matrix/VK hashes await the non-overlapping Rust gate.

All SHA-256 domain separation uses `tag || 0x00 || payload`. A 32-byte digest is mapped canonically into BLS12-381 `Fr` with `from_be_bytes_mod_order`; the original SHA-256 hashes remain in fixture metadata for audit.

## Configuration identity

Tag: `plan-a-r3-config-v1`.

Payload fields, in order:

1. relation label `plan-a-r3-blind-update-config-v1`;
2. the full Poseidon descriptor;
3. the serialized Poseidon-parameter fingerprint;
4. ordered public inputs: config, deployment, circuit, owner, position, cap, admission version, old leaf, new leaf, old version, new version, old epoch, new epoch, identity binding;
5. exact StateLeaf layout: owner, grant root, version, epoch, expiry, active, salt, position.

## Deployment identity

Tag: `plan-a-deployment-v1`. The functional gate uses the explicit isolated label `r3-functional-gate-isolated-deployment-2026-10-29`. A deployment artifact must replace this label with its frozen deployment identifier; it is not a universal production deployment ID.

## Matrix hash

The fixture finalizes the constraint system and serializes A, B and C in order. Each matrix and row is length-prefixed with little-endian u64; every coefficient uses arkworks canonical compressed serialization and every variable index is encoded as little-endian u64. SHA-256 of these bytes is `matrix_sha256`.

The public Poseidon input `H_BlindUpdateIdentity(config_digest, deployment, circuit_id)` constrains all identity fields while leaving the matrix independent of their values. Setup can therefore precede final circuit-ID derivation without a self-reference.

## Circuit identity and VK binding

The fixture serializes the verifying key with arkworks canonical compressed encoding and records its SHA-256. Circuit identity uses tag `plan-a-r3-circuit-v1` and payload:

`plan-a-r3-blind-update-relation-v1|matrix-sha256=<hex>|vk-sha256=<hex>`.

The external verifier independently hashes the configured VK file and requires equality with `PLAN_A_BLIND_UPDATE_VK_ID`, then requires the public circuit ID to equal `PLAN_A_BLIND_CIRCUIT_ID`. Fixture output records both raw hashes and all three field identities. The pending post-review gate must archive that output before any E2 freeze.

