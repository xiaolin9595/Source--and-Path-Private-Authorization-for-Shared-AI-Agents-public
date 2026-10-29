# DAC fixed-policy service adapter call contract

The runtime-owned service integration receives a proof bundle containing:

- `FixedPolicyStatement` and relation version `2`;
- canonical compressed `Proof<BW6_761>` bytes and the decoded proof;
- the frozen wrapper `VerifyingKey<BW6_761>` selected by deployment ID;
- registry signature for the installed header;
- terminal Schnorr signature over the exact statement digests and proof bytes.

The service must use this sequence:

1. Construct `DeltaZeroAdapter::new(generator, registry_public_key,
   deployment_id)` from deployment configuration.
2. Recompute the typed header digest through `compute_header_digest`; call
   `install_header(statement, registry_signature)`. Header tuple versions must
   increase strictly.
3. Parse the proof with canonical arkworks decoding and reject trailing bytes.
   Keep the original request body and proof bytes; the statement's canonical
   request limbs must be derived by the same request canonicalizer used before
   proving.
4. Call `verify_at_read(vk, statement, 2, proof, exact_proof_bytes,
   terminal_signature)`. This rechecks the header and request digests, request
   clock, public-input encoder, Groth16 proof, canonical proof bytes, and the
   terminal signature. Retain the returned opaque `VerificationTicket` only in
   the current request transaction.
5. Immediately before the resource operation commits, fetch the trusted clock
   and the currently installed authenticated header under the same service
   lock/transaction. Call `commit(ticket, statement, 2, exact_proof_bytes,
   terminal_signature, trusted_now)`. Treat success as the nonce-consuming
   authorization commit.

The service must never accept a caller-selected root, terminal, request digest,
or old public statement in place of the expected request and current header.
Any change to body, arguments, proof bytes, nonce, terminal key, clock window,
header, deployment ID, or tuple version must fail before the business action.
The service driver must retain negatives for body/argument mutation, proof-byte
mutation, stale header, revoked-between-read-and-commit, wrong terminal,
expired clock, and nonce replay.

The backend-specific RA/state roots and terminal keys may differ from Joint.
They are tied by the versioned canonical semantic manifest and typed circuit
openings, not by trusting a mapper or comparing root bytes.
