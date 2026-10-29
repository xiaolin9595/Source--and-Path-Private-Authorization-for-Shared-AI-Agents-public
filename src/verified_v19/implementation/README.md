# Plan A joint circuit prototype

This independent crate contains the T1 primitives, the typed fixed-shape joint
relation, native reference verifier, proof/Agent CLIs and registry-backed HTTP
adapter. `CONTRACT.md` is normative. Compilation, tests and measurements are
run only by the designated experiment coordinator on benchmark-host.

`src/plain.rs` is a protocol-independent native verifier for the same signed-chain authorization contract. It checks the admitted RA entitlement, active state leaf, root-grant membership, every signature and parent/key link, policy attenuation, revocation non-membership, canonical padding, and final terminal binding with ordinary native cryptography and comparisons. It does not synthesize or inspect an R1CS and is not an RFC 8693 JWT or UCAN implementation.

Representative remote gates:

```text
cargo +1.95.0 test --all-targets
cargo +1.95.0 test --release --test fixed_shape_matrix
cargo +1.95.0 run --release --bin plan_a_proof_cli -- trial ...
```

The formal experiment uses the in-process `trial` driver for ten fresh setups
per configuration and reports proving-key cold load separately. `e5-interleaved`
uses one loaded key, deterministic label shuffling and independent `OsRng`
proof randomness. Raw remote logs and manifests, rather than this README, are
the evidence for reported measurements.


### Version provenance

The E2 and E5 runs use their frozen source manifests, whose synthetic fixture had `state_version=7`. The final trusted-enrollment fixture starts at version zero. That bootstrap-only change and later external service/signature work do not retroactively change the recorded E2/E5 relation source hashes or results.
