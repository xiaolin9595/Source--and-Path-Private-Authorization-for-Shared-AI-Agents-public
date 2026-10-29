# Shared matched semantic schema freeze — 2026-10-24

The Joint and DAC matched builders import the same public module:
`src/semantic_schema.rs`.

```text
cc9ac439db133dcd4ae94d86eeed27a2237e4b1d855988f5d13fff8cca164977  src/semantic_schema.rs
```

`SemanticManifest` is the sole typed authorization/update input. Its fields
include the complete entitlement, state, five grants, business request and
three ordered updates. `CanonicalHttpRequest` is separate because it is an
actual invocation, not an authorization record. Its domain-separated digest
is injected into each backend's public request inputs.

This is a source-interface freeze, not execution evidence. Any source edit
requires a new hash and coordinated rebuild of both backend builders.
