# Matched Joint service builder

Source-only pending the sole `benchmark-host` gate.

This crate owns the Joint half of the matched typed-input boundary.  Its only
entry point, `build_joint_actuals`, accepts the DAC wrapper's public
`semantic_schema::SemanticManifest` and `CanonicalHttpRequest`; it does not import the paired binary's
private constants and never calls the legacy fixed L3 fixture.

For a selected update it returns two `JointCircuit<2>` witnesses and the Rust
typed-canonical `semantic_input_sha256`: actual depth 1 uses `root-c` plus a
canonical disabled slot, while actual depth 2 uses `root-b -> child-b`.  Both
derive all keys, records, roots, paths, request limbs, update values and
revocation witnesses from the supplied manifest.

The runtime driver must call it with the same deserialized manifest value sent
to `matched_builder::build_matched_circuit`, check both semantic projections,
and attach the returned semantic hash to every raw result row.
