# Matched resident JSONL wire v1

The service sends one compact JSON object per line. IDs in the shared semantic
schema are JSON `u64` numbers. Backend-native keys, roots, proofs and signatures
are lowercase canonical hex strings. VKs and parameters never appear in proof
envelopes; resident processes load them from digest-pinned trusted startup
configuration.

`materialize-and-verify-header` receives `command`, `canonical_manifest`,
`semantic_input_sha256`, `update_index`, `header_envelope` and
`backend_profile`. `header_envelope` contains `header` and
`registry_signature`. A header always contains `semantic_input_sha256`,
`tuple_version`, `state_epoch`, `revocation_epoch`, `issued_at`, and the
backend-native roots/accumulator. The only success response is
`{"valid":true,"header":...}`.

`verify-at-read` receives `command`, `canonical_manifest`, `expected` and
`envelope`; it returns `{"valid":true,"ticket":"opaque"}`. `commit` receives
the same object plus top-level `ticket` and returns `{"valid":true}`.

Expected contains: `semantic_input_sha256`, `backend`, numeric `deployment_id`,
`logical_id_mapping_version`, `policy_version`, `schema_version`, `profile`,
numeric `update_index`, `installed_header`, numeric `terminal`, native
`terminal_key`, numeric `resource`, `one_hot_action_u16`, `interval_lo`,
`interval_hi`, `nonce_u64`, `trusted_now`, `http`, and `backend_profile`.
`http` is exactly `{audience,body_sha256,method,path}`.

The resource body is strict canonical JSON
`{"nonce_u64":<u64>,"operation":"read"}`. The service derives the operational
nonce and body digest from these bytes. The proof binds both through the
canonical HTTP digest and the nonce public input. `manifest.request.nonce_u64`
is the lifecycle base nonce.

The proof envelope contains `semantic_input_sha256`, `update_index`, canonical
proof and terminal signature, plus the DAC fixed public statement when needed.
It contains no actual delegation depth. `actual` exists only in offline timing
rows.

Lifecycle producer bundles contain `phases[{update_index,header_envelope}]` and
`cases`. Required cases are `t0_a`, `t0_b`, `t0_c`, `t1_b`, `t1_c`, `t2_c`,
`negative_body`, `negative_proof`, `negative_terminal`, `expired`,
`old_ticket`, `removed_a`, and `revoked_b`. Every case is
`{update_index,body,envelope}` with a separately proved, previously unused
operational nonce. The three mutation cases are first rejected and then
submitted unchanged to prove that failure did not consume their nonce.

The machine-readable command fixtures are
`matched_joint_jsonl_contract_fixture.json` and
`matched_dac_jsonl_contract_fixture.json`. The DAC fixture stores one shared
typed manifest, expected request, header envelope and proof envelope; the
proof-free `dac_jsonl_contract_check` binary expands its three templates into
complete commands and deserializes them through the same `ResidentCommand`
enum as the resident verifier. `validate_matched_jsonl_contract.py` checks the
common field sets and success-response shapes for both backends. These short
checks do not run setup, prove or verify.
