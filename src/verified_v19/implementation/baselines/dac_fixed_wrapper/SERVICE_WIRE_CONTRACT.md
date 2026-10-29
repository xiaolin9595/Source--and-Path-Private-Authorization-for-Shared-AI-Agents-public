# Matched DAC producer and resident verifier contract

Status: source frozen for the sole benchmark-host runner. Retained v21 proves the
underlying relation, but predates this producer/resident integration gate.

## Canonical producer

`paired_semantic_manifest` parses one `SemanticManifest`, constructs both DAC
actual-length witnesses from that value, and calls the public
`matched_builder::build_matched_circuit`. With `MATCHED_DAC_PRODUCER_OUT` it
uses a fresh `OsRng` seed for native issuer, holder, accumulator and commitment
parameters, performs fresh `OsRng` Groth16 setup, and emits proofs under one
verifying key. `MATCHED_DAC_PRODUCER_MODE=lifecycle` emits t0 A/B/C, t1 B/C,
and t2 C; `formal-t1` emits only the t1 actual-one/actual-two timing pair.
Optional outputs are:

- `MATCHED_DAC_VK_OUT`: raw canonical compressed trusted verifying key;
- `MATCHED_DAC_TRUSTED_CONFIG_OUT`: resident configuration; and
- `MATCHED_DAC_PRODUCER_OUT`: measurements, header, expected request, both
  proof envelopes, and their semantic input hash.

The proof envelopes contain no verifying key, generator, registry key, setup
parameter or deployment choice. Those values exist only in the separately
installed trusted configuration. Actual length is experiment row metadata and
is absent from the proof envelope and circuit public inputs.

## HTTP binding

`CanonicalHttpRequest` contains `audience`, lowercase `body_sha256`, uppercase
`method`, and `path`. Compact UTF-8 JSON is in ASCII key order. Four
little-endian u64 limbs of
`SHA-256("plan-a-matched-http-v1\0" || canonical_http_json)` are the circuit's
`canonical_request_lo/hi`. The circuit request digest commits those limbs.
The terminal signature transcript commits that request digest, the installed
header digest, circuit id, relation version, terminal key, nonce, and exact
proof bytes. The resident rebuilds the HTTP digest from trusted expected input
before verification.

## Resident JSONL verifier

Start `dac_resident_jsonl` with `DAC_TRUSTED_CONFIG_PATH`. It loads and decodes
the fixed verifying key, generator, registry key, deployment, semantic hash,
ordered trusted statements and backend profile once. Its commands are:

1. `materialize-and-verify-header`: checks the canonical manifest hash,
   selected update, backend profile and exact trusted statement, then installs
   the registry-signed header.
2. `verify-at-read`: checks the same manifest, exact expected HTTP/business
   request and trusted clock interval, verifies with the resident key, and
   returns a one-use opaque ticket.
3. `commit`: repeats manifest/request/clock/envelope checks, consumes the
   ticket, and runs the adapter's header, transcript and atomic nonce checks.

Unknown JSON fields fail deserialization. Reusing a ticket or nonce fails.
`fixed_policy_adapter_cli` remains a smaller synthetic smoke boundary and is
not the matched resident service.

All new code remains source-only until locked/offline server format, release,
producer, resident positive, argument/body mutation, caller-VK injection and
nonce-replay gates pass. Formal timing still requires the separate paired
trial driver.
