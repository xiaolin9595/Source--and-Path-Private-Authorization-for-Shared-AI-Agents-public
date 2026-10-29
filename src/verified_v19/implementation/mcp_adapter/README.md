# Synthetic MCP legacy integration gate

This independent adapter exercises the official MCP Python SDK over stdio and
calls the existing Plan A HTTP `/resource/read` endpoint. It does not modify
the HTTP service or the Rust proof implementation.

## Fixed profile

- MCP protocol: `2025-11-25` (legacy handshake era).
- Official Python SDK: `mcp==1.29.1`.
- Required real method sequence: `initialize`, `tools/list`, then
  `tools/call`.

MCP `2026-07-28` removed `initialize`, so this experiment cannot simultaneously
claim that revision and retain the required handshake. The output sets
`mcp_2026_07_28_compatible=false`. Authentication uses the existing synthetic
Plan A proof envelope. There is no OAuth discovery, bearer-token acquisition or
production identity-provider interaction, so the output also sets
`production_oauth_compatible=false`.

## Binding boundary

The `read_resource` tool accepts public resource, one-hot action, nonce,
terminal key and UTF-8 body arguments plus an authorization envelope. The
adapter first requires resource, action, nonce and terminal to equal their
envelope values. It then forwards the exact UTF-8 body and canonical envelope
to the existing HTTP service. That service recomputes the body digest and
canonical request, verifies the private authorization proof and terminal
signature under the current header, and consumes the nonce atomically.

The gate requires three case manifests from three actually distinct private
owners. Each manifest has this audit-only shape:

```json
{
  "private_owner_commitment": "distinct owner commitment",
  "private_witness_source_sha256": "64 lowercase hex characters",
  "body_utf8": "payload",
  "envelope": {"the": "real Plan A proof envelope"}
}
```

Owner commitments and witness-source digests are retained in the gate artifact
to establish that the three proofs came from distinct fixtures; neither is
sent in MCP tool arguments or to the HTTP resource endpoint. The three
envelopes must use distinct nonces and otherwise share the terminal and common
public request fields.

Before accepting the three calls, the gate checks mutated resource, terminal
and nonce tool arguments and a mutated body. It then repeats the first valid
call and requires the HTTP service's `nonce-replay` rejection.

`wire_proxy.py` is a transparent stdio subprocess between the official SDK
client and server. It retains the exact newline-delimited JSON-RPC bytes in
separate client-to-server and server-to-client files. The gate pairs every
request and response by JSON-RPC id, checks the real method sequence, and puts
each frame's byte length and SHA-256 digest in the trace. It also reads the
installed `mcp` package version and binds the runner-produced resolved package
lock by path and SHA-256.

## Remote-only execution

Compilation and execution belong on `benchmark-host` under the sole runner lock. The
runner must retain the exact SDK wheel and transitive dependency hashes, Python
version, resolved lockfile, source hashes, the three case manifests, both raw
wire logs, server stderr, gate stdout and the output trace. Single gate timings
are functional evidence only and are not a performance distribution.
