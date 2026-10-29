# B1 protocol baselines

These binaries are independent public-provenance comparators. They do not
rename the existing native plaintext verifier and they do not claim the
source/depth/serial privacy of Joint or the DAC wrapper.

## RFC 8693 JWT nested-actor profile

`rfc8693_jwt` uses an actual compact JWT/JWS implementation and the RFC 8693
`act` nesting rule. A local authorization-server profile validates each input
token, authenticates the caller as its current actor, checks current time and
deployment revocation state, and issues an attenuated successor. The resource server validates the
JWS, issuer, audience, current actor, scope, resource, time interval, closed
request interval, expected policy version, exact `Delta=0` header and request digest. The deployment
profile carries all ancestor `jti` values so implementation-specific
introspection can propagate ancestor revocation; this is intentionally public
and is not a claim that RFC 8693 mandates revocation propagation.

This executable is a local nested-`act` profile gate. It does not implement an
RFC 8693 HTTP token-exchange endpoint or the standard's `grant_type`,
`subject_token_type`, request, and response wire fields, so it does not emit a
"complete RFC 8693 profile" result.

The benchmark uses HS256, so the AS and resource server share a key. It records
that trust choice. The base access token remains a bearer token. A deployment
extension adds an independently registered Ed25519 terminal proof over the
exact JWT, request/header, nonce and validity interval. The reusable in-memory
adapter rechecks current authorization, terminal proof, exact bytes, clock,
`Delta=0` header and nonce at commit. Negatives cover signature mutation,
header advance, ancestor revocation between read and commit, clock expiry,
byte mutation and replay. This supplies the
local Joint business commit contract while remaining an explicitly non-RFC
extension. The RFC 8693 HTTP request/response wire profile is still absent.

Primary standard: [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html),
with JWT claims from [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html).

## UCAN 1.0 delegation/invocation profile

`ucan_v1` uses `pq-ucan 0.1.2` to produce strict DAG-CBOR, CIDv1/SHA-256,
Varsig, Ed25519 `did:key` delegations and a signed invocation. Its execution
validator resolves and verifies the complete chain, command attenuation, time
bounds, every policy, executor and replay guard. Retained negatives cover
policy widening, expiry, wrong executor, missing proof and replay. Removing one
path from the resolver store rejects it while a separately signed path remains
valid.

The selected library describes itself as pre-release and unaudited. It does
not implement the signed UCAN Revocation sub-specification. Removing a CID from
the proof store is therefore labeled resolver denial, not native UCAN
revocation. A deployment extension now signs a versioned public set of revoked
proof CIDs with a separate Ed25519 authority. The gate rejects a revoked
ancestor, accepts a byte-independent path, and rejects a tampered registry.
Registry versions advance monotonically and a still-valid older signed registry
cannot be reinstalled.
This is an authenticated serial registry, not the UCAN signed-revocation
sub-specification. The shared service adapter binds the fully validated,
terminal-signed invocation to exact bytes, nonce, clock and the active header;
it also rejects revocation between read and commit. This supplies the local
Joint business commit contract while preserving the explicit protocol-profile
difference and public provenance leakage.

## Shared service adapter

`src/service_adapter.rs` is protocol agnostic. Its `authenticated` parameter
is a caller premise: the JWT binary supplies successful JWS/business checks
plus the external terminal Ed25519 proof; the UCAN binary must supply a fully
validated terminal-signed invocation. The adapter binds that result to exact
artifact bytes, validity interval, nonce and a monotonic active header. It is
an in-memory experiment adapter; production integration must place validation
and the nonce/header commit under the service's real transaction boundary.

Primary specifications:

* [UCAN core 1.0.0](https://github.com/ucan-wg/spec)
* [UCAN Delegation](https://github.com/ucan-wg/delegation)
* [UCAN Invocation](https://github.com/ucan-wg/invocation)
* [UCAN Revocation](https://github.com/ucan-wg/revocation)

## Remote-only gates

The experiment policy requires compilation and execution on `benchmark-host`:

```text
cargo run --release --locked --bin rfc8693_jwt
cargo run --release --locked --bin ucan_v1
```

Every emitted boolean is asserted before the JSON row is printed. Results are
valid only with the retained Cargo lockfile, dependency provenance and runner
logs.
