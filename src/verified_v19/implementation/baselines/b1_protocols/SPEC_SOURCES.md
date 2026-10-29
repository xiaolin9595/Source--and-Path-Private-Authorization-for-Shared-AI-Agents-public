# B1 protocol and implementation source manifest

Retrieval date: 2026-10-24. The remote run artifact must retain this file,
`Cargo.toml`, the resolved `Cargo.lock`, crate checksums/provenance, compiler
version and the exact tested source tree.

## JWT/token exchange row

- RFC 8693, *OAuth 2.0 Token Exchange*, Standards Track, January 2020:
  <https://www.rfc-editor.org/rfc/rfc8693.html>. The row implements the nested
  `act` claim shape and a local exchange function. It does not implement the
  RFC 8693 token-endpoint request/response wire protocol.
- RFC 7519, *JSON Web Token (JWT)*, Standards Track, May 2015:
  <https://www.rfc-editor.org/rfc/rfc7519.html>.
- Direct crates fixed by the manifest: `jsonwebtoken=9.3.1` and
  `ed25519-dalek=2.1.1`. The latter implements the local terminal proof
  deployment extension; it is not attributed to RFC 8693.

## UCAN row

- UCAN core repository: <https://github.com/ucan-wg/spec>.
- UCAN Delegation specification, document version 1.0.0 and envelope tag
  `ucan/dlg@1.0.0`: <https://github.com/ucan-wg/delegation>.
- UCAN Invocation specification: <https://github.com/ucan-wg/invocation>.
- UCAN Revocation specification: <https://github.com/ucan-wg/revocation>.

The four UCAN repositories did not publish GitHub Releases when inspected;
the experiment therefore records the document-declared protocol version and
these repository sources rather than inventing a release identifier. The
implementation dependency is fixed to `pq-ucan=0.1.2`. Its actual resolved
crate checksum and all transitive versions come from the remote runner's
retained lockfile/provenance record.

The direct `ipld-core` dependency is fixed to `0.4.3`. The official crates.io
index entry records crate checksum
`090f624976d72f0b0bb71b86d58dc16c15e069193067cb3a3a09d655246cbbda`:
<https://raw.githubusercontent.com/rust-lang/crates.io-index/master/ip/ld/ipld-core>.
The remote bootstrap verifies this checksum before using the official crate
archive; it does not replace or modify the crate source.

The signed, versioned public revoked-CID registry in this crate is a deployment
extension. It is not presented as an implementation of the UCAN Revocation
sub-specification.
