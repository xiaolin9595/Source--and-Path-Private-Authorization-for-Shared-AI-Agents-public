# B1 protocol runner gate

Run only on `benchmark-host` under the shared compilation lock.

1. Preserve source manifest and resolved `Cargo.lock`.
2. Record compiler version and crate download provenance/checksums.
3. Run `cargo fmt -- --check` and `cargo check --release --locked`.
4. Run both release binaries separately and retain stdout/stderr/time/RSS.
5. Do not call the UCAN resolver-denial negative a signed-revocation result.
6. Do not call either standards profile complete or provenance-private. The
   local Joint commit-contract result is supplied only by the stated
   deployment extensions.

Required JWT booleans: accepted plus every exchange/authorization rejection,
external terminal PoP acceptance, bad-PoP rejection, atomic commit acceptance,
adapter replay rejection, Delta=0 rejection, commit-clock expiry rejection and
changed-artifact and revoked-between-read-and-commit rejection. Require
`same_joint_commit_contract_complete=true`
but `rfc8693_profile_complete=false`; the terminal proof/commit adapter is a
deployment extension, not an RFC 8693 claim. Required UCAN booleans: accepted,
the five validator negatives, resolver-denied ancestor rejection and
independent-path survival; signed-registry acceptance, revoked-ancestor
rejection, independent-path survival and tamper rejection; atomic commit,
registry rollback rejection; adapter replay, Delta=0, commit-clock,
changed-artifact and
revoked-between-read-and-commit rejections. Require
`same_joint_commit_contract_complete=true` but
`signed_revocation_subspec_implemented=false`: the public authenticated CID
registry is a deployment extension.

## Formal measurement gate

The two functional binaries above must pass before any formal timing run.
Then follow `FORMAL_GATE_REQUEST.md` and require all of the following:

- JWT and UCAN semantic lengths 1, 2, and 3, with 10 fresh protocol setups per
  protocol/length cell (60 raw rows total);
- one randomly sampled in-range request interval shared by the two protocols
  in each paired length/trial, with independently fresh OS-random keys,
  identifiers, nonces, and signatures;
- balanced execution order, five JWT-first and five UCAN-first trials for every
  length;
- separate raw timing for setup, initial issuance, later attenuation/exchange
  refresh, complete issuance, terminal presentation construction, full
  verification, and signed public revocation-state update (message signing and
  monotone installation for both the inactive-JTI and CID registries);
- bytes by signed level and for total signed grants, final presentation,
  terminal binding under the common signature-plus-nonce definition, and
  public signed revocation state;
- accepted current path, rejected revoked path, and surviving independent path
  in every row, with the independent artifact created before revocation and
  byte-identical afterward;
- retained raw observations plus median and two-sided 95% percentile bootstrap
  confidence intervals from 10,000 resamples.

These are ordinary protocol key setups and workloads, not SNARK setups. The B1
results remain public disclosure-chain references with visible depth and
identifiers; they are not same-privacy comparisons.
