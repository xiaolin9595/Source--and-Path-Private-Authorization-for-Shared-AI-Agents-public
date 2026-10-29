# B1 formal trial gate (run only after the functional gates pass)

This package is a disclosure-chain reference measurement. It is not a
same-privacy comparator for Joint, SR, or the DAC wrapper. JWT ancestry and
serials and UCAN proof CIDs/depth remain verifier-visible.

## Required order on benchmark-host

1. Preserve the source tree, `Cargo.lock`, command lines, tool versions, stdout,
   stderr, exit codes, wall time, maximum RSS, and SHA-256 hashes in a new
   versioned result directory.
2. Run `cargo fmt -- --check` and release `cargo check --locked --offline`.
3. Run the existing `rfc8693_jwt` functional gate and validate every required
   boolean in its JSON. Stop if it fails.
4. Run the existing `ucan_v1` functional gate and validate every required
   boolean in its JSON. Stop if it fails.
5. Only then run `cargo run --release --locked --offline --bin formal_trials`
   once and retain stdout as `FORMAL_RAW.json`.
6. Run `python3 tools/summarize_formal_trials.py FORMAL_RAW.json
   FORMAL_SUMMARY.json`; retain its stdout/stderr and exit code.

The formal driver performs 10 fresh setups for each protocol and each semantic
length 1, 2, and 3. Each paired trial samples one request interval and uses that
same interval for JWT and UCAN; protocol keys, identifiers, nonces, and
signatures remain independently fresh. Within every length the protocol order
is balanced 5/5. The raw file retains all 60 observations. The measured timing
boundaries are OS-random key setup, initial owner issuance, later attenuation
or exchange refresh, complete issuance, terminal presentation construction,
full verification, and signed public revocation-state update. JWT uses an
authenticated inactive-JTI registry and UCAN uses the authenticated CID
registry extension, so each revocation update includes signing and monotone
installation and each byte count includes the canonical message plus Ed25519
signature. These are ordinary protocol
setups, not SNARK setup. Byte fields retain every signed grant by level, their
sum, final presentation, terminal binding (Ed25519 signature plus nonce in
both profiles), and public revocation-state bytes. Each independent alternate
path is signed before the revocation update and its original bytes must remain
unchanged when survival is checked.
The summarizer validates the paired matrix and lifecycle predicates before
reporting medians and two-sided 95% percentile bootstrap confidence intervals
from 10,000 deterministic resamples.

Do not replace a failed dependency, standard implementation, functional gate,
or formal predicate with another version or implementation. Preserve the
diagnostic and ask for a narrow source fix.
