# B1 official-source offline bootstrap

This procedure operates only on a fresh disposable runner copy. It does not
change the retained v1/v2 failure artifacts and does not replace the selected
JWT or UCAN libraries.

1. Copy the frozen B1 source into a new result/work directory. Record source
   hashes and save `Cargo.toml` as `Cargo.toml.before-offline-bootstrap`.
2. Run `tools/prepare_offline_ipld.py` on that copy. It downloads only the
   official `ipld-core-0.4.3.crate` archive from `static.crates.io`, retries
   transient failures, requires SHA-256
   `090f624976d72f0b0bb71b86d58dc16c15e069193067cb3a3a09d655246cbbda`,
   rejects archive traversal and links, and writes provenance. The script
   changes only the disposable manifest: the direct dependency becomes the
   exact extracted official path, and `[patch.crates-io]` makes pq-ucan's
   compatible transitive `ipld-core = "0.4"` use the same bytes.
   If the server cannot reach `static.crates.io`, transfer the locally retained
   official archive `offline_resources/b1_crates/ipld-core-0.4.3.crate` and
   official `offline_resources/b1_crates/pq-ucan-0.1.2.crate` and the
   registry-checksummed `offline_resources/b1_crates/cid-0.11.3.crate`, then
   pass them with `--archive ABSOLUTE_IPLD_PATH --pq-ucan-archive
   ABSOLUTE_PQ_PATH --cid-archive ABSOLUTE_CID_PATH`.
   The script requires fixed SHA-256 values
   `090f624976d72f0b0bb71b86d58dc16c15e069193067cb3a3a09d655246cbbda`
   and
   `c4f26f4e23e6a928ec6dafd6be3839af162b48e6fdf1fc15af6718f514da014e`
   and
   `21a304f95f84d169a6f31c4d0a30d784643aaa0bbc9c1e449a2c23e963ec4971`
   before extraction, records the pre-transferred transport, and performs no
   network request in this mode. The disposable manifest path-patches both
   exact registry sources. The cid transport mirror is disclosed and its bytes
   must match the crates.io checksum in pq-ucan's publisher lock; this is not a
   version or implementation substitution.
3. Preserve the prepared manifest and its diff, then run
   `cargo generate-lockfile --offline`. If another index entry is missing,
   stop and retain the first exact diagnostic; do not substitute a library or
   relax a version.
   Retain `pq-ucan-0.1.2.Cargo.lock` extracted from the official crate as
   dependency metadata only. It is not the root gate lock and must not replace
   the root resolver output. It records the publisher's resolved direct set,
   including bs58 0.5.1, cid 0.11.3, ed25519-dalek 3.0.0, getrandom 0.4.3,
   ipld-core 0.4.3, rand_core 0.10.1, sha2 0.11.0 and thiserror 2.0.21; the
   server resolver remains authoritative for the root feature union.
4. Once `Cargo.lock` exists, run `tools/prefetch_locked_crates.py` with that
   lock and `${REMOTE_HOME}/.cargo/registry/cache`. It verifies every already cached
   archive against the lock checksum, copies verified archives from other cache
   namespaces into the selected official cache directory when necessary, and
   downloads each missing archive only from
   `https://static.crates.io/crates/...`, verifying before installation. The
   provenance distinguishes preexisting cache bytes of unknown transport origin
   from archives downloaded by this run. Retain its JSON provenance and lock
   SHA-256.
5. From then on run all B1 gates with `--locked --offline`: format check,
   release check, JWT binary and UCAN binary. Preserve exact stdout/stderr,
   exit codes, time/RSS, prepared source and dependency provenance. No passing
   status is allowed until both binaries' asserted negative gates complete.
   Only after both functional gates pass, follow `FORMAL_GATE_REQUEST.md` for
   the 6 configurations x 10 fresh paired trials and bootstrap summary.
   Write every exit-code artifact with an actual newline, for example
   `printf '%s\n' "$status" > STEP.exitcode`; reject literal `0n`/`101n`
   artifacts. The retained v5 top-level time status remains authoritative, but
   its malformed per-step text files must not be copied into the next result.

The path patch is transport/bootstrap machinery for byte-identical official
crate source. It is not evidence that a registry build was exercised and must
be reported in the artifact. A later healthy-network reproduction may remove
the disposable path patch while retaining exact `ipld-core=0.4.3` and compare
the resulting crate checksum and behavior.
