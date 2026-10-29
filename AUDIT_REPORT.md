# Public staging audit

Audit date: 2026-10-29 (Asia/Shanghai)

## Scope and inventory

- Whitelist-only staging tree assembled independently under
  `public_release_staging`; the parent M3 Git repository was not reinitialized
  and no parent remote was changed.
- 1,255 published files including this report and the generated hash manifest;
  the manifest contains 1,254 entries because it excludes itself. Two ignored
  historical rustfmt stdout/stderr files discovered during the pre-push Git
  audit were removed as local execution outputs.
- Approximately 15.9 MB of file content (filesystem allocation may be larger on
  the external volume).
- No manuscript PDF, private related-work text, raw/private trace, result,
  `target`, log, or AppleDouble file is included.

## Sensitive-field scan

The final tree was scanned for local absolute paths, local volume/user markers,
private host aliases, WeChat identifiers, PEM private-key headers, common GitHub
and cloud-token prefixes, and OpenAI-style secret prefixes. Hits: 0.

This pattern scan is a release gate, not a proof that arbitrary secrets cannot
exist. The whitelist and manual exclusions remain the primary control.

## License check

- Root MIT scope is limited by `LICENSE_SCOPE.json`.
- 37 license/copyright/notice files are retained after adding the declared
  Apache-2.0 license text for the `hrada-sr-full-f-bbs` path crate.
- Each retained top-level vendored subtree has a bundled license, copyright, or
  notice file within two directory levels.
- Dock source is identified as upstream revision
  `224f195bb8babc2d0de5256135120e0aca9fbd19`; `730fa...` is explicitly labeled
  as a historical repository-local state, not a Dock revision.

## Reproduction checks

- Latest R3 blind-update Rust integration test, locked and offline: 4 passed.
- v19 Rust library tests, locked and offline: 10 passed.
- Latest Python service and real loopback HTTP suite: 15 passed. This includes
  the true Groth16 fixture/service-core socket path, the concurrent CAS check,
  canonical 20-digit `u64` TEXT storage, decoded 9/11 verification, and the
  loopback HTTP route/schema checks.
- The machine's default `stable` rustup shim was broken; successful Rust checks
  used the installed `1.89.0` toolchain. This is an environment issue, not a
  source change.

## Remote readiness

The authenticated local GitHub account has admin and push permission for the
empty public target repository. The remote reports default branch `main`, size
0, and public visibility. No push, commit, or pull request was performed during
this audit.
