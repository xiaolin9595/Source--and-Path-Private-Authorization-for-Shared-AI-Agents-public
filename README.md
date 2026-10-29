# Source- and Path-Private Authorization for Shared AI Agents

This repository is a source-only public release candidate for the experimental
code accompanying the project. It intentionally excludes the manuscript,
review correspondence, raw traces, private datasets, local execution logs, and
large generated results.

## Release status

- `src/verified_v19/` is the previously reviewed v19 source baseline.
- `experimental/r3_coverage_candidate/` is the source snapshot frozen for the
  formal E1 run. The run is in progress and has no reportable result yet.
- `experimental/blind_update_snapshot/` implements the new blind-update
  functionality, identity/VK binding, canonical `u64` TEXT persistence,
  lock-scoped legacy CAS handling, and real loopback HTTP tests. This remains an
  experimental functional snapshot: it is not an E2 performance result and is
  not a claim of complete security validation.
- `analysis/r5_wrapper_breakdown/` contains the wrapper-counting source. Its
  Dock dependency is the public revision
  `224f195bb8babc2d0de5256135120e0aca9fbd19`; the repository-local
  `730fa...` hash is not a Dock revision.
- `analysis/e3_intersection/` contains analysis scripts only. The private raw
  datasets and generated results are excluded.

See `RELEASE_STATUS.md`, `REPRODUCE.md`, and `PUBLIC_RELEASE_MANIFEST.md` before
using the experimental snapshots.

## Licensing

The root MIT license applies only to original code and original analysis or
reproduction scripts, as described in `LICENSE_SCOPE.json`. Vendored software
retains its own licenses. See `THIRD_PARTY_NOTICES.md` and license files in the
relevant subtrees.

