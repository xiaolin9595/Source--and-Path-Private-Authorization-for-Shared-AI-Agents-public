# Public release manifest

## Included source groups

1. `src/verified_v19/implementation/`: reviewed v19 implementation, service
   adapters, experiment drivers, and tests.
2. `src/verified_v19/zk-hrada-m3-backend/`: reviewed v19 backend source.
3. `third_party/`: only the third-party source closure required by retained v19
   path dependencies, with bundled license and notice files.
4. `experimental/r3_coverage_candidate/`: R3 source frozen for the current E1
   formal run and its vendored dependency closure; no E1 result is claimed.
5. `experimental/blind_update_snapshot/`: blind-update implementation, tests,
   service adapter, identity derivation, corrected persistence/CAS behavior,
   real loopback HTTP tests, and vendored dependency closure; no E2 performance
   or complete security-acceptance claim.
6. `analysis/r5_wrapper_breakdown/`: R5 counting source with public-relative
   Dock paths plus the source manifest.
7. `analysis/e3_intersection/`: analysis and CSV/ARFF equivalence scripts only.

## Deliberately excluded

- paper PDFs, TeX manuscript, author manual, private reviewer material;
- `related_work_private/`, including the private ZK-HADA PDF extraction;
- raw/private traces, original datasets, measurement outputs, figures, and
  large result directories;
- build products (`target/`), logs, cache files, and AppleDouble files;
- secrets, credentials, tokens, private keys, and local absolute paths;
- source with unclear provenance pending review.

`FILE_MANIFEST.sha256` is generated from the final staging tree immediately
before commit. `AUDIT_REPORT.md` records the sensitivity and license checks.
