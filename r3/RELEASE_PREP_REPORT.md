# Release preparation report

## Outcome

A buildable anonymous release candidate was created locally. Nothing was
uploaded or published. The candidate contains about 153 MiB of source and path
dependencies, authorized sanitized raw observations, compact result summaries,
successful R4 functional-gate evidence, license material, and executable
reproduction entry points. It contains no proving keys, build directories,
private dataset extracts, supervisor/PID records, or historical failed-run logs.
The bounded historical layer and R6 compact component study are now included.
Unified recomputation passed, including byte-identical R6 analysis
`5f180c1fd0efe36a2a2934905b788b93917e136e8670452dd35aaa06bd499514`.
The package-relative R6 wrapper has a distinct hash from the preserved frozen
runner and is documented as a layout adaptation, not an identical source file.
The Dockerfile now prefetches every manifest with a bundled lockfile, including
the R4 checked-CRS crate, R6 adapter, and standalone patched ark-r1cs-std crate,
before setting Cargo offline. This closes the dependency-cache gap exposed by
the first actual container smoke; the root process owns the rebuilt-image log.

For the historical grid, a bounded search of the preserved final-v17 snapshot
and checklist tree found frozen seed/resample metadata but no original
per-cell/per-metric RNG stream derivation. The candidate therefore recomputes
only raw point statistics and shape, and pins the retained CI source by hash.

R4's complete compact formal timing observations and frozen analysis are now
included. No partial result or placeholder performance number was introduced;
the ten large bundles remain deliberately excluded.

## Identity and verification

- Candidate identity: `FILELIST.sha256` (generated after all content changes).
- Sanitization schema: `anonymous-release-sanitization-v1`.
- Sanitization result: PASS, zero findings.
- Maximum allowed single file in the scanner: 50 MiB; no included file exceeds
  that bound.
- R4 frozen-analyzer unit tests in the candidate: 8 passed.
- R4 included-timing recomputer tests: 4 passed; both Level-3 fresh-bundle
  relation drivers passed a locked offline compile check.
- Included JSON documents: parsed successfully.
- Offline Cargo metadata resolved with every bundled path dependency.
- Real crypto smoke: randomized-dummy gate, signed blind-update proof/CAS gate,
  and checked-key rejection gate all passed.
- Existing-data recomputation: E1, R2, R3/E2, and R4 timing outputs matched byte
  for byte. R4's compact path validates recorded bundle digests, not omitted
  bundle bytes.
- R2 complete-entry control test: one fresh setup, all nine warmup/gate cells,
  three measurement rows, E1-key collision checks, and Agent/receiver
  verification passed in 102.60 seconds without starting the 600/4,500 run.
- E3 aggregate-only renderer reproduced the V21 four-panel PDF byte for byte in
  1.72 seconds in the warm environment; a new isolated venv installation plus
  render took 70.37 seconds and produced the same hash.
- Rust/Cargo dependency inventory: 119 locked packages, zero unknown license
  declarations. The separately pinned Python plotting environment is listed in
  `requirements-e3-figure.txt` and `licenses/PYTHON_PLOTTING_LICENSES.csv`.
- Container recipe: fixed Rust 1.89.0 base, locked dependency fetch, offline
  execution entrypoint, and build-time data recomputation. The local Docker
  image was subsequently built from the recorded context: all three smoke gates,
  unified recomputation, and E3 PDF/SVG generation passed. The recorded value is
  a local image ID, not a registry digest; the archive remains outside Git.

The sanitization check rejects macOS user paths, mounted personal paths, Unix
home paths, private-key markers, common GitHub/AWS token forms, WeChat IDs,
symlinks, sensitive key filenames, and files larger than 50 MiB. It also rejects
AppleDouble metadata files.

## Included evidence boundaries

- E1 includes four complete sanitized session record/schedule pairs; R2 includes
  its sanitized calibration/formal joined rows; R3/E2 includes all 300 sanitized
  observation rows. All three include frozen analysis entry points.
- E3 includes protocol/results/validation and analysis scripts, not source data.
- R4 includes toy-checker success, actual Joint HTTP gate success, intentional
  valid-subgroup mutation rejection, and ten compact formal timing cells. The
  functional gates and descriptive performance observations remain distinct.
- Large/final raw collections should be added only in a later reviewed release
  layer with stable hashes and redistribution clearance.
- Fixture owners, signing keys, and database contents used by included tests are
  synthetic test material, not production credentials. No live database or
  terminal environment dump is included.

## Remaining release gates

1. R6 is now closed with ten compact observations, frozen analysis, package-
   relative source, and a byte-match recomputation. Large R4 key
   bundles remain outside Git and require separate asset review.
2. Rerun sanitization and regenerate `FILELIST.sha256` after any addition.
3. After final freeze, manually update the existing anonymous endpoint from its
   intended generation identified by `FILELIST.sha256`, download the anonymous ZIP, and verify it
   against the final `FILELIST.sha256`.

The endpoint exists, but its auto-update is disabled and it currently represents
the older public commit, not this local candidate. No upload, GitHub permission
change, or endpoint update was performed by this preparation task.
