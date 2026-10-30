# Add-only public release merge plan

## Goal and invariant

Merge this candidate into the existing public artifact without rewriting or
removing the historical v19, grid, DAC, membership, R5, or earlier experimental
materials. The existing public tree remains the provenance anchor. The new
R1--R6/E1--E3 plus bounded historical results are added under a versioned
`r3/` namespace.

No step in this plan publishes, pushes, uploads, deletes, or edits the old
repository. It is an execution checklist for the root release process. R4 and
R6 compact evidence are present and frozen in this candidate.

## Proposed merged tree

```text
/
  README.md                         # append navigation; do not replace history
  LICENSE
  LICENSE_SCOPE.json
  THIRD_PARTY_NOTICES.md
  src/verified_v19/                 # unchanged historical entry
  experimental/                     # unchanged grid/membership/older snapshots
  analysis/r5_wrapper_breakdown/    # unchanged historical DAC comparison
  third_party/                      # unchanged historical notices/source
  r3/
    README.md
    REPRODUCE.md
    SOURCE_INDEX.md
    RESULT_INDEX.md
    LICENSE
    LICENSE_SCOPE.json
    THIRD_PARTY_NOTICES.md
    sources/
    results/
    scripts/
    docker/
    Dockerfile
    CONTAINER.md
    VERIFICATION_REPORT.json
    VERIFICATION_R2_CONTROL.json
    SANITIZATION_REPORT.json
    FILELIST.sha256
```

The top-level README should receive only a short navigation section:

- “Historical verified v19 and earlier baselines” → existing paths.
- “R3 revision: R1--R6 implementation, E1--E3, and historical results” → `r3/`.
- R4/R6 completion status → the candidate result indexes and frozen analyses.

## Copy/add-only manifest

1. Copy the final contents of `release_candidate_anonymous/` to a new `r3/`
   directory. Do not copy its local filesystem metadata, temporary outputs, or
   any generated Cargo `target/` directory.
2. Append navigation to the top-level README; retain all existing reproduction
   commands and historical status statements under an explicit historical
   heading.
3. Add a top-level `RELEASE_GENERATIONS.md` mapping the immutable historical
   paths and hashes to the new `r3/FILELIST.sha256`. Do not rename old files.
4. Preserve the top-level MIT/license-scope files. The nested `r3/` license and
   scope remain authoritative for that subtree; more specific third-party files
   take precedence.
5. Add no proving keys, SQLite databases, build trees, terminal environments,
   supervisor/PID logs, private extracts, or failed-run logs.
6. R4/R6 compact timings are add-only after their frozen analyses passed. The large R4
   setup/key bundles remain outside Git and require a separately reviewed asset
   inventory.

## Conflicts and items that must not be deleted

- `src/verified_v19/` is the old verified-code entry and must remain byte-for-byte
  available; the new R1 source must not silently replace it.
- Existing `experimental/r3_coverage_candidate/` and
  `experimental/blind_update_snapshot/` are historical snapshots. Keep their
  names and hashes; point current readers to `r3/` instead of overwriting them.
- Existing grid, DAC, membership, matched-baseline, and R5 analysis files remain
  necessary to reproduce earlier manuscript claims and version differences.
- Existing third-party Dock/Arkworks/zkcrypto source and notices cannot be
  removed merely because `r3/` contains its own dependency closure.
- Do not collapse the top-level and nested license scopes: measurements,
  datasets, manuscript assets, and third-party code are not automatically
  relicensed by the project MIT file.
- Historical experiment identities and new sanitized-package identities must be
  shown in separate columns. A relocated path, redacted host alias, or sanitized
  manifest receives a new package hash and is never called byte-identical to its
  private-path source.

## E3 figure status

The prior five-file E3 subset was incomplete. The candidate now includes:

- `r3/results/e3/figures/e3_intersection_curves.pdf`, the actual V21 four-panel
  PDF, SHA-256
  `fea45aa7c7df89b6951c43272fae196e14986b14db74ce60434d664814e129fe`;
- `r3/results/e3/aggregate/fixed_cohort_summary.csv`, 80 public aggregate rows,
  SHA-256
  `f0419124342cf3723db19c101a17ada96b15b7257d8dbbdd1f4870ee71ff9c6f`;
- `r3/sources/e3_analysis/render_e3_figure.py`, the aggregate-only renderer;
- the full analysis and CSV/ARFF equivalence scripts plus official retrieval
  instructions.

The aggregate-only renderer was executed locally and reproduced the PDF hash
byte for byte in 1.72 seconds. Private CSV/ARFF transports remain excluded.

## Final ZIP and anonymous-rewrite verification

1. Assemble a fresh merge directory from the old public snapshot plus the
   add-only operations above. Never build the ZIP from a working tree containing
   `.git`, `target`, live databases, keys, or private logs.
2. Run both the old top-level audit and `r3/scripts/sanitize_release.py`. Reject
   symlinks, AppleDouble files, personal paths, host aliases, credentials, and
   unexpected files over the stated size bound.
3. Generate an origin manifest over every ZIP member using normalized relative
   POSIX paths. Store it as `ORIGIN_RELEASE_MANIFEST.sha256`; separately retain
   the Git commit selected for publication.
4. Create the ZIP deterministically with sorted members, fixed permissions, and
   a documented timestamp policy. Extract it into a fresh directory and verify
   the origin manifest before any upload.
5. After final root approval, manually select the intended public release
   generation. Do not infer generation identity from the endpoint or assume it
   updated itself; use `RELEASE_GENERATIONS.md` and the ZIP manifest.
6. Download the anonymous service ZIP through the public endpoint, remove only
   its service-added top directory from path comparison, and generate
   `ANONYMOUS_ZIP_MANIFEST.sha256`.
7. Compare origin and anonymous manifests by relative path and byte hash. Record
   any service rewrite in an explicit mapping. Code, raw timing rows, aggregate
   data, licenses, and analysis scripts must remain byte-identical; an unexplained
   rewrite is a release blocker.
8. Verify that README links resolve inside the anonymous ZIP and that the public
   page exposes no author name, private repository URL, personal path, account,
   or hidden Git metadata.
9. Only after these checks may the manuscript's anonymous URL be described as
   corresponding to the final candidate. Keep origin commit identity and
   anonymous-ZIP identity distinct in the audit report.

## Container release asset: verified, publication pending

The candidate Dockerfile and entrypoint were built and executed against the
context recorded in `CONTAINER_VERIFICATION.json`. Smoke, unified recomputation,
E3 PDF/SVG generation, and a fresh packaged R6 depth-3 trial passed. The
Dockerfile now spells the immutable digest of the same effective base used by
that build; this post-test pinning does not claim a second rebuild. The recorded local image ID is not a registry
digest. The compressed archive is outside Git and has its own size and SHA-256.
Publication remains a separate root release decision.

1. pin the base image by immutable digest, not tag alone;
2. build from the final ZIP-equivalent tree;
3. run `recompute` and `smoke` inside the image;
4. record image digest, architecture, SBOM, locked-package inventory, build log,
   and observed timings;
5. confirm the image contains no keys, runs, private data, Git history, or build
   credentials;
6. list the image in the asset inventory without placing its layers in Git.

Until upload and download verification pass, documentation must say “container
verified locally; archive not yet published,” not “container image released.”
