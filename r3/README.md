# Anonymous artifact release

This release is assembled from the reviewed R1--R6, E1--E3, and bounded
historical main-result work. It contains buildable source trees, the complete path-dependency
closure, authorized sanitized measurements, licenses, and integrity metadata.
Release generations are identified by `FILELIST.sha256` and mapped in
[`../RELEASE_GENERATIONS.md`](../RELEASE_GENERATIONS.md). The declared anonymous endpoint is
`https://anonymous.4open.science/r/joint-authorization-2027/`; after publication,
download its ZIP and compare every member against the selected generation before
describing the endpoint as identical.

Important boundaries:

- Large proving keys, build trees, private dataset extracts, and raw remote-host
  logs are intentionally absent.
- R4 compact five-plus-five formal observations and R6 ten-cell component
  observations are included with frozen analyses. Large R4 bundles remain
  deliberately excluded; see
  `R4_FORMAL_RESULTS_BOUNDARY.md`.
- The Docker image was built and its smoke/recompute/E3 rendering checks passed
  against the recorded pre-documentation context. See `CONTAINER.md` and
  `CONTAINER_VERIFICATION.json`; the image archive remains outside Git.
- The same image also passed a fresh R6 depth-3 packaged trial after building
  the adapter and R3 service/mutation binaries inside the container; all seven
  correctness flags were true for population 8.
- Patched path dependencies are bundled. Registry dependencies are fixed by the
  complete Cargo lockfiles and can be fetched normally on a new machine.
- The included HTTP and mutation records are successful gate evidence, not
  performance samples.

Start with `SOURCE_INDEX.md`, `RESULT_INDEX.md`, and `REPRODUCE.md`. Verify the
release with:

```sh
sha256sum -c FILELIST.sha256
python3 scripts/sanitize_release.py . --report SANITIZATION_REPORT.json
```

`MEDIA_METADATA_REVIEW.md` records the PDF/PNG/SVG anonymity inspection and the
downloaded-ZIP verification recommendation.

The project-authored material is released under `LICENSE`, subject to the scope
statement in `LICENSE_SCOPE.json`. Dependency attributions are in
`THIRD_PARTY_NOTICES.md` and `licenses/third_party/`.
