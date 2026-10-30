# Result index

| Study | Included compact evidence | Deliberately not included |
|---|---|---|
| E1 / R1 | Four complete sanitized session record/schedule pairs, frozen analyzer, reproduced analysis, and result review | Proofs, keys, remote supervisor logs |
| R2 | Sanitized calibration/formal joined rows, frozen analyzer, reproduced analysis, and paper metrics | Keys, telemetry, supervisor logs |
| E2 / R3 | Sanitized 300-row observation file, frozen analyzer, reproduced analysis, and paper metrics | Databases, keys, remote environment logs |
| E3 | Frozen protocol, result/validation reports, format-equivalence JSON, aggregate figure rows, and the four-panel PDF | Private extracts and downloaded source datasets |
| R4 | V5 toy/HTTP/mutation gates plus ten complete compact formal timing cells, frozen full-bundle analyzer, included-observation recomputer, and byte-identical analysis | Large PK/checking-material bundles, build products, host telemetry, and private paths |
| R6 | Ten compact component observations (five each at depths 16 and 20), frozen analyzer, byte-identical analysis, schedule, and paper metrics | Huge public trees, SQLite databases, binaries, telemetry, and host logs |
| Historical main results | Compact grid/depth/DAC/membership/lifecycle records plus frozen analyzers and bounded read-only adapters | Key material and unrelated diagnostics |

E1, R2, and R3/E2 now have local raw-observation recomputation. E3 remains
aggregate-only and retains official retrieval requirements.

R6 measures the existing full reconstruction path, not incremental throughput.
`scripts/recompute_r6.py` reproduces its frozen analysis byte-for-byte from the
ten included small `RESULT.json` files.

Using the component-tree algorithm from `SOURCE_INDEX.md`, `results/r6` has 15
files and SHA-256
`d558028de92fe4f91583c890e82fd21fad622b19ec789a1f7a28fd38e6043f60`;
`results/historical` has 1,147 files and SHA-256
`a5204b70c8c04a0f73c93f591812f3d73d26cd7b29d70a23680f4f12e40899b7`.
The latter includes the explicit grid CI provenance boundary: raw point
statistics and shape are recomputed, while CI endpoints retain the hashed
frozen source because the original RNG stream derivation was not found.

The paper's E3 four-panel figure is
`results/e3/figures/e3_intersection_curves.pdf` (SHA-256
`fea45aa7c7df89b6951c43272fae196e14986b14db74ce60434d664814e129fe`).
It is byte-identical to both independently rendered experiment copies and the
V21-referenced PDF. Its 80 public aggregate input rows are in
`results/e3/aggregate/fixed_cohort_summary.csv` (SHA-256
`f0419124342cf3723db19c101a17ada96b15b7257d8dbbdd1f4870ee71ff9c6f`),
and `sources/e3_analysis/render_e3_figure.py` regenerates the PDF without the
private source records.

The sorted tree SHA-256 of `results/r2/raw` is
`37da61b1dc3010f00c328bde9bc77947478af2462dabe8e1fba93731ecb1afe4` (three
files). The corresponding digest of `results/r3_e2/raw` is
`ca3e1992b88ab7fa4f03f357e201adb4b117d391e7762bcf1798abf7cbe9b9b1` (one
file), using the same component-tree algorithm documented in `SOURCE_INDEX.md`.
The corresponding E1 raw tree digest is
`0fba2edeb5fee6475908d4a0d2f0242dbfec57fb1cdbefbf7362abba2c8550f4`
(eight files).

R4 gate records establish functional acceptance/rejection behavior. The
separate `formal_v5` cells support only the descriptive five-sample medians and
ranges recorded in their frozen analysis; they do not establish a confidence
interval or stable speedup. The included-observation recomputer checks the ten
small logs and measurement-time digest records, while the unchanged full
analyzer requires and rehashes every large bundle. The ten large setup/key
bundles remain outside Git; if disclosure is required, list them for separate
release-asset review first. Live databases, terminal environment captures, and
host-specific logs are never release inputs.
