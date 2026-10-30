# R6 full-reconstruction maintenance metrics

The formal run completed five deterministic synthetic workloads at each population with no failed cells. Every trial passed the header-signature, stale-CAS, changed-root, unchanged-row, updated-leaf, target-path, and unchanged-holder-path checks. Values below are medians with min--max ranges; no confidence interval is claimed.

| Population | Complete maintenance | Reciprocal sequential latency rate | Full refresh | Initial population |
|---:|---:|---:|---:|---:|
| 65,536 (depth 16) | 7.215 s (7.128--8.691) | 0.1386 s^-1 (0.1151--0.1403) | 8.190 s (6.540--8.320) | 16.307 s (15.599--17.729) |
| 1,048,576 (depth 20) | 126.099 s (123.939--131.596) | 0.007930 s^-1 (0.007599--0.008068) | 122.938 s (117.754--124.013) | 259.815 s (248.962--264.637) |

The reciprocal rate is calculated separately for every trial as `1 / complete_maintenance_seconds`, then summarized across the five rates. It is not the reciprocal of a mean latency and is not a sustained or concurrent throughput claim.

`complete_maintenance` starts immediately before the conditional CAS and ends after root materialization, canonical header construction, and synthetic fixture signing. Public-payload construction, public JSON serialization, and output-file writing occur after that endpoint. The total contains two audit-event flush-and-fsync operations; the residual after the non-overlapping CAS, database-read, materializer-process, and snapshot/signing components is orchestration and logging overhead, not cryptographic work. `full_refresh` is the sum of the receiver header-verification subprocess and holder refresh subprocess; it excludes the intervening export. `initial_population` excludes the later initial-root materialization.

Whole-process peak RSS medians were 69,320 KiB self and 71,680 KiB children at depth 16, and 652,288 KiB self and 1,116,720 KiB children at depth 20. These are Linux `ru_maxrss` process maxima and are not stage-specific memory measurements.

The public-state JSON sizes were 6,084,385 and 98,504,257 bytes. One path carried 512 or 640 raw sibling bytes at depths 16 or 20; two paths carried 1,024 or 1,280 bytes. Directions and JSON framing are reported separately in `formal_20261030_01/ANALYSIS.json`.

This is a subprocess-backed component measurement (including the recorded process-startup costs), not an HTTP end-to-end measurement, of the audited implementation's full sparse-root and dense-holder reconstruction. It assumes a prevalidated update, uses a synthetic fixture signer and synthetic grant-root field values, and does not measure HTTP, Groth16, enrollment, complete authorization-population construction, an incremental tree, or production throughput.

Primary evidence: `formal_20261030_01/ANALYSIS.json`, SHA-256 `5f180c1fd0efe36a2a2934905b788b93917e136e8670452dd35aaa06bd499514`. The local `ANALYSIS_LOCAL.json` is byte-identical.
