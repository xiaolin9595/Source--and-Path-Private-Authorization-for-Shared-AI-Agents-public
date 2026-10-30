# R2 paper metrics

The frozen R2 attempt completed 600 independent calibration presentations and 4,500 formal presentations across four fresh formal sessions. Every proof and terminal signature verified, every receiver frame was 2,567 bytes, and no real stderr file was nonempty. Re-running the frozen analyzer on the downloaded records reproduced `ANALYSIS.json` byte-for-byte with SHA-256 `28ccaa81e7c1c8e5482fd44b56d717470829b4a6001a054be2c9962fa15caea2`.

Calibration used 200 observations per length. The nearest-rank p99 ready times were 3,124.069, 3,023.279 and 3,104.032 ms for lengths 1–3, producing the preregistered `Tpad = 3,250 ms`.

## Primary padded screen

| Length | Pooled pA+pB n | Receiver median (ms) | Mean actual wait (ms) | Wait bootstrap 95% (ms) | Overflow |
|---:|---:|---:|---:|---:|---:|
| 1 | 1,000 | 3,250.232103 | 432.916 | [415.454, 451.751] | 1/1,000 |
| 2 | 1,000 | 3,250.231252 | 443.190 | [424.420, 462.619] | 3/1,000 |
| 3 | 1,000 | 3,250.230768 | 450.034 | [420.269, 479.106] | 1/1,000 |

The pooled padded length classifier achieved 480/1,500 = 32.0%, below the frozen 45% threshold. Pairwise absolute median differences were 0.000851 ms (1–2), 0.001335 ms (1–3; maximum), and 0.000484 ms (2–3), all far below 15 ms. Their session/block bootstrap 95% intervals were [0.000159, 0.011353], [0.000167, 0.011096], and [0.000147, 0.012150] ms. Thus the frozen empirical screen passed. Five of 3,000 padded presentations overflowed (0.167%); all remained in the primary analysis. Mean actual wait pooled over all padded observations was 442.046 ms.

## Controls and diagnostics

The unpadded length classifier achieved 283/750 = 37.73%; its receiver medians were 2,787.384, 2,777.003 and 2,776.579 ms for lengths 1–3.

The pA-versus-pB A/A classifier achieved 723/1,500 = 48.2% overall. Per-length accuracies were 52.2% (261/500), 46.0% (230/500), and 46.4% (232/500). Paired pA-minus-pB median differences were 0.001912, 0.001461 and 0.001137 ms by length, and 0.001530 ms overall.

These results establish only that the preregistered screen passed for this frozen loopback workload and observation model. They do not establish constant-time computation or eliminate all timing and repeated-observation channels.
