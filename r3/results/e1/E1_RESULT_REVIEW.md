# E1 formal-result review

Date: 2026-10-29 (Asia/Shanghai). This review reports the one frozen formal attempt; it does not redefine its thresholds or claim timing independence.

## Completion and integrity

- Remote status: `COMPLETE`; all four sessions have `COMPLETE` markers.
- Formal measurements: 4,500/4,500, with 1,125 per session. Each session also retained one header and nine gates outside the formal measurements.
- The frozen analyzer consumed sessions 1 and 3 for training and sessions 2 and 4 for testing.
- Supervisor and analyzer stderr are empty. No failed or malformed record was reported by the frozen run.

## Predeclared screen

The screen required both (i) every pooled dummy pairwise absolute median difference to be at most 15 ms and (ii) held-out nearest-median three-class accuracy to be at most 45%.

The held-out classifier criterion passed: 535/1,500 = 35.67%. The absolute-median criterion failed:

| Pair | Absolute median difference | Threshold | Result |
|---|---:|---:|---|
| length 2 vs. 1 | 1.109 ms | <=15 ms | pass |
| length 3 vs. 1 | 16.245 ms | <=15 ms | fail |
| length 3 vs. 2 | 15.135 ms | <=15 ms | fail |

Therefore `screen_pass=false`. The failure margins above the point threshold are 1.245 ms and 0.135 ms. They must not be rounded down or re-screened under a relaxed threshold.

## Supporting results

- Dummy pooled medians: length 1 = 2,793.418 ms; length 2 = 2,792.309 ms; length 3 = 2,777.174 ms.
- Per-label held-out length classification: aA = 36.00%; aB = 32.13%.
- A/A label classification within lengths was 52.4%, 51.4%, and 50.4%; paired aA-minus-aB medians were 6.219, -0.859, and 1.107 ms.
- Original-relation length classification was 60.27%, with medians 2,524.372, 2,590.632, and 2,660.240 ms for lengths 1, 2, and 3.
- Session/block bootstrap 95% intervals for the dummy absolute differences were [0.246, 15.835], [1.307, 27.855], and [1.981, 26.769] ms for 2-1, 3-1, and 3-2.

## Interpretation and protocol consequence

Random valid dummy slots substantially reduced the tested length classifier relative to the original relation, but the frozen attempt did not meet both predeclared point criteria. This is an empirical near miss, not evidence of timing independence or elimination of all side channels. Under the frozen protocol, R2 becomes a necessary candidate. R2 has not been started: its release buckets, observer, independent calibration set, actual-arrival measurement and overflow handling must first be frozen, and the E1 test data cannot be used to choose the padding threshold.

Authoritative machine output: `ANALYSIS.json` in this directory.
