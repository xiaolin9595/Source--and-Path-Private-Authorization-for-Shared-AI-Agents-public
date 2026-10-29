# Release status

This package distinguishes reviewed historical source from work in progress.

| Area | Status | Permitted interpretation |
|---|---|---|
| v19 source baseline | previously reviewed source snapshot | baseline code for historical experiments |
| R3 coverage candidate | source frozen; formal E1 run in progress, no result yet | inspect and reproduce the source, but do not cite an E1 outcome |
| blind update | corrected functional snapshot with identity binding, canonical u64 persistence, lock-scoped legacy CAS handling, and real HTTP tests | functional snapshot only; not an E2 performance result or complete security acceptance |
| R5 wrapper breakdown | analysis source snapshot | reproduce counts after satisfying pinned third-party dependencies |
| E3 intersection | scripts only | retrieve the original public datasets independently; no private/raw dataset is included |

No statement in this repository should be read as a claim that the new E1
formal run has produced a result or that the E2 study is complete. The E1
source is frozen for its current run; the experimental material still requires
result review before it can become an accepted release.

The corrected blind-update Rust relation and true Groth16 loopback HTTP/socket
path have been validated locally. That functional validation can proceed
independently of the E1 result; it does not constitute an E2 measurement.

