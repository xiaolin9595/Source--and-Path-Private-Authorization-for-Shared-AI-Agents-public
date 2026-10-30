# E2 paper metrics

The frozen run completed all 300 formal blind root replacements in ten fresh
Groth16 setup clusters, with 30 separately initialized and excluded warmups.
All formal updates were accepted; there were no missing rows or errors. Values
below are medians in milliseconds with descriptive 95% whole-setup bootstrap
intervals in brackets (10,000 replicates, seed 20261029, shared cluster-index
vectors, type-7 percentile interpolation).

| Measured interval | n | Median ms | 95% interval ms |
|---|---:|---:|---:|
| Witness preparation | 300 | 0.893 | [0.884, 0.899] |
| Proof generation with loaded PK | 300 | 174.838 | [162.691, 181.115] |
| Owner signing and serialization | 300 | 1.770 | [1.713, 1.909] |
| Pure proof verification in actual verifier | 300 | 6.521 | [6.484, 6.582] |
| Complete external-verifier service stage | 300 | 16.314 | [16.003, 16.601] |
| Atomic SQLite replacement | 300 | 11.549 | [11.451, 11.585] |
| HTTP request to committed response | 300 | 29.524 | [29.157, 30.097] |
| Direct client preparation to response | 300 | 206.624 | [193.872, 214.243] |

Deployment costs over ten setups were 190.180 ms [183.529, 205.124] for
randomized Groth16 setup, 4,544.118 ms [4,270.054, 5,007.492] for checked
proving-key loading, and 4.300 ms [4.232, 5.032] for verification-key loading
and preparation.

The paired update-30 minus update-1 difference was 3.160 ms [2.491, 7.796]
for HTTP latency and -4.150 ms [-8.889, 4.785] for direct client latency. These
are paired ten-setup summaries, not differences between pooled marginal
medians. The positive HTTP difference describes this run and is not a general
deployment guarantee.

The relation used 11,427 constraints, 14 public inputs (15 instance variables
including the constant), and 8,567 witness variables. Compressed proofs were
192 bytes, proving keys 2,846,544 bytes, verification keys 1,064 bytes, and
complete encoded requests 1,032–1,036 bytes. The matrix SHA-256 was
`b5b94001cc975f101a5aba22cce1429a0bc7643a0d146f7a6e884aacb3815875`.

The experiment directly seeded trusted admission and initial state before
measurement; it did not measure full enrollment. Fresh roots were random field
elements, so grant-tree construction was outside the measured client interval.
Snapshot publication was functionally gated but not part of update acceptance,
and access-proof refresh was not exercised. Nested intervals above must not be
summed as disjoint costs. The shared-host bootstrap intervals are descriptive
of setup-cluster variation in this run.

Integrity: observations SHA-256
`5ca2bbc0e0eb1f44db4ba19d0920d1801602ea3379c3e0f2c476c63382f93cf3`;
remote and locally reproduced analysis SHA-256
`a7e8f0e0bc050db5c6bd2a8ff547911117da3a1c5fbe695da7d3689af009e5ad`.
The two analysis files are byte-for-byte identical.
