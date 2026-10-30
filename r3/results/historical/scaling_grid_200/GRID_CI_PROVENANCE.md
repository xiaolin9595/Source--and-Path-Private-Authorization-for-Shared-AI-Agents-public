# Scaling-grid interval provenance boundary

The included 200 raw observations, 20-cell shape, success flags, medians,
minima, maxima, and constant shape fields are recomputed from `TRIALS.jsonl`.
The frozen interval source is `E2_CELL_SUMMARY_CI.json` with SHA-256
`37dc461f64acbcfaa50326e7e1d3a26865ac60a0bf287db227b59948ea8137e3`.
It records base seed 20261023 and 10,000 percentile-bootstrap resamples.

A bounded search of the preserved final-v17 artifact snapshot and its associated
checklist experiment tree covered Python, shell, Markdown, and JSON files for
the seed, bootstrap, resampling, and percentile terms. It found the frozen
metadata and unrelated later-study analyzers, but not the original grid
per-cell/per-metric random-stream derivation. Therefore this release **does not
claim to recompute the grid CI endpoints**. It validates raw point statistics,
shape/cardinality, interval containment, and the exact hash of the retained
frozen CI source. No seed stream was guessed and no endpoint was tuned.
