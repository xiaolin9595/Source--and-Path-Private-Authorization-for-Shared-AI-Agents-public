# E3 frozen-protocol results

## Scope and provenance

The analysis implements `E3_PROTOCOL_FROZEN.md` without downloading the UCI payload. It uses the 32,769-row Amazon Employee Access Challenge table (30,872 approved rows) and treats the seven role columns as an anonymous role-profile candidate. `MGR_ID` is reported only as a manager-bucket sensitivity analysis. Neither construct is an employee identity or a verified authorization source, and the dataset has no request timestamps; the 100 PCG64 permutations per unit are simulated without-replacement request orders, not chronological traces.

The computation was run from `raw_private/train.csv` (SHA-256 `3728631068926a60b2e812f1b63614e89a95c8b654a84f8ddb56fcd18fbfe47a`). To resolve the format/provenance question, the previously frozen OpenML ARFF was recovered read-only from the experiment host (SHA-256 `4f33c09f3612b5de1294ca664eec7fd1bb56a94b05d0352219794a37e4acc8cc`). `FORMAT_EQUIVALENCE.json` proves equality of the complete ten-column record multisets after mapping ARFF `target` to CSV `ACTION`, reordering fields, requiring each token to be integral, and serializing it as a base-10 integer. Both have 32,769 rows and 32,769 unique complete records; their multiplicity-preserving canonical multiset SHA-256 is identically `96f7430fde9b9a8690dd0f2c97686faed5aafabb6a47d6754b20b21b6dd8f7ba`. Thus the CSV transport is content-equivalent to the frozen OpenML copy for all ten columns; this is not inferred merely from row counts.

## Fixed-cohort coverage

The primary curves hold the cohort fixed at units with at least ten distinct approved resources.

| Candidate / arm | Units before filter | Eligible | Excluded | Approved rows covered | Approved rows excluded |
|---|---:|---:|---:|---:|---:|
| role-profile A (department random requests) | 445 | 301 | 144 | 30,089 | 783 |
| role-profile B (fixed latent profile proxy) | 6,282 | 679 | 5,603 | 12,972 | 17,900 |
| manager-bucket A | 445 | 301 | 144 | 30,089 | 783 |
| manager-bucket B | 4,956 | 819 | 4,137 | 16,566 | 14,306 |

The B-arm role-profile curve therefore describes a strongly selected, resource-diverse subset: only 679 of 6,282 `(department, role-profile)` units qualify, covering 42.02% of approved rows. It must not be generalized to all profiles. `k_specific_sensitivity.csv` supplies an all-available-at-each-k analysis, explicitly with a changing cohort.

## Primary role-profile B result

The table below is macro-averaged over the 679 eligible units (100 permutations each). Candidate count is the department intersection. “Pool increment” is global minus department count for the identical request sequence.

| k | Candidate median [IQR] | Mean | Singleton | At least 2 | Global median | Global mean | Pool increment median | Pool increment mean |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 2 [1, 4] | 3.1103 | 40.96% | 59.04% | 8 | 65.8601 | 4 | 62.7497 |
| 2 | 1 [1, 1] | 1.3124 | 80.19% | 19.81% | 1 | 3.9784 | 0 | 2.6659 |
| 5 | 1 [1, 1] | 1.0103 | 99.03% | 0.97% | 1 | 1.0269 | 0 | 0.0166 |
| 10 | 1 [1, 1] | 1.00025 | 99.975% | 0.025% | 1 | 1.00031 | 0 | 0.000059 |

For this selected proxy cohort, intersections usually become singleton quickly: among uncensored trajectories the median first-singleton step is 2. However, 17 of 67,900 trajectories (0.0250%) remain right-censored after k=10 and still have at least two candidates; 67,883 trajectories (99.9750%) reach a singleton by k=10. These are **proxy-candidate** results under the common-source role-profile assumption, not person re-identification or proof of a real authorization source. The global pool is nested and never smaller, but its average advantage is concentrated at small k and almost vanishes by k=10 in this cohort; this is an empirical observation, not a monotonic benefit claim for non-nested role families.

Arm A addresses a different question: randomly selected requests from a department can have different latent sources. Its intersection may become empty (role-profile A zero fraction is 72.39% at k=2 and 99.52% at k=10); emptiness is not an attack success. Def. 4 already permits multiple adaptive presentations, so this experiment adds only a candidate-evolution observation under the stated proxy assumptions, not a correction from a single-show guarantee.

## Artifacts

- `E3_intersection_analysis/analyze_e3.py`: frozen analysis and plotting implementation.
- `E3_intersection_analysis/results/run1/`: primary raw tables and metadata.
- `E3_intersection_analysis/results/run2/`: independent deterministic rerun.
- `E3_intersection_analysis/figures/run1/e3_intersection_curves.{svg,pdf}`: curves.
- `E3_intersection_analysis/compare_csv_arff_multiset.py` and `FORMAT_EQUIVALENCE.json`: full format-equivalence proof.
- `E3_VALIDATION.md`: mechanical checks and interpretation boundaries.

Raw CSV/ARFF transports remain under `raw_private/` and are excluded from the public artifact.
