# E3 mechanical validation

- Input: exactly 32,769 rows and 30,872 approved rows.
- Full transport equivalence: all ten columns normalized; ARFF `target` mapped to CSV `ACTION`; record order ignored but duplicate multiplicity retained. Canonical counters are equal, with zero unmatched multiplicity in either direction.
- Frozen randomness: NumPy PCG64, seed 2026102903; units and resources sorted before 100 without-replacement permutations.
- Expected output cardinality: 2,100,000 fixed-cohort trajectory rows, 80 fixed-cohort summary rows, 40 changing-cohort sensitivity rows, and 210,000 first-singleton rows.
- Toy manual check: department intersections `(2,1,1)`, global intersections `(3,3,2)`, first singleton at step 2.
- Every candidate trajectory is non-increasing; every global pool count is at least the corresponding department count; every pool increment is nonnegative.
- Arm B is never empty, as required when requests are sampled from a fixed latent proxy profile/bucket.
- First-singleton censoring is encoded as `first_singleton_k=11` with `right_censored_after_k10=1`; an explicit assertion checks this equivalence for every trajectory. Role-profile B has 17/67,900 censored trajectories, consistent with its k=10 `>=2` fraction of 0.0250%.
- Determinism: all six core CSV/JSON outputs are byte-identical between `run1` and `run2`. After removing creation dates and fixing Matplotlib's SVG hash salt, both SVG and PDF figures are also byte-identical.
- Both analysis scripts pass `python3 -m py_compile`.

Interpretation checks: A-arm empty intersections are not labeled attacks; B-arm candidates are not identities; `MGR_ID` is not called an employee ID or authorization; randomized order is not called time; role-family partitions are not treated as nested pooling; and fixed-k=10 coverage exclusions are reported alongside the curves.
