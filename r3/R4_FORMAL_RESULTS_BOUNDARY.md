# R4 formal measurement inclusion boundary

Status: **complete and independently numerically reviewed**.

The authorized design used five fresh setups for each of the two actual
relations and reports descriptive medians and ranges. The candidate includes
all ten compact timing cells and the byte-identical frozen `ANALYSIS.json`.
There are no partial samples and no stable-speedup or confidence-interval claim.

The package does not distribute the ten large PK/checking-material bundles.
Therefore `recompute_included_r4_timings.py` checks the pre-recorded digests and
small observations but does not claim to rehash those omitted bytes. The frozen
`analyze_r4_formal.py` remains the full Level-3 analyzer: it requires every
bundle and independently hashes its PK, VK, and checking material before using a
cell. Any separately hosted parameter asset still requires a specific file
inventory and review first.
