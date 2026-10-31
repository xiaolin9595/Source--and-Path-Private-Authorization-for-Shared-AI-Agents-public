# Data retrieval

No raw trace or private dataset is distributed here. The E3 analysis accepts
CSV/ARFF inputs supplied by the researcher. Retrieve the original public
datasets from their authoritative publishers, record the source URL, retrieval
date, license, and file hash, and then use
`analysis/e3_intersection/compare_csv_arff_multiset.py` to confirm that converted
CSV and ARFF representations describe the same multiset before analysis.

Generated figures, tables, and result directories are deliberately omitted.
Only small synthetic fixtures used directly by tests are included.

See [Data sources and terms](r3/DATA_SOURCES_AND_TERMS.md) for source-specific roles, provider metadata, applicable terms,
and frozen input identifiers. Third-party data are not relicensed by the code license.
