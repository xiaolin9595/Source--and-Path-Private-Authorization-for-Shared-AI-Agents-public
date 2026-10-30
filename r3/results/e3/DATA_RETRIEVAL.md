# Data retrieval

No raw trace or private dataset is distributed here. Retrieve the Amazon
Employee Access Challenge CSV from the official Kaggle competition data page:

`https://www.kaggle.com/competitions/amazon-employee-access-challenge/data`

The independently frozen transport is OpenML dataset 4135, version 1:

`https://www.openml.org/search?type=data&id=4135`

Record the retrieval date, provider terms, and file hash. The reviewed CSV
`train.csv` SHA-256 is
`3728631068926a60b2e812f1b63614e89a95c8b654a84f8ddb56fcd18fbfe47a`; the
reviewed OpenML ARFF SHA-256 is
`4f33c09f3612b5de1294ca664eec7fd1bb56a94b05d0352219794a37e4acc8cc`.
Use `sources/e3_analysis/compare_csv_arff_multiset.py` to confirm that CSV and
ARFF representations describe the same multiplicity-preserving ten-column
multiset before analysis.

Generated figures, tables, and result directories are deliberately omitted.
Only small synthetic fixtures used directly by tests are included.

