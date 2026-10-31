# Data sources and terms

Terms and provider metadata reviewed: **2026-10-31**.

This record distinguishes the dataset used for quantitative analysis, its original competition source, and a separate dataset consulted for schema information. The artifact provides analysis scripts, retrieval instructions, and aggregate results. Original source datasets remain with their providers. The MIT license for original code does not relicense third-party data.

## Amazon Employee Access Challenge: original source

- Source: [Kaggle competition](https://www.kaggle.com/c/amazon-employee-access-challenge) and [data page](https://www.kaggle.com/c/amazon-employee-access-challenge/data).
- Terms: [Competition Rules](https://www.kaggle.com/c/amazon-employee-access-challenge/rules) and [Kaggle Terms of Use](https://www.kaggle.com/terms).
- Role: original source of the records distributed as OpenML dataset 4135; this is not a second pooled dataset.
- The competition rules restrict private sharing outside teams. Their MIT requirement concerns prize-winning methodology, not a data license. No standard open-data license was identified in the reviewed competition page. Rules for other Kaggle competitions are not substituted for this competition's rules.
- Source review recorded on **2026-10-24**; official rule content reviewed again on **2026-10-31**.

## OpenML 4135: quantitative analysis input

- Dataset: [Amazon_employee_access, dataset 4135](https://www.openml.org/d/4135), version **1**.
- Provider evidence: [official metadata API](https://www.openml.org/api/v1/json/data/4135); [OpenML terms](https://www.openml.org/terms).
- File: **1681098**, [Amazon_employee_access.arff](https://openml.org/data/v1/download/1681098/Amazon_employee_access.arff).
- Use: candidate-count proxies and simulated repeated-request intersections over **32,769** records, including **30,872** approved records. The CSV representation used in the intersection analysis was checked against the frozen ARFF input.
- The API reports `licence: Public` and `visibility: public`. These are recorded as provider metadata, not converted into a Creative Commons, public-domain, or unrestricted-redistribution grant. The original Kaggle terms remain separately documented above; OpenML's general terms are not treated as proof of additional rights from the original data owner.
- Source review and analysis are recorded by **2026-10-24**; metadata and terms were checked again on **2026-10-31**. The precise first-download timestamp was not separately retained. The latter date is a metadata/terms access date, not a new raw-data acquisition date.

Frozen input identifiers:

| Identifier | Value |
|---|---|
| Provider MD5 | `5502ee73e563ddf5b699ffe0c633905b` |
| Analysis-input SHA-256 | `4f33c09f3612b5de1294ca664eec7fd1bb56a94b05d0352219794a37e4acc8cc` |

Obtain the input from the documented provider and review the applicable terms before use. The aggregate analysis does not identify employees or reconstruct actual delegation histories.

## UCI 216: schema inspection

- Source: [Amazon Access Samples, dataset 216](https://archive.ics.uci.edu/dataset/216/amazon+access+samples).
- Citation: Montanez, K. (2011). *Amazon Access Samples*. UCI Machine Learning Repository. [doi:10.24432/C5JW2K](https://doi.org/10.24432/C5JW2K).
- Provider-listed license: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/). Preserve attribution and the license link, and indicate changes where applicable.
- Use in this manuscript: schema inspection only. These records do not supply the quantitative results and are not combined with OpenML 4135.
- Source evidence accessed **2026-10-25**; dataset page and license checked again **2026-10-31**.

The UCI dataset is distinct from the Kaggle/OpenML competition table. Its license is recorded for that dataset alone and is not applied to the competition records.
