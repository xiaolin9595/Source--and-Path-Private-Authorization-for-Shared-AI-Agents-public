# DAC matched-service source candidate

Status: frozen source candidate awaiting the sole benchmark-host proof-free format,
locked/offline compile, Rust command-deserialization and shared Python contract
gates. This file is not pass evidence. The retained v21 relation/full-proof
artifacts remain separate and are not overwritten by this candidate.

The wire is `plan-a-matched-jsonl-v1`. `trusted_now` occurs only inside the
service-built `expected` object. Materialization returns the bare authenticated
header. Caller proof envelopes contain no VK, parameters, actual delegation
depth or trusted deployment keys. The shared case plan supplies thirteen
independent operational nonces and bodies; `actual` occurs only in formal
offline timing rows.

```text
cc9ac439db133dcd4ae94d86eeed27a2237e4b1d855988f5d13fff8cca164977  implementation/baselines/dac_fixed_wrapper/src/semantic_schema.rs
37a856a658893ace442b6643a4ccb48744c717245229ea10a65b1dc064c3f3ca  implementation/baselines/dac_fixed_wrapper/src/matched_builder.rs
021dabf9dabd60b035fd229920ede3cd706ece384be1b1c9e5a034b1fcab92ca  implementation/baselines/dac_fixed_wrapper/src/service_wire.rs
406665345fac0f40a8a46ecafe1a7006a7c9fd5e317a017ae56e8848f046d874  implementation/baselines/dac_fixed_wrapper/src/bin/dac_resident_jsonl.rs
1e185c0c12cd4e210a86c67fa794c1c57ecd365152ea8508570ef4a43a2af6e2  implementation/baselines/dac_fixed_wrapper/src/bin/dac_jsonl_contract_check.rs
b4d92aa3f7ee1a061b5911b5ecc34b9d95ab36b511bda494417fcff095e4e880  implementation/baselines/paired_semantic_manifest/src/main.rs
9d5255eb7bd34b61038a2096577cd6c0e353ca9d7d21ee4cddf2f8c83d8e1aee  implementation/service/matched_case_plan_v1.json
9399d0ccd83f731f421ce0d29a20157fec88957c1eea205e4c05932c4c62c789  implementation/service/matched_dac_jsonl_contract_fixture.json
10b5ff50f9104fd57f14c20647ec3e3e910df8caaa78aec977a9e1c5c775bff4  implementation/service/validate_matched_jsonl_contract.py
57f0bab3a72e66d046a332808e7e6a69995d7d9d77d7edc79c6c963f184df77f  implementation/service/MATCHED_JSONL_WIRE_V1.md
```

Any server rustfmt-only changes must be recorded as a source transition and
this manifest regenerated before setup, proof, correctness or timing runs.
