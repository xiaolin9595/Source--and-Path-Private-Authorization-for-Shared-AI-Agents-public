# Source index

| Area | Candidate path | Role | Status and boundary |
|---|---|---|---|
| E1 original | `sources/e1_original/` | Canonical-zero Native baseline relation | Complete source and lockfile; shares the bundled path-dependency closure. |
| R1 | `sources/r1_randomized_dummy/` | Randomized-dummy joint relation and its production binaries | Complete reviewed source, tests, and lockfile. |
| R2 | `sources/r2_presentation/` | Actual loopback Agent/receiver presentation binary | Complete source and lockfile. |
| R3 | `sources/r3_blind_update/` | Blind-update relation, service components, and measurement binaries | Current-source snapshot used for the reviewed R3/E2 work; no build output or key material included. |
| R4 checker | `sources/r4_checked_crs/` | Exact checked-key loading and sidecar generation | V5 compact snapshot: checker, generator, and functional tests. |
| R4 service | `sources/r4_service/` | Checked Agent/SR entry points, HTTP gates, and formal analyzer | Gate/final-analysis source snapshot; compact formal observations and analysis are included separately. |
| R6 | `sources/r6_tree_maintenance/` | Existing full tree reconstruction, conditional CAS, signing, and holder refresh measurement | Frozen runner/analyzer preserved; package-relative wrapper and adapter source included. This is not an incremental-tree implementation. |
| E3 | `sources/e3_analysis/` | Set-intersection and CSV/ARFF equivalence analysis | Scripts only; source datasets and private extracts are excluded. |
| Dependency closure | `sources/synthesis_patch/`, `sources/third_party/` | Patched ark-r1cs-std and zkcrypto path dependencies | Bundled with upstream licenses; all path references resolve inside this candidate. |

All project Rust packages identify as version `0.1.0`; release identity is therefore
defined by `FILELIST.sha256`, not by that package version alone. Cargo lockfiles
are complete. The R4 checker is a full ark-groth16-derived crate, with the V5
checked-key additions and functional tests.

No frozen historical R1/R2/R3 source tree was modified. Files were copied into a
new release directory. The R4 service manifest's checked-ark path was relocated
to its anonymous-package-relative location; that packaging edit necessarily has
a new candidate hash and is not described as byte-identical to the frozen
manifest. Source identities inside the candidate are governed by
`FILELIST.sha256`.

Host-specific aliases in copied protocols/service documentation were replaced
with the logical phrase `shared Linux host`. Those documentation files therefore
also receive new package hashes. No Rust or Python execution logic was changed
by that redaction.

## Component tree identities

Each digest below is SHA-256 over the sorted UTF-8 lines
`<file-sha256>  <component-relative-path>\n`:

| Component | Files | Tree SHA-256 |
|---|---:|---|
| `sources/e1_original` | 30 | `9dccd916cb817a6675e1cc282036141f60ecb80544916f3cc11c4a8169652538` |
| `sources/r1_randomized_dummy` | 31 | `1df48060e35c38d97aed2db4fb4f1be801588744029e205688f7e02a4768dc39` |
| `sources/r2_presentation` | 32 | `7b1e57f7cb3f00c3286a962d066bc31755ddf90242414d3e0d1bb8afbaa74e07` |
| `sources/r3_blind_update` | 35 | `72d503531b2ce30df4b06cccf9af93adaada68f0eaea7a6cc3342f32c212a904` |
| `sources/r4_checked_crs` | 19 | `b04f015aad0c77e42f6f63d965a10f10be59b897241cdf662ec34772c39082b2` |
| `sources/r4_service` | 66 | `a495012c988dff67e66ee4b025136831de03fcfd11d95793c89d914f1b767c8f` |
| `sources/r6_tree_maintenance` | 9 | `fe03d9948904683c5417ada069062fcb15c6e4946913313ee980e8e6f0d186f4` |
| `sources/synthesis_patch` | 60 | `a1af9385f5db86d410291ed02f0a1c83c59cc2c32757f78f74747efd6590caf4` |
| `sources/third_party` | 82 | `a7d214f7f91b05ab6cb0c689c49236bc619810847e009bb3c0656d1579687da8` |
