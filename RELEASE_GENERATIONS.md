# Release generations

This tree is assembled add-only.

| Generation | Identity | Scope |
|---|---|---|
| Historical public source release | Git commit `6bc2c731d1bdd85fa7ecd86a2fcb35c74fdaa3cb` | Existing `src/verified_v19/`, `experimental/`, `analysis/`, `third_party/`, root licenses, and their original documentation. |
| R3 artifact generation | `r3/FILELIST.sha256` file SHA-256 `cef37b705bd3b8afce2f605970d3e94286ff41069647b850bc78d203aebede60` | R1--R6/E1--E3, bounded historical compact observations, reproduction scripts, licenses, and verified container recipe. |

The nested manifest is authoritative only for `r3/`. Historical status text is
preserved for provenance and must not be read as the status of the R3 subtree.
The locally verified container archive is not a Git member; its identity and
the exact build-context mapping are recorded in `r3/CONTAINER_VERIFICATION.json`.
