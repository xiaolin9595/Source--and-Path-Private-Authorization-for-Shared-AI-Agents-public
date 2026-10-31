# Release generations

This tree is assembled add-only.

| Generation | Identity | Scope |
|---|---|---|
| Historical public source release | Git commit `6bc2c731d1bdd85fa7ecd86a2fcb35c74fdaa3cb` | Existing `src/verified_v19/`, `experimental/`, `analysis/`, `third_party/`, root licenses, and their original documentation. |
| R3 artifact generation | `r3/FILELIST.sha256` file SHA-256 `d196631f05535595e7374d15d54b9bb076d15b6859ef8828ae94de311a489c46` | R1--R6/E1--E3, bounded historical compact observations, reproduction scripts, licenses, and verified container recipe. |

The nested manifest is authoritative only for `r3/`. Historical status text is
preserved for provenance and must not be read as the status of the R3 subtree.
The locally verified container archive is not a Git member; its identity and
the exact build-context mapping are recorded in `r3/CONTAINER_VERIFICATION.json`.

The post-release anonymity correction replaces four historical machine-specific
example commands with artifact-relative commands and rewrites the sanitizer's
three equivalent personal-path alternatives as one grouped expression. The
scanner still detects all three path classes; scientific code, observations and
the tested container image are unchanged.
