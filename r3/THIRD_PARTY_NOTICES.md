# Third-party notices

The source snapshots depend on third-party Rust crates identified precisely by
their Cargo lockfiles. Those dependencies are not relicensed by the root MIT
license. Their upstream license and copyright files remain authoritative.

The R1/R3/R4 code uses Arkworks crates (including ark-groth16, ark-relations,
ark-r1cs-std, ark-ec, ark-ff, and ark-serialize) and zkcrypto crates (including
bls12_381, ff, group, and pairing). The checked-CRS changes derive from
ark-groth16. The upstream MIT and Apache-2.0 texts retained for that component
are in `licenses/third_party/`.

The patched path-dependency source is bundled under `sources/synthesis_patch/`
and `sources/third_party/`, with its upstream license files. Registry dependency
identities and declared licenses are listed in
`licenses/THIRD_PARTY_LICENSES.csv`, generated from the complete locked graphs.
Any redistribution must preserve every bundled license, copyright, and notice
file.

Dataset licenses are separate from the software license. E3 source datasets are
not included here; any later redistribution must follow their original terms
and preserve provenance and retrieval hashes.

The aggregate-only E3 renderer uses the pinned Python packages in
`requirements-e3-figure.txt`. Their declared licenses are indexed in
`licenses/PYTHON_PLOTTING_LICENSES.csv`; upstream package license texts remain
authoritative. These packages are installed into an isolated venv and are not
relicensed by the project MIT license.

