# Final add-only merge-tree manifest review

The release operation adds this candidate as `r3/` beneath the existing public
tree. It does not replace or delete historical `src/verified_v19/`, grid, DAC,
membership, R5, license, or third-party paths. The authoritative member list and
byte identities are `FILELIST.sha256`; the existing public tree retains its own
historical manifest and commit identity.

Required new top-level subtree members include documentation and license files,
`sources/`, `results/`, `scripts/`, `docker/`, `Dockerfile`, container
verification, media-metadata review, artifact appendix, and the complete final
file list. Build targets, Git metadata, large keys/checking material, databases,
private extracts, host logs, and the external container archive are excluded.

Reviewed component identities use sorted lines
`<file-sha256>  <component-relative-path>\n`:

- `sources/r4_service`: 66 files,
  `a495012c988dff67e66ee4b025136831de03fcfd11d95793c89d914f1b767c8f`;
- `sources/r6_tree_maintenance`: 9 files,
  `fe03d9948904683c5417ada069062fcb15c6e4946913313ee980e8e6f0d186f4`;
- `results/r6`: 15 files,
  `d558028de92fe4f91583c890e82fd21fad622b19ec789a1f7a28fd38e6043f60`;
- `results/historical`: 1,147 files,
  `a5204b70c8c04a0f73c93f591812f3d73d26cd7b29d70a23680f4f12e40899b7`.

Before publication, assemble the old public tree plus this subtree, generate a
separate origin ZIP manifest, download the anonymous-platform ZIP, normalize
only its service-added leading directory, and compare every path/hash. The
container archive is verified separately by its compressed-byte SHA-256 and is
not a Git member. No anonymous URL or registry publication is performed by this
review.
