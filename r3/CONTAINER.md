# Container reproduction

`Dockerfile` pins Rust `1.89.0-bookworm` to immutable base digest
`sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff`, installs Python 3 and Linux CPU
affinity support, creates a dedicated E3 plotting venv from
`requirements-e3-figure.txt`, resolves every registry dependency from the
complete Cargo lockfiles during image construction, and then makes Cargo
offline. It does not install plotting packages into Debian's system Python.
Bundled path dependencies never require a second source checkout.

Build and run:

```sh
docker build --pull -t joint-artifact:candidate .
docker run --rm joint-artifact:candidate recompute
docker run --rm joint-artifact:candidate smoke
```

For a complete experiment, mount a new output directory and forward the real
driver arguments. For example:

```sh
mkdir -p runs
docker run --rm --cpuset-cpus=0-9 -v "$PWD/runs:/artifact/runs" \
  joint-artifact:candidate r2-complete /artifact/runs/r2-complete
```

The final pre-documentation build context had `FILELIST.sha256` digest
`2f6b4d99d33520331d4e45a0d1590cee297da0cb6b372dcb1c43bd4140c8411f`.
It was built and executed successfully. The local image ID (not a registry
digest) was
`sha256:27896e2a43fec98e8437f21fab3f741497be9360bf7221908d2d1d373a3a9878`
and its reported size was 688,537,941 bytes. Inside that image:

- `recompute` completed the unified E1/R2/R3/R4/R6 and historical validation;
- `smoke` passed all three cryptographic/negative gates;
- E3 PDF and SVG generation passed.
- a fresh packaged R6 trial built its adapter plus R3 service/mutation binaries
  inside the image and ran depth 3, seed 4243. Population was 8, all seven
  correctness flags were true, and `RESULT.json` SHA-256 was
  `aad3c8915b804bae267a0af9bea381c39d1dc4afd544b248abec421f6000e8d9`.

The image was archived outside Git as
`pets2027-artifact-r3_20261030-2f6b4d99.tar.gz` (684,410,346 compressed bytes),
SHA-256
`c81c8f1c22a41d41ea9b973939f3ee8ddbbdc5ef3f84acc9e5c0f7457f522fac`.
Load it with:

```sh
gzip -dc pets2027-artifact-r3_20261030-2f6b4d99.tar.gz | docker load
```

The tarball is a separately reviewed release asset and is not stored in this
Git tree. `CONTAINER_VERIFICATION.json` records the machine-readable mapping.
Subsequent documentation-only edits change the release `FILELIST.sha256` but do
not retroactively change the tested build context or image; this avoids a
self-referential rebuild requirement. The image ID is local content identity,
not a claim that a registry image has been published.

The verified platform was Docker client/server 29.5.3 on `linux/amd64`; the
image was `linux/amd64`. It contained rustc 1.89.0 commit
`29483883eed69d5fb4db01964cdf2af4d86e9cb2`, Cargo 1.89.0, and Python 3.11.2.
System and plotting-package versions are frozen in
`CONTAINER_PACKAGE_INVENTORY.txt`. The successful R6 entrypoint used `shell -c`;
an earlier `shell -lc` invocation error is not experimental evidence and is not
included in the release.
