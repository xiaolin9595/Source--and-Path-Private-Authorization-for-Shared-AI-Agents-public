# Release generations

Each release generation is selected by the SHA-256 of its `FILELIST.sha256`.
Historical public material remains add-only and retains its original commit and
manifests. The current candidate's final documentation-only generation is the
`FILELIST.sha256` shipped beside this file. Its container mapping deliberately
points to the earlier tested build-context generation
`2f6b4d99d33520331d4e45a0d1590cee297da0cb6b372dcb1c43bd4140c8411f`;
see `CONTAINER_VERIFICATION.json`.

After publication, record the selected public commit and anonymous-ZIP manifest
in the external release audit. Do not infer generation identity from a URL,
branch name, image tag, or local Docker image ID alone.
