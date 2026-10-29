# R3 blind owner-state update prototype

This isolated tree implements the frozen `R3_IMPLEMENTATION_SPEC.md` owner-update scope. It does not modify `implementation_r3`, R1/E1 sources, the paper, or OPTIONCAST.

## Implemented path

`implementation/src/blind_update.rs` defines a Groth16 relation over the exact existing `StateLeaf` layout. Public inputs bind config/deployment/circuit identity, a Poseidon identity binding, the SR-authenticated owner/position/cap/admission version, old/new leaves, versions, and epochs. Private witnesses are only old/new grant root, expiry, active bit, and salt. The relation enforces both hashes, integer ranges, no-wrap version increment, strict epoch increase, Boolean/monotone active, and the admitted expiry cap. It does not claim to prove salt freshness.

`implementation/src/blind_update_sr.rs` is the in-process reference SR: it validates the registered prime-order public key, verifies Groth16 and a signature over the complete transition plus SHA-256 of the canonical compressed proof, then rechecks admission and current state under one lock before CAS.

`implementation/src/bin/plan_a_service_core.rs` and `service/service.py` integrate the same checks into the real external verifier and SQLite service path. `POST /state/blind-update` accepts only the public statement, proof, and signature. It reads the public key/cap/admission version from the admission database, verifies cryptography outside the database writer transaction, and rechecks admission plus old leaf/version/epoch inside `BEGIN IMMEDIATE`. After a blind update, both admission lookup and legacy CAS reject the blind sentinel, preventing a verified legacy request from racing a blind commit. Full-u64 metadata is persisted as canonical fixed-width decimal TEXT and compared only after numeric parsing; legacy signed-INTEGER databases are migrated in place.

The new request, response, and post-update row contain no grant root, state expiry, active bit, salt, or opening. Initial enrollment remains visible in the historical baseline.

## Scope boundary: suspension

The inspected baseline has no authority suspension, tombstone, or recovery API. It only supports owner `active=true -> false` and forbids owner `false -> true`. This implementation preserves that behavior inside the proof and does not invent a new authority role or recovery path. The handbook statement that SR active suspension already exists is therefore not implemented evidence.

## Reproduce the functional gate on `206160G`

```sh
rsync -a --delete --exclude target ./ 206160G:/home/lzb/r3_blind_update_impl_codex/
ssh 206160G 'cd /home/lzb/r3_blind_update_impl_codex/implementation && PATH=/home/lzb/.cargo/bin:$PATH CARGO_HOME=/home/lzb/pets2027_r3_e1_original_20261029/.cargo-home cargo +1.95.0 test --test blind_update --offline'
ssh 206160G 'cd /home/lzb/r3_blind_update_impl_codex/implementation && PATH=/home/lzb/.cargo/bin:$PATH CARGO_HOME=/home/lzb/pets2027_r3_e1_original_20261029/.cargo-home cargo +1.95.0 build --bin blind_update_fixture --bin plan_a_service_core --offline'
ssh 206160G 'cd /home/lzb/r3_blind_update_impl_codex/service && BLIND_UPDATE_FIXTURE_BIN=/home/lzb/r3_blind_update_impl_codex/implementation/target/debug/blind_update_fixture PLAN_A_SERVICE_CORE_BIN=/home/lzb/r3_blind_update_impl_codex/implementation/target/debug/plan_a_service_core python3 test_blind_update_service.py -v'
```

This is a functional/compile/proof gate, not formal E2 sampling. During formal E1 use of `206160G`, do not run these Rust commands concurrently; the post-review rerun is intentionally pending.

## Source-diff command

From `revision_r3_2026_10_29`:

```sh
diff -ruN implementation_r3/implementation blind_update_impl/implementation
diff -ruN ../../implementation/service blind_update_impl/service
```

