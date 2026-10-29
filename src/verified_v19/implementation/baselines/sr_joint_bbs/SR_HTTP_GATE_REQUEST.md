# SR/BBS HTTP gate request

This gate must run only on `benchmark-host`, after the current E5 lock is released. No compile or experiment was run while E5 owned the server.

## Frozen implementation

- `src/http_bridge.rs`
- `src/bin/sr_http_agent.rs`
- `src/bin/sr_http_verifier.rs`
- `src/bin/sr_http_setup.rs`
- `Cargo.toml`
- `../../service/service.py`
- `../../service/sr_resident_http_trace.py`

The service keeps the existing Joint core for registry signatures, enrollment, state/revocation root materialization and header publication. Only envelopes with the exact enabled `proof_scheme=sr-bbs23-cdl-v1` schema are sent to the separately configured SR verifier. The client can select this enabled scheme and its fixed `config_id`; it cannot provide verifier parameters, issuer key, deployment, legacy mapping, full Joint circuit id or a tuple/snapshot mapping.

## Commands for the runner

From `implementation/baselines/sr_joint_bbs`:

```sh
cargo check --all-targets
cargo build --release --bin sr_http_setup --bin sr_http_agent --bin sr_http_verifier --bin portfolio_sweep
```

From `implementation` (using the already built Joint core and mutation CLI):

```sh
python3 service/sr_resident_http_trace.py \
  --agent target/release/sr_http_agent \
  --setup target/release/sr_http_setup \
  --sr-verifier target/release/sr_http_verifier \
  --joint-core target/release/plan_a_service_core \
  --requests 10 \
  --out evidence/sr_http_trace.json
```

Because the SR crate has its own Cargo workspace, replace all three SR binary paths (`sr_http_setup`, `sr_http_agent`, and `sr_http_verifier`) with `baselines/sr_joint_bbs/target/release/...` when invoking from `implementation`. Preserve the source manifest and SHA-256 hashes beside the trace.

`sr_http_setup` is the only setup command that creates public verifier material. It writes the exact verifier material and parameter digest plus the unique H0/H1/H2 tuple-to-complete-snapshot map. The verifier reads only this file through `VerifierParams::from_canonical_bytes`; its request path does not call fixture construction, compilation, issuer setup or signing. The resident benchmark process emulates the trusted issuer: it reconstructs the fixture issuer, checks it against that public config, and issues only H0 before its ready message. It retains H0 for the malicious-holder test.

The trace records show time, total HTTP time, canonical Agent input bytes, authorization header bytes, BBS showing bytes, body bytes and response bytes for every request. Its gates cover a real invalid showing without nonce consumption, a two-request nonce race with exactly one commit, nonce/resource/action/full-circuit/config/deployment mutations, and field-modulus resource alias rejection. H1 is published only after the service records B's capability revocation and materializes its new revocation root. H2 is published only after an authenticated owner state update deactivates A and the service materializes the new state root; setup independently requires native compilation of H2 to yield zero credentials.

The malicious-holder gates use the cached signed H0 credential to create a fresh BBS showing over the complete H1 canonical request and sign the fresh terminal transcript correctly. They repeat this with the cached H1 credential and H2. The trace separately records that each terminal signature verifies and each anonymous proof fails under the new generation's expected signed epoch. These are not mutations of an old showing.

The runner also invokes the SR verifier directly to reject a trusted-config substitution and a different snapshot under the same tuple version. It advances the trusted clock after terminal verification and checks that the commit transaction rejects the now-expired request. This gate reports Delta zero only. Any future Delta-positive claim must separately show acceptance before `retired_at + Delta` and rejection after its inclusive deadline.

## Known deployment limitation

This executable is a deterministic benchmark deployment. Production must replace fixture setup and Agent seed reconstruction with an authenticated issuer/key store and provision serialized issued credentials through the trusted local Agent channel.

The lifecycle fixture is `L=3, DS=3, DRA=3, DRev=4`. Its trace explicitly sets `matched_e2_performance=false`; do not compare its timings with the planned `DS=20, DRA=20, DRev=32` Joint profile.

## Same-profile Joint HTTP control

Run the existing Joint resident driver at the SR fixture's small-tree profile and Delta zero:

```sh
python3 service/resident_http_trace.py \
  --agent target/release/plan_a_agent_cli \
  --core target/release/plan_a_service_core \
  --pk artifacts/l3-ds3-dra3-drev4.pk \
  --vk artifacts/l3-ds3-dra3-drev4.vk \
  --l 3 --active 3 --ds 3 --dra 3 --drev 4 \
  --fixture two-source-a \
  --delta-seconds 0 --requests 10 \
  --out evidence/joint_http_l3_ds3_dra3_drev4.json
```

Both traces now report the profile, Delta, method, path, audience, body, nonce decoded length, canonical request bytes, proof/showing bytes, authorization bytes, response bytes, process mode and initialization boundary. Both use `nonce=1000+i`, `now=150`, a 30-second request interval, body `payload`, and ten or more resident-Agent requests. The public verifier remains a one-shot subprocess in both HTTP paths.

The canonical two-source builder now lives once in `plan_a_joint_circuit::fixture::two_source_same_terminal`; the SR fixture module only re-exports it. With `--fixture two-source-a`, the Joint Agent proves source A, emits both owner admissions, and uses exactly the SR H0 snapshot roots, terminal, resource, action and interval. The existing L3/DS3/DRA3/DRev4 proving key remains valid because the relation and shape are unchanged. Default `--fixture fixed` behavior is unchanged for frozen E2/E5 reproduction.

The Joint canonical request contains `vk_id`; SR contains `proof_scheme` and `config_id`, so wire formats and canonical request byte lengths remain transparently different and are reported. The runner must compare both traces' `h0` objects and require equality for snapshot, digest, terminal, resource, action and interval before using the same-H0 control.

After the service commits B's capability revocation and installs H1, the runner sends the resident process `{"command":"refresh-h1"}`. That command performs native H1 compilation, real BBS issuance and credential serialization before caching H1; the trace records compile, issue, compile-plus-issue, command wall, client-observed wall and credential bytes separately. H1 showing occurs only after this command succeeds. This is a colocated trusted-issuer emulation: production credential network delivery is not measured and the benchmark Agent must not be described as a production SDK holding the issuer key. Per-request show time remains separate.
