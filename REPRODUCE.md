# Minimal reproduction entry points

Prerequisites are Rust/Cargo matching the lockfiles and Python 3. The `--offline`
commands require registry crates already present in the local Cargo cache;
vendored path dependencies are included in this repository. On a new machine,
populate the cache once with network access:

```sh
cargo fetch --locked --manifest-path src/verified_v19/implementation/Cargo.toml
cargo fetch --locked --manifest-path experimental/blind_update_snapshot/implementation/Cargo.toml
```

```sh
# Previously reviewed v19 unit and integration tests
cargo test --locked --offline \
  --manifest-path src/verified_v19/implementation/Cargo.toml --lib

# R3 blind-update functional tests (experimental, not an E2 benchmark)
cargo test --locked --offline \
  --manifest-path experimental/blind_update_snapshot/implementation/Cargo.toml \
  --test blind_update

# Build the real fixture and service-core executables used by HTTP integration
cargo build --locked --offline \
  --manifest-path experimental/blind_update_snapshot/implementation/Cargo.toml \
  --bin blind_update_fixture --bin plan_a_service_core

# Run service logic and real loopback HTTP integration from the service folder
(cd experimental/blind_update_snapshot/service && \
  BLIND_UPDATE_FIXTURE_BIN=../implementation/target/debug/blind_update_fixture \
  PLAN_A_SERVICE_CORE_BIN=../implementation/target/debug/plan_a_service_core \
  python3 -m unittest test_service_logic.py test_blind_update_service.py)
```

The E3 scripts require independently obtained source datasets. Do not substitute
private local extracts. Dataset retrieval and format expectations are documented
in `DATA_RETRIEVAL.md`.

