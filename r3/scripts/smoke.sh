#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target=$(mktemp -d "${TMPDIR:-/tmp}/joint-release-smoke.XXXXXX")
cleanup() { find "$target" -depth -delete; }
trap cleanup EXIT INT TERM
export CARGO_TARGET_DIR="$target"

cd "$root"
cargo metadata --locked --offline --no-deps --format-version 1 \
  --manifest-path sources/r1_randomized_dummy/Cargo.toml >/dev/null
cargo test --locked --offline \
  --manifest-path sources/r1_randomized_dummy/Cargo.toml --lib \
  fixture::tests::r1_dummy_crypto_and_enabled_authorization_gates -- --exact
cargo test --locked --offline \
  --manifest-path sources/r3_blind_update/Cargo.toml --test blind_update \
  real_proof_signature_admission_and_atomic_cas -- --exact
cargo test --locked --offline \
  --manifest-path sources/r4_checked_crs/Cargo.toml --test r4_checked \
  material_strict_decoding_and_callback_gate -- --exact
echo SMOKE_PASS
