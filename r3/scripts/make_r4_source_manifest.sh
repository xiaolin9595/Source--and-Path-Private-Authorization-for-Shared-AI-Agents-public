#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_SHA256" >&2
  exit 64
fi

root=$(cd "$(dirname "$0")/.." && pwd)
output=$1
case "$output" in
  /*) ;;
  *) output="$root/$output" ;;
esac
mkdir -p "$(dirname "$output")"

cd "$root"
find sources/r4_service sources/r4_checked_crs sources/synthesis_patch sources/third_party \
  -type f \
  ! -path '*/target/*' \
  ! -path '*/.git/*' \
  ! -name '._*' \
  -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 sha256sum > "$output"

test -s "$output"
if grep -Eq '(^|/)target/|(^|/)\.git/|/\._' "$output"; then
  echo "excluded path leaked into source manifest" >&2
  exit 1
fi
for required in \
  sources/r4_service/Cargo.toml \
  sources/r4_service/Cargo.lock \
  sources/r4_checked_crs/Cargo.toml \
  sources/r4_checked_crs/src/checked.rs \
  sources/synthesis_patch/ark-r1cs-std/Cargo.toml \
  sources/third_party/bls12_381-0.7.1/Cargo.toml; do
  grep -Fq "  $required" "$output" || {
    echo "required source missing from manifest: $required" >&2
    exit 1
  }
done
echo "R4_SOURCE_MANIFEST_PASS $output"
