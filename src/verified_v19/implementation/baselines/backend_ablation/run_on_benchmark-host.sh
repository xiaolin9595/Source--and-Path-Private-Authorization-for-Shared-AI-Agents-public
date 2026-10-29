#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

repo="${E8_REPO:-${REMOTE_DATA}/pets2027/M3-min}"
crate="$repo/work/plan_a_2026_10_23/implementation/baselines/backend_ablation"
lock=${REMOTE_DATA}/pets2027/results/.experiment.lock
run_id="legacy_relation_composition_ablation_exploratory_n3_$(date -u +%Y%m%dT%H%M%SZ)"
output_root="${E8_OUTPUT_ROOT:-${REMOTE_DATA}/pets2027/plan_a_20261023/runs}"
artifact_root="$output_root/$run_id"
target_dir="$artifact_root/cargo-target"

if [[ "$(hostname)" != "benchmark-node" ]]; then
  echo "REFUSING: E8 is authorized only on benchmark-host (hostname benchmark-node)." >&2
  exit 2
fi
if [[ ! -f "$crate/Cargo.toml" || ! -f "$repo/zk-hrada-m3-backend/Cargo.toml" ]]; then
  echo "REFUSING: expected reviewed checkout is missing." >&2
  exit 2
fi

mkdir -p "$artifact_root"
exec 9>"$lock"
if ! flock -n 9; then
  echo "REFUSING: the global experiment lock is held (E5 or another run is active)." >&2
  rmdir "$artifact_root" 2>/dev/null || true
  exit 75
fi

source_manifest() {
  {
    find "$crate" "$repo/zk-hrada-m3-backend/src/protocols" \
      -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) \
      -print0
    printf '%s\0' \
      "$repo/zk-hrada-m3-backend/Cargo.toml" \
      "$repo/zk-hrada-m3-backend/Cargo.lock"
  } | sort -z | xargs -0 sha256sum
}

finalize() {
  status=$?
  trap - EXIT
  set +e
  {
    date --iso-8601=seconds
    hostname
    free -h
  } >"$artifact_root/environment-after.txt" 2>&1
  if [[ -f "$artifact_root/source-manifest-before.sha256" ]]; then
    source_manifest >"$artifact_root/source-manifest-after.sha256"
    diff -u \
      "$artifact_root/source-manifest-before.sha256" \
      "$artifact_root/source-manifest-after.sha256" \
      >"$artifact_root/source-manifest.diff"
  fi
  printf '%s\n' "$status" >"$artifact_root/exit-status.txt"
  find "$artifact_root" \
    -path "$target_dir" -prune -o \
    -type f ! -name 'artifact-manifest.sha256' -print0 \
    | sort -z | xargs -0 sha256sum \
    >"$artifact_root/artifact-manifest.sha256"
  exit "$status"
}
trap finalize EXIT

{
  date --iso-8601=seconds
  hostname
  uname -a
  rustc +1.95.0 --version --verbose
  cargo +1.95.0 --version --verbose
  lscpu
  free -h
} >"$artifact_root/environment-before.txt" 2>&1

if [[ -d "$repo/.git" ]]; then
  git -C "$repo" rev-parse HEAD >"$artifact_root/repository-head.txt"
  git -C "$repo" status --short --untracked-files=all >"$artifact_root/git-status-before.txt"
  git -C "$repo" diff -- \
    zk-hrada-m3-backend/src/protocols/hrada_auth.rs \
    zk-hrada-m3-backend/src/protocols/hrada_poseidon_baseline.rs \
    work/plan_a_2026_10_23/implementation/baselines/backend_ablation \
    >"$artifact_root/source-diff.patch"
else
  printf '%s\n' 'unavailable: coordinated server source tree has no Git metadata' \
    >"$artifact_root/repository-head.txt"
  : >"$artifact_root/git-status-before.txt"
  : >"$artifact_root/source-diff.patch"
fi

if [[ ! -f "$crate/Cargo.lock" ]]; then
  cp "$repo/zk-hrada-m3-backend/Cargo.lock" "$crate/Cargo.lock"
fi
cargo +1.95.0 fetch --manifest-path "$crate/Cargo.toml" \
  >"$artifact_root/lock-fetch.stdout" 2>"$artifact_root/lock-fetch.stderr"
source_manifest >"$artifact_root/source-manifest-before.sha256"
if [[ -d "$repo/.git" ]]; then
  git -C "$repo" status --short --untracked-files=all \
    >"$artifact_root/git-status-after-lock.txt"
else
  : >"$artifact_root/git-status-after-lock.txt"
fi
tar -C "$repo" \
  --exclude='work/plan_a_2026_10_23/implementation/baselines/backend_ablation/target' \
  -czf "$artifact_root/source-freeze.tar.gz" \
  zk-hrada-m3-backend/Cargo.toml \
  zk-hrada-m3-backend/Cargo.lock \
  zk-hrada-m3-backend/src/protocols/hrada_auth.rs \
  zk-hrada-m3-backend/src/protocols/hrada_poseidon_baseline.rs \
  work/plan_a_2026_10_23/implementation/baselines/backend_ablation

CARGO_TARGET_DIR="$target_dir" cargo +1.95.0 build \
  --release --locked --manifest-path "$crate/Cargo.toml" \
  >"$artifact_root/build.stdout" 2>"$artifact_root/build.stderr"
binary="$target_dir/release/legacy-backend-ablation"
sha256sum "$binary" >"$artifact_root/binary.sha256"

cd "$artifact_root"
/usr/bin/time -v taskset -c 0-9 env \
  RAYON_NUM_THREADS=10 OMP_NUM_THREADS=1 \
  "$binary" >run.stdout 2>run.stderr
