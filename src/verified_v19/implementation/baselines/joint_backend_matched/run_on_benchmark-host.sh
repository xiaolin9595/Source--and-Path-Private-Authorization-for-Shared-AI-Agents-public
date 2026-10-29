#!/usr/bin/env bash
set -euo pipefail

if [[ "$(hostname -s)" != "benchmark-node" ]]; then
  echo "REFUSING: expected physical host benchmark-node (SSH alias benchmark-host)." >&2
  exit 64
fi

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plan_root="$(cd "${crate_dir}/../../.." && pwd)"
lock_file="${E8_EXPERIMENT_LOCK:-${REMOTE_DATA}/pets2027/results/.experiment.lock}"
run_root="${E8_JOINT_RUN_ROOT:-${plan_root}/results/e8_joint_backend_matched}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="${run_root}/${stamp}"
mkdir -p "${output}"

exec 9>"${lock_file}"
if ! flock -n 9; then
  echo "REFUSING: global experiment lock is held." >&2
  exit 75
fi

hostnamectl > "${output}/HOST.txt" 2>&1 || hostname > "${output}/HOST.txt"
rustc -Vv > "${output}/RUSTC.txt"
cargo -V > "${output}/CARGO.txt"

# The independent experiment crate is intentionally checked in without a
# machine-generated lockfile.  The coordinated server runner creates it once,
# records the resolution, and uses --locked for every build and execution step.
if [[ ! -f "${crate_dir}/Cargo.lock" ]]; then
  taskset -c 0-9 cargo generate-lockfile \
    > "${output}/LOCKFILE.stdout" 2> "${output}/LOCKFILE.stderr"
fi
cargo metadata --locked --no-deps --format-version 1 \
  > "${output}/CARGO_METADATA.json" 2> "${output}/CARGO_METADATA.stderr"
find "${crate_dir}" -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' -o -name '*.md' -o -name '*.sh' \) \
  -not -path '*/target/*' -print0 | sort -z | xargs -0 sha256sum > "${output}/SOURCE_SHA256.txt"

export RAYON_NUM_THREADS=10
export OMP_NUM_THREADS=1
export E8_JOINT_REPS="${E8_JOINT_REPS:-3}"
export E8_JOINT_OUTPUT="${output}/raw"

taskset -c 0-9 cargo check --locked --all-targets > "${output}/CHECK.stdout" 2> "${output}/CHECK.stderr"
taskset -c 0-9 cargo test --locked --release > "${output}/TEST.stdout" 2> "${output}/TEST.stderr"
taskset -c 0-9 cargo build --locked --release > "${output}/BUILD.stdout" 2> "${output}/BUILD.stderr"
taskset -c 0-9 cargo run --locked --release > "${output}/RUN.stdout" 2> "${output}/RUN.stderr"

find "${output}" -type f -print0 | sort -z | xargs -0 sha256sum > "${output}/ARTIFACT_SHA256.txt"
printf '%s\n' "${output}"
