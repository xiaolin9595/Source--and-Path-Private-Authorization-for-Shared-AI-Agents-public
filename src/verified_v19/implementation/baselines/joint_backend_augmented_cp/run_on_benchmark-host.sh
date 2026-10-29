#!/usr/bin/env bash
set -euo pipefail

if [[ "$(hostname -s)" != "benchmark-node" ]]; then
  echo "REFUSING: expected physical host benchmark-node (SSH alias benchmark-host)." >&2
  exit 64
fi

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
plan_root="$(cd "${crate_dir}/../../.." && pwd)"
legacy_root="$(cd "${crate_dir}/../../../../.." && pwd)/zk-hrada-m3-backend"
lego_root="${plan_root}/../sr_comparison_2026_10_23/native_probe/source/legogroth16"
lock_file="${E8_EXPERIMENT_LOCK:-${REMOTE_DATA}/pets2027/results/.experiment.lock}"
run_root="${E8_AUGMENTED_RUN_ROOT:-${plan_root}/results/e8_joint_augmented_three_backend_formal}"
formal_repetitions="${E8_AUGMENTED_FORMAL_REPS:-12}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
output="${run_root}/${stamp}"
mkdir -p "${output}"

if [[ "${formal_repetitions}" -lt 12 || $((formal_repetitions % 6)) -ne 0 ]]; then
  echo "REFUSING: formal repetitions must be at least 12 and divisible by six." >&2
  exit 65
fi
if [[ ! -f "${crate_dir}/Cargo.lock" ]]; then
  echo "REFUSING: audited CP cross-version Cargo.lock is missing." >&2
  exit 66
fi

exec 9>"${lock_file}"
if ! flock -n 9; then
  echo "REFUSING: global experiment lock is held." >&2
  exit 75
fi

run_logged() {
  local label="$1"
  shift
  set +e
  /usr/bin/time -v -o "${output}/${label}.time" \
    "$@" > "${output}/${label}.stdout" 2> "${output}/${label}.stderr"
  local status=$?
  set -e
  printf '%s\n' "${status}" > "${output}/${label}.exitcode"
  if [[ "${status}" -ne 0 ]]; then
    echo "FAILED: ${label} (exit ${status})." >&2
    exit "${status}"
  fi
}

hostnamectl > "${output}/HOST.txt" 2>&1 || hostname > "${output}/HOST.txt"
rustc -Vv > "${output}/RUSTC.txt"
cargo -V > "${output}/CARGO.txt"

cd "${crate_dir}"
run_logged FMT cargo fmt --all -- --check
run_logged METADATA cargo metadata --locked --offline --no-deps --format-version 1
{
  find "${crate_dir}" "${crate_dir}/../joint_backend_matched" \
    "${plan_root}/implementation/src" "${lego_root}" \
    -type f \( -name '*.rs' -o -name '*.py' -o -name 'Cargo.toml' -o -name 'Cargo.lock' -o -name '*.md' -o -name '*.sh' \) \
    -not -path '*/target/*' -not -path '*/__pycache__/*' -print0
  printf '%s\0' \
    "${plan_root}/implementation/Cargo.toml" \
    "${legacy_root}/Cargo.toml" \
    "${legacy_root}/src/protocols/hrada_membership.rs"
} | sort -z | xargs -0 sha256sum > "${output}/SOURCE_SHA256.txt"
sha256sum "${crate_dir}/Cargo.lock" > "${output}/CARGO_LOCK_SHA256.txt"
git -C "${legacy_root}" rev-parse HEAD > "${output}/LEGACY_CP_GIT_REVISION.txt" 2> "${output}/LEGACY_CP_GIT_REVISION.stderr" || true

export RAYON_NUM_THREADS=10
export OMP_NUM_THREADS=1
run_logged CHECK taskset -c 0-9 cargo check --release --locked --offline --all-targets
run_logged TEST taskset -c 0-9 cargo test --release --locked --offline
run_logged BUILD taskset -c 0-9 cargo build --release --locked --offline

# Correctness is a dependency of formal timing. This one-repetition run must
# validate before the twelve-trial process is allowed to start.
run_logged CORRECTNESS_RUN taskset -c 0-9 env \
  E8_AUGMENTED_REPS=1 \
  E8_AUGMENTED_OUTPUT="${output}/correctness/raw" \
  "${crate_dir}/target/release/joint-backend-augmented-cp"
run_logged CORRECTNESS_VALIDATE python3 "${crate_dir}/analyze_e8.py" \
  --mode correctness \
  --input "${output}/correctness/raw/results.json" \
  --artifact-root "${output}/correctness/raw" \
  --source-manifest "${output}/SOURCE_SHA256.txt" \
  --output "${output}/correctness/VALIDATION.json"

run_logged FORMAL_RUN taskset -c 0-9 env \
  E8_AUGMENTED_REPS="${formal_repetitions}" \
  E8_AUGMENTED_OUTPUT="${output}/formal/raw" \
  "${crate_dir}/target/release/joint-backend-augmented-cp"
run_logged FORMAL_ANALYZE python3 "${crate_dir}/analyze_e8.py" \
  --mode formal \
  --input "${output}/formal/raw/results.json" \
  --artifact-root "${output}/formal/raw" \
  --source-manifest "${output}/SOURCE_SHA256.txt" \
  --output "${output}/formal/ANALYSIS.json"

artifact_manifest="${output}/ARTIFACT_SHA256.txt.tmp"
find "${output}" -type f ! -name 'ARTIFACT_SHA256.txt*' -print0 \
  | sort -z | xargs -0 sha256sum > "${artifact_manifest}"
mv "${artifact_manifest}" "${output}/ARTIFACT_SHA256.txt"
printf '%s\n' "${output}"

