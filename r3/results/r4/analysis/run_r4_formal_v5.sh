#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 RUN_ROOT BLIND_BINARY JOINT_BINARY FREEZE_MANIFEST" >&2
  exit 64
fi
run=$1
blind_bin=$2
joint_bin=$3
freeze_manifest=$4
test ! -e "$run"
test -x "$blind_bin"; test -x "$joint_bin"; test -f "$freeze_manifest"
mkdir -p "$run/frozen" "$run/blind" "$run/joint"

printf '%s\n' "$$" > "$run/supervisor.pid"
printf '%q ' "$0" "$@" > "$run/command.txt"; printf '\n' >> "$run/command.txt"
cp "$freeze_manifest" "$run/frozen/SOURCE_DEPENDENCY_SHA256SUMS"
cp "$0" "$run/frozen/run_r4_formal_v5.sh"
sha256sum "$blind_bin" "$joint_bin" "$freeze_manifest" "$0" > "$run/FROZEN_SHA256SUMS"
sha256sum -c "$freeze_manifest" > "$run/frozen/manifest_verify.stdout"
cp "$blind_bin" "$run/frozen/r4_checked_blind"
cp "$joint_bin" "$run/frozen/r4_checked_joint"
chmod 0555 "$run/frozen/r4_checked_blind" "$run/frozen/r4_checked_joint"
blind_bin="$run/frozen/r4_checked_blind"
joint_bin="$run/frozen/r4_checked_joint"
date --iso-8601=seconds > "$run/started_at.txt"
export RAYON_NUM_THREADS=10 OMP_NUM_THREADS=1
{
  printf 'PATH=%s\n' "$PATH"
  printf 'RUSTC=%s\n' "${RUSTC:-$(command -v rustc || true)}"
  printf 'CARGO_HOME=%s\n' "${CARGO_HOME:-}"
  printf 'CARGO=%s\n' "$(command -v cargo || true)"
  printf 'PYTHON3=%s\n' "$(command -v python3)"
  printf 'RAYON_NUM_THREADS=%s\n' "$RAYON_NUM_THREADS"
  printf 'OMP_NUM_THREADS=%s\n' "$OMP_NUM_THREADS"
  printf 'LANG=%s\n' "${LANG:-}"
  printf 'LC_ALL=%s\n' "${LC_ALL:-}"
  printf 'TZ=%s\n' "${TZ:-}"
  rustc -Vv 2>/dev/null || true
  cargo -V 2>/dev/null || true
  python3 --version 2>&1
  uname -a
} > "$run/environment.txt"
lscpu > "$run/lscpu.txt"
taskset -pc $$ > "$run/affinity.txt"

telemetry_pid=
cleanup() {
  code=$?
  if [[ -n "${telemetry_pid:-}" ]]; then kill "$telemetry_pid" 2>/dev/null || true; wait "$telemetry_pid" 2>/dev/null || true; fi
  jobs -pr | xargs -r kill 2>/dev/null || true
  if (( code != 0 )); then
    printf 'FAIL %s relation=%s index=%s\n' "$code" "${current_relation:-none}" "${current_index:-0}" > "$run/FAILED"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
(
  while :; do
    printf '{"timestamp":"%s","loadavg":"%s","mem_available_kib":%s}\n' \
      "$(date --iso-8601=seconds)" "$(cut -d' ' -f1-3 /proc/loadavg)" \
      "$(awk '/MemAvailable:/{print $2}' /proc/meminfo)"
    sleep 60
  done
) > "$run/telemetry.jsonl" & telemetry_pid=$!

validate_setup() {
  python3 - "$1" "$2" "$3" <<'PY'
import json,sys
x=json.load(open(sys.argv[1])); relation=sys.argv[2]; expected=int(sys.argv[3])
assert x["event"]=="setup" and x["constraints"]==expected
assert x["domain"]==(16384 if relation=="blind" else 262144)
assert x["instances"]==(15 if relation=="blind" else 24)
assert x["witnesses"]==(8567 if relation=="blind" else 172232)
assert all(len(x[k])==64 for k in ("pk_sha256","vk_sha256","material_sha256"))
PY
}

validate_checked() {
  python3 - "$1" <<'PY'
import json,sys
rows=[json.loads(line) for line in open(sys.argv[1]) if line.strip()]
x=rows[-1]
assert x["event"]=="gate" and x["verified"] is True
assert x["failed_bundle_rejected"] is True and len(x["receipt"])==64
assert x["full_load_ns"]>=x["file_read_ns"]
for value in [x["full_load_ns"],x["prove_ns"],x["verify_ns"],*x["metrics"].values()]:
    assert isinstance(value,int) and value>=0
PY
}

validate_ordinary() {
  python3 - "$1" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x["event"]=="ordinary_load"
assert x["canonical_exact"] is True and x["embedded_vk_equal"] is True
for key in ("file_read_ns","pk_decode_ns","vk_decode_ns","prepare_vk_ns","full_load_ns"):
    assert isinstance(x[key],int) and x[key]>=0
PY
}

run_mode() {
  local binary=$1 mode=$2 bundle=$3 prefix=$4
  /usr/bin/time -v -o "${prefix}.time" timeout 1800 taskset -c 0-9 "$binary" "$mode" "$bundle" \
    > "${prefix}.jsonl" 2> "${prefix}.stderr"
  test ! -s "${prefix}.stderr"
  if [[ "$mode" == gate ]]; then validate_checked "${prefix}.jsonl"; else validate_ordinary "${prefix}.jsonl"; fi
}

run_relation() {
  local relation=$1 binary=$2 constraints=$3
  for index in 1 2 3 4 5; do
    current_relation=$relation; current_index=$index
    local cell="$run/$relation/setup_$(printf '%02d' "$index")"
    local bundle="$cell/bundle"
    mkdir -p "$cell"
    /usr/bin/time -v -o "$cell/setup.time" timeout 1800 taskset -c 0-9 "$binary" setup "$bundle" \
      > "$cell/setup.jsonl" 2> "$cell/setup.stderr"
    test ! -s "$cell/setup.stderr"
    validate_setup "$cell/setup.jsonl" "$relation" "$constraints"
    sha256sum "$bundle/pk.bin" "$bundle/vk.bin" "$bundle/checking.bin" > "$cell/BUNDLE_SHA256SUMS"
    if (( index % 2 == 1 )); then
      printf 'checked,ordinary\n' > "$cell/order.txt"
      run_mode "$binary" gate "$bundle" "$cell/checked"
      run_mode "$binary" ordinary "$bundle" "$cell/ordinary"
    else
      printf 'ordinary,checked\n' > "$cell/order.txt"
      run_mode "$binary" ordinary "$bundle" "$cell/ordinary"
      run_mode "$binary" gate "$bundle" "$cell/checked"
    fi
    date --iso-8601=seconds > "$cell/completed_at.txt"
    printf 'PASS\n' > "$cell/COMPLETE"
  done
}

run_relation blind "$blind_bin" 11427
run_relation joint "$joint_bin" 187556
date --iso-8601=seconds > "$run/completed_at.txt"
printf 'PASS\n' > "$run/COMPLETE"
