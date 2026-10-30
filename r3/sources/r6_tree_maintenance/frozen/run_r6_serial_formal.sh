#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 11 ]]; then
  echo "usage: $0 RUN_ROOT ADAPTER SERVICE_CORE MUTATION_CLI RUNNER ANALYZER DESIGN ADAPTER_SOURCE ADAPTER_LOCK SERVICE_PY PILOT_RESULT" >&2
  exit 64
fi

run=$1; adapter=$2; service_core=$3; mutation_cli=$4; runner=$5
analyzer=$6; design=$7; adapter_source=$8; adapter_lock=$9; service_py=${10}; pilot_result=${11}
[[ ! -e "$run" ]] || { echo "refusing existing run root: $run" >&2; exit 64; }
for executable in "$adapter" "$service_core" "$mutation_cli"; do
  [[ -x "$executable" ]] || { echo "missing executable: $executable" >&2; exit 64; }
done
for source in "$runner" "$analyzer" "$adapter_source" "$adapter_lock" "$service_py" "$pilot_result" \
  "$(dirname "$runner")/r6_schedule.py"; do
  [[ -f "$source" ]] || { echo "missing source: $source" >&2; exit 64; }
done

# Preserve the authorized attempt01 failure mode: a missing protocol is an
# environment/preflight failure before any trial START_MANIFEST or sample.
if [[ ! -f "$design" ]]; then
  mkdir -p "$run"
  printf '%s\n' "$$" > "$run/SUPERVISOR.pid"
  printf '%q ' "$0" "$@" > "$run/SUPERVISOR.command"; printf '\n' >> "$run/SUPERVISOR.command"
  sha256sum "$adapter" "$service_core" "$mutation_cli" "$runner" "$analyzer" \
    "$adapter_source" "$adapter_lock" "$service_py" "$pilot_result" \
    "$(dirname "$runner")/r6_schedule.py" "$0" \
    > "$run/ATTEMPT01_SCIENTIFIC_SHA256SUMS"
  cat > "$run/PREFLIGHT_FAILURE.json" <<EOF
{"schema":"r6-preflight-failure-v1","reason":"missing-R6_MEASUREMENT_DESIGN.md","design_path":"$design","start_manifest_written":false,"samples_started":0,"scientific_source_changed":false}
EOF
  printf 'FAILED rc=66 phase=preflight missing=R6_MEASUREMENT_DESIGN.md samples=0\n' > "$run/FAILED"
  date -u +%Y-%m-%dT%H:%M:%SZ > "$run/failed_at.txt"
  exit 66
fi

for tool in python3 taskset timeout setsid sha256sum lscpu; do command -v "$tool" >/dev/null; done
[[ -x /usr/bin/time ]]

mkdir -p "$run/frozen/bin" "$run/frozen/r6_preparation/adapter/src" \
  "$run/frozen/blind_update_impl/service" "$run/frozen/pilot_evidence" \
  "$run/formal/depth16" "$run/formal/depth20"
exec > >(tee "$run/supervisor.stdout") 2> >(tee "$run/supervisor.stderr" >&2)

cp "$adapter" "$run/frozen/bin/r6-tree-adapter"
cp "$service_core" "$run/frozen/bin/plan_a_service_core"
cp "$mutation_cli" "$run/frozen/bin/plan_a_mutation_cli"
cp "$runner" "$run/frozen/r6_preparation/run_trial.py"
cp "$analyzer" "$run/frozen/r6_preparation/analyze_r6.py"
cp "$(dirname "$runner")/r6_schedule.py" "$run/frozen/r6_preparation/r6_schedule.py"
cp "$design" "$run/frozen/R6_MEASUREMENT_DESIGN.md"
cp "$adapter_source" "$run/frozen/r6_preparation/adapter/src/main.rs"
cp "$adapter_lock" "$run/frozen/r6_preparation/adapter/Cargo.lock"
cp "$service_py" "$run/frozen/blind_update_impl/service/service.py"
cp "$pilot_result" "$run/frozen/pilot_evidence/RESULT.json"
cp "$0" "$run/frozen/r6_preparation/run_r6_serial_formal.sh"
find "$run/frozen" -type f -exec chmod 0444 {} +
chmod 0555 "$run/frozen/bin/"*

adapter="$run/frozen/bin/r6-tree-adapter"
service_core="$run/frozen/bin/plan_a_service_core"
mutation_cli="$run/frozen/bin/plan_a_mutation_cli"
runner="$run/frozen/r6_preparation/run_trial.py"
analyzer="$run/frozen/r6_preparation/analyze_r6.py"
schedule="$run/frozen/r6_preparation/r6_schedule.py"
adapter_source="$run/frozen/r6_preparation/adapter/src/main.rs"
adapter_lock="$run/frozen/r6_preparation/adapter/Cargo.lock"
pilot_result="$run/frozen/pilot_evidence/RESULT.json"

python3 - "$pilot_result" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x['schema']=='r6-full-reconstruction-trial-v2' and x['valid'] is True
assert x['depth']==16 and x['population']==65536 and x['seed']==2026103099
assert all(value is True for value in x['correctness'].values())
PY
sha256sum "$pilot_result" > "$run/PILOT_EVIDENCE.sha256"

find "$run/frozen" -type f -print0 | sort -z | xargs -0 sha256sum > "$run/FROZEN_SHA256SUMS"
printf '%s\n' "$$" > "$run/SUPERVISOR.pid"
printf '%q ' "$0" "$@" > "$run/SUPERVISOR.command"; printf '\n' >> "$run/SUPERVISOR.command"
date --iso-8601=seconds > "$run/started_at.txt"

export RAYON_NUM_THREADS=10 OMP_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1
export LC_ALL=${LC_ALL:-C.UTF-8}
{
  printf 'PATH=%s\n' "$PATH"
  printf 'PYTHON3=%s\n' "$(command -v python3)"
  printf 'TASKSET=%s\n' "$(command -v taskset)"
  printf 'TIMEOUT=%s\n' "$(command -v timeout)"
  printf 'SETSID=%s\n' "$(command -v setsid)"
  printf 'RAYON_NUM_THREADS=%s\n' "$RAYON_NUM_THREADS"
  printf 'OMP_NUM_THREADS=%s\n' "$OMP_NUM_THREADS"
  printf 'PYTHONDONTWRITEBYTECODE=%s\n' "$PYTHONDONTWRITEBYTECODE"
  printf 'LANG=%s\n' "${LANG:-}"
  printf 'LC_ALL=%s\n' "${LC_ALL:-}"
  printf 'TZ=%s\n' "${TZ:-}"
  python3 --version 2>&1
  uname -a
} > "$run/ENVIRONMENT_ALLOWLIST.txt"
lscpu > "$run/lscpu.txt"
taskset -pc 0-9 $$ > "$run/affinity.txt"
python3 "$schedule" > "$run/SCHEDULE.tsv"

complete=0
telemetry_pid=""
active_pid=""
current_cell="none"
cleanup() {
  rc=$?
  trap - EXIT INT TERM
  if [[ -n "$telemetry_pid" ]]; then kill "$telemetry_pid" 2>/dev/null || true; wait "$telemetry_pid" 2>/dev/null || true; fi
  if [[ -n "$active_pid" ]]; then kill -- "-$active_pid" 2>/dev/null || true; wait "$active_pid" 2>/dev/null || true; fi
  if [[ $complete -ne 1 ]]; then
    printf 'FAILED rc=%s cell=%s\n' "$rc" "$current_cell" > "$run/FAILED"
    date --iso-8601=seconds > "$run/failed_at.txt"
  fi
  exit "$rc"
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
) > "$run/RESOURCE_TELEMETRY.jsonl" 2> "$run/RESOURCE_TELEMETRY.stderr" &
telemetry_pid=$!

validate_trial() {
  python3 - "$1" "$2" "$3" <<'PY'
import json,sys
directory,depth,seed=sys.argv[1],int(sys.argv[2]),int(sys.argv[3])
result=json.load(open(directory+'/RESULT.json'))
manifest=json.load(open(directory+'/START_MANIFEST.json'))
assert result['schema']=='r6-full-reconstruction-trial-v2' and result['valid'] is True
assert result['depth']==depth and result['population']==1<<depth and result['seed']==seed
assert manifest['depth']==depth and manifest['seed']==seed
assert set(manifest['formal_seeds'])==set(range(2026103001,2026103006))
assert all(value is True for value in result['correctness'].values())
assert not __import__('os').path.exists(directory+'/FAILURE.json')
events=[json.loads(line)['event'] for line in open(directory+'/EVENTS.jsonl') if line.strip()]
assert events[-1]=='trial_complete'
PY
}

run_cell() {
  local phase=$1 depth=$2 seed=$3 parent cell rc
  [[ "$phase" == formal ]] || { echo "non-formal cell in frozen schedule" >&2; return 64; }
  parent="$run/formal/depth$depth"
  cell="$parent/seed_$seed"
  [[ ! -e "$cell" ]] || { echo "refusing existing cell: $cell" >&2; return 64; }
  mkdir -p "$cell"
  current_cell="$phase-depth$depth-seed$seed"
  setsid /usr/bin/time -v -o "$cell/trial.time" \
    timeout --signal=TERM --kill-after=30 1800 \
    taskset -c 0-9 python3 "$runner" --depth "$depth" --seed "$seed" \
      --output "$cell/output" --adapter "$adapter" --service-core "$service_core" \
      --mutation-cli "$mutation_cli" --adapter-source "$adapter_source" \
      --adapter-lock "$adapter_lock" --timeout 1800 \
      > "$cell/trial.stdout" 2> "$cell/trial.stderr" &
  active_pid=$!
  set +e; wait "$active_pid"; rc=$?; set -e
  active_pid=""
  if [[ $rc -ne 0 ]]; then
    printf 'FAILED rc=%s\n' "$rc" > "$cell/FAILED"
    return "$rc"
  fi
  if ! validate_trial "$cell/output" "$depth" "$seed"; then
    printf 'FAILED rc=1 validation=trial-output\n' > "$cell/FAILED"
    return 1
  fi
  sha256sum "$cell/output/START_MANIFEST.json" "$cell/output/EVENTS.jsonl" \
    "$cell/output/RESULT.json" > "$cell/RESULT_SHA256SUMS"
  date --iso-8601=seconds > "$cell/completed_at.txt"
  printf 'COMPLETE\n' > "$cell/COMPLETE"
}

while IFS=$'\t' read -r phase depth seed; do
  run_cell "$phase" "$depth" "$seed"
done < "$run/SCHEDULE.tsv"

mapfile -t formal_results < <(find "$run/formal" -mindepth 4 -maxdepth 4 -type f -path '*/output/RESULT.json' | sort)
[[ ${#formal_results[@]} -eq 10 ]]
setsid timeout --signal=TERM --kill-after=10 300 \
  taskset -c 0-9 python3 "$analyzer" --results "${formal_results[@]}" --output "$run/ANALYSIS.json" \
  > "$run/analyzer.stdout" 2> "$run/analyzer.stderr" &
active_pid=$!
set +e; wait "$active_pid"; rc=$?; set -e
active_pid=""
[[ $rc -eq 0 ]]
python3 - "$run/ANALYSIS.json" <<'PY'
import json,sys
x=json.load(open(sys.argv[1]))
assert x['schema']=='r6-full-reconstruction-analysis-v1' and x['valid'] is True
assert set(x['populations'])=={'65536','1048576'}
assert all(x['populations'][key]['trial_count']==5 for key in x['populations'])
PY
find "$run/formal" -type f \( -name RESULT.json -o -name START_MANIFEST.json -o -name EVENTS.jsonl \) \
  -print0 | sort -z | xargs -0 sha256sum > "$run/FORMAL_DATA_SHA256SUMS"
sha256sum "$run/ANALYSIS.json" "$run/SCHEDULE.tsv" "$run/FROZEN_SHA256SUMS" > "$run/FINAL_SHA256SUMS"
date --iso-8601=seconds > "$run/completed_at.txt"
printf 'COMPLETE pilot=evidence-only formal_depth16=5 formal_depth20=5\n' > "$run/COMPLETE"
complete=1

