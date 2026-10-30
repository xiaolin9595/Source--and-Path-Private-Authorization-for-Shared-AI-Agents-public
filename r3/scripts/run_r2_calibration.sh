#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 7 ]]; then
  echo "usage: run_r2_calibration.sh BINARY DRIVER ANALYZER PROTOCOL SOURCE_MANIFEST GATE_MANIFEST OUTPUT" >&2
  exit 2
fi
binary=$1
driver=$2
analyzer=$3
protocol=$4
source_manifest=$5
gate_manifest=$6
output=$7
[[ ! -e "$output" ]] || { echo "refusing existing output: $output" >&2; exit 2; }
mkdir -p "$output"
exec > >(tee "$output/supervisor.stdout") 2> >(tee "$output/supervisor.stderr" >&2)
export RAYON_NUM_THREADS=10 OMP_NUM_THREADS=1
printf '%s\n' "$$" > "$output/SUPERVISOR.pid"
printf '%q ' "$0" "$@" > "$output/SUPERVISOR.command"
printf '\n' >> "$output/SUPERVISOR.command"

complete=0
telemetry_pid=""
active_pid=""
cleanup() {
  rc=$?
  trap - EXIT INT TERM
  [[ -z "$telemetry_pid" ]] || { kill "$telemetry_pid" 2>/dev/null || true; wait "$telemetry_pid" 2>/dev/null || true; }
  [[ -z "$active_pid" ]] || { kill -- "-$active_pid" 2>/dev/null || true; wait "$active_pid" 2>/dev/null || true; }
  if [[ $complete -ne 1 ]]; then printf 'FAILED rc=%s\n' "$rc" > "$output/FAILED"; fi
  exit "$rc"
}
trap cleanup EXIT INT TERM

frozen="$output/frozen"
mkdir "$frozen"
cp "$binary" "$frozen/r2_loopback"
cp "$driver" "$frozen/run_r2_session.py"
cp "$analyzer" "$frozen/analyze_r2.py"
cp "$protocol" "$frozen/R2_PROTOCOL_FROZEN.md"
cp "$source_manifest" "$frozen/SOURCE_MANIFEST"
cp "$gate_manifest" "$frozen/R2_GATE_MANIFEST.md"
chmod a-w "$frozen"/*
sha256sum "$frozen"/* > "$output/PREFLIGHT_IDENTITIES.sha256"
binary="$frozen/r2_loopback"; driver="$frozen/run_r2_session.py"; analyzer="$frozen/analyze_r2.py"
protocol="$frozen/R2_PROTOCOL_FROZEN.md"
source_manifest_sha=$(sha256sum "$frozen/SOURCE_MANIFEST" | cut -d' ' -f1)
gate_manifest_sha=$(sha256sum "$frozen/R2_GATE_MANIFEST.md" | cut -d' ' -f1)
config_sha=$(sha256sum "$protocol" | cut -d' ' -f1)
implementation_sha=$(sha256sum "$binary" | cut -d' ' -f1)
{
  date -Ins; uname -a; lscpu
  rustc -Vv
  python3 --version
  printf 'RAYON_NUM_THREADS=%s\nOMP_NUM_THREADS=%s\nCPUSET=0-9\n' "$RAYON_NUM_THREADS" "$OMP_NUM_THREADS"
} > "$output/ENVIRONMENT.txt"
(
  while true; do
    printf '{"unix_s":%s,"loadavg":"%s","mem_available_kib":%s}\n' \
      "$(date +%s)" "$(cut -d' ' -f1-3 /proc/loadavg)" \
      "$(awk '/MemAvailable/{print $2}' /proc/meminfo)"
    sleep 60
  done
) > "$output/RESOURCE_TELEMETRY.jsonl" 2> "$output/RESOURCE_TELEMETRY.stderr" &
telemetry_pid=$!

run_owned() {
  setsid "$@" & active_pid=$!
  wait "$active_pid"
  active_pid=""
}

for session in 1 2; do
  setup="$output/setup$(printf '%02d' "$session")"
  run_owned taskset -c 0-9 "$binary" setup "$setup" > "$output/setup$(printf '%02d' "$session").jsonl"
  for key in "$setup/pk.compressed" "$setup/vk.compressed"; do
    key_sha=$(sha256sum "$key" | cut -d' ' -f1)
    if [[ -n ${R2_USED_KEY_HASHES_FILE:-} ]] && grep -qx "$key_sha" "$R2_USED_KEY_HASHES_FILE"; then
      echo "refusing reused setup key $key_sha" >&2; exit 1
    fi
    [[ -z ${R2_USED_KEY_HASHES_FILE:-} ]] || printf '%s\n' "$key_sha" >> "$R2_USED_KEY_HASHES_FILE"
  done
  setup_id="r2-calibration-$(printf '%02d' "$session")-$(sha256sum "$setup/pk.compressed" | cut -c1-16)"
  run_owned python3 "$driver" \
    --phase calibration --session "$session" --binary "$binary" \
    --pk "$setup/pk.compressed" --vk "$setup/vk.compressed" \
    --output "$output/session$(printf '%02d' "$session")" --setup-id "$setup_id" \
    --config-sha256 "$config_sha" --gate-manifest-sha256 "$gate_manifest_sha" \
    --source-manifest-sha256 "$source_manifest_sha" --tpad-ms 0
  session_dir="$output/session$(printf '%02d' "$session")"
  [[ -f "$session_dir/COMPLETE" ]]
  [[ $(wc -l < "$session_dir/records.jsonl") -eq 300 ]]
  [[ $(wc -l < "$session_dir/gates.jsonl") -eq 9 ]]
  if find "$session_dir" -name '*.stderr' -type f -size +0 | grep -q .; then
    echo "nonempty session stderr" >&2; exit 1
  fi
done

cat "$output/session01/records.jsonl" "$output/session02/records.jsonl" > "$output/calibration_joined.jsonl"
cat > "$output/analysis_input_manifest.json" <<EOF
{"schema":"r2-analysis-input-manifest-v1","provenance":"measured","source_kind":"r2_loopback","phases":{"calibration":{"source_manifest_sha256":"$source_manifest_sha","gate_manifest_sha256":"$gate_manifest_sha"}}}
EOF
run_owned python3 "$analyzer" --validation-manifest "$output/analysis_input_manifest.json" \
  --calibration "$output/calibration_joined.jsonl" --output "$output/calibration_result.json"
sha256sum "$binary" "$driver" "$analyzer" "$protocol" "$output"/setup*/{pk,vk}.compressed \
  "$output"/session*/schedule.json "$output/calibration_joined.jsonl" > "$output/FROZEN_IDENTITIES.sha256"
printf 'COMPLETE implementation_sha256=%s config_sha256=%s\n' "$implementation_sha" "$config_sha" > "$output/COMPLETE"
complete=1
