#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || (${2:-} != "" && ${2:-} != "--control-test") ]]; then
  echo "usage: $0 NEW_OUTPUT_DIRECTORY [--control-test]" >&2
  exit 2
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output=$1
control_test=0
[[ ${2:-} != "--control-test" ]] || control_test=1
[[ ! -e "$output" ]] || { echo "refusing existing output: $output" >&2; exit 2; }
command -v taskset >/dev/null || { echo "complete R2 rerun requires Linux taskset" >&2; exit 1; }
command -v sha256sum >/dev/null || { echo "complete R2 rerun requires sha256sum" >&2; exit 1; }
mkdir -p "$output"
output=$(CDPATH= cd -- "$output" && pwd)

export RAYON_NUM_THREADS=10 OMP_NUM_THREADS=1
manifest="$root/sources/r2_presentation/Cargo.toml"
cargo build --locked --release --manifest-path "$manifest" --bin r2_loopback
target_dir=${CARGO_TARGET_DIR:-$root/sources/r2_presentation/target}
binary="$target_dir/release/r2_loopback"
driver="$root/results/r2/analysis/run_r2_session.py"
analyzer="$root/results/r2/analysis/analyze_r2.py"
protocol="$root/results/r2/R2_PROTOCOL_FROZEN.md"
source_manifest="$root/results/r2/R2_SOURCE_MANIFEST.md"
gate_manifest="$root/results/r2/R2_GATE_MANIFEST.md"

python3 - "$root" "$output/RUN_MANIFEST.json" <<'PY'
import hashlib,json,platform,sys
from pathlib import Path
root=Path(sys.argv[1]); out=Path(sys.argv[2])
names=["FILELIST.sha256","sources/r2_presentation/Cargo.lock",
       "results/r2/R2_PROTOCOL_FROZEN.md","results/r2/R2_SOURCE_MANIFEST.md",
       "results/r2/R2_GATE_MANIFEST.md","results/r2/analysis/run_r2_session.py",
       "results/r2/analysis/analyze_r2.py"]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
value={"schema":"r2-anonymous-package-run-v1","package_files":{n:sha(root/n) for n in names},
       "python":platform.python_version(),"note":"identities are hashes of the sanitized anonymous package, not byte-identity claims for private-path manifests"}
out.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
PY

# Refuse collision with every E1 original/dummy setup identity recovered in the
# packaged raw headers, then let the frozen supervisors append all new R2 keys.
used="$output/USED_KEY_HASHES.txt"
python3 - "$root/results/e1/raw" "$used" <<'PY'
import json,sys
from pathlib import Path
values=set()
for path in sorted(Path(sys.argv[1]).glob("session*/records.jsonl")):
    header=json.loads(path.open().readline())
    for name in ("setup_o","setup_a"):
        values.add(header[name]["pk_sha256"]); values.add(header[name]["vk_sha256"])
assert len(values)==16
Path(sys.argv[2]).write_text("".join(x+"\n" for x in sorted(values)))
PY
export R2_USED_KEY_HASHES_FILE="$used"

if [[ $control_test -eq 1 ]]; then
  setup="$output/control-setup"
  taskset -c 0-9 "$binary" setup "$setup" > "$output/control-setup.jsonl"
  pk_sha=$(sha256sum "$setup/pk.compressed" | cut -d' ' -f1)
  vk_sha=$(sha256sum "$setup/vk.compressed" | cut -d' ' -f1)
  ! grep -qx "$pk_sha" "$used"
  ! grep -qx "$vk_sha" "$used"
  printf '%s\n%s\n' "$pk_sha" "$vk_sha" >> "$used"
  config_sha=$(sha256sum "$protocol" | cut -d' ' -f1)
  gate_sha=$(sha256sum "$gate_manifest" | cut -d' ' -f1)
  source_sha=$(sha256sum "$source_manifest" | cut -d' ' -f1)
  python3 "$driver" --phase calibration --session 1 --binary "$binary" \
    --pk "$setup/pk.compressed" --vk "$setup/vk.compressed" \
    --output "$output/control-session" --setup-id "r2-control-${pk_sha:0:16}" \
    --config-sha256 "$config_sha" --gate-manifest-sha256 "$gate_sha" \
    --source-manifest-sha256 "$source_sha" --tpad-ms 0 --gate-rows 3
  [[ -f "$output/control-session/COMPLETE" ]]
  [[ $(wc -l < "$output/control-session/gates.jsonl") -eq 9 ]]
  [[ $(wc -l < "$output/control-session/records.jsonl") -eq 3 ]]
  python3 - "$output" "$pk_sha" "$vk_sha" "$config_sha" "$gate_sha" "$source_sha" <<'PY'
import json,sys
from pathlib import Path
out=Path(sys.argv[1])
value={"schema":"r2-control-test-v1","status":"PASS","fresh_setup":True,
       "e1_key_identities_checked":16,"gate_rows":9,"measurement_rows":3,
       "pk_sha256":sys.argv[2],"vk_sha256":sys.argv[3],
       "config_sha256":sys.argv[4],"gate_manifest_sha256":sys.argv[5],
       "source_manifest_sha256":sys.argv[6]}
(out/"CONTROL_TEST.json").write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
PY
  printf 'CONTROL_TEST_PASS gate_rows=9 measurement_rows=3\n' > "$output/COMPLETE"
  exit 0
fi

"$root/scripts/run_r2_calibration.sh" "$binary" "$driver" "$analyzer" \
  "$protocol" "$source_manifest" "$gate_manifest" "$output/calibration"
[[ -f "$output/calibration/COMPLETE" ]]
[[ $(wc -l < "$output/calibration/calibration_joined.jsonl") -eq 600 ]]

"$root/scripts/run_r2_formal.sh" "$binary" "$driver" "$analyzer" "$protocol" \
  "$output/calibration/calibration_joined.jsonl" \
  "$output/calibration/calibration_result.json" "$source_manifest" \
  "$gate_manifest" "$output/formal"
[[ -f "$output/formal/COMPLETE" ]]
[[ $(wc -l < "$output/formal/formal_joined.jsonl") -eq 4500 ]]
[[ $(sort -u "$used" | wc -l) -eq 28 ]]
sha256sum "$output/RUN_MANIFEST.json" "$output/calibration/calibration_result.json" \
  "$output/formal/ANALYSIS.json" "$used" > "$output/FINAL_IDENTITIES.sha256"
printf 'COMPLETE calibration_rows=600 formal_rows=4500\n' > "$output/COMPLETE"
