#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 OUTPUT_DIRECTORY" >&2
  exit 2
fi
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
venv=${E3_FIGURE_VENV:-$root/.venv-e3-figure}
if [[ ! -x "$venv/bin/python" ]]; then
  python3 -m venv "$venv"
  "$venv/bin/python" -m pip install --disable-pip-version-check \
    --requirement "$root/requirements-e3-figure.txt"
fi
"$venv/bin/python" - "$root/requirements-e3-figure.txt" <<'PY'
from importlib.metadata import version
from pathlib import Path
import sys
for line in Path(sys.argv[1]).read_text().splitlines():
    if not line or line.startswith("#"):
        continue
    name, expected = line.split("==", 1)
    actual = version(name)
    if actual != expected:
        raise SystemExit(f"dependency mismatch: {name} {actual} != {expected}")
PY
exec "$venv/bin/python" "$root/sources/e3_analysis/render_e3_figure.py" \
  "$root/results/e3/aggregate/fixed_cohort_summary.csv" --output "$1"
