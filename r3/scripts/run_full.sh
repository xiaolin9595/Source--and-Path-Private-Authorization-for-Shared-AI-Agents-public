#!/usr/bin/env bash
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mode=${1:-}
test -n "$mode" || { echo "usage: $0 {e1|r2|r2-complete|e2|r4} DRIVER_ARGUMENTS..." >&2; exit 2; }
shift

case "$mode" in
  e1)
    exec python3 "$root/results/e1/analysis/run_session.py" "$@"
    ;;
  r2)
    exec python3 "$root/results/r2/analysis/run_r2_session.py" "$@"
    ;;
  r2-complete)
    exec "$root/scripts/run_r2_complete.sh" "$@"
    ;;
  e2)
    exec python3 "$root/results/r3_e2/analysis/run_e2.py" "$@"
    ;;
  r4)
    exec "$root/sources/r4_service/run_r4_formal_v5.sh" "$@"
    ;;
  *)
    echo "unknown mode: $mode" >&2
    exit 2
    ;;
esac
