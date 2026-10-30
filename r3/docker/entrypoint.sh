#!/usr/bin/env bash
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case "${1:-recompute}" in
  smoke)
    exec "$root/scripts/smoke.sh"
    ;;
  recompute)
    exec python3 "$root/scripts/recompute_existing.py"
    ;;
  shell)
    shift
    exec bash "$@"
    ;;
  *)
    exec "$root/scripts/run_full.sh" "$@"
    ;;
esac
