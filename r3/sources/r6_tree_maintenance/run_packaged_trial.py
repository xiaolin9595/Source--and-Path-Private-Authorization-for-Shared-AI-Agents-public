#!/usr/bin/env python3
"""Package-relative entry point for the frozen R6 trial implementation.

The frozen runner is preserved verbatim in ``frozen/run_trial.py``.  This
wrapper changes only its repository-layout bindings before invoking its CLI.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
source = (HERE / "frozen" / "run_trial.py").read_text(encoding="utf-8")
source = source.replace(
    'ROOT = Path(__file__).resolve().parents[1]\nSERVICE_DIR = ROOT / "blind_update_impl" / "service"',
    f'ROOT = Path({str(HERE)!r})\nSERVICE_DIR = ROOT / "service"',
    1,
)
if f'ROOT = Path({str(HERE)!r})' not in source:
    raise SystemExit("frozen runner layout marker not found")
exec(compile(source, str(HERE / "frozen" / "run_trial.py"), "exec"),
     {"__name__": "__main__", "__file__": str(HERE / "frozen" / "run_trial.py")})
