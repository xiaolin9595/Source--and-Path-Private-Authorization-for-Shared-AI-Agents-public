#!/usr/bin/env python3
"""Transparent stdio proxy that preserves exact newline-delimited MCP wire bytes."""
from __future__ import annotations

import os
import subprocess
import sys
import threading
from pathlib import Path


def pump(source, destination, log_path: Path, close_destination: bool) -> None:
    with log_path.open("wb") as log:
        for line in iter(source.readline, b""):
            log.write(line)
            log.flush()
            destination.write(line)
            destination.flush()
    if close_destination:
        destination.close()


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: wire_proxy.py SERVER.py")
    prefix_value = os.environ.get("PLAN_A_MCP_WIRE_LOG_PREFIX")
    if not prefix_value:
        raise SystemExit("PLAN_A_MCP_WIRE_LOG_PREFIX is required")
    prefix = Path(prefix_value)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    child = subprocess.Popen(
        [sys.executable, sys.argv[1]],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        env=os.environ,
    )
    assert child.stdin is not None and child.stdout is not None
    upstream = threading.Thread(
        target=pump,
        args=(
            sys.stdin.buffer,
            child.stdin,
            Path(f"{prefix}.client-to-server.jsonl"),
            True,
        ),
    )
    downstream = threading.Thread(
        target=pump,
        args=(
            child.stdout,
            sys.stdout.buffer,
            Path(f"{prefix}.server-to-client.jsonl"),
            False,
        ),
    )
    upstream.start()
    downstream.start()
    upstream.join()
    downstream.join()
    raise SystemExit(child.wait())


if __name__ == "__main__":
    main()
