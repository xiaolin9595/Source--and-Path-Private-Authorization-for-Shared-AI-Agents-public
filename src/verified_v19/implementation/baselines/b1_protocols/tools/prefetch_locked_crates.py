#!/usr/bin/env python3
"""Fill a Cargo registry cache from an already resolved lockfile with checksums."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any


def parse_lock(path: Path) -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {}
        elif current is not None and " = " in line:
            key, raw_value = line.split(" = ", 1)
            if key in {"name", "version", "source", "checksum"}:
                current[key] = json.loads(raw_value)
    if current is not None:
        packages.append(current)
    return [
        package
        for package in packages
        if package.get("source", "").startswith("registry+")
        and "checksum" in package
    ]


def fetch(url: str, destination: Path, attempts: int) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "plan-a-artifact/1"})
            with urllib.request.urlopen(request, timeout=90) as response:
                with destination.open("wb") as output:
                    shutil.copyfileobj(response, output)
            return
        except Exception as error:
            last_error = error
            if destination.exists():
                destination.unlink()
            if attempt != attempts:
                time.sleep(min(2**attempt, 20))
    raise SystemExit(f"download failed after {attempts} attempts for {url}: {last_error}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path)
    parser.add_argument("--provenance-out", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=8)
    args = parser.parse_args()
    packages = parse_lock(args.lock)
    if not packages:
        raise SystemExit("lockfile has no checksum-bearing registry packages")
    cache_dirs = sorted(path for path in args.cache_root.glob("*") if path.is_dir())
    destination_dir = args.cache_dir
    if destination_dir is None:
        official = [path for path in cache_dirs if path.name.startswith("index.crates.io-")]
        if not official:
            raise SystemExit("no official index.crates.io cache dir; pass --cache-dir")
        destination_dir = official[0]
    destination_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    for package in packages:
        name = package["name"]
        version = package["version"]
        checksum = package["checksum"]
        filename = f"{name}-{version}.crate"
        destination = destination_dir / filename
        candidates = [
            path / filename
            for path in cache_dirs
            if path != destination_dir and (path / filename).exists()
        ]
        cache_source: str | None = None
        if destination.exists():
            actual = digest(destination)
            if actual != checksum:
                raise SystemExit(
                    f"destination cache checksum mismatch for {destination}: {actual}"
                )
            status = "cached-in-destination"
            transport_origin = "preexisting-cache-unknown; checksum matches lock"
        elif candidates:
            source = candidates[0]
            actual = digest(source)
            if actual != checksum:
                raise SystemExit(f"cached checksum mismatch for {source}: {actual}")
            shutil.copyfile(source, destination)
            if digest(destination) != checksum:
                raise SystemExit(f"copied cache checksum mismatch for {destination}")
            status = "copied-from-verified-cache"
            transport_origin = "preexisting-cache-unknown; checksum matches lock"
            cache_source = str(source)
        else:
            quoted_name = urllib.parse.quote(name, safe="")
            url = f"https://static.crates.io/crates/{quoted_name}/{filename}"
            with tempfile.TemporaryDirectory(dir=destination_dir) as temporary:
                partial = Path(temporary) / filename
                fetch(url, partial, args.attempts)
                actual = digest(partial)
                if actual != checksum:
                    raise SystemExit(f"download checksum mismatch for {filename}: {actual}")
                shutil.move(partial, destination)
            status = "downloaded"
            transport_origin = "https://static.crates.io"
        rows.append(
            {
                "name": name,
                "version": version,
                "source": package["source"],
                "url": f"https://static.crates.io/crates/{urllib.parse.quote(name, safe='')}/{filename}",
                "checksum": checksum,
                "path": str(destination),
                "status": status,
                "transport_origin": transport_origin,
                "cache_source": cache_source,
                "bytes": destination.stat().st_size,
            }
        )
    args.provenance_out.parent.mkdir(parents=True, exist_ok=True)
    args.provenance_out.write_text(
        json.dumps(
            {
                "schema": "plan-a-locked-crate-cache-v1",
                "lock_path": str(args.lock),
                "lock_sha256": digest(args.lock),
                "new_downloads_official_static_only": True,
                "packages": rows,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
