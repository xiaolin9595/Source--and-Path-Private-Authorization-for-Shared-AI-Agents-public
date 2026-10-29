#!/usr/bin/env python3
"""Fetch the pinned Poseidon authors' repository once and create an offline bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

REMOTE = "https://extgit.iaik.tugraz.at/krypto/hadeshash.git"
COMMIT = "9d80ec0473ad7cde5a12f3aac46439ad0da68c0a"
SCRIPT = Path("code/scripts/calc_round_numbers.py")
ARCHIVE_URL = (
    "https://extgit.iaik.tugraz.at/krypto/hadeshash/-/archive/"
    f"{COMMIT}/hadeshash-{COMMIT}.tar.gz"
)
RAW_SCRIPT_URL = (
    "https://extgit.iaik.tugraz.at/krypto/hadeshash/-/raw/"
    f"{COMMIT}/{SCRIPT}"
)
ARCHIVE_SHA256 = "e27359cc8bf5c38cd74776ab995b793a86fdeafe7c88aca7653041b9a1eaeac4"
SCRIPT_SHA256 = "b850ecf8d403c3ac3fced726deff540574ec3ca713f1f19cad55beff4ea1d094"


def run(command: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True)
    if check and result.returncode != 0:
        raise SystemExit(
            f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr}"
        )
    return result


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def extract_official_archive(archive: Path, output: Path) -> Path:
    expected_root = f"hadeshash-{COMMIT}"
    output_resolved = output.resolve()
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise SystemExit("official archive is empty")
        for member in members:
            parts = Path(member.name).parts
            if not parts or parts[0] != expected_root:
                raise SystemExit(f"unexpected archive root: {member.name}")
            target = (output / member.name).resolve()
            if output_resolved not in target.parents and target != output_resolved:
                raise SystemExit(f"unsafe archive path: {member.name}")
            if member.issym() or member.islnk():
                raise SystemExit(f"archive link rejected: {member.name}")
        bundle.extractall(output)
    extracted = output / expected_root
    if not extracted.is_dir():
        raise SystemExit("official archive root missing after extraction")
    return extracted


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument(
        "--official-archive",
        type=Path,
        help="pre-transferred official commit archive; disables Git network fetch",
    )
    parser.add_argument(
        "--official-raw-script",
        type=Path,
        help="independently downloaded official raw calculator at the same commit",
    )
    args = parser.parse_args()
    output = args.out.resolve()
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    output.mkdir(parents=True)
    repository = output / "repository"
    if (args.official_archive is None) != (args.official_raw_script is None):
        raise SystemExit(
            "--official-archive and --official-raw-script must be supplied together"
        )
    if args.official_archive is not None:
        supplied_archive = args.official_archive.resolve()
        supplied_raw = args.official_raw_script.resolve()
        if not supplied_archive.is_file() or not supplied_raw.is_file():
            raise SystemExit("pre-transferred official archive/raw resource missing")
        if sha256(supplied_archive) != ARCHIVE_SHA256:
            raise SystemExit("official archive SHA-256 mismatch")
        if sha256(supplied_raw) != SCRIPT_SHA256:
            raise SystemExit("official raw calculator SHA-256 mismatch")
        extracted = extract_official_archive(supplied_archive, output)
        extracted.rename(repository)
        script_path = repository / SCRIPT
        if sha256(script_path) != SCRIPT_SHA256:
            raise SystemExit("archive calculator does not match official raw calculator")
        retained_archive = output / f"hadeshash-{COMMIT}.tar.gz"
        shutil.copyfile(supplied_archive, retained_archive)
        shutil.copyfile(supplied_raw, output / "calc_round_numbers.official-raw.py")
        provenance = {
            "schema": "plan-a-poseidon-reference-prefetch-v2",
            "remote": REMOTE,
            "commit": COMMIT,
            "fetch_mode": "pre-transferred-official-https-archive-plus-raw",
            "official_archive_url": ARCHIVE_URL,
            "official_archive_sha256": ARCHIVE_SHA256,
            "official_raw_script_url": RAW_SCRIPT_URL,
            "script_relative_path": str(SCRIPT),
            "script_sha256": SCRIPT_SHA256,
            "archive_and_independent_raw_script_match": True,
            "repository_path": str(repository),
            "network_required_for_later_gate": False,
            "git_head_claimed": False,
        }
        (output / "PROVENANCE.json").write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n"
        )
        shutil.copyfile(script_path, output / "calc_round_numbers.py")
        return

    repository.mkdir()
    run(["git", "init"], repository)
    run(["git", "remote", "add", "origin", REMOTE], repository)
    fetched = False
    for attempt in range(1, args.attempts + 1):
        result = run(
            ["git", "fetch", "--depth", "1", "origin", COMMIT],
            repository,
            check=False,
        )
        (output / f"FETCH_ATTEMPT_{attempt}.stdout").write_text(result.stdout)
        (output / f"FETCH_ATTEMPT_{attempt}.stderr").write_text(result.stderr)
        (output / f"FETCH_ATTEMPT_{attempt}.exitcode").write_text(
            f"{result.returncode}\n"
        )
        if result.returncode == 0:
            fetched = True
            break
        time.sleep(min(2**attempt, 20))
    fetch_mode = "exact-commit-shallow"
    if not fetched:
        result = run(["git", "fetch", "origin"], repository, check=False)
        (output / "FETCH_FULL_FALLBACK.stdout").write_text(result.stdout)
        (output / "FETCH_FULL_FALLBACK.stderr").write_text(result.stderr)
        (output / "FETCH_FULL_FALLBACK.exitcode").write_text(
            f"{result.returncode}\n"
        )
        if result.returncode != 0:
            raise SystemExit(
                "could not fetch pinned commit by exact SHA or full official-repository fallback"
            )
        fetch_mode = "full-official-repository-fallback"
    run(["git", "checkout", "--detach", COMMIT], repository)
    head = run(["git", "rev-parse", "HEAD"], repository).stdout.strip()
    if head != COMMIT:
        raise SystemExit(f"wrong checked-out commit: {head}")
    status = run(["git", "status", "--porcelain"], repository).stdout
    if status:
        raise SystemExit(f"reference checkout is dirty: {status}")
    script_path = repository / SCRIPT
    script_digest = sha256(script_path)
    bundle = output / "hadeshash-pinned.bundle"
    run(["git", "bundle", "create", str(bundle), "HEAD"], repository)
    verify = output / "offline-verify"
    run(["git", "clone", str(bundle), str(verify)], output)
    run(["git", "checkout", "--detach", COMMIT], verify)
    verify_head = run(["git", "rev-parse", "HEAD"], verify).stdout.strip()
    verify_digest = sha256(verify / SCRIPT)
    if verify_head != COMMIT or verify_digest != script_digest:
        raise SystemExit("offline bundle verification mismatch")
    provenance = {
        "schema": "plan-a-poseidon-reference-prefetch-v1",
        "remote": REMOTE,
        "commit": COMMIT,
        "head": head,
        "fetch_mode": fetch_mode,
        "script_relative_path": str(SCRIPT),
        "script_sha256": script_digest,
        "bundle_path": str(bundle),
        "bundle_sha256": sha256(bundle),
        "offline_verify_path": str(verify),
        "offline_verify_head": verify_head,
        "network_required_for_later_gate": False,
    }
    (output / "PROVENANCE.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n"
    )
    shutil.copyfile(script_path, output / "calc_round_numbers.py")


if __name__ == "__main__":
    main()
