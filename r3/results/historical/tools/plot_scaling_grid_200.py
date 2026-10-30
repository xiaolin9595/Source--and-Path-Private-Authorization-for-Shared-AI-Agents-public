#!/usr/bin/env python3
"""Render retained E2 scaling data without rerunning an experiment.

TRIALS.jsonl is the completeness/correctness ledger. The saved CI summary is
the only source of plotted estimates; this script does not resample data.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402


EXPECTED_LMAX = (1, 2, 3, 4, 5)
EXPECTED_DEPTHS = (10, 16, 20, 24)
EXPECTED_REPETITIONS = 10
EXPECTED_TRIALS = len(EXPECTED_LMAX) * len(EXPECTED_DEPTHS) * EXPECTED_REPETITIONS
COLORS = ("#0072B2", "#E69F00", "#009E73", "#CC79A7", "#D55E00")
MARKERS = ("o", "s", "^", "D", "P")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_and_validate(raw_dir: Path) -> tuple[list[dict], dict[str, str]]:
    trials_path = raw_dir / "TRIALS.jsonl"
    ci_path = raw_dir / "E2_CELL_SUMMARY_CI.json"
    summary_path = raw_dir / "SUMMARY.json"
    trials = [json.loads(line) for line in trials_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    ci = json.loads(ci_path.read_text(encoding="utf-8"))

    if len(trials) != EXPECTED_TRIALS or summary.get("completed_trials") != EXPECTED_TRIALS:
        raise ValueError(f"expected {EXPECTED_TRIALS} retained trials, found {len(trials)}")
    counts: Counter[tuple[int, int]] = Counter()
    repetitions: defaultdict[tuple[int, int], set[int]] = defaultdict(set)
    raw_constants: defaultdict[tuple[int, int], set[tuple[int, int]]] = defaultdict(set)
    for trial in trials:
        measurement = trial.get("measurement", {})
        if trial.get("exit_code") != 0 or measurement.get("ok") is not True:
            raise ValueError("E2 contains a failed or unverifiable retained trial")
        key = (int(trial["l_max"]), int(trial["state_depth"]))
        counts[key] += 1
        repetitions[key].add(int(trial["repetition"]))
        raw_constants[key].add((int(measurement["constraints"]), int(measurement["pk_bytes"])))

    expected_cells = {(lmax, depth) for lmax in EXPECTED_LMAX for depth in EXPECTED_DEPTHS}
    if set(counts) != expected_cells:
        raise ValueError("retained raw trials do not cover the expected 5x4 E2 grid")
    for key in expected_cells:
        if counts[key] != EXPECTED_REPETITIONS or repetitions[key] != set(range(EXPECTED_REPETITIONS)):
            raise ValueError(f"cell {key} does not contain repetitions 0..9 exactly once")
        if len(raw_constants[key]) != 1:
            raise ValueError(f"constraints or proving-key size varies within cell {key}")

    if ci.get("statistics", {}).get("n_per_cell") != EXPECTED_REPETITIONS:
        raise ValueError("CI ledger has an unexpected per-cell sample count")
    cells = ci.get("cells", [])
    if len(cells) != len(expected_cells):
        raise ValueError("CI ledger does not contain exactly 20 cells")
    seen: set[tuple[int, int]] = set()
    for cell in cells:
        key = (int(cell["l_max"]), int(cell["state_depth"]))
        if key in seen or key not in expected_cells:
            raise ValueError(f"duplicate or unexpected CI cell {key}")
        seen.add(key)
        if int(cell["n"]) != EXPECTED_REPETITIONS:
            raise ValueError(f"CI cell {key} has n != 10")
        constraints, pk_bytes = next(iter(raw_constants[key]))
        if int(cell["constraints"]) != constraints or int(cell["compressed_pk_bytes"]) != pk_bytes:
            raise ValueError(f"CI ledger disagrees with raw constants for cell {key}")
        lo, med, hi = (float(cell[name]) for name in ("prove_ms_ci95_lo", "prove_ms_median", "prove_ms_ci95_hi"))
        if not lo <= med <= hi:
            raise ValueError(f"invalid proof-time interval for cell {key}")

    hashes = {path.name: sha256(path) for path in (trials_path, ci_path, summary_path)}
    return sorted(cells, key=lambda c: (int(c["l_max"]), int(c["state_depth"]))), hashes


def style_axes(ax: plt.Axes) -> None:
    ax.set_xticks(EXPECTED_DEPTHS)
    ax.grid(True, axis="y", color="#D9D9D9", linewidth=0.7)
    ax.spines[["top", "right"]].set_visible(False)


def series(cells: list[dict], lmax: int) -> list[dict]:
    return sorted((cell for cell in cells if int(cell["l_max"]) == lmax), key=lambda c: int(c["state_depth"]))


def save_all(fig: plt.Figure, stem: Path) -> list[Path]:
    outputs = []
    for suffix, kwargs in (("pdf", {}), ("svg", {}), ("png", {"dpi": 240})):
        path = stem.with_suffix(f".{suffix}")
        fig.savefig(path, bbox_inches="tight", metadata={"Creator": "plot_e2_scaling_v2.py"}, **kwargs)
        outputs.append(path)
    return outputs


def render(cells: list[dict], out_dir: Path) -> list[Path]:
    plt.rcParams.update({"font.size": 8.5, "axes.labelsize": 8.5, "axes.titlesize": 9,
                         "legend.fontsize": 7.5, "pdf.fonttype": 42, "ps.fonttype": 42})
    out_dir.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.55), constrained_layout=True)
    for index, lmax in enumerate(EXPECTED_LMAX):
        rows = series(cells, lmax)
        depths = [int(row["state_depth"]) for row in rows]
        medians = [float(row["prove_ms_median"]) / 1000.0 for row in rows]
        lower = [(float(row["prove_ms_median"]) - float(row["prove_ms_ci95_lo"])) / 1000.0 for row in rows]
        upper = [(float(row["prove_ms_ci95_hi"]) - float(row["prove_ms_median"])) / 1000.0 for row in rows]
        axes[0].errorbar(depths, medians, yerr=[lower, upper], color=COLORS[index], marker=MARKERS[index],
                         linewidth=1.25, markersize=4, capsize=2, label=rf"$L_{{\max}}={lmax}$")
        axes[1].plot(depths, [float(row["compressed_pk_mib"]) for row in rows], color=COLORS[index],
                     marker=MARKERS[index], linewidth=1.25, markersize=4, label=rf"$L_{{\max}}={lmax}$")
    axes[0].set_title("(a) Proof generation")
    axes[0].set_xlabel("State-tree depth")
    axes[0].set_ylabel("Median time (s), 95% CI")
    axes[1].set_title("(b) Compressed proving key")
    axes[1].set_xlabel("State-tree depth")
    axes[1].set_ylabel("Size (MiB)")
    for ax in axes:
        style_axes(ax)
    axes[1].legend(frameon=False, loc="best")
    outputs = save_all(fig, out_dir / "E2_SCALING_MAIN_V2")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(3.5, 2.55), constrained_layout=True)
    for index, lmax in enumerate(EXPECTED_LMAX):
        rows = series(cells, lmax)
        ax.plot([int(row["state_depth"]) for row in rows], [int(row["constraints"]) for row in rows],
                color=COLORS[index], marker=MARKERS[index], linewidth=1.25, markersize=4,
                label=rf"$L_{{\max}}={lmax}$")
    ax.set_title("Joint-relation constraints")
    ax.set_xlabel("State-tree depth")
    ax.set_ylabel("Constraints")
    style_axes(ax)
    ax.legend(frameon=False, loc="best")
    outputs.extend(save_all(fig, out_dir / "E2_CONSTRAINTS_APPENDIX_V2"))
    plt.close(fig)
    return outputs


def write_source_table(cells: list[dict], path: Path) -> None:
    fields = ("l_max", "state_depth", "n", "constraints", "prove_ms_median",
              "prove_ms_ci95_lo", "prove_ms_ci95_hi", "compressed_pk_bytes", "compressed_pk_mib")
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(cells)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", type=Path, required=True, help="retained results/e2_formal_v1/raw directory")
    parser.add_argument("--out-dir", type=Path, required=True, help="standalone v2 figure output directory")
    args = parser.parse_args()
    cells, inputs = load_and_validate(args.raw_dir.resolve())
    out_dir = args.out_dir.resolve()
    outputs = render(cells, out_dir)
    table_path = out_dir / "E2_SCALING_PLOTTED_VALUES_V2.csv"
    write_source_table(cells, table_path)
    outputs.append(table_path)
    manifest = {
        "schema": "plan-a-e2-figure-v2",
        "input_hashes": inputs,
        "validation": {"trials": EXPECTED_TRIALS, "cells": 20, "trials_per_cell": EXPECTED_REPETITIONS},
        "statistics": "Retained medians and retained 95% percentile-bootstrap intervals; no intervals recomputed.",
        "outputs": {path.name: sha256(path) for path in outputs},
    }
    (out_dir / "E2_FIGURE_MANIFEST_V2.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
