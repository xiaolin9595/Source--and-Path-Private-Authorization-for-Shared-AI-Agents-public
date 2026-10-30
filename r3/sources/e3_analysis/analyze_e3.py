#!/usr/bin/env python3
"""Frozen E3 proxy-candidate intersection analysis.

The input has neither employee IDs nor timestamps.  Outputs therefore describe
role-profile or manager-bucket proxies under seeded random resource sequences;
they are not user re-identification or chronological traces.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Sequence

import matplotlib.pyplot as plt
import numpy as np


plt.rcParams["svg.hashsalt"] = "pets2027-e3-20261029"


SEED = 2026102903
K_MAX = 10
PERMUTATIONS = 100
EXPECTED_CSV = [
    "ACTION", "RESOURCE", "MGR_ID", "ROLE_ROLLUP_1", "ROLE_ROLLUP_2",
    "ROLE_DEPTNAME", "ROLE_TITLE", "ROLE_FAMILY_DESC", "ROLE_FAMILY",
    "ROLE_CODE",
]
ROLE_FIELDS = EXPECTED_CSV[3:]
EXPECTED_ROWS = 32769
EXPECTED_APPROVED = 30872
FROZEN_ARFF_SHA256 = "4f33c09f3612b5de1294ca664eec7fd1bb56a94b05d0352219794a37e4acc8cc"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if path.suffix.lower() == ".csv":
        with path.open(encoding="utf-8", newline="") as stream:
            reader = csv.DictReader(stream)
            rows = list(reader)
            return list(reader.fieldnames or []), rows
    attrs: list[str] = []
    rows: list[dict[str, str]] = []
    in_data = False
    with path.open(encoding="utf-8", newline="") as stream:
        for raw in stream:
            line = raw.strip()
            if not line or line.startswith("%"):
                continue
            lower = line.lower()
            if lower.startswith("@attribute"):
                attrs.append(line.split(None, 2)[1].strip("'\""))
            elif lower == "@data":
                in_data = True
            elif in_data:
                values = next(csv.reader([line]))
                rows.append(dict(zip(attrs, values)))
    return attrs, rows


def percentile(values: Sequence[float], q: float) -> float:
    return float(np.percentile(np.asarray(values, dtype=float), q, method="linear"))


@dataclass(frozen=True)
class Spec:
    name: str
    candidate: Callable[[dict[str, str]], tuple[str, ...]]


def make_indexes(
    approved: list[dict[str, str]], spec: Spec
) -> tuple[
    dict[tuple[str, str], set[tuple[str, ...]]],
    dict[str, set[tuple[str, ...]]],
    dict[str, set[str]],
    dict[tuple[str, tuple[str, ...]], set[str]],
    Counter[str],
    Counter[tuple[str, tuple[str, ...]]],
]:
    by_dept_resource: dict[tuple[str, str], set[tuple[str, ...]]] = defaultdict(set)
    by_resource: dict[str, set[tuple[str, ...]]] = defaultdict(set)
    dept_resources: dict[str, set[str]] = defaultdict(set)
    conditioned_resources: dict[tuple[str, tuple[str, ...]], set[str]] = defaultdict(set)
    dept_rows: Counter[str] = Counter()
    conditioned_rows: Counter[tuple[str, tuple[str, ...]]] = Counter()
    for row in approved:
        department = row["ROLE_DEPTNAME"]
        resource = row["RESOURCE"]
        candidate = spec.candidate(row)
        by_dept_resource[(department, resource)].add(candidate)
        by_resource[resource].add(candidate)
        dept_resources[department].add(resource)
        conditioned_resources[(department, candidate)].add(resource)
        dept_rows[department] += 1
        conditioned_rows[(department, candidate)] += 1
    return (
        by_dept_resource,
        by_resource,
        dept_resources,
        conditioned_resources,
        dept_rows,
        conditioned_rows,
    )


def trajectory(
    department: str,
    resources: Sequence[str],
    by_dept_resource: dict[tuple[str, str], set[tuple[str, ...]]],
    by_resource: dict[str, set[tuple[str, ...]]],
) -> tuple[list[int], list[int]]:
    dept_intersection: set[tuple[str, ...]] | None = None
    global_intersection: set[tuple[str, ...]] | None = None
    dept_counts: list[int] = []
    global_counts: list[int] = []
    for resource in resources:
        dept_candidates = by_dept_resource[(department, resource)]
        global_candidates = by_resource[resource]
        dept_intersection = (
            set(dept_candidates)
            if dept_intersection is None
            else dept_intersection.intersection(dept_candidates)
        )
        global_intersection = (
            set(global_candidates)
            if global_intersection is None
            else global_intersection.intersection(global_candidates)
        )
        if not dept_intersection.issubset(global_intersection):
            raise AssertionError("department intersection is not nested in global intersection")
        dept_counts.append(len(dept_intersection))
        global_counts.append(len(global_intersection))
    if any(a < b for a, b in zip(dept_counts, dept_counts[1:])):
        raise AssertionError("department candidate counts increased")
    if any(a < b for a, b in zip(global_counts, global_counts[1:])):
        raise AssertionError("global candidate counts increased")
    return dept_counts, global_counts


def first_singleton(counts: Sequence[int]) -> int:
    return next((index + 1 for index, value in enumerate(counts) if value == 1), K_MAX + 1)


def collect_fixed(
    spec: Spec,
    arm: str,
    units: Sequence[tuple[str, tuple[str, ...] | None]],
    unit_resources: dict[tuple[str, tuple[str, ...] | None], set[str]],
    unit_weights: dict[tuple[str, tuple[str, ...] | None], int],
    by_dept_resource: dict[tuple[str, str], set[tuple[str, ...]]],
    by_resource: dict[str, set[tuple[str, ...]]],
    rng: np.random.Generator,
) -> list[dict[str, int | str]]:
    records: list[dict[str, int | str]] = []
    for unit_index, unit in enumerate(units):
        department, _condition = unit
        resources = np.asarray(sorted(unit_resources[unit]), dtype=object)
        for permutation_index in range(PERMUTATIONS):
            chosen = rng.permutation(resources)[:K_MAX].tolist()
            dept_counts, global_counts = trajectory(
                department, chosen, by_dept_resource, by_resource
            )
            if arm == "B" and any(value == 0 for value in dept_counts):
                raise AssertionError("conditioned arm B became empty")
            singleton = first_singleton(dept_counts)
            for k, (dept_count, global_count) in enumerate(
                zip(dept_counts, global_counts), start=1
            ):
                records.append({
                    "candidate_unit": spec.name,
                    "arm": arm,
                    "unit_index": unit_index,
                    "permutation_index": permutation_index,
                    "unit_weight": unit_weights[unit],
                    "k": k,
                    "department_candidates": dept_count,
                    "global_candidates": global_count,
                    "pool_increment": global_count - dept_count,
                    "first_singleton_k": singleton,
                    "singleton_right_censored": int(singleton == K_MAX + 1),
                })
    return records


def summarize(records: list[dict[str, int | str]], weighting: str) -> list[dict[str, float | int | str]]:
    output: list[dict[str, float | int | str]] = []
    groups: dict[tuple[str, str, int], list[dict[str, int | str]]] = defaultdict(list)
    for record in records:
        groups[(str(record["candidate_unit"]), str(record["arm"]), int(record["k"]))].append(record)
    for (unit, arm, k), group in sorted(groups.items()):
        if weighting == "macro":
            weights = np.ones(len(group), dtype=float)
        else:
            weights = np.asarray([int(row["unit_weight"]) for row in group], dtype=float)
        weights /= weights.sum()
        dept = np.asarray([int(row["department_candidates"]) for row in group], dtype=float)
        glob = np.asarray([int(row["global_candidates"]) for row in group], dtype=float)
        delta = glob - dept
        # Quantiles stay unweighted so the frozen macro cohort remains legible;
        # row weighting is reported for means and event fractions only.
        output.append({
            "candidate_unit": unit,
            "arm": arm,
            "weighting": weighting,
            "k": k,
            "n_trajectories": len(group),
            "department_median": percentile(dept, 50),
            "department_q1": percentile(dept, 25),
            "department_q3": percentile(dept, 75),
            "department_mean": float(np.sum(weights * dept)),
            "department_zero_fraction": float(np.sum(weights * (dept == 0))),
            "department_singleton_fraction": float(np.sum(weights * (dept == 1))),
            "department_ge2_fraction": float(np.sum(weights * (dept >= 2))),
            "global_median": percentile(glob, 50),
            "global_q1": percentile(glob, 25),
            "global_q3": percentile(glob, 75),
            "global_mean": float(np.sum(weights * glob)),
            "pool_increment_median": percentile(delta, 50),
            "pool_increment_mean": float(np.sum(weights * delta)),
            "pool_non_decrease_fraction": float(np.sum(weights * (glob >= dept))),
        })
    return output


def write_csv(path: Path, records: list[dict[str, object]]) -> None:
    if not records:
        raise ValueError(f"no records for {path}")
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)


def k_specific(
    spec: Spec,
    arm: str,
    all_resources: dict[tuple[str, tuple[str, ...] | None], set[str]],
    all_weights: dict[tuple[str, tuple[str, ...] | None], int],
    by_dept_resource: dict[tuple[str, str], set[tuple[str, ...]]],
    by_resource: dict[str, set[tuple[str, ...]]],
) -> list[dict[str, object]]:
    output: list[dict[str, object]] = []
    for k in range(1, K_MAX + 1):
        rng = np.random.Generator(np.random.PCG64(SEED + k + (0 if arm == "A" else 100)))
        eligible = sorted(unit for unit, resources in all_resources.items() if len(resources) >= k)
        counts: list[int] = []
        weights: list[int] = []
        for unit in eligible:
            department, _condition = unit
            resources = np.asarray(sorted(all_resources[unit]), dtype=object)
            for _ in range(PERMUTATIONS):
                chosen = rng.permutation(resources)[:k].tolist()
                dept_counts, _ = trajectory(department, chosen, by_dept_resource, by_resource)
                if arm == "B" and dept_counts[-1] == 0:
                    raise AssertionError("k-specific conditioned arm B became empty")
                counts.append(dept_counts[-1])
                weights.append(all_weights[unit])
        values = np.asarray(counts, dtype=float)
        normalized_weights = np.asarray(weights, dtype=float)
        normalized_weights /= normalized_weights.sum()
        output.append({
            "candidate_unit": spec.name,
            "arm": arm,
            "k": k,
            "eligible_units": len(eligible),
            "trajectories": len(counts),
            "median": percentile(values, 50),
            "q1": percentile(values, 25),
            "q3": percentile(values, 75),
            "macro_mean": float(values.mean()),
            "macro_zero_fraction": float((values == 0).mean()),
            "macro_singleton_fraction": float((values == 1).mean()),
            "row_weighted_mean": float(np.sum(normalized_weights * values)),
            "row_weighted_zero_fraction": float(np.sum(normalized_weights * (values == 0))),
            "row_weighted_singleton_fraction": float(np.sum(normalized_weights * (values == 1))),
            "cohort_changes_across_k": True,
        })
    return output


def manual_validation() -> dict[str, bool]:
    a, b, c = ("a",), ("b",), ("c",)
    dept = {("d", "r1"): {a, b}, ("d", "r2"): {b, c}, ("d", "r3"): {b}}
    glob = {"r1": {a, b, c}, "r2": {a, b, c}, "r3": {a, b}}
    dept_counts, global_counts = trajectory("d", ["r1", "r2", "r3"], dept, glob)
    return {
        "toy_department_counts_equal_2_1_1": dept_counts == [2, 1, 1],
        "toy_global_counts_equal_3_3_2": global_counts == [3, 3, 2],
        "toy_first_singleton_equal_2": first_singleton(dept_counts) == 2,
    }


def plot_summary(summary: list[dict[str, object]], out: Path) -> None:
    fig, axes = plt.subplots(2, 2, figsize=(9.0, 6.7), sharex=True)
    for row_index, unit in enumerate(("role_profile", "manager_bucket")):
        for col_index, arm in enumerate(("A", "B")):
            axis = axes[row_index, col_index]
            rows = [r for r in summary if r["candidate_unit"] == unit and r["arm"] == arm and r["weighting"] == "macro"]
            x = np.asarray([int(r["k"]) for r in rows])
            median = np.asarray([float(r["department_median"]) for r in rows])
            q1 = np.asarray([float(r["department_q1"]) for r in rows])
            q3 = np.asarray([float(r["department_q3"]) for r in rows])
            pooled = np.asarray([float(r["global_median"]) for r in rows])
            axis.fill_between(x, q1, q3, alpha=0.18, color="#3569a8")
            axis.plot(x, median, marker="o", color="#3569a8", label="Department median (IQR)")
            axis.plot(x, pooled, marker="s", color="#c84e42", label="Global-pool median")
            axis.set_title(f"{unit.replace('_', ' ')}, arm {arm}")
            # Linear scaling keeps the Arm-A zero intersections visible and
            # avoids ambiguous symlog ticks at zero and one.  All plotted
            # series are medians (the largest is eight), so no tail is clipped.
            axis.set_ylim(bottom=-0.15)
            axis.set_xticks(range(1, K_MAX + 1))
            axis.grid(alpha=0.25)
            if row_index == 1:
                axis.set_xlabel("request count k (seeded random order)")
            if col_index == 0:
                axis.set_ylabel("proxy candidates")
    handles, labels = axes[0, 0].get_legend_handles_labels()
    fig.suptitle("Repeated-request proxy intersections (fixed k=10 cohorts)", y=0.985)
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.94), ncol=2, frameon=False)
    fig.tight_layout(rect=(0, 0, 1, 0.88))
    fig.savefig(
        out / "e3_intersection_curves.svg",
        bbox_inches="tight",
        metadata={"Date": None},
    )
    fig.savefig(
        out / "e3_intersection_curves.pdf",
        bbox_inches="tight",
        metadata={"CreationDate": None, "ModDate": None},
    )
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--figures", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    args.figures.mkdir(parents=True, exist_ok=True)

    columns, rows = read_rows(args.input)
    if columns not in (EXPECTED_CSV, [*EXPECTED_CSV[1:], "target"]):
        raise SystemExit(f"unexpected columns: {columns}")
    if "target" in columns:
        approved = [row for row in rows if row["target"] == "1"]
    else:
        approved = [row for row in rows if row["ACTION"] == "1"]
    if len(rows) != EXPECTED_ROWS or len(approved) != EXPECTED_APPROVED:
        raise SystemExit(f"frozen row counts differ: rows={len(rows)} approved={len(approved)}")

    specs = [
        Spec("role_profile", lambda row: tuple(row[field] for field in ROLE_FIELDS)),
        Spec("manager_bucket", lambda row: (row["MGR_ID"],)),
    ]
    all_records: list[dict[str, object]] = []
    coverage: list[dict[str, object]] = []
    specific_records: list[dict[str, object]] = []

    for spec_index, spec in enumerate(specs):
        (
            by_dept_resource,
            by_resource,
            dept_resources,
            conditioned_resources,
            dept_rows,
            conditioned_rows,
        ) = make_indexes(approved, spec)
        arm_a_resources = {(department, None): resources for department, resources in dept_resources.items()}
        arm_a_weights = {(department, None): dept_rows[department] for department in dept_resources}
        arm_b_resources = dict(conditioned_resources)
        arm_b_weights = dict(conditioned_rows)

        for arm, resources_by_unit, weights_by_unit in (
            ("A", arm_a_resources, arm_a_weights),
            ("B", arm_b_resources, arm_b_weights),
        ):
            eligible = sorted(unit for unit, resources in resources_by_unit.items() if len(resources) >= K_MAX)
            excluded = len(resources_by_unit) - len(eligible)
            covered_rows = sum(weights_by_unit[unit] for unit in eligible)
            coverage.append({
                "candidate_unit": spec.name,
                "arm": arm,
                "units_before": len(resources_by_unit),
                "units_eligible_fixed_k10": len(eligible),
                "units_excluded": excluded,
                "approved_rows_total": len(approved),
                "approved_rows_covered_by_eligible_units": covered_rows,
                "approved_rows_excluded": len(approved) - covered_rows,
            })
            rng = np.random.Generator(np.random.PCG64(SEED + spec_index * 1000 + (0 if arm == "A" else 100)))
            all_records.extend(collect_fixed(
                spec, arm, eligible, resources_by_unit, weights_by_unit,
                by_dept_resource, by_resource, rng,
            ))
            specific_records.extend(k_specific(
                spec, arm, resources_by_unit, weights_by_unit,
                by_dept_resource, by_resource,
            ))

    macro = summarize(all_records, "macro")
    row_weighted = summarize(all_records, "approved_row_weighted")
    summary = macro + row_weighted
    write_csv(args.out / "fixed_cohort_trajectories.csv", all_records)
    write_csv(args.out / "fixed_cohort_summary.csv", summary)
    write_csv(args.out / "cohort_coverage.csv", coverage)
    write_csv(args.out / "k_specific_sensitivity.csv", specific_records)

    singleton_rows: list[dict[str, object]] = []
    unique_trajectories = {
        (r["candidate_unit"], r["arm"], r["unit_index"], r["permutation_index"]): r
        for r in all_records if r["k"] == 1
    }
    for (unit, arm, _index, _permutation), row in sorted(unique_trajectories.items()):
        singleton_rows.append({
            "candidate_unit": unit,
            "arm": arm,
            "first_singleton_k": row["first_singleton_k"],
            "right_censored_after_k10": row["singleton_right_censored"],
        })
    write_csv(args.out / "first_singleton.csv", singleton_rows)

    validation = manual_validation()
    validation.update({
        "all_manual_checks": all(validation.values()),
        "all_pool_increments_nonnegative": all(int(r["pool_increment"]) >= 0 for r in all_records),
        "arm_b_never_empty": all(int(r["department_candidates"]) >= 1 for r in all_records if r["arm"] == "B"),
        "fixed_input_rows": len(rows) == EXPECTED_ROWS,
        "fixed_input_approved_rows": len(approved) == EXPECTED_APPROVED,
        "singleton_censoring_consistent": all(
            (int(r["first_singleton_k"]) == K_MAX + 1)
            == bool(int(r["singleton_right_censored"]))
            for r in all_records
        ),
    })
    metadata = {
        "schema": "pets2027-e3-proxy-intersection-v1",
        "input": {
            "path_basename": args.input.name,
            "sha256": digest(args.input),
            "frozen_openml_arff_sha256": FROZEN_ARFF_SHA256,
            "rows": len(rows),
            "approved_rows": len(approved),
            "raw_input_not_for_public_artifact": True,
        },
        "protocol": {
            "seed": SEED,
            "rng": "numpy PCG64",
            "k_max": K_MAX,
            "permutations_per_unit": PERMUTATIONS,
            "sampling": "without replacement; sorted units/resources before RNG",
            "no_time_order_claim": True,
            "proxy_not_identity": True,
        },
        "coverage": coverage,
        "validation": validation,
    }
    (args.out / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    plot_summary(summary, args.figures)
    print(json.dumps(metadata, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
