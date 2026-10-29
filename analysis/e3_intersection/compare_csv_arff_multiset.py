#!/usr/bin/env python3
"""Prove canonical 10-column row-multiset equality for CSV and OpenML ARFF."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path


CANONICAL = (
    "ACTION", "RESOURCE", "MGR_ID", "ROLE_ROLLUP_1", "ROLE_ROLLUP_2",
    "ROLE_DEPTNAME", "ROLE_TITLE", "ROLE_FAMILY_DESC", "ROLE_FAMILY",
    "ROLE_CODE",
)
ARFF_TO_CANONICAL = {
    "target": "ACTION",
    "RESOURCE": "RESOURCE",
    "MGR_ID": "MGR_ID",
    "ROLE_ROLLUP_1": "ROLE_ROLLUP_1",
    "ROLE_ROLLUP_2": "ROLE_ROLLUP_2",
    "ROLE_DEPTNAME": "ROLE_DEPTNAME",
    "ROLE_TITLE": "ROLE_TITLE",
    "ROLE_FAMILY_DESC": "ROLE_FAMILY_DESC",
    "ROLE_FAMILY": "ROLE_FAMILY",
    "ROLE_CODE": "ROLE_CODE",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def integer_token(value: str) -> str:
    value = value.strip()
    parsed = float(value)
    if not parsed.is_integer():
        raise ValueError(f"non-integral value: {value!r}")
    return str(int(parsed))


def csv_rows(path: Path) -> list[tuple[str, ...]]:
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if tuple(reader.fieldnames or ()) != CANONICAL:
            raise ValueError(f"unexpected CSV schema/order: {reader.fieldnames}")
        return [tuple(integer_token(row[name]) for name in CANONICAL) for row in reader]


def arff_rows(path: Path) -> tuple[list[str], list[tuple[str, ...]]]:
    attributes: list[str] = []
    data: list[list[str]] = []
    in_data = False
    with path.open(encoding="utf-8") as stream:
        for raw in stream:
            line = raw.strip()
            if not line or line.startswith("%"):
                continue
            if not in_data and line.lower().startswith("@attribute"):
                attributes.append(line.split(None, 2)[1].strip("'\""))
            elif line.lower() == "@data":
                in_data = True
            elif in_data:
                data.append(next(csv.reader([line], skipinitialspace=True)))
    mapped = [ARFF_TO_CANONICAL.get(name, name) for name in attributes]
    if set(mapped) != set(CANONICAL) or len(mapped) != len(CANONICAL):
        raise ValueError(f"unexpected ARFF schema: {attributes}")
    index = {name: mapped.index(name) for name in CANONICAL}
    rows = [tuple(integer_token(row[index[name]]) for name in CANONICAL) for row in data]
    return attributes, rows


def multiset_digest(counter: Counter[tuple[str, ...]]) -> str:
    h = hashlib.sha256()
    for row, count in sorted(counter.items()):
        h.update(("\x1f".join(row) + "\x1e" + str(count) + "\n").encode())
    return h.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("csv", type=Path)
    parser.add_argument("arff", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    left = csv_rows(args.csv)
    arff_attributes, right = arff_rows(args.arff)
    left_counter, right_counter = Counter(left), Counter(right)
    report = {
        "schema": "pets2027-e3-format-equivalence-v1",
        "csv_sha256": sha256(args.csv),
        "arff_sha256": sha256(args.arff),
        "canonical_columns": list(CANONICAL),
        "arff_attributes_in_file_order": arff_attributes,
        "target_mapping": {"ARFF target": "CSV ACTION"},
        "normalization": "parse every value as numeric, require integral, serialize base-10 integer; preserve duplicate multiplicity",
        "csv_rows": len(left),
        "arff_rows": len(right),
        "csv_unique_rows": len(left_counter),
        "arff_unique_rows": len(right_counter),
        "csv_duplicate_rows_beyond_first": len(left) - len(left_counter),
        "arff_duplicate_rows_beyond_first": len(right) - len(right_counter),
        "canonical_multiset_sha256_csv": multiset_digest(left_counter),
        "canonical_multiset_sha256_arff": multiset_digest(right_counter),
        "canonical_record_multisets_equal": left_counter == right_counter,
        "csv_only_multiplicity": sum((left_counter - right_counter).values()),
        "arff_only_multiplicity": sum((right_counter - left_counter).values()),
    }
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["canonical_record_multisets_equal"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
