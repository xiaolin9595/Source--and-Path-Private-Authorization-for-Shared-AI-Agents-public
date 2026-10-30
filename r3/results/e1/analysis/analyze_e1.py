#!/usr/bin/env python3
"""Fail-closed preregistered E1 analyzer. This does not run collection."""

import argparse
import json
import random
import math
import statistics
from collections import Counter, defaultdict
from pathlib import Path

LABELS = ("o", "aA", "aB")
LENGTHS = (1, 2, 3)
SESSIONS = (1, 2, 3, 4)
BLOCKS = 125

def expected_schedule(session):
    rng=random.Random(2026102900+session);cells=[(n,l) for n in LENGTHS for l in LABELS];rows=[];warm=cells[:];rng.shuffle(warm)
    for i,(length,label) in enumerate(warm): rows.append((-1,length,"gate" if label=="o" else label,"o" if label=="o" else "a"))
    for block in range(BLOCKS):
        order=cells[:];rng.shuffle(order)
        for length,label in order: rows.append((block,length,label,"o" if label=="o" else "a"))
    return rows


def load(paths):
    rows = []
    for path in paths:
        with Path(path).open(encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("event") == "measurement":
                    row["source"] = str(path)
                    row["line"] = line_no
                    rows.append(row)
    return rows


def validate(rows):
    expected = {
        (session, block, length, label)
        for session in SESSIONS
        for block in range(BLOCKS)
        for length in LENGTHS
        for label in LABELS
    }
    actual = Counter((r["session"], r["block"], r["length"], r["label"]) for r in rows)
    duplicates = [key for key, count in actual.items() if count != 1]
    missing = sorted(expected - set(actual))
    extra = sorted(set(actual) - expected)
    if duplicates or missing or extra or len(rows) != 4500:
        raise SystemExit(
            f"incomplete matrix: rows={len(rows)} duplicate={duplicates[:3]} "
            f"missing={missing[:3]} extra={extra[:3]}"
        )
    for row in rows:
        required = (
            "online_total_ms", "padding_prepare_ms", "prove_ms",
            "serialize_ms", "verified", "mutated_public_rejected",
            "proof_sha256", "binary_sha256", "relation_sha256", "pk_sha256",
        )
        if any(key not in row for key in required):
            raise SystemExit(f"missing required field at {row['source']}:{row['line']}")
        if not row["verified"] or not row["mutated_public_rejected"]:
            raise SystemExit(f"correctness failure at {row['source']}:{row['line']}")
        phases=[row["padding_prepare_ms"],row["prove_ms"],row["serialize_ms"]]
        if any(not isinstance(value,(int,float)) or not math.isfinite(value) or value < 0 for value in [row["online_total_ms"],*phases]):
            raise SystemExit(f"invalid timing at {row['source']}:{row['line']}")
        if row["online_total_ms"] + 0.2 < sum(phases):
            raise SystemExit(f"subphases exceed total at {row['source']}:{row['line']}")
        route="o" if row["label"]=="o" else "a"
        if row.get("route") != route:
            raise SystemExit(f"label/route mismatch at {row['source']}:{row['line']}")
        expected=expected_schedule(row["session"])[row["schedule_position"]]
        if expected != (row["block"],row["length"],row["label"],row["route"]):
            raise SystemExit(f"schedule mismatch at {row['source']}:{row['line']}")
    proof_hashes = [r["proof_sha256"] for r in rows]
    if len(set(proof_hashes)) != len(proof_hashes):
        raise SystemExit("duplicate proof hash")
    original={(r["binary_sha256"],r["relation_sha256"]) for r in rows if r["label"]=="o"}
    dummy={(r["binary_sha256"],r["relation_sha256"]) for r in rows if r["label"] in ("aA","aB")}
    if len(original)!=1 or len(dummy)!=1 or original==dummy: raise SystemExit("unstable or aliased binary/relation identity")
    pk={(r["session"],"o" if r["label"]=="o" else "a",r["pk_sha256"]) for r in rows}
    if len(pk)!=8 or len({value for _,_,value in pk})!=8: raise SystemExit("PK identities are not unique per session and relation")
    schedule_hashes=[{r.get("schedule_sha256") for r in rows if r["session"]==session} for session in SESSIONS]
    if any(len(values)!=1 or not isinstance(next(iter(values)),str) or len(next(iter(values)))!=64 for values in schedule_hashes): raise SystemExit("missing or unstable schedule hash within session")


def nearest(value, prototypes):
    return min(LENGTHS, key=lambda length: (abs(value - prototypes[length]), length))


def analyze(rows):
    dummy = [r for r in rows if r["label"] in ("aA", "aB")]
    medians = {
        length: statistics.median(r["online_total_ms"] for r in dummy if r["length"] == length)
        for length in LENGTHS
    }
    differences = {
        f"{right}-{left}": abs(medians[right] - medians[left])
        for left, right in ((1, 2), (1, 3), (2, 3))
    }
    training = [r for r in dummy if r["session"] in (1, 3)]
    testing = [r for r in dummy if r["session"] in (2, 4)]
    prototypes = {
        length: statistics.median(r["online_total_ms"] for r in training if r["length"] == length)
        for length in LENGTHS
    }
    confusion = defaultdict(Counter)
    for row in testing:
        confusion[row["length"]][nearest(row["online_total_ms"], prototypes)] += 1
    correct = sum(confusion[length][length] for length in LENGTHS)
    accuracy = correct / len(testing)
    by_label = {}
    for label in ("aA", "aB"):
        label_train = [r for r in rows if r["label"] == label and r["session"] in (1, 3)]
        label_test = [r for r in rows if r["label"] == label and r["session"] in (2, 4)]
        label_proto = {length: statistics.median(r["online_total_ms"] for r in label_train if r["length"] == length) for length in LENGTHS}
        label_correct = sum(nearest(r["online_total_ms"], label_proto) == r["length"] for r in label_test)
        by_label[label] = {"prototypes_ms": label_proto, "correct": label_correct, "total": len(label_test), "accuracy": label_correct / len(label_test)}
    aa = {}
    for length in LENGTHS:
        train = [r for r in rows if r["length"] == length and r["session"] in (1, 3) and r["label"] in ("aA", "aB")]
        test = [r for r in rows if r["length"] == length and r["session"] in (2, 4) and r["label"] in ("aA", "aB")]
        proto = {label: statistics.median(r["online_total_ms"] for r in train if r["label"] == label) for label in ("aA", "aB")}
        predictions = [(r["label"], min(("aA", "aB"), key=lambda label: (abs(r["online_total_ms"] - proto[label]), label))) for r in test]
        aa[length] = {"prototypes_ms": proto, "correct": sum(a == p for a, p in predictions), "total": len(predictions), "confusion": {actual: dict(Counter(p for a, p in predictions if a == actual)) for actual in ("aA", "aB")}}
        aa[length]["accuracy"] = aa[length]["correct"] / aa[length]["total"]
        pairs=[]
        for session in SESSIONS:
            for block in range(BLOCKS):
                cell={r["label"]:r["online_total_ms"] for r in rows if r["session"]==session and r["block"]==block and r["length"]==length and r["label"] in ("aA","aB")}
                pairs.append(cell["aA"]-cell["aB"])
        aa[length]["paired_aA_minus_aB_ms"]={"median":statistics.median(pairs),"mean":statistics.fmean(pairs),"n":len(pairs)}
    rng = random.Random(2026102917)
    boot = {name: [] for name in differences}
    block_index={(session,block):[r for r in dummy if r["session"]==session and r["block"]==block] for session in SESSIONS for block in range(BLOCKS)}
    for _ in range(1000):
        sampled = []
        for sampled_session in rng.choices(SESSIONS, k=len(SESSIONS)):
            chosen_blocks = rng.choices(range(BLOCKS), k=BLOCKS)
            for block in chosen_blocks:
                sampled.extend(block_index[(sampled_session,block)])
        bm = {length: statistics.median(r["online_total_ms"] for r in sampled if r["length"] == length) for length in LENGTHS}
        for left, right in ((1, 2), (1, 3), (2, 3)):
            boot[f"{right}-{left}"].append(abs(bm[right] - bm[left]))
    bootstrap = {}
    for name, values in boot.items():
        values.sort(); bootstrap[name] = {"p2_5": values[24], "p97_5": values[974], "replicates": 1000}
    original_rows=[r for r in rows if r["label"]=="o"]
    original_medians={length:statistics.median(r["online_total_ms"] for r in original_rows if r["length"]==length) for length in LENGTHS}
    original_train=[r for r in original_rows if r["session"] in (1,3)];original_test=[r for r in original_rows if r["session"] in (2,4)]
    original_proto={length:statistics.median(r["online_total_ms"] for r in original_train if r["length"]==length) for length in LENGTHS}
    original_correct=sum(nearest(r["online_total_ms"],original_proto)==r["length"] for r in original_test)
    session_summary={str(session):{label:{str(length):statistics.median(r["online_total_ms"] for r in rows if r["session"]==session and r["label"]==label and r["length"]==length) for length in LENGTHS} for label in LABELS} for session in SESSIONS}
    return {
        "schema": "pets2027-e1-analysis-pre-freeze-v1",
        "rows": len(rows),
        "dummy_medians_ms": medians,
        "original_medians_ms":original_medians,
        "original_length_classification":{"prototypes_ms":original_proto,"correct":original_correct,"total":len(original_test),"accuracy":original_correct/len(original_test)},
        "per_session_label_length_medians_ms":session_summary,
        "dummy_absolute_median_differences_ms": differences,
        "all_median_differences_le_15ms": all(value <= 15.0 for value in differences.values()),
        "training_sessions": [1, 3],
        "testing_sessions": [2, 4],
        "prototypes_ms": prototypes,
        "confusion": {str(k): dict(v) for k, v in confusion.items()},
        "classifier_correct": correct,
        "classifier_total": len(testing),
        "classifier_accuracy": accuracy,
        "classifier_accuracy_le_45pct": accuracy <= 0.45,
        "per_dummy_label_length_classification": by_label,
        "aa_label_classification_by_length": aa,
        "session_block_bootstrap_absolute_difference_95pct": bootstrap,
        "screen_pass": all(value <= 15.0 for value in differences.values()) and accuracy <= 0.45,
        "limitations": "Empirical screen only; not a timing-independence or side-channel elimination claim.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl", nargs="+")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    rows = load(args.jsonl)
    validate(rows)
    result = analyze(rows)
    Path(args.output).write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
