#!/usr/bin/env python3
"""Fail-closed analyzer for the frozen R2 loopback experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

SCHEMA = "r2-observation-v1"
ARMS = ("u", "pA", "pB")
LENGTHS = (1, 2, 3)
HASH_FIELDS = (
    "schedule_sha256", "pk_sha256", "vk_sha256", "config_sha256", "implementation_sha256",
    "source_manifest_sha256", "agent_challenge_sha256", "receiver_challenge_sha256",
    "agent_proof_sha256", "receiver_proof_sha256", "agent_envelope_sha256",
    "receiver_envelope_sha256", "gate_manifest_sha256",
)
INT_FIELDS = (
    "session", "block", "length", "schedule_position", "length_private", "frame_bytes",
    "receiver_frame_bytes", "t_agent_ns", "t_prepared_ns", "t_proved_ns", "t_ready_ns",
    "k", "deadline_ns", "t_send_call_ns", "t_send_return_ns", "overshoot_ns",
    "actual_wait_ns", "t_challenge_send_ns", "t_arrival_ns", "t_verify_start_ns",
    "t_verify_end_ns", "primary_duration_ns",
)
BOOL_FIELDS = ("padded_private", "overflow", "arrival_recorded_before_verification", "proof_verified", "signature_verified")
REQUIRED = {
    "schema", "phase", "arm", "setup_id", "provenance", "event_agent", "event_receiver",
    *HASH_FIELDS, *INT_FIELDS, *BOOL_FIELDS,
}
Z95 = 1.959963984540054


class ValidationError(ValueError):
    """Raised when evidence fails the frozen schema or design."""


def canonical_schedule(phase: str, session: int) -> tuple[list[dict[str, Any]], str]:
    if phase == "calibration":
        blocks, seed, cells = 100, 2026102960 + session, [(n, "u") for n in LENGTHS]
    elif phase == "formal":
        blocks, seed = 125, 2026102970 + session
        cells = [(n, arm) for n in LENGTHS for arm in ARMS]
    else:
        raise ValidationError(f"bad phase: {phase!r}")
    rng = random.Random(seed)
    schedule: list[dict[str, Any]] = []
    for block in range(1, blocks + 1):
        shuffled = list(cells)
        rng.shuffle(shuffled)
        schedule.extend(
            {"block": block, "length": length, "arm": arm, "schedule_position": position}
            for position, (length, arm) in enumerate(shuffled)
        )
    encoded = json.dumps(schedule, sort_keys=True, separators=(",", ":")).encode()
    return schedule, hashlib.sha256(encoded).hexdigest()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                raise ValidationError(f"{path}:{line_no}: blank line")
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValidationError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(value, dict):
                raise ValidationError(f"{path}:{line_no}: row is not an object")
            rows.append(value)
    return rows


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValidationError(f"{path}: manifest is not an object")
    return value


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _hex64(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _require_row_types(row: dict[str, Any], index: int) -> None:
    missing = sorted(REQUIRED - row.keys())
    if missing:
        raise ValidationError(f"row {index}: missing fields {missing}")
    if row["schema"] != SCHEMA:
        raise ValidationError(f"row {index}: bad schema")
    if row["provenance"] not in ("measured", "synthetic"):
        raise ValidationError(f"row {index}: invalid provenance")
    for field in INT_FIELDS:
        if not _is_int(row[field]):
            raise ValidationError(f"row {index}: {field} must be integer")
        if row[field] < 0:
            raise ValidationError(f"row {index}: {field} is negative")
    for field in BOOL_FIELDS:
        if not isinstance(row[field], bool):
            raise ValidationError(f"row {index}: {field} must be boolean")
    for field in HASH_FIELDS:
        if not _hex64(row[field]):
            raise ValidationError(f"row {index}: {field} must be lowercase sha256")
    if not isinstance(row["setup_id"], str) or not row["setup_id"]:
        raise ValidationError(f"row {index}: empty setup_id")
    if row["event_agent"] != "agent_complete" or row["event_receiver"] != "receiver_complete":
        raise ValidationError(f"row {index}: wrong event markers")


def _validate_rows(rows: list[dict[str, Any]], phase: str, tpad_ns: int | None, gate: bool) -> dict[str, Any]:
    phase_sessions = (1, 2) if phase == "calibration" else (1, 2, 3, 4)
    if gate:
        observed_sessions = {row.get("session") for row in rows if isinstance(row, dict)}
        if len(rows) != 9 or len(observed_sessions) != 1 or not observed_sessions <= set(phase_sessions):
            raise ValidationError(f"{phase} gate: expected nine rows from one valid session")
        sessions = tuple(observed_sessions)
    else:
        sessions = phase_sessions
    blocks = 100 if phase == "calibration" else 125
    expected_arms = ("u",) if phase == "calibration" else ARMS
    expected_count = 9 if gate else len(sessions) * blocks * len(LENGTHS) * len(expected_arms)
    if len(rows) != expected_count:
        raise ValidationError(f"{phase}: expected {expected_count} rows, got {len(rows)}")

    expected_cells: dict[tuple[int, int, int, str], int] = {}
    expected_hash: dict[int, str] = {}
    for session in sessions:
        schedule, digest = canonical_schedule(phase, session)
        expected_hash[session] = digest
        for cell in (schedule[:9] if gate else schedule):
            expected_cells[(session, cell["block"], cell["length"], cell["arm"])] = cell["schedule_position"]

    seen: set[tuple[int, int, int, str]] = set()
    session_identity: dict[int, tuple[str, str, str, str, str]] = {}
    frame_sizes: set[int] = set()
    challenge_hashes: set[str] = set()
    proof_hashes: set[str] = set()
    gate_hashes: set[str] = set()
    source_manifests: set[str] = set()
    provenances: set[str] = set()
    expected_order: list[tuple[int, int, int, str, int]] = []
    for session in sessions:
        schedule, _ = canonical_schedule(phase, session)
        expected_order.extend(
            (session, cell["block"], cell["length"], cell["arm"], cell["schedule_position"])
            for cell in (schedule[:9] if gate else schedule)
        )
    observed_order: list[tuple[int, int, int, str, int]] = []
    last_challenge_send: dict[int, int] = {}
    for index, row in enumerate(rows, 1):
        _require_row_types(row, index)
        if row["phase"] != phase or row["session"] not in sessions:
            raise ValidationError(f"row {index}: phase/session mismatch")
        if row["block"] not in range(1, blocks + 1) or row["length"] not in LENGTHS or row["arm"] not in expected_arms:
            raise ValidationError(f"row {index}: invalid cell coordinates")
        key = (row["session"], row["block"], row["length"], row["arm"])
        if key in seen:
            raise ValidationError(f"row {index}: duplicate cell {key}")
        seen.add(key)
        observed_order.append((row["session"], row["block"], row["length"], row["arm"], row["schedule_position"]))
        if key not in expected_cells or row["schedule_position"] != expected_cells[key]:
            raise ValidationError(f"row {index}: schedule position mismatch")
        if row["schedule_sha256"] != expected_hash[row["session"]]:
            raise ValidationError(f"row {index}: schedule hash mismatch")

        identity = tuple(row[name] for name in ("setup_id", "pk_sha256", "vk_sha256", "config_sha256", "implementation_sha256"))
        if row["session"] in session_identity and session_identity[row["session"]] != identity:
            raise ValidationError(f"row {index}: session identity changed")
        session_identity[row["session"]] = identity

        padded = row["arm"] != "u"
        if row["length_private"] != row["length"] or row["padded_private"] != padded:
            raise ValidationError(f"row {index}: private schedule join mismatch")
        if row["frame_bytes"] <= 0 or row["frame_bytes"] > 1024 * 1024 or row["receiver_frame_bytes"] != row["frame_bytes"]:
            raise ValidationError(f"row {index}: frame size mismatch")
        frame_sizes.add(row["frame_bytes"])
        if not row["arrival_recorded_before_verification"] or not row["proof_verified"] or not row["signature_verified"]:
            raise ValidationError(f"row {index}: correctness gate failed")
        for kind in ("challenge", "proof", "envelope"):
            if row[f"agent_{kind}_sha256"] != row[f"receiver_{kind}_sha256"]:
                raise ValidationError(f"row {index}: independent {kind} digest mismatch")
        if row["agent_challenge_sha256"] in challenge_hashes:
            raise ValidationError(f"row {index}: duplicate challenge")
        if row["agent_proof_sha256"] in proof_hashes:
            raise ValidationError(f"row {index}: duplicate proof")
        challenge_hashes.add(row["agent_challenge_sha256"])
        proof_hashes.add(row["agent_proof_sha256"])
        gate_hashes.add(row["gate_manifest_sha256"])
        source_manifests.add(row["source_manifest_sha256"])
        provenances.add(row["provenance"])

        ordered = [row[name] for name in ("t_agent_ns", "t_prepared_ns", "t_proved_ns", "t_ready_ns", "t_send_call_ns", "t_send_return_ns")]
        if ordered != sorted(ordered):
            raise ValidationError(f"row {index}: agent timestamps out of order")
        if not (row["t_challenge_send_ns"] <= row["t_agent_ns"] and row["t_challenge_send_ns"] <= row["t_arrival_ns"] <= row["t_verify_start_ns"] <= row["t_verify_end_ns"]):
            raise ValidationError(f"row {index}: receiver timestamps out of order")
        if row["t_send_call_ns"] > row["t_arrival_ns"]:
            raise ValidationError(f"row {index}: arrival precedes send call on shared monotonic clock")
        if row["primary_duration_ns"] != row["t_arrival_ns"] - row["t_challenge_send_ns"]:
            raise ValidationError(f"row {index}: primary duration is not complete receiver arrival")
        if row["session"] in last_challenge_send and row["t_challenge_send_ns"] <= last_challenge_send[row["session"]]:
            raise ValidationError(f"row {index}: receiver challenge-send time is not strictly increasing")
        last_challenge_send[row["session"]] = row["t_challenge_send_ns"]
        if row["actual_wait_ns"] != row["t_send_call_ns"] - row["t_ready_ns"]:
            raise ValidationError(f"row {index}: actual wait mismatch")

        if padded:
            if tpad_ns is None or tpad_ns <= 0:
                raise ValidationError("formal padded rows require frozen tpad_ns")
            elapsed = row["t_ready_ns"] - row["t_agent_ns"]
            expected_k = max(1, (elapsed + tpad_ns - 1) // tpad_ns)
            expected_deadline = row["t_agent_ns"] + expected_k * tpad_ns
            expected_overshoot = row["t_send_call_ns"] - expected_deadline
            if row["k"] != expected_k or row["deadline_ns"] != expected_deadline:
                raise ValidationError(f"row {index}: padded deadline/k mismatch")
            if row["t_send_call_ns"] < expected_deadline or row["overshoot_ns"] != expected_overshoot:
                raise ValidationError(f"row {index}: early release or overshoot mismatch")
            if row["overflow"] != (row["k"] > 1):
                raise ValidationError(f"row {index}: overflow mismatch")
        else:
            if (row["k"] != 0 or row["deadline_ns"] != row["t_ready_ns"] or row["overflow"]
                    or row["overshoot_ns"] != row["t_send_call_ns"] - row["deadline_ns"]):
                raise ValidationError(f"row {index}: unpadded release fields invalid")

    if observed_order != expected_order:
        raise ValidationError(f"{phase}: rows are not in canonical randomized execution order")
    if seen != set(expected_cells):
        raise ValidationError(f"{phase}: missing cells")
    if len(frame_sizes) != 1:
        raise ValidationError(f"{phase}: envelope size is not fixed")
    if len(gate_hashes) != 1 or len(source_manifests) != 1 or len(provenances) != 1:
        raise ValidationError(f"{phase}: gate/source/provenance identity changed")
    configs = {value[3] for value in session_identity.values()}
    implementations = {value[4] for value in session_identity.values()}
    if len(configs) != 1 or len(implementations) != 1:
        raise ValidationError(f"{phase}: config/implementation identity changed")
    if len({value[0] for value in session_identity.values()}) != len(sessions):
        raise ValidationError(f"{phase}: setup identities are not fresh")
    if len({value[1] for value in session_identity.values()}) != len(sessions) or len({value[2] for value in session_identity.values()}) != len(sessions):
        raise ValidationError(f"{phase}: PK/VK identities are not fresh")
    return {
        "session_identity": session_identity, "frame_bytes": next(iter(frame_sizes)),
        "schedule_sha256": expected_hash, "challenge_hashes": challenge_hashes,
        "proof_hashes": proof_hashes, "gate_manifest_sha256": next(iter(gate_hashes)),
        "source_manifest_sha256": next(iter(source_manifests)), "provenance": next(iter(provenances)),
    }


def validate_rows(rows: list[dict[str, Any]], phase: str, tpad_ns: int | None = None) -> dict[str, Any]:
    """Validate a complete 600-row calibration or 4500-row formal dataset."""
    return _validate_rows(rows, phase, tpad_ns, gate=False)


def validate_gate_rows(rows: list[dict[str, Any]], phase: str, tpad_ns: int | None = None) -> dict[str, Any]:
    """Validate a nine-row real gate with the same row/timing/hash checks."""
    return _validate_rows(rows, phase, tpad_ns, gate=True)


def nearest_rank(values: Iterable[int], probability: float) -> int:
    ordered = sorted(values)
    if not ordered:
        raise ValidationError("empty statistic")
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def calibration_result(rows: list[dict[str, Any]]) -> dict[str, Any]:
    validation = validate_rows(rows, "calibration")
    by_length = {length: [r["t_ready_ns"] - r["t_agent_ns"] for r in rows if r["length"] == length] for length in LENGTHS}
    p99 = {str(length): nearest_rank(values, 0.99) for length, values in by_length.items()}
    base = max(p99.values()) + 100_000_000
    tpad_ns = ((base + 50_000_000 - 1) // 50_000_000) * 50_000_000
    digest_rows = json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()
    return {
        "rows": len(rows), "per_length_n": {str(k): len(v) for k, v in by_length.items()},
        "nearest_rank_p99_ready_ns": p99, "finite_tail_resolution": "rank 198 of 200 per length",
        "tpad_ns": tpad_ns, "calibration_digest_sha256": hashlib.sha256(digest_rows).hexdigest(),
        "frame_bytes": validation["frame_bytes"], "provenance": validation["provenance"],
        "source_manifest_sha256": validation["source_manifest_sha256"],
        "synthetic": validation["provenance"] == "synthetic",
    }


def validate_input_manifest(manifest: dict[str, Any], validations: dict[str, dict[str, Any]]) -> dict[str, str]:
    if manifest.get("schema") != "r2-analysis-input-manifest-v1":
        raise ValidationError("bad analysis input manifest schema")
    provenance = manifest.get("provenance")
    source_kind = manifest.get("source_kind")
    phases = manifest.get("phases")
    if provenance not in ("measured", "synthetic") or not isinstance(source_kind, str) or not source_kind:
        raise ValidationError("bad analysis provenance/source_kind")
    if not isinstance(phases, dict):
        raise ValidationError("analysis input manifest lacks phases")
    for phase, validation in validations.items():
        phase_manifest = phases.get(phase)
        if not isinstance(phase_manifest, dict):
            raise ValidationError(f"analysis input manifest lacks {phase}")
        source_digest = phase_manifest.get("source_manifest_sha256")
        gate_digest = phase_manifest.get("gate_manifest_sha256")
        if not _hex64(source_digest) or not _hex64(gate_digest):
            raise ValidationError(f"bad {phase} manifest digests")
        if source_digest != validation["source_manifest_sha256"] or gate_digest != validation["gate_manifest_sha256"]:
            raise ValidationError(f"{phase} row/manifest identity mismatch")
        if provenance != validation["provenance"]:
            raise ValidationError(f"{phase} row/manifest provenance mismatch")
    return {"provenance": provenance, "source_kind": source_kind}


def median(values: Iterable[int | float]) -> float:
    return float(statistics.median(list(values)))


def wilson(success: int, total: int) -> list[float]:
    if total <= 0:
        raise ValidationError("Wilson interval with zero total")
    p = success / total
    denominator = 1.0 + Z95 * Z95 / total
    center = (p + Z95 * Z95 / (2 * total)) / denominator
    radius = Z95 * math.sqrt(p * (1 - p) / total + Z95 * Z95 / (4 * total * total)) / denominator
    return [center - radius, center + radius]


def _nearest_label(value: int, centers: dict[Any, float], tie_order: tuple[Any, ...]) -> Any:
    return min(tie_order, key=lambda label: (abs(value - centers[label]), tie_order.index(label)))


def _length_classifier(train_rows: list[dict[str, Any]], test_rows: list[dict[str, Any]]) -> dict[str, Any]:
    centers = {length: median(r["primary_duration_ns"] for r in train_rows if r["length"] == length) for length in LENGTHS}
    predictions = [(_nearest_label(r["primary_duration_ns"], centers, LENGTHS), r["length"]) for r in test_rows]
    confusion = {str(actual): {str(pred): 0 for pred in LENGTHS} for actual in LENGTHS}
    for predicted, actual in predictions:
        confusion[str(actual)][str(predicted)] += 1
    correct = sum(predicted == actual for predicted, actual in predictions)
    return {"correct": correct, "total": len(predictions), "accuracy": correct / len(predictions), "confusion": confusion, "tie_break": "smallest-length"}


def _core_metrics(rows: list[dict[str, Any]]) -> dict[str, float]:
    padded = [r for r in rows if r["arm"] in ("pA", "pB")]
    medians = {length: median(r["primary_duration_ns"] for r in padded if r["length"] == length) for length in LENGTHS}
    metrics: dict[str, float] = {}
    for a, b in ((1, 2), (1, 3), (2, 3)):
        metrics[f"median_absdiff_ns_{a}_{b}"] = abs(medians[a] - medians[b])
    for length in LENGTHS:
        selected = [r for r in padded if r["length"] == length]
        metrics[f"wait_mean_ns_pooled_padded_len{length}"] = statistics.fmean(r["actual_wait_ns"] for r in selected)
        metrics[f"overflow_fraction_pooled_padded_len{length}"] = statistics.fmean(1.0 if r["overflow"] else 0.0 for r in selected)
        for arm in ("pA", "pB"):
            arm_rows = [r for r in selected if r["arm"] == arm]
            metrics[f"wait_mean_ns_{arm}_len{length}"] = statistics.fmean(r["actual_wait_ns"] for r in arm_rows)
            metrics[f"overflow_fraction_{arm}_len{length}"] = statistics.fmean(1.0 if r["overflow"] else 0.0 for r in arm_rows)
    return metrics


def _bootstrap(rows: list[dict[str, Any]], replicates: int = 1000) -> dict[str, list[float]]:
    by_session_block: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_session_block[(row["session"], row["block"])].append(row)
    rng = random.Random(2026102980)
    samples: dict[str, list[float]] = defaultdict(list)
    for _ in range(replicates):
        replicate: list[dict[str, Any]] = []
        for session in [rng.choice((1, 2, 3, 4)) for _ in range(4)]:
            for _block_occurrence in range(125):
                block = rng.randint(1, 125)
                replicate.extend(by_session_block[(session, block)])
        for name, value in _core_metrics(replicate).items():
            samples[name].append(value)
    if replicates != 1000:
        return {name: [min(values), max(values)] for name, values in samples.items()}
    return {name: [sorted(values)[24], sorted(values)[974]] for name, values in samples.items()}


def formal_result(rows: list[dict[str, Any]], tpad_ns: int, bootstrap_reps: int = 1000) -> dict[str, Any]:
    validation = validate_rows(rows, "formal", tpad_ns)
    train = [r for r in rows if r["session"] in (1, 3)]
    test = [r for r in rows if r["session"] in (2, 4)]
    padded_train = [r for r in train if r["arm"] in ("pA", "pB")]
    padded_test = [r for r in test if r["arm"] in ("pA", "pB")]
    length_classifiers = {
        "pooled_padded": _length_classifier(padded_train, padded_test),
        **{
            arm: _length_classifier([r for r in train if r["arm"] == arm], [r for r in test if r["arm"] == arm])
            for arm in ARMS
        },
    }
    length_correct = length_classifiers["pooled_padded"]["correct"]
    length_total = length_classifiers["pooled_padded"]["total"]

    aa_centers = {
        length: {arm: median(r["primary_duration_ns"] for r in train if r["length"] == length and r["arm"] == arm) for arm in ("pA", "pB")}
        for length in LENGTHS
    }
    aa_predictions = [(_nearest_label(r["primary_duration_ns"], aa_centers[r["length"]], ("pA", "pB")), r["arm"]) for r in test if r["arm"] in ("pA", "pB")]
    aa_correct = sum(predicted == actual for predicted, actual in aa_predictions)
    aa_confusion = {actual: {predicted: 0 for predicted in ("pA", "pB")} for actual in ("pA", "pB")}
    for predicted, actual in aa_predictions:
        aa_confusion[actual][predicted] += 1
    aa_per_length: dict[str, Any] = {}
    for length in LENGTHS:
        predictions = [
            (_nearest_label(r["primary_duration_ns"], aa_centers[length], ("pA", "pB")), r["arm"])
            for r in test if r["length"] == length and r["arm"] in ("pA", "pB")
        ]
        confusion_for_length = {actual: {predicted: 0 for predicted in ("pA", "pB")} for actual in ("pA", "pB")}
        for predicted, actual in predictions:
            confusion_for_length[actual][predicted] += 1
        correct = sum(predicted == actual for predicted, actual in predictions)
        aa_per_length[str(length)] = {"correct": correct, "total": len(predictions), "accuracy": correct / len(predictions), "confusion": confusion_for_length, "tie_break": "pA"}

    cell = {(r["session"], r["block"], r["length"], r["arm"]): r for r in rows}
    paired = [
        cell[(s, b, length, "pA")]["primary_duration_ns"] - cell[(s, b, length, "pB")]["primary_duration_ns"]
        for s in (1, 2, 3, 4) for b in range(1, 126) for length in LENGTHS
    ]
    paired_by_length = {
        str(length): [
            cell[(s, b, length, "pA")]["primary_duration_ns"] - cell[(s, b, length, "pB")]["primary_duration_ns"]
            for s in (1, 2, 3, 4) for b in range(1, 126)
        ] for length in LENGTHS
    }
    core = _core_metrics(rows)
    pairwise = {name: value for name, value in core.items() if name.startswith("median_absdiff")}
    primary_pass = max(pairwise.values()) <= 15_000_000 and length_correct / length_total <= 0.45

    groups: dict[str, Any] = {}
    for arm in ARMS:
        for length in LENGTHS:
            selected = [r for r in rows if r["arm"] == arm and r["length"] == length]
            overflow = sum(r["overflow"] for r in selected)
            groups[f"{arm}_length{length}"] = {
                "n": len(selected), "primary_median_ns": median(r["primary_duration_ns"] for r in selected),
                "ready_median_ns": median(r["t_ready_ns"] - r["t_agent_ns"] for r in selected),
                "wait_mean_ns": statistics.fmean(r["actual_wait_ns"] for r in selected),
                "wait_q50_ns": median(r["actual_wait_ns"] for r in selected),
                "wait_q99_ns": nearest_rank((r["actual_wait_ns"] for r in selected), 0.99),
                "overshoot_q99_ns": nearest_rank((r["overshoot_ns"] for r in selected), 0.99),
                "overflow_count": overflow, "overflow_rate": overflow / len(selected),
                "overflow_wilson95": wilson(overflow, len(selected)),
                "phase_medians_ns": {
                    "prepare": median(r["t_prepared_ns"] - r["t_agent_ns"] for r in selected),
                    "prove": median(r["t_proved_ns"] - r["t_prepared_ns"] for r in selected),
                    "finalize_sign_serialize": median(r["t_ready_ns"] - r["t_proved_ns"] for r in selected),
                    "send_call_to_return": median(r["t_send_return_ns"] - r["t_send_call_ns"] for r in selected),
                    "receiver_verify": median(r["t_verify_end_ns"] - r["t_verify_start_ns"] for r in selected),
                },
            }

    session_medians = {
        str(session): {
            f"{arm}_length{length}": median(
                r["primary_duration_ns"] for r in rows
                if r["session"] == session and r["arm"] == arm and r["length"] == length
            )
            for arm in ARMS for length in LENGTHS
        } for session in (1, 2, 3, 4)
    }

    return {
        "rows": len(rows), "tpad_ns": tpad_ns, "frame_bytes": validation["frame_bytes"],
        "primary": {
            "pairwise_abs_median_difference_ns": pairwise,
            "length_classifier": length_classifiers["pooled_padded"],
            "length_classifiers": length_classifiers,
            "thresholds": {"max_pairwise_median_difference_ns": 15_000_000, "max_accuracy": 0.45},
            "pass": primary_pass,
        },
        "aa_classifier": {"correct": aa_correct, "total": len(aa_predictions), "accuracy": aa_correct / len(aa_predictions), "confusion": aa_confusion, "tie_break": "pA", "per_length": aa_per_length},
        "paired_aa_pA_minus_pB_ns": {
            "all_lengths": {"n": len(paired), "mean": statistics.fmean(paired), "median": median(paired)},
            "per_length": {
                length: {"n": len(values), "mean": statistics.fmean(values), "median": median(values)}
                for length, values in paired_by_length.items()
            },
        },
        "session_medians_ns": session_medians, "groups": groups, "bootstrap95": _bootstrap(rows, bootstrap_reps),
        "overflow_policy": "all overflow rows retained in every primary statistic",
        "provenance": validation["provenance"], "source_manifest_sha256": validation["source_manifest_sha256"],
        "synthetic": validation["provenance"] == "synthetic",
    }


def analyze(calibration_rows: list[dict[str, Any]], formal_rows: list[dict[str, Any]], input_manifest: dict[str, Any], bootstrap_reps: int = 1000) -> dict[str, Any]:
    calibration = calibration_result(calibration_rows)
    formal_validation = validate_rows(formal_rows, "formal", calibration["tpad_ns"])
    cal_validation = validate_rows(calibration_rows, "calibration")
    for position, label in ((0, "setup"), (1, "PK"), (2, "VK")):
        calibration_values = {value[position] for value in cal_validation["session_identity"].values()}
        formal_values = {value[position] for value in formal_validation["session_identity"].values()}
        if calibration_values & formal_values:
            raise ValidationError(f"calibration and formal {label} identities overlap")
    cal_config_impl = {(v[3], v[4]) for v in cal_validation["session_identity"].values()}
    formal_config_impl = {(v[3], v[4]) for v in formal_validation["session_identity"].values()}
    if cal_config_impl != formal_config_impl:
        raise ValidationError("calibration and formal config/implementation identities differ")
    if cal_validation["challenge_hashes"] & formal_validation["challenge_hashes"]:
        raise ValidationError("challenge replay across calibration/formal")
    if cal_validation["proof_hashes"] & formal_validation["proof_hashes"]:
        raise ValidationError("proof reuse across calibration/formal")
    if cal_validation["provenance"] != formal_validation["provenance"]:
        raise ValidationError("calibration and formal provenance differ")
    metadata = validate_input_manifest(input_manifest, {"calibration": cal_validation, "formal": formal_validation})
    provenance = metadata["provenance"]
    return {
        "schema": "r2-analysis-v1", "provenance": provenance, "source_kind": metadata["source_kind"],
        "synthetic": provenance == "synthetic", "calibration": calibration,
        "formal": formal_result(formal_rows, calibration["tpad_ns"], bootstrap_reps),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--formal", type=Path)
    parser.add_argument("--validation-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        calibration_rows = load_jsonl(args.calibration)
        input_manifest = load_json(args.validation_manifest)
        if args.formal is None:
            validation = validate_rows(calibration_rows, "calibration")
            metadata = validate_input_manifest(input_manifest, {"calibration": validation})
            result = {"schema": "r2-calibration-analysis-v1", **metadata, "synthetic": metadata["provenance"] == "synthetic", "calibration": calibration_result(calibration_rows)}
        else:
            result = analyze(calibration_rows, load_jsonl(args.formal), input_manifest)
    except (OSError, ValidationError, ValueError, statistics.StatisticsError) as exc:
        parser.error(str(exc))
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

