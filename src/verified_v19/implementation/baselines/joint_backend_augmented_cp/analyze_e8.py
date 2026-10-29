#!/usr/bin/env python3
"""Fail-closed validation and paired analysis for the E8 three-backend gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Iterable


BACKENDS = ("inline", "poseidon_split", "cp_rsa_split")
PHASES = ("setup_ms", "prove_ms", "verify_ms")
EXPECTED_ARTIFACTS = (
    "inline-pk.bin",
    "inline-vk.bin",
    "inline-proof.bin",
    "poseidon-core-pk.bin",
    "poseidon-core-vk.bin",
    "poseidon-member-pk.bin",
    "poseidon-member-vk.bin",
    "poseidon-core-proof.bin",
    "poseidon-member-proof.bin",
    "cp-core-pk.bin",
    "cp-core-vk.bin",
    "cp-core-proof.bin",
    "cp-membership-proof.bin",
    "cp-statement.bin",
    "cp-parameters.bin",
    "cp-current-bridge-parameters.bin",
    "mapping-certificate.bin",
    "mapping-public-key.bin",
)
LIFECYCLE_KEYS = (
    "old_prime_absent",
    "successor_prime_present",
    "independent_member_survives",
    "old_mapping_not_live",
    "retired_prime_reuse_rejected",
    "wrong_g_rejected",
    "wrong_h_rejected",
    "wrong_declared_h_rejected",
    "swapped_g_h_rejected",
    "wrong_commitment_rejected",
    "cross_prime_commitment_splice_rejected",
    "wrong_position_rejected",
    "validly_signed_wrong_position_rejected",
    "different_prime_rejected",
    "alternate_prime_for_live_generation_rejected",
    "canonical_point_roundtrip_and_scalar_modulus_checked",
    "base_field_modulus_checked",
    "legacy_to_current_coordinate_roundtrip_checked",
    "current_curve_and_subgroup_checked",
    "ordered_nonidentity_distinct_g_h_checked",
    "fresh_successor_all_three_backends",
    "retired_proof_all_three_backends_rejected",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def finite_positive(value: Any, label: str) -> float:
    require(isinstance(value, (int, float)), f"{label}: expected a number")
    converted = float(value)
    require(math.isfinite(converted) and converted > 0.0, f"{label}: expected finite positive value")
    return converted


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    index = round(probability * (len(ordered) - 1))
    return ordered[index]


def summarize(values: Iterable[float], rng: random.Random, resamples: int) -> dict[str, Any]:
    observed = [float(value) for value in values]
    require(bool(observed), "cannot summarize an empty sample")
    medians = []
    for _ in range(resamples):
        medians.append(statistics.median(observed[rng.randrange(len(observed))] for _ in observed))
    return {
        "n": len(observed),
        "median": statistics.median(observed),
        "min": min(observed),
        "max": max(observed),
        "median_percentile_bootstrap_95": [percentile(medians, 0.025), percentile(medians, 0.975)],
    }


def artifact_size_fields(sample: dict[str, Any]) -> dict[str, int]:
    inline = sample["inline"]
    poseidon = sample["poseidon_split"]
    cp = sample["cp_rsa_split"]
    return {
        "inline_pk_bytes": inline["pk_bytes"],
        "inline_vk_bytes": inline["vk_bytes"],
        "inline_proof_bytes": inline["proof_bytes"],
        "poseidon_core_pk_bytes": poseidon["core_pk_bytes"],
        "poseidon_membership_pk_bytes": poseidon["membership_pk_bytes"],
        "poseidon_core_vk_bytes": poseidon["core_vk_bytes"],
        "poseidon_membership_vk_bytes": poseidon["membership_vk_bytes"],
        "poseidon_proof_bundle_bytes": poseidon["proof_bundle_bytes"],
        "cp_core_pk_bytes": cp["core_pk_bytes"],
        "cp_core_vk_bytes": cp["core_vk_bytes"],
        "cp_proof_bundle_bytes": cp["proof_bundle_bytes"],
        "cp_parameter_bytes": cp["cp_parameter_bytes"],
        "cp_bridge_parameter_bytes": cp["bridge_parameter_bytes"],
        "mapping_certificate_bytes": cp["mapping_certificate_bytes"],
        "mapping_public_key_bytes": cp["mapping_public_key_bytes"],
    }


def validate_sample(sample: dict[str, Any], index: int, artifact_root: Path) -> None:
    require(sample.get("repetition") == index, f"sample {index}: repetition mismatch")
    order = sample.get("backend_order")
    require(isinstance(order, list) and sorted(order) == sorted(BACKENDS), f"sample {index}: invalid backend order")
    semantics = sample.get("same_canonical_semantics", {})
    require(semantics.get("joint_fixture") is True, f"sample {index}: Joint fixture mismatch")
    require(semantics.get("mapping_record") is True, f"sample {index}: mapping record mismatch")
    require(semantics.get("hidden_prime_leaf_position") is True, f"sample {index}: hidden binding mismatch")
    require(semantics.get("public_core_inputs") == 27, f"sample {index}: public input count mismatch")
    require(sample.get("full_proof_verify") == {backend: True for backend in BACKENDS}, f"sample {index}: incomplete proof/verify gate")
    require(sample.get("public_mutations_rejected") == {backend: 27 for backend in BACKENDS}, f"sample {index}: incomplete 27-field mutation matrix")

    relation = sample.get("relation_metrics", {})
    for component in ("augmented_inline", "augmented_core", "poseidon_membership"):
        metrics = relation.get(component)
        require(isinstance(metrics, dict), f"sample {index}: missing {component} relation metrics")
        for field in ("constraints", "instances", "witnesses"):
            require(isinstance(metrics.get(field), int) and metrics[field] > 0, f"sample {index}: invalid {component}.{field}")

    lifecycle = sample.get("lifecycle", {})
    for key in LIFECYCLE_KEYS:
        require(lifecycle.get(key) is True, f"sample {index}: lifecycle gate {key} failed")
    if index == 0:
        require(lifecycle.get("same_crs_enabled_lengths_checked") is True, "sample 0: enabled-length gate did not run")
        require(lifecycle.get("same_crs_enabled_lengths") == [1, 2, 3], "sample 0: enabled-length matrix incomplete")
    else:
        require(lifecycle.get("same_crs_enabled_lengths_checked") is False, f"sample {index}: unexpected enabled-length timing work")
        require(lifecycle.get("same_crs_enabled_lengths") is None, f"sample {index}: misleading enabled-length claim")
    for phase in (
        "initial_mapping_and_accumulator_ms",
        "successor_prime_generation_ms",
        "replace_and_confirm_ms",
    ):
        finite_positive(lifecycle.get(phase), f"sample {index}.{phase}")

    for backend in BACKENDS:
        measurements = sample.get(backend)
        require(isinstance(measurements, dict), f"sample {index}: missing {backend}")
        for phase in PHASES:
            finite_positive(measurements.get(phase), f"sample {index}.{backend}.{phase}")

    rep_root = artifact_root / f"rep-{index}"
    require(rep_root.is_dir(), f"sample {index}: missing artifact directory")
    for name in EXPECTED_ARTIFACTS:
        path = rep_root / name
        require(path.is_file() and path.stat().st_size > 0, f"sample {index}: missing artifact {name}")
    inline = sample["inline"]
    poseidon = sample["poseidon_split"]
    cp = sample["cp_rsa_split"]
    expected_sizes = {
        "inline-pk.bin": inline["pk_bytes"],
        "inline-vk.bin": inline["vk_bytes"],
        "inline-proof.bin": inline["proof_bytes"],
        "poseidon-core-pk.bin": poseidon["core_pk_bytes"],
        "poseidon-member-pk.bin": poseidon["membership_pk_bytes"],
        "poseidon-core-vk.bin": poseidon["core_vk_bytes"],
        "poseidon-member-vk.bin": poseidon["membership_vk_bytes"],
        "cp-core-pk.bin": cp["core_pk_bytes"],
        "cp-core-vk.bin": cp["core_vk_bytes"],
        "cp-parameters.bin": cp["cp_parameter_bytes"],
        "cp-current-bridge-parameters.bin": cp["bridge_parameter_bytes"],
        "mapping-certificate.bin": cp["mapping_certificate_bytes"],
        "mapping-public-key.bin": cp["mapping_public_key_bytes"],
    }
    for name, expected in expected_sizes.items():
        require((rep_root / name).stat().st_size == expected, f"sample {index}: size mismatch for {name}")
    require(
        sum((rep_root / name).stat().st_size for name in ("poseidon-core-proof.bin", "poseidon-member-proof.bin"))
        == poseidon["proof_bundle_bytes"],
        f"sample {index}: Poseidon proof bundle size mismatch",
    )
    require(
        sum((rep_root / name).stat().st_size for name in ("cp-core-proof.bin", "cp-membership-proof.bin", "cp-statement.bin"))
        == cp["proof_bundle_bytes"],
        f"sample {index}: CP proof bundle size mismatch",
    )
    require(sha256(rep_root / "cp-parameters.bin") == sample["cp_rsa_split"]["cp_parameter_sha256"], f"sample {index}: CP parameter digest mismatch")
    require(sha256(rep_root / "cp-current-bridge-parameters.bin") == sample["cp_rsa_split"]["bridge_parameter_sha256"], f"sample {index}: bridge digest mismatch")


def analyze(args: argparse.Namespace) -> dict[str, Any]:
    result_path = args.input.resolve()
    artifact_root = args.artifact_root.resolve()
    source_manifest = args.source_manifest.resolve()
    require(result_path.is_file(), "missing results.json")
    require(source_manifest.is_file(), "missing source manifest")
    result = json.loads(result_path.read_text(encoding="utf-8"))
    require(result.get("schema") == "plan-a-e8-certified-state-map-three-backend-v1", "wrong result schema")
    require(result.get("status") == "success", "unsuccessful E8 result")
    require("RSA-2048" in result.get("cp_security_boundary", ""), "missing CP/RSA parameter boundary")
    require("not labeled 128-bit-equivalent" in result.get("cp_security_boundary", ""), "missing cross-backend strength boundary")
    require("mapping issuer" in result.get("additional_trust_and_setup_duties", ""), "missing mapping-issuer duty boundary")
    samples = result.get("samples")
    repetitions = result.get("fresh_setup_repetitions")
    require(isinstance(samples, list) and isinstance(repetitions, int) and len(samples) == repetitions, "sample/repetition mismatch")
    if args.mode == "correctness":
        require(repetitions == 1, "correctness bring-up must contain exactly one repetition")
    else:
        require(repetitions >= 12 and repetitions % 6 == 0, "formal timing requires complete six-order cycles and at least 12 fresh setups")

    for index, sample in enumerate(samples):
        require(isinstance(sample, dict), f"sample {index}: expected object")
        validate_sample(sample, index, artifact_root)

    orders = [">".join(sample["backend_order"]) for sample in samples]
    order_counts = Counter(orders)
    position_counts = {
        backend: [sum(sample["backend_order"][position] == backend for sample in samples) for position in range(3)]
        for backend in BACKENDS
    }
    if args.mode == "formal":
        require(len(order_counts) == 6 and len(set(order_counts.values())) == 1, "six backend orders are not balanced")
        expected_position_count = repetitions // 3
        require(all(counts == [expected_position_count] * 3 for counts in position_counts.values()), "backend positions are not balanced")

    rng = random.Random(args.bootstrap_seed)
    backend_summaries: dict[str, Any] = {}
    for backend in BACKENDS:
        backend_summaries[backend] = {
            phase: summarize((sample[backend][phase] for sample in samples), rng, args.bootstrap_repetitions)
            for phase in PHASES
        }
    paired: dict[str, Any] = {}
    for phase in PHASES:
        paired[phase] = {}
        for left_index, left in enumerate(BACKENDS):
            for right in BACKENDS[left_index + 1 :]:
                label = f"{left}_minus_{right}"
                differences = [sample[left][phase] - sample[right][phase] for sample in samples]
                paired[phase][label] = {
                    "direction": f"{left} minus {right}",
                    **summarize(differences, rng, args.bootstrap_repetitions),
                }

    artifact_fields = artifact_size_fields(samples[0])
    for index, sample in enumerate(samples[1:], start=1):
        current = artifact_size_fields(sample)
        require(set(current) == set(artifact_fields), f"sample {index}: artifact accounting fields differ")
    artifact_summaries = {
        field: {
            "n": repetitions,
            "median": statistics.median(artifact_size_fields(sample)[field] for sample in samples),
            "min": min(artifact_size_fields(sample)[field] for sample in samples),
            "max": max(artifact_size_fields(sample)[field] for sample in samples),
        }
        for field in artifact_fields
    }

    return {
        "schema": "plan-a-e8-certified-state-map-three-backend-analysis-v1",
        "validated": True,
        "mode": args.mode,
        "results_sha256": sha256(result_path),
        "source_manifest_sha256": sha256(source_manifest),
        "fresh_setup_repetitions": repetitions,
        "order_schedule": "all six permutations, repeated in repetition-index order",
        "order_counts": dict(sorted(order_counts.items())),
        "backend_position_counts": position_counts,
        "bootstrap": {
            "estimand": "median across paired fresh-setup trials",
            "interval": "95% percentile bootstrap",
            "resamples": args.bootstrap_repetitions,
            "seed": args.bootstrap_seed,
        },
        "correctness": {
            "same_augmented_relation_all_three_backends": True,
            "full_proof_verify_all_trials": True,
            "all_27_public_mutations_rejected_all_trials": True,
            "bridge_negative_matrix_all_trials": True,
            "successor_lifecycle_all_trials": True,
            "same_crs_enabled_lengths_checked_once": True,
            "all_artifacts_retained_and_nonempty": True,
            "cp_and_bridge_digests_match": True,
        },
        "timings_ms": backend_summaries,
        "paired_signed_differences_ms": paired,
        "mapping_and_lifecycle_ms": {
            phase: summarize(
                (sample["lifecycle"][phase] for sample in samples),
                rng,
                args.bootstrap_repetitions,
            )
            for phase in (
                "initial_mapping_and_accumulator_ms",
                "successor_prime_generation_ms",
                "replace_and_confirm_ms",
            )
        },
        "artifact_bytes": artifact_summaries,
        "interpretation_boundary": (
            "Wall times are separated into setup, prove, verify and mapping/accumulator transition. "
            "They compare this certified-state-map augmented relation on one host; they do not "
            "measure a production MPC ceremony, network delivery, or the retained native Joint relation."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--artifact-root", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("correctness", "formal"))
    parser.add_argument("--bootstrap-repetitions", type=int, default=10_000)
    parser.add_argument("--bootstrap-seed", type=int, default=4_538_008)
    args = parser.parse_args()
    require(args.bootstrap_repetitions == 10_000, "formal gate fixes 10,000 bootstrap resamples")
    value = analyze(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(args.output), "mode": args.mode}))


if __name__ == "__main__":
    main()
