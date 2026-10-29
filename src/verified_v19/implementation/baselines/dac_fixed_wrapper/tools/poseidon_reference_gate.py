#!/usr/bin/env python3
"""Run the pinned Poseidon authors' round calculator without editing it.

This wrapper is an evidence gate. It does not replace the reference script,
derive arkworks constants, or claim an end-to-end security level.
"""

import argparse
import ast
import difflib
import hashlib
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path


EXPECTED_COMMIT = "9d80ec0473ad7cde5a12f3aac46439ad0da68c0a"
FQ_MODULUS = int(
    "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177"
)
WIDTH = 3
ALPHA = 5
SECURITY_BITS = 128
SECURITY_MARGIN = True
EXPECTED_RECOMMENDED_ROUNDS = (8, 55)
IMPLEMENTED_ROUNDS = (8, 57)
EXPECTED_SCRIPT_SHA256 = "b850ecf8d403c3ac3fced726deff540574ec3ca713f1f19cad55beff4ea1d094"
EXPECTED_DIVISION_LINES = {
    21: "n = int(ceil(float(N_fixed) / t_fixed))",
    41: "n = ceil(float(N) / t)",
    45: "R_F_4 = float(0.18 * min(n, M) - 1 - R_P) / (t - 1) # Groebner 2",
    54: "n = ceil(float(N) / t)",
    58: "R_F_4 = float(0.14 * min(n, M) - 1 - R_P) / (t - 1) # Groebner 2",
    67: "n = ceil(float(N) / t)",
    70: "R_F_2 = float(log(t, 2) + 0.5 * min(n, M) - R_P) / log(t, 2) # Groebner 1",
    71: "R_F_3 = float(0.25 * min(n, M) - 1 - R_P) / (t - 1) # Groebner 2",
    84: "n = ceil(float(N) / t)",
    146: "n = int(ceil(float(N_fixed) / t_fixed))",
    175: "n = int(ceil(float(N_fixed) / t_fixed))",
}


def translate_python2_print_statements(source: str) -> tuple[str, int]:
    """Apply the only compatibility edit needed by the pinned Python 2 file."""
    translated: list[str] = []
    changed = 0
    for line in source.splitlines(keepends=True):
        newline = "\n" if line.endswith("\n") else ""
        content = line[:-1] if newline else line
        stripped = content.lstrip()
        if stripped.startswith("print >>"):
            raise SystemExit("unsupported Python 2 redirected print statement")
        if stripped.startswith("print "):
            indent = content[: len(content) - len(stripped)]
            translated.append(f"{indent}print({stripped[6:]}){newline}")
            changed += 1
        else:
            translated.append(line)
    if changed == 0:
        raise SystemExit("pinned Python 2 calculator had no print statements to translate")
    return "".join(translated), changed


def value_after(lines: list[str], prefix: str) -> int:
    matches = [line for line in lines if line.startswith(prefix)]
    if not matches:
        raise SystemExit(f"missing official calculator output: {prefix}")
    return int(matches[0][len(prefix) :])


def audit_python2_numeric_semantics(source: str) -> list[int]:
    division_lines = {
        number: line.strip()
        for number, line in enumerate(source.splitlines(), 1)
        if " / " in line
    }
    if division_lines != EXPECTED_DIVISION_LINES:
        raise SystemExit("Python 2 division audit no longer matches pinned source")
    # Every division has an explicitly floating left operand: float(...), or
    # ceil(float(...))'s expression. Python 2 and Python 3 therefore both use
    # real division. range() is consumed only by for-loops, and every ceil()
    # value reaching the published result vector is converted through int().
    return sorted(division_lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--script", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--compatibility-dir", required=True, type=Path)
    parser.add_argument("--implementation-source", required=True, type=Path)
    args = parser.parse_args()

    if args.commit != EXPECTED_COMMIT:
        raise SystemExit(f"wrong reference commit: {args.commit}")
    script_bytes = args.script.read_bytes()
    script_sha256 = hashlib.sha256(script_bytes).hexdigest()
    if script_sha256 != EXPECTED_SCRIPT_SHA256:
        raise SystemExit(f"wrong pinned calculator bytes: {script_sha256}")
    source = script_bytes.decode("utf-8")
    division_lines = audit_python2_numeric_semantics(source)
    translated, translated_print_statements = translate_python2_print_statements(source)
    translated_bytes = translated.encode("utf-8")
    translated_sha256 = hashlib.sha256(translated_bytes).hexdigest()
    compatibility_dir = args.compatibility_dir.resolve()
    if compatibility_dir.exists():
        raise SystemExit(f"refusing to overwrite compatibility evidence: {compatibility_dir}")
    compatibility_dir.mkdir(parents=True)
    retained_translation = compatibility_dir / "calc_round_numbers.python3-compat.py"
    retained_translation.write_bytes(translated_bytes)
    patch_text = "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            translated.splitlines(keepends=True),
            fromfile="calc_round_numbers.py.official-python2",
            tofile="calc_round_numbers.python3-compat.py",
        )
    )
    patch_path = compatibility_dir / "PY2_TO_PY3_PRINT_ONLY.patch"
    patch_path.write_text(patch_text)
    patch_sha256 = hashlib.sha256(patch_text.encode("utf-8")).hexdigest()
    compatibility_record = {
        "schema": "plan-a-poseidon-python2-compatibility-v1",
        "official_script_sha256": script_sha256,
        "official_original_bytes_executed": False,
        "translation": "print statements only; exact original hash gated",
        "translated_print_statements": translated_print_statements,
        "translated_script_sha256": translated_sha256,
        "patch_sha256": patch_sha256,
        "python2_division_operator_lines": division_lines,
        "all_divisions_force_real_division_in_python2_and_python3": True,
        "range_semantics_relevant": False,
        "ceil_type_difference_affects_integer_result": False,
    }
    compatibility_json = compatibility_dir / "COMPATIBILITY.json"
    compatibility_json.write_text(
        json.dumps(compatibility_record, indent=2, sort_keys=True) + "\n"
    )
    calculator_n = FQ_MODULUS.bit_length() * WIDTH
    with tempfile.TemporaryDirectory() as temporary:
        translated_path = Path(temporary) / retained_translation.name
        translated_path.write_bytes(retained_translation.read_bytes())
        completed = subprocess.run(
            [
                sys.executable,
                str(translated_path),
                str(calculator_n),
                str(WIDTH),
                str(SECURITY_BITS),
                "1",
                "1",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
    if completed.returncode != 0:
        raise SystemExit(
            f"translated official calculator failed ({completed.returncode}):\n"
            f"{completed.stderr}"
        )
    stdout_lines = completed.stdout.splitlines()
    recommendation = f"Recommendation for N={calculator_n}, t={WIDTH}:"
    try:
        recommendation_index = stdout_lines.index(recommendation)
    except ValueError as error:
        raise SystemExit("official calculator target recommendation missing") from error
    target_end = recommendation_index + 5
    if len(stdout_lines) < target_end:
        raise SystemExit("official calculator target output truncated")
    target_lines = stdout_lines[:target_end]
    additional_lines = stdout_lines[target_end:]
    official_result = ast.literal_eval(stdout_lines[recommendation_index - 1])
    if not isinstance(official_result, list) or len(official_result) != 4:
        raise SystemExit("unexpected official calculator result vector")
    rounds = (
        value_after(target_lines, "R_F = "),
        value_after(target_lines, "R_P = "),
    )
    if rounds != EXPECTED_RECOMMENDED_ROUNDS:
        raise SystemExit(
            f"official recommendation changed: got {rounds}, "
            f"expected {EXPECTED_RECOMMENDED_ROUNDS}"
        )
    if [int(value) for value in official_result[:2]] != list(rounds):
        raise SystemExit("official result vector and printed rounds disagree")
    implementation_bytes = args.implementation_source.read_bytes()
    implementation_text = implementation_bytes.decode("utf-8")
    implementation_markers = [
        f"const POSEIDON_FULL_ROUNDS: usize = {IMPLEMENTED_ROUNDS[0]};",
        f"const POSEIDON_PARTIAL_ROUNDS: usize = {IMPLEMENTED_ROUNDS[1]};",
        f"RF={IMPLEMENTED_ROUNDS[0]}|RP={IMPLEMENTED_ROUNDS[1]}|",
    ]
    missing_markers = [
        marker for marker in implementation_markers if marker not in implementation_text
    ]
    if missing_markers:
        raise SystemExit(
            f"implemented schedule does not match frozen source: {missing_markers}"
        )
    if IMPLEMENTED_ROUNDS[0] != rounds[0] or IMPLEMENTED_ROUNDS[1] < rounds[1]:
        raise SystemExit(
            "implemented schedule must retain the recommended full rounds and "
            "at least the recommended partial rounds"
        )

    print(
        json.dumps(
            {
                "reference_commit": args.commit,
                "reference_script_sha256": script_sha256,
                "reference_script_path": str(args.script),
                "python2_compatibility_mode": "exact-hash-gated print-statement translation in a temporary copy",
                "translated_print_statements": translated_print_statements,
                "translated_temporary_script_sha256": translated_sha256,
                "official_original_bytes_modified": False,
                "official_original_bytes_executed": False,
                "compatibility_copy_executed": True,
                "compatibility_patch_sha256": patch_sha256,
                "compatibility_record_sha256": hashlib.sha256(
                    compatibility_json.read_bytes()
                ).hexdigest(),
                "python2_division_operator_lines": division_lines,
                "all_divisions_force_real_division_in_python2_and_python3": True,
                "official_cli_N": calculator_n,
                "official_cli_N_semantics": "total state bit width N=t*n=3*377; field element bit length n is recorded separately as 377",
                "official_cli_t": WIDTH,
                "official_cli_M": SECURITY_BITS,
                "official_cli_field_case": 1,
                "official_cli_sbox_case": 1,
                "official_stdout_sha256": hashlib.sha256(
                    completed.stdout.encode("utf-8")
                ).hexdigest(),
                "reference_import_stdout": "\n".join(additional_lines) + "\n",
                "target_stdout": "\n".join(target_lines) + "\n",
                "field_modulus_decimal": str(FQ_MODULUS),
                "field_modulus_bits": FQ_MODULUS.bit_length(),
                "gcd_alpha_p_minus_one": math.gcd(ALPHA, FQ_MODULUS - 1),
                "width": WIDTH,
                "alpha": ALPHA,
                "security_bits": SECURITY_BITS,
                "security_margin": SECURITY_MARGIN,
                "recommended_full_rounds": rounds[0],
                "recommended_partial_rounds": rounds[1],
                "implemented_full_rounds": IMPLEMENTED_ROUNDS[0],
                "implemented_partial_rounds": IMPLEMENTED_ROUNDS[1],
                "implementation_extra_partial_rounds": IMPLEMENTED_ROUNDS[1]
                - rounds[1],
                "implementation_source_path": str(args.implementation_source),
                "implementation_source_sha256": hashlib.sha256(
                    implementation_bytes
                ).hexdigest(),
                "implementation_schedule_markers": implementation_markers,
                "implemented_schedule_matches_frozen_source": True,
                "implemented_schedule_is_exact_official_recommendation": IMPLEMENTED_ROUNDS
                == rounds,
                "min_sbox_cost": int(official_result[2]),
                "min_size_cost": int(official_result[3]),
                "gate_passed": True,
                "scope": "deprecated pinned reference round-number calculator only; the implementation adds two partial rounds beyond the observed recommendation; constants/MDS and end-to-end wrapper security are separate",
            },
            indent=2,
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
