import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from analyze_r2 import ValidationError, analyze, calibration_result, canonical_schedule, formal_result, validate_rows


def h(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def synthetic_manifest():
    return {
        "schema": "r2-analysis-input-manifest-v1",
        "provenance": "synthetic",
        "source_kind": "unit_test_fixture",
        "phases": {
            phase: {
                "source_manifest_sha256": h(f"{phase}-source-manifest"),
                "gate_manifest_sha256": h("gate-manifest"),
            }
            for phase in ("calibration", "formal")
        },
    }


def synthetic_rows(phase: str, tpad_ns: int = 200_000_000):
    sessions = (1, 2) if phase == "calibration" else (1, 2, 3, 4)
    rows = []
    frame_bytes = 4096
    for session in sessions:
        schedule, digest = canonical_schedule(phase, session)
        for cell in schedule:
            length, arm, block = cell["length"], cell["arm"], cell["block"]
            challenge = 10_000_000_000_000 + session * 10_000_000_000 + block * 10_000_000 + cell["schedule_position"] * 1_000_000
            agent = challenge + 100_000
            ready_elapsed = 60_000_000 + length * 5_000_000 + (block % 5) * 1_000_000
            if phase == "formal" and block % 50 == 0:
                ready_elapsed += 250_000_000
            ready = agent + ready_elapsed
            padded = arm != "u"
            if padded:
                k = max(1, (ready_elapsed + tpad_ns - 1) // tpad_ns)
                deadline = agent + k * tpad_ns
                send_call = deadline + 1_000_000
                overshoot = 1_000_000
            else:
                k, deadline, send_call, overshoot = 0, ready, ready + 100_000, 100_000
            arrival = challenge + (send_call - agent) + 2_000_000 + length * 100_000
            row = {
                "schema": "r2-observation-v1", "phase": phase, "session": session, "block": block,
                "length": length, "arm": arm, "schedule_position": cell["schedule_position"], "schedule_sha256": digest,
                "setup_id": f"{phase}-setup-{session}", "pk_sha256": h(f"{phase}-pk-{session}"),
                "vk_sha256": h(f"{phase}-vk-{session}"), "config_sha256": h("config"),
                "implementation_sha256": h("implementation"), "source_manifest_sha256": h(f"{phase}-source-manifest"),
                "provenance": "synthetic", "gate_manifest_sha256": h("gate-manifest"),
                "agent_challenge_sha256": h(f"challenge-{phase}-{session}-{block}-{cell['schedule_position']}"),
                "receiver_challenge_sha256": h(f"challenge-{phase}-{session}-{block}-{cell['schedule_position']}"),
                "agent_proof_sha256": h(f"proof-{phase}-{session}-{block}-{cell['schedule_position']}"),
                "receiver_proof_sha256": h(f"proof-{phase}-{session}-{block}-{cell['schedule_position']}"),
                "agent_envelope_sha256": h(f"envelope-{phase}-{session}-{block}-{cell['schedule_position']}"),
                "receiver_envelope_sha256": h(f"envelope-{phase}-{session}-{block}-{cell['schedule_position']}"),
                "event_agent": "agent_complete",
                "length_private": length, "padded_private": padded, "frame_bytes": frame_bytes,
                "t_agent_ns": agent, "t_prepared_ns": agent + 10_000_000, "t_proved_ns": ready - 1_000_000,
                "t_ready_ns": ready, "k": k, "deadline_ns": deadline, "t_send_call_ns": send_call,
                "t_send_return_ns": send_call + 500_000, "overflow": k > 1, "overshoot_ns": overshoot,
                "actual_wait_ns": send_call - ready, "event_receiver": "receiver_complete",
                "receiver_frame_bytes": frame_bytes, "t_challenge_send_ns": challenge, "t_arrival_ns": arrival,
                "t_verify_start_ns": arrival + 100_000, "t_verify_end_ns": arrival + 2_000_000,
                "primary_duration_ns": arrival - challenge, "arrival_recorded_before_verification": True,
                "proof_verified": True, "signature_verified": True,
            }
            rows.append(row)
    return rows


class AnalyzeR2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cal = synthetic_rows("calibration")
        cls.tpad = calibration_result(cls.cal)["tpad_ns"]
        cls.formal = synthetic_rows("formal", cls.tpad)

    def assert_rejected(self, mutate, phase="formal"):
        rows = copy.deepcopy(self.formal if phase == "formal" else self.cal)
        mutate(rows)
        with self.assertRaises(ValidationError):
            validate_rows(rows, phase, self.tpad if phase == "formal" else None)

    def test_exact_cardinality_calibration_and_formal(self):
        self.assertEqual(len(self.cal), 600)
        self.assertEqual(len(self.formal), 4500)
        self.assertEqual(validate_rows(self.formal, "formal", self.tpad)["frame_bytes"], 4096)

    def test_calibration_formula_and_fresh_key_separation(self):
        result = calibration_result(self.cal)
        self.assertEqual(result["per_length_n"], {"1": 200, "2": 200, "3": 200})
        self.assertEqual(result["tpad_ns"] % 50_000_000, 0)
        combined = analyze(self.cal, self.formal, synthetic_manifest(), bootstrap_reps=5)
        self.assertTrue(combined["synthetic"])

    def test_calibration_only_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "calibration.jsonl"
            manifest_path = Path(tmp) / "manifest.json"
            output_path = Path(tmp) / "calibration_result.json"
            input_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in self.cal), encoding="utf-8")
            manifest_path.write_text(json.dumps(synthetic_manifest()), encoding="utf-8")
            subprocess.run(
                [sys.executable, "analyze_r2.py", "--validation-manifest", str(manifest_path),
                 "--calibration", str(input_path), "--output", str(output_path)],
                check=True,
            )
            result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(result["schema"], "r2-calibration-analysis-v1")
            self.assertTrue(result["calibration"]["synthetic"])

    def test_primary_is_complete_receiver_arrival(self):
        self.assert_rejected(lambda rows: rows[0].__setitem__("primary_duration_ns", rows[0]["primary_duration_ns"] + 1))
        self.assert_rejected(lambda rows: rows[0].__setitem__("arrival_recorded_before_verification", False))
        self.assert_rejected(lambda rows: rows[0].__setitem__("t_arrival_ns", rows[0]["t_send_call_ns"] - 1))

    def test_independent_digests_gate_and_replay_rejected(self):
        self.assert_rejected(lambda rows: rows[0].__setitem__("receiver_challenge_sha256", h("wrong")))
        self.assert_rejected(lambda rows: rows[1].__setitem__("agent_proof_sha256", rows[0]["agent_proof_sha256"]))
        self.assert_rejected(lambda rows: rows[1].__setitem__("receiver_proof_sha256", rows[0]["receiver_proof_sha256"]))
        self.assert_rejected(lambda rows: rows[0].__setitem__("proof_verified", False))
        self.assert_rejected(lambda rows: rows[0].__setitem__("signature_verified", False))
        self.assert_rejected(lambda rows: rows[0].__setitem__("gate_manifest_sha256", h("other-gate")))

    def test_missing_duplicate_and_wrong_arm_rejected(self):
        self.assert_rejected(lambda rows: rows.pop())
        self.assert_rejected(lambda rows: rows.__setitem__(1, copy.deepcopy(rows[0])))
        self.assert_rejected(lambda rows: rows[0].__setitem__("arm", "bad"))

    def test_noninteger_negative_and_order_rejected(self):
        self.assert_rejected(lambda rows: rows[0].__setitem__("t_arrival_ns", float(rows[0]["t_arrival_ns"])))
        self.assert_rejected(lambda rows: rows[0].__setitem__("actual_wait_ns", -1))
        self.assert_rejected(lambda rows: rows[0].__setitem__("t_verify_start_ns", rows[0]["t_arrival_ns"] - 1))

    def test_schedule_and_private_join_rejected(self):
        self.assert_rejected(lambda rows: rows[0].__setitem__("schedule_position", 99))
        self.assert_rejected(lambda rows: rows[0].__setitem__("schedule_sha256", h("wrong")))
        self.assert_rejected(lambda rows: rows[0].__setitem__("length_private", 2 if rows[0]["length"] != 2 else 1))
        self.assert_rejected(lambda rows: rows.__setitem__(slice(0, 2), [rows[1], rows[0]]))
        self.assert_rejected(lambda rows: rows[1].__setitem__("t_challenge_send_ns", rows[0]["t_challenge_send_ns"]))

    def test_overflow_unknown_or_filtered_is_rejected(self):
        self.assert_rejected(lambda rows: rows[0].__setitem__("overflow", None))
        overflowing = next(i for i, row in enumerate(self.formal) if row["overflow"])
        self.assert_rejected(lambda rows: rows[overflowing].__setitem__("overflow", False))
        self.assert_rejected(lambda rows: rows.pop(overflowing))

    def test_early_release_and_bad_wait_rejected(self):
        padded = next(i for i, row in enumerate(self.formal) if row["arm"] == "pA")
        self.assert_rejected(lambda rows: rows[padded].__setitem__("t_send_call_ns", rows[padded]["deadline_ns"] - 1))
        self.assert_rejected(lambda rows: rows[padded].__setitem__("actual_wait_ns", rows[padded]["actual_wait_ns"] + 1))

    def test_fresh_keys_and_fixed_frame_rejected(self):
        self.assert_rejected(lambda rows: rows[0].__setitem__("pk_sha256", h("changed-within-session")))
        self.assert_rejected(lambda rows: rows[0].__setitem__("receiver_frame_bytes", 4095))
        formal = copy.deepcopy(self.formal)
        for row in formal:
            if row["session"] == 1:
                row["setup_id"] = self.cal[0]["setup_id"]
                row["pk_sha256"] = self.cal[0]["pk_sha256"]
                row["vk_sha256"] = self.cal[0]["vk_sha256"]
        with self.assertRaises(ValidationError):
            analyze(self.cal, formal, synthetic_manifest(), bootstrap_reps=2)
        formal = copy.deepcopy(self.formal)
        reused_pk = self.cal[0]["pk_sha256"]
        for row in formal:
            if row["session"] == 1:
                row["pk_sha256"] = reused_pk
        with self.assertRaises(ValidationError):
            analyze(self.cal, formal, synthetic_manifest(), bootstrap_reps=2)
        formal = copy.deepcopy(self.formal)
        formal[0]["agent_challenge_sha256"] = self.cal[0]["agent_challenge_sha256"]
        formal[0]["receiver_challenge_sha256"] = self.cal[0]["receiver_challenge_sha256"]
        with self.assertRaises(ValidationError):
            analyze(self.cal, formal, synthetic_manifest(), bootstrap_reps=2)

    def test_validation_manifest_is_fail_closed(self):
        manifest = synthetic_manifest()
        manifest["provenance"] = "measured"
        with self.assertRaises(ValidationError):
            analyze(self.cal, self.formal, manifest, bootstrap_reps=2)
        manifest = synthetic_manifest()
        manifest["phases"]["formal"]["source_manifest_sha256"] = h("wrong")
        with self.assertRaises(ValidationError):
            analyze(self.cal, self.formal, manifest, bootstrap_reps=2)

    def test_formal_reports_screen_aa_wilson_and_bootstrap(self):
        result = formal_result(self.formal, self.tpad, bootstrap_reps=5)
        self.assertEqual(result["rows"], 4500)
        self.assertEqual(result["paired_aa_pA_minus_pB_ns"]["all_lengths"]["n"], 1500)
        self.assertEqual(result["paired_aa_pA_minus_pB_ns"]["per_length"]["1"]["n"], 500)
        self.assertEqual(result["primary"]["length_classifier"]["total"], 1500)
        self.assertEqual(result["aa_classifier"]["total"], 1500)
        self.assertEqual(result["primary"]["length_classifiers"]["u"]["total"], 750)
        self.assertEqual(result["primary"]["length_classifiers"]["pA"]["total"], 750)
        self.assertEqual(result["aa_classifier"]["per_length"]["1"]["total"], 500)
        self.assertIn("overflow_wilson95", result["groups"]["pA_length1"])
        self.assertIn("median_absdiff_ns_1_2", result["bootstrap95"])
        self.assertIn("1", result["session_medians_ns"])


if __name__ == "__main__":
    unittest.main()
