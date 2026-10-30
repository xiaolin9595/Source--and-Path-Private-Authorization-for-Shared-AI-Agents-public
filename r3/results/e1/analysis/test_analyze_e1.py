import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("analyze_e1.py")
SPEC = importlib.util.spec_from_file_location("analyze_e1", MODULE_PATH)
ANALYZER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYZER)


def synthetic_rows():
    rows = []
    for session in ANALYZER.SESSIONS:
        positions = {(block, length, label): position for position, (block, length, label, _) in enumerate(ANALYZER.expected_schedule(session)) if block >= 0}
        for block in range(ANALYZER.BLOCKS):
            for length in ANALYZER.LENGTHS:
                for label in ANALYZER.LABELS:
                    identity = f"{session}-{block}-{length}-{label}"
                    rows.append(
                        {
                            "session": session,
                            "block": block,
                            "length": length,
                            "label": label,
                            "online_total_ms": 1000.0 + length,
                            "padding_prepare_ms": 1.0,
                            "prove_ms": 998.0,
                            "serialize_ms": 1.0,
                            "verified": True,
                            "mutated_public_rejected": True,
                            "proof_sha256": identity,
                            "binary_sha256": "binary-o" if label == "o" else "binary-a",
                            "relation_sha256": "original" if label == "o" else "r1",
                            "pk_sha256": f"pk-{session}-{label == 'o'}",
                            "route": "o" if label == "o" else "a",
                            "schedule_position": positions[(block, length, label)],
                            "schedule_sha256": f"{session:064x}",
                            "source": "synthetic",
                            "line": len(rows) + 1,
                        }
                    )
    return rows


class AnalyzerValidationTests(unittest.TestCase):
    def test_complete_matrix_passes_validation(self):
        rows = synthetic_rows()
        ANALYZER.validate(rows)
        result = ANALYZER.analyze(rows)
        self.assertEqual(result["rows"], 4500)

    def test_missing_row_fails(self):
        with self.assertRaises(SystemExit):
            ANALYZER.validate(synthetic_rows()[:-1])

    def test_duplicate_row_fails(self):
        rows = synthetic_rows()
        rows[-1] = dict(rows[0], proof_sha256="different-proof")
        with self.assertRaises(SystemExit):
            ANALYZER.validate(rows)

    def test_label_shuffle_fails(self):
        rows = synthetic_rows()
        rows[0]["label"] = "aC"
        with self.assertRaises(SystemExit):
            ANALYZER.validate(rows)

    def test_schedule_position_shuffle_fails(self):
        rows = synthetic_rows()
        rows[0]["schedule_position"], rows[1]["schedule_position"] = rows[1]["schedule_position"], rows[0]["schedule_position"]
        with self.assertRaises(SystemExit):
            ANALYZER.validate(rows)

    def test_binary_identity_change_fails(self):
        rows = synthetic_rows()
        rows[0]["binary_sha256"] = "changed"
        with self.assertRaises(SystemExit):
            ANALYZER.validate(rows)

    def test_pk_reuse_fails(self):
        rows = synthetic_rows()
        for row in rows:
            if row["session"] == 2 and row["label"] == "o":
                row["pk_sha256"] = "pk-1-True"
        with self.assertRaises(SystemExit):
            ANALYZER.validate(rows)

    def test_invalid_timing_fails(self):
        rows = synthetic_rows()
        rows[0]["online_total_ms"] = float("nan")
        with self.assertRaises(SystemExit):
            ANALYZER.validate(rows)


if __name__ == "__main__":
    unittest.main()
