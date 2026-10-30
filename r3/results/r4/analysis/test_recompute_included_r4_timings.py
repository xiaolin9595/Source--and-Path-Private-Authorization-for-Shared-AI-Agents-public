#!/usr/bin/env python3
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("recompute_included_r4_timings.py")
SPEC = importlib.util.spec_from_file_location("recompute_included_r4_timings", MODULE)
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)


class IncludedTimingTests(unittest.TestCase):
    def test_recorded_digest_parser_requires_exact_three(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sums"
            path.write_text("0" * 64 + "  /private/pk.bin\n")
            with self.assertRaises(ValueError):
                M.recorded_digests(path)

    def test_duplicate_digest_name_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sums"
            path.write_text(("0" * 64 + "  a/pk.bin\n") * 2 + "1" * 64 + "  a/checking.bin\n")
            with self.assertRaises(ValueError):
                M.recorded_digests(path)

    def test_signed_pair_difference_retained(self):
        self.assertEqual(M.finite(-1, "paired_extra_checked_ns"), -1)

    def test_cardinality_is_exactly_five(self):
        with self.assertRaises(ValueError):
            M.summary([1, 2, 3, 4])


if __name__ == "__main__":
    unittest.main()
