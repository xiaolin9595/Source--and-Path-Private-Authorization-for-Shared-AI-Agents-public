#!/usr/bin/env python3
import importlib.util, tempfile, unittest
from pathlib import Path

MODULE=Path(__file__).with_name("analyze_r4_formal.py")
spec=importlib.util.spec_from_file_location("analyze_r4_formal",MODULE);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class TestSummary(unittest.TestCase):
    def test_five_value_descriptive_summary(self):
        self.assertEqual(m.summary([5,1,3,2,4]),{"median":3,"min":1,"max":5,"unit":"ns"})
    def test_wrong_cardinality_rejected(self):
        with self.assertRaises(ValueError): m.summary([1,2,3,4])
    def test_negative_rejected(self):
        with self.assertRaises(ValueError): m.finite_nonnegative(-1,"x")
    def test_negative_paired_difference_is_finite_and_retained(self):
        self.assertEqual(m.finite(-7,"paired_extra_checked_ns"),-7)
    def test_total_and_internal_unallocated(self):
        names=("pk_decode_ns","vk_decode_ns","material_decode_ns","relation_ns","powers_ns",
               "reconstruction_ns","direct_query_ns","b_cross_ns","equation_ns","binding_ns")
        checked={"file_read_ns":5,"full_load_ns":120,"metrics":{name:10 for name in names}}
        checked["metrics"]["checker_total_ns"]=108
        got=m.checked_derived(checked)
        self.assertEqual(got["checked_internal_unallocated_ns"],8)
        self.assertEqual(got["checked_external_wrapper_ns"],7)
        self.assertEqual(got["checked_total_unallocated_ns"],15)
    def test_rss_parser_rejects_missing(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"time";p.write_text("Elapsed: 1\n")
            with self.assertRaises(ValueError): m.rss(p)
    def test_wall_time_parser(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"time";p.write_text("Elapsed (wall clock) time (h:mm:ss or m:ss): 1:02.50\n")
            self.assertEqual(m.wall_ns(p),62_500_000_000)
    def test_runner_uses_environment_allowlist(self):
        runner=MODULE.with_name("run_r4_formal_v5.sh").read_text()
        self.assertNotIn("env |",runner)
        for key in ("PATH=","RUSTC=","CARGO_HOME=","RAYON_NUM_THREADS=","OMP_NUM_THREADS=","LANG=","LC_ALL="):
            self.assertIn(key,runner)

if __name__=="__main__": unittest.main()
