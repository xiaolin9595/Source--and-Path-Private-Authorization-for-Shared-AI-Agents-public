import copy
import unittest

from analyze_e2 import AnalysisError, FORMAL, SETUPS, WARMUPS, analyze, type7


def h(value: int) -> str:
    return f"{value:064x}"


def fixture():
    rows = []
    global_ids = {
        "source_manifest_sha256": h(1), "driver_sha256": h(2), "analyzer_sha256": h(3),
        "protocol_sha256":h(4), "gate_manifest_sha256":h(5), "config_sha256": h(6),
        "matrix_sha256": h(7), "config_digest": h(8),
    }
    rows.append({"schema":"e2-observation-v1","event":"collection","setups":SETUPS,
                 "updates":FORMAL,"warmups":WARMUPS,**global_ids})
    for setup in range(1, SETUPS + 1):
        per = {"deployment_id":h(50+setup),"pk_sha256": h(100 + setup), "vk_sha256": h(200 + setup),
               "circuit_id": h(300 + setup), "owner_sha256": h(400 + setup), "db_sha256": h(500 + setup)}
        initial_leaf = h(10_000 + setup * 100)
        rows.append({"schema":"e2-observation-v1","event":"setup","setup_id":setup,**global_ids,**per,
                     "formal_initial_leaf":initial_leaf,"formal_initial_version":0,"formal_initial_epoch":100,
                     "constraints":12000,"instance_variables":15,"witness_variables":11000,
                     "pk_bytes":100000,"vk_bytes":1016,
                     "timings_ns":{"setup":1_000_000+setup,"pk_load":None,"vk_load_prepare":10_000+setup}})
        warm_per = {**per,"owner_sha256":h(600+setup),"db_sha256":h(700+setup)}
        old = h(20_000 + setup * 100)
        for position in range(1, WARMUPS + 1):
            new = h(20_000 + setup * 100 + position)
            rows.append(update(global_ids,warm_per,setup,"warmup",position,old,new,position-1,position,200+position-1,200+position))
            old = new
        old = initial_leaf
        for position in range(1, FORMAL + 1):
            new = h(10_000 + setup * 100 + position)
            rows.append(update(global_ids,per,setup,"formal",position,old,new,position-1,position,99+position,100+position))
            old = new
    return rows


def update(global_ids, per, setup, phase, position, old, new, old_version, new_version, old_epoch, new_epoch):
    base = 1_000_000 + setup * 10_000 + position * 100
    return {"schema":"e2-observation-v1","event":"update","setup_id":setup,"phase":phase,"position":position,
            **global_ids,**per,"accepted":True,"error":None,"old_leaf":old,"new_leaf":new,
            "old_version":old_version,"new_version":new_version,"old_epoch":old_epoch,"new_epoch":new_epoch,
            "proof_sha256":h(30_000+setup*100+position+(1000 if phase=="warmup" else 0)),
            "request_sha256":h(40_000+setup*100+position+(1000 if phase=="warmup" else 0)),
            "proof_bytes":192,"request_bytes":1034,
            "timings_ns":{"witness_prepare":base,"proof_generate_loaded_pk":base+1,
              "owner_sign_serialize":base+2,"pure_proof_verify":base+3,"server_verify_external":base+4,
              "atomic_replace":base+5,"http_request_to_committed_response":base+6,
              "client_prepare_to_response":base+7,"publication":None}}


class AnalyzerTest(unittest.TestCase):
    def test_complete_matrix_and_statistics(self):
        result = analyze(fixture())
        self.assertTrue(result["complete"])
        self.assertEqual(result["formal_updates"], 300)
        self.assertEqual(result["warmups"], 30)
        self.assertEqual(result["bootstrap_prng"], "Python random.Random (MT19937), randrange(10)")
        self.assertTrue(result["bootstrap_index_vectors_shared_across_metrics"])
        self.assertIn("type-7", result["percentile_method"])
        self.assertEqual(result["pooled_timing"]["proof_generate_loaded_pk"]["whole_setup_bootstrap_95pct"]["replicates"], 10000)
        self.assertEqual(result["setup_costs"]["setup"]["ten_observation_bootstrap_95pct"]["replicates"], 10000)
        self.assertIsNone(result["pooled_timing"]["publication"])
        self.assertEqual(len(result["position_by_setup_ns"]["1"]), 30)
        witness_ci=result["pooled_timing"]["witness_prepare"]["whole_setup_bootstrap_95pct"]
        proof_ci=result["pooled_timing"]["proof_generate_loaded_pk"]["whole_setup_bootstrap_95pct"]
        self.assertEqual(proof_ci["p2_5"]-witness_ci["p2_5"],1)
        self.assertEqual(proof_ci["p97_5"]-witness_ci["p97_5"],1)
        self.assertEqual(type7([0.0,10.0],0.025),0.25)

    def assert_rejected(self, mutate):
        rows = fixture(); mutate(rows)
        with self.assertRaises(AnalysisError): analyze(rows)

    def test_missing_duplicate_and_failed_rows_rejected(self):
        self.assert_rejected(lambda rows: rows.pop())
        self.assert_rejected(lambda rows: rows.pop(0))
        self.assert_rejected(lambda rows: rows.__setitem__(-1, copy.deepcopy(rows[-2])))
        self.assert_rejected(lambda rows: rows[-1].update(accepted=False,error="failure"))

    def test_chain_and_identity_drift_rejected(self):
        self.assert_rejected(lambda rows: next(r for r in rows if r.get("phase")=="formal" and r["position"]==2).update(old_leaf=h(999999)))
        self.assert_rejected(lambda rows: rows[-1].update(vk_sha256=h(999998)))
        self.assert_rejected(lambda rows: next(r for r in rows if r["event"]=="setup" and r["setup_id"]==2).update(
            pk_sha256=next(r for r in rows if r["event"]=="setup" and r["setup_id"]==1)["pk_sha256"]))

    def test_hash_acceptance_timing_and_schema_rejected(self):
        self.assert_rejected(lambda rows: rows[-1].update(proof_sha256="bad"))
        self.assert_rejected(lambda rows: rows[-1]["timings_ns"].update(publication=0))
        self.assert_rejected(lambda rows: rows[-1]["timings_ns"].pop("atomic_replace"))
        self.assert_rejected(lambda rows: rows[-1]["timings_ns"].update(atomic_replace=None))

    def test_warmup_is_separate_and_formal_positions_complete(self):
        self.assert_rejected(lambda rows: next(r for r in rows if r.get("phase")=="warmup").update(
            owner_sha256=next(r for r in rows if r["event"]=="setup" and r["setup_id"]==1)["owner_sha256"]))
        self.assert_rejected(lambda rows: next(r for r in rows if r.get("phase")=="formal" and r["position"]==30).update(position=29))


if __name__ == "__main__":
    unittest.main()
