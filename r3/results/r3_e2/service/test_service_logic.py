import base64
import hashlib
import json
import tempfile
import threading
import unittest
from pathlib import Path

from service import App, Store, canonical, tagged_digest


class RecordingVerifier:
    """Logic-test double only; outputs from this test are ineligible for E7."""
    def __init__(self): self.calls = []
    def call(self, payload): self.calls.append(payload); return True


class AdvancingVerifier(RecordingVerifier):
    def __init__(self, clock_state): super().__init__(); self.clock_state=clock_state
    def call(self, payload):
        result=super().call(payload)
        if payload["command"] == "terminal-verify": self.clock_state[0]=1001
        return result

class SignalingVerifier(RecordingVerifier):
    def __init__(self,event): super().__init__(); self.event=event
    def call(self,payload):
        result=super().call(payload)
        if payload["command"]=="terminal-verify": self.event.set()
        return result


class ServiceLogicTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.tmp.name) / "state.sqlite")
        self.verifier = RecordingVerifier()
        # All request/commit checks use the same injected trusted test clock.
        self.app = App(self.store, self.verifier, 10, "https://service.example", clock=lambda: 101)
        self.snapshot = {"deployment_id":"","tuple_version":1,"ra_root":"00"*32,"state_epoch":1,"state_root":"11"*32,"revocation_epoch":1,"revocation_root":"22"*32,"issued_at":100}
        body = canonical(self.snapshot)
        self.digest = self.app.install_header(body, "dGVzdC1zaWc=", 100)

    def tearDown(self): self.tmp.cleanup()

    def envelope(self, nonce_byte=1):
        nonce = base64.urlsafe_b64encode(bytes([nonce_byte])*16).decode().rstrip("=")
        return {"protocol_version":"plan-a-http-v1","deployment_id":"","audience":"https://service.example","resource":"files","action_onehot":1,"nonce":nonce,"request_time":100,"expires_at":1000,"terminal_agent_pk":"agent_pk_shared_001","circuit_id":"plan-a-joint-v1","vk_id":"vk-1","snapshot_digest":self.digest,"relation_request_digest":"01","proof_b64":"cHJvb2Y=","signature_b64":"c2ln"}

    def test_header_republication_does_not_extend(self):
        body = canonical(self.snapshot); sig = "dGVzdC1zaWc="
        with self.assertRaisesRegex(ValueError, "header-republication"):
            self.app.install_header(body, sig, 105)

    def test_mixed_root_tuple_rejected(self):
        mixed = dict(self.snapshot); mixed["revocation_root"] = "33"*32
        self.assertIsNone(self.store.accepted_snapshot(tagged_digest(b"plan-a-snapshot-v1", mixed), 100, 10))

    def test_old_header_inclusive_delta_boundary(self):
        newer = {"deployment_id":"","tuple_version":2,"ra_root":"00"*32,"state_epoch":2,"state_root":"44"*32,"revocation_epoch":2,"revocation_root":"55"*32,"issued_at":105}
        body=canonical(newer); self.app.install_header(body,"dGVzdC1zaWc=",105)
        self.assertIsNotNone(self.store.accepted_snapshot(self.digest,115,10))
        self.assertIsNone(self.store.accepted_snapshot(self.digest,116,10))
        self.assertIsNotNone(self.store.accepted_snapshot(tagged_digest(b"plan-a-snapshot-v1",newer),10000,10))

    def test_same_tuple_version_different_tuple_rejected(self):
        changed=dict(self.snapshot); changed["state_root"]="66"*32; changed["issued_at"]=101
        with self.assertRaisesRegex(ValueError,"tuple-version-not-increasing"):
            self.app.install_header(canonical(changed),"dGVzdC1zaWc=",101)

    def test_future_issued_and_epoch_rollback_rejected(self):
        future=dict(self.snapshot); future["tuple_version"]=2; future["state_epoch"]=2; future["issued_at"]=200
        with self.assertRaisesRegex(ValueError,"future-header"):
            self.app.install_header(canonical(future),"dGVzdC1zaWc=",101)
        newer=dict(self.snapshot); newer["tuple_version"]=2; newer["state_epoch"]=2; newer["revocation_epoch"]=2; newer["issued_at"]=101
        self.app.install_header(canonical(newer),"dGVzdC1zaWc=",101)
        rollback=dict(self.snapshot); rollback["tuple_version"]=3; rollback["issued_at"]=102
        with self.assertRaisesRegex(ValueError,"epoch-rollback"):
            self.app.install_header(canonical(rollback),"dGVzdC1zaWc=",102)

    def test_concurrent_nonce_exactly_once(self):
        env=self.envelope(); results=[]; barrier=threading.Barrier(8)
        def worker(): barrier.wait(); results.append(self.app.invoke(env,"POST","/resource/read",b"payload",101)[0])
        threads=[threading.Thread(target=worker) for _ in range(8)]
        [t.start() for t in threads]; [t.join() for t in threads]
        self.assertEqual(results.count(200),1); self.assertEqual(results.count(409),7)

    def test_cross_deployment_rejected_before_verification(self):
        env=self.envelope(9);env["deployment_id"]="other-deployment"
        status,value=self.app.invoke(env,"POST","/resource/read",b"payload",101)
        self.assertEqual((status,value),(400,{"error":"protocol-or-audience"}))

    def test_q_binds_every_field(self):
        env=self.envelope(2)
        status,_=self.app.invoke(env,"POST","/resource/read",b"payload",101); self.assertEqual(status,200)
        statement=self.verifier.calls[-2]["public_statement"]
        original=statement["canonical_request_sha256"]
        request=statement["request"]
        mutations={"deployment_id":"other-deployment","method":"GET","path":"/other","body_sha256":"00"*32,"audience":"https://other.example","resource":"other","action_onehot":2,"nonce":self.envelope(3)["nonce"],"request_time":99,"expires_at":999,"terminal_agent_pk":"other-agent","circuit_id":"other-circuit","vk_id":"other-vk","snapshot_digest":"ff"*32}
        for key,value in mutations.items():
            changed=dict(request); changed[key]=value
            self.assertNotEqual(original,tagged_digest(b"plan-a-request-v1",changed),key)

    def test_commit_rechecks_expiry_after_slow_verification(self):
        clock_state=[101]
        verifier=AdvancingVerifier(clock_state)
        app=App(self.store,verifier,10,"https://service.example",clock=lambda:clock_state[0])
        status,value=app.invoke(self.envelope(4),"POST","/resource/read",b"payload",101)
        self.assertEqual((status,value),(409,{"error":"stale-after-verification"}))

    def test_commit_clock_is_read_after_database_lock_wait(self):
        reached=threading.Event(); clock_state=[101]
        app=App(self.store,SignalingVerifier(reached),10,"https://service.example",clock=lambda:clock_state[0])
        blocker=self.store.connect(); blocker.execute("BEGIN IMMEDIATE")
        result=[]
        worker=threading.Thread(target=lambda:result.append(app.invoke(self.envelope(5),"POST","/resource/read",b"payload",101)))
        worker.start(); self.assertTrue(reached.wait(2)); clock_state[0]=1001; blocker.rollback(); blocker.close()
        worker.join(5); self.assertFalse(worker.is_alive())
        self.assertEqual(result,[(409,{"error":"stale-after-verification"})])


if __name__ == "__main__": unittest.main()
