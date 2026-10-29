import json
import http.client
import os
import sqlite3
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from http.server import ThreadingHTTPServer

from service import App, CoreVerifier, Store, canonical, decode_u64, encode_u64, handler_for


class BlindUpdateServiceTest(unittest.TestCase):
    def test_loopback_http_handler_routes_exact_blind_schema(self):
        class EchoVerifier:
            def response(self, payload):
                statement=payload["statement"]
                return {"valid":True,**{k:statement[k] for k in (
                    "owner_commitment","position","old_leaf","new_leaf","old_version","new_version",
                    "old_epoch","new_epoch","expiry_cap","admission_version")}}
        with tempfile.TemporaryDirectory() as tmp_name:
            deployment,owner,position="02"*32,"04"*32,5
            store=Store(Path(tmp_name)/"socket.sqlite")
            with store.connect() as db:
                db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",(deployment,owner,position,"pk","salt",encode_u64(100),encode_u64(0)))
                db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",(deployment,owner,position,encode_u64(8),encode_u64(10),1,"aa"*32,1))
            app=App(store,EchoVerifier(),0,"test",clock=lambda:2,deployment_id=deployment)
            server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(app))
            thread=threading.Thread(target=server.serve_forever);thread.start()
            statement={"config_digest":"01"*32,"deployment_id":deployment,"circuit_id":"03"*32,
                "owner_commitment":owner,"position":position,"expiry_cap":100,"admission_version":0,
                "old_leaf":"aa"*32,"new_leaf":"bb"*32,"old_version":8,"new_version":9,
                "old_epoch":10,"new_epoch":11}
            request={"command":"blind-state-update-verify","statement":statement,"proof_b64":"AA==","signature_b64":"AA=="}
            connection=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=10)
            connection.request("POST","/state/blind-update",body=canonical(request))
            response=connection.getresponse();self.assertEqual(response.status,201);response.read();connection.close()
            connection=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=10)
            duplicate=canonical(request)[:-1]+b',"proof_b64":"AA=="}'
            connection.request("POST","/state/blind-update",body=duplicate)
            response=connection.getresponse();self.assertEqual(response.status,400);response.read();connection.close()
            connection=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=10)
            connection.request("POST","/not-blind-update",body=b"{}")
            response=connection.getresponse();self.assertEqual(response.status,404);response.read();connection.close()
            server.shutdown();server.server_close();thread.join()

    def test_real_verifier_hidden_wire_and_atomic_cas(self):
        fixture = Path(os.environ["BLIND_UPDATE_FIXTURE_BIN"])
        core = Path(os.environ["PLAN_A_SERVICE_CORE_BIN"])
        with tempfile.TemporaryDirectory() as tmp_name:
            tmp = Path(tmp_name)
            metadata = json.loads(subprocess.check_output([fixture, tmp], text=True))
            request = json.loads((tmp / "request.json").read_text())
            seed = json.loads((tmp / "seed.json").read_text())
            forbidden = {"opening", "grant_root", "state_expiry", "active", "salt"}

            def assert_hidden(value):
                if isinstance(value, dict):
                    self.assertTrue(forbidden.isdisjoint(value))
                    for child in value.values():
                        assert_hidden(child)
                elif isinstance(value, list):
                    for child in value:
                        assert_hidden(child)

            assert_hidden(request)
            db_path = tmp / "service.sqlite"
            store = Store(db_path)
            with store.connect() as db:
                db.execute(
                    "INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",
                    (metadata["deployment_id"], seed["owner_commitment"], seed["position"],
                     seed["owner_public_key"], seed["registration_salt"], encode_u64(seed["max_expiry"]),
                     encode_u64(seed["admission_version"])),
                )
                db.execute(
                    "INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",
                    (metadata["deployment_id"], seed["owner_commitment"], seed["position"],
                     encode_u64(seed["old_version"]), encode_u64(seed["old_epoch"]), 1, seed["old_leaf"], 1),
                )
            os.environ.update({
                "PLAN_A_DEPLOYMENT_ID": metadata["deployment_id"],
                "PLAN_A_BLIND_CONFIG_DIGEST": metadata["config_digest"],
                "PLAN_A_BLIND_CIRCUIT_ID": metadata["circuit_id"],
                "PLAN_A_BLIND_UPDATE_VK_PATH": str(tmp / "blind_update.vk"),
                "PLAN_A_BLIND_UPDATE_VK_ID": metadata["vk_sha256"],
            })
            app = App(store, CoreVerifier([str(core)], 120.0), 0, "test", clock=lambda: 99,
                      deployment_id=metadata["deployment_id"])
            corrupt_proof = {**request, "proof_b64": "AAAA"}
            self.assertEqual(app.blind_state_update(canonical(corrupt_proof))[0], 403)
            corrupt_signature = {**request, "signature_b64": "AAAA"}
            self.assertEqual(app.blind_state_update(canonical(corrupt_signature))[0], 403)
            body = canonical(request)
            server = ThreadingHTTPServer(("127.0.0.1", 0), handler_for(app))
            server_thread = threading.Thread(target=server.serve_forever)
            server_thread.start()
            results = []
            lock = threading.Lock()

            def apply():
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=120)
                connection.request("POST", "/state/blind-update", body=body,
                                   headers={"Content-Type": "application/json"})
                response = connection.getresponse()
                result = (response.status, json.loads(response.read()))
                connection.close()
                with lock:
                    results.append(result)

            threads = [threading.Thread(target=apply) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            duplicate = body[:-1] + b',"proof_b64":"AAAA"}'
            connection.request("POST", "/state/blind-update", body=duplicate)
            self.assertEqual(connection.getresponse().status, 400)
            connection.close()
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
            connection.request("POST", "/wrong-route", body=body)
            self.assertEqual(connection.getresponse().status, 404)
            connection.close()
            server.shutdown(); server.server_close(); server_thread.join()
            self.assertEqual(sorted(status for status, _ in results), [201, 409])
            success = next(value for status, value in results if status == 201)
            assert_hidden(success)
            self.assertEqual(set(success), {"valid", "new_leaf", "new_version", "new_epoch", "publication_status"})
            with sqlite3.connect(db_path) as db:
                row = db.execute("SELECT leaf,state_version,state_epoch,active FROM owner_states").fetchone()
                self.assertEqual(row[:3], (request["statement"]["new_leaf"], encode_u64(9), encode_u64(11)))
                self.assertEqual((decode_u64(row[1]), decode_u64(row[2])), (9, 11))
                self.assertIsNone(row[3])

    def test_u64_storage_boundaries_and_legacy_integer_migration(self):
        self.assertEqual(decode_u64(2**63 - 1), 2**63 - 1)
        self.assertEqual(decode_u64(encode_u64(2**63)), 2**63)
        self.assertEqual(decode_u64(encode_u64(2**64 - 1)), 2**64 - 1)
        with self.assertRaises(ValueError):
            encode_u64(2**64)
        with tempfile.TemporaryDirectory() as tmp_name:
            store = Store(Path(tmp_name) / "u64.sqlite")
            deployment, owner, position = "02" * 32, "04" * 32, 5
            with store.connect() as db:
                db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",
                           (deployment, owner, position, "pk", "salt", encode_u64(2**64-1), encode_u64(2**64-1)))
                # Legacy signed-INTEGER state remains readable during migration.
                db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",
                           (deployment, owner, position, 2**63-1, 2**63-1, 0, "aa"*32, 1))
            statement={"deployment_id":deployment,"owner_commitment":owner,"position":position,
                       "expiry_cap":2**64-1,"admission_version":2**64-1,"old_leaf":"aa"*32,
                       "new_leaf":"bb"*32,"old_version":2**63-1,"new_version":2**63,
                       "old_epoch":2**63-1,"new_epoch":2**63}
            self.assertEqual(store.cas_blind_state_update(statement, statement, 2), "committed")
            with store.connect() as db:
                row=db.execute("SELECT state_version,state_epoch FROM owner_states").fetchone()
            self.assertEqual((decode_u64(row[0]),decode_u64(row[1])),(2**63,2**63))
            statement.update(old_leaf="bb"*32,new_leaf="cc"*32,old_version=2**63,
                             new_version=2**64-1,old_epoch=2**63,new_epoch=2**64-1)
            self.assertEqual(store.cas_blind_state_update(statement, statement, 3), "committed")
            with store.connect() as db:
                row=db.execute("SELECT state_version,state_epoch FROM owner_states").fetchone()
            self.assertEqual((decode_u64(row[0]),decode_u64(row[1])),(2**64-1,2**64-1))

    def test_existing_signed_schema_is_migrated_without_data_loss(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            path=Path(tmp_name)/"legacy.sqlite"
            with sqlite3.connect(path) as db:
                db.executescript("""
                CREATE TABLE owner_states(deployment_id TEXT NOT NULL,owner_commitment TEXT NOT NULL,
                  position INTEGER NOT NULL,state_version INTEGER NOT NULL,state_epoch INTEGER NOT NULL,
                  active INTEGER NOT NULL,leaf TEXT NOT NULL,updated_at INTEGER NOT NULL,
                  PRIMARY KEY(deployment_id,owner_commitment,position));
                CREATE TABLE admissions(deployment_id TEXT NOT NULL,owner_commitment TEXT NOT NULL,
                  position INTEGER NOT NULL,owner_public_key TEXT NOT NULL,registration_salt TEXT NOT NULL,
                  max_expiry INTEGER NOT NULL,PRIMARY KEY(deployment_id,owner_commitment),
                  UNIQUE(deployment_id,position));
                """)
                db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",("d","o",1,7,8,0,"leaf",9))
                db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?)",("d","o",1,"pk","salt",10))
            store=Store(path)
            with store.connect() as db:
                state=dict(db.execute("SELECT * FROM owner_states").fetchone())
                admission=dict(db.execute("SELECT * FROM admissions").fetchone())
                state_info={r[1]:r for r in db.execute("PRAGMA table_info(owner_states)")}
            self.assertEqual((decode_u64(state["state_version"]),decode_u64(state["state_epoch"])),(7,8))
            self.assertEqual((decode_u64(admission["max_expiry"]),decode_u64(admission["admission_version"])),(10,0))
            self.assertEqual(state_info["active"][3],0)

    def test_legacy_cas_rejects_blind_sentinel_after_inactive_race(self):
        with tempfile.TemporaryDirectory() as tmp_name:
            store=Store(Path(tmp_name)/"race.sqlite")
            deployment,owner,position="02"*32,"04"*32,5
            with store.connect() as db:
                db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",
                           (deployment,owner,position,"pk","salt",encode_u64(100),encode_u64(0)))
                db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",
                           (deployment,owner,position,encode_u64(8),encode_u64(10),0,"aa"*32,1))
            legacy={"deployment_id":deployment,"owner_commitment":owner,"position":position,
                    "owner_public_key":"pk","registration_salt":"salt","max_expiry":100,
                    "expected_version":8,"current_epoch":10,"current_active":False}
            blind={"deployment_id":deployment,"owner_commitment":owner,"position":position,
                   "expiry_cap":100,"admission_version":0,"old_leaf":"aa"*32,"new_leaf":"bb"*32,
                   "old_version":8,"new_version":9,"old_epoch":10,"new_epoch":11}
            self.assertEqual(store.cas_blind_state_update(blind,blind,2),"committed")
            self.assertEqual(store.cas_state_update(legacy,{"new_version":9,"new_epoch":11,
                "active":False,"new_leaf":"cc"*32},3),"blind-mode")


if __name__ == "__main__":
    unittest.main()
