#!/usr/bin/env python3
"""Two-update real HTTP gate for the isolated R4 checked profile."""
import argparse, hashlib, http.client, json, os, subprocess, tempfile, threading
from pathlib import Path
from http.server import ThreadingHTTPServer

from service import App, ResidentCheckedVerifier, Store, canonical, encode_u64, handler_for

def line(process):
    value = process.stdout.readline()
    if not value: raise RuntimeError(f"agent-exit-{process.poll()}")
    return json.loads(value)

def command(process, value):
    process.stdin.write(json.dumps(value, separators=(",", ":")) + "\n")
    process.stdin.flush()
    return line(process)

def post(port, value):
    connection=http.client.HTTPConnection("127.0.0.1",port,timeout=300)
    connection.request("POST","/state/blind-update",canonical(value),{"Content-Type":"application/json"})
    response=connection.getresponse(); body=response.read(); connection.close()
    return response.status,json.loads(body)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--agent",type=Path,required=True)
    parser.add_argument("--core",type=Path,required=True)
    parser.add_argument("--blind-bundle",type=Path,required=True)
    parser.add_argument("--joint-bundle",type=Path,required=True)
    args=parser.parse_args()
    metadata=json.loads((args.blind_bundle/"metadata.json").read_text())
    os.environ.update({
        "PLAN_A_DEPLOYMENT_ID":metadata["deployment_id"],
        "PLAN_A_BLIND_CONFIG_DIGEST":metadata["config_digest"],
        "PLAN_A_BLIND_CIRCUIT_ID":metadata["circuit_id"],
        "PLAN_A_BLIND_UPDATE_VK_ID":metadata["vk_sha256"],
    })
    wrong_env=dict(os.environ); wrong_env["PLAN_A_BLIND_UPDATE_VK_ID"]="00"*32
    wrong=subprocess.run([str(args.core),"blind-only",str(args.blind_bundle)],env=wrong_env,
        input=b"",stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
    assert wrong.returncode==2 and b"blind-vk-id-mismatch" in wrong.stderr
    agent=subprocess.Popen([str(args.agent),"serve",str(args.blind_bundle)],stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    ready=line(agent)
    assert ready["event"]=="ready" and ready["profile"]=="r4-checked-v5" and ready["validation_count"]==1
    with tempfile.TemporaryDirectory() as temporary:
        store=Store(Path(temporary)/"gate.sqlite")
        with store.connect() as db:
            db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",(metadata["deployment_id"],ready["owner_commitment"],ready["position"],ready["owner_public_key"],ready["registration_salt"],encode_u64(ready["expiry_cap"]),encode_u64(ready["admission_version"])))
            db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",(metadata["deployment_id"],ready["owner_commitment"],ready["position"],encode_u64(ready["initial_version"]),encode_u64(ready["initial_epoch"]),1,ready["initial_leaf"],1))
        verifier=ResidentCheckedVerifier([str(args.core),"blind-only",str(args.blind_bundle)],1800,300)
        assert verifier.ready["validation_count"]==1
        app=App(store,verifier,0,"r4-gate",deployment_id=metadata["deployment_id"])
        server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(app)); thread=threading.Thread(target=server.serve_forever);thread.start()
        requests=[]
        try:
            for _ in range(2):
                produced=command(agent,{"command":"next"}); request=produced["request"]
                status,response=post(server.server_port,request)
                assert status==201 and response.get("valid") is True
                command(agent,{"command":"commit"}); requests.append(request)
            status,_=post(server.server_port,requests[-1]); assert status in (403,409)
        finally:
            server.shutdown();server.server_close();thread.join();verifier.close()
        # Restart proves a fresh validation, rather than a persistent hash receipt.
        restarted=ResidentCheckedVerifier([str(args.core),"blind-only",str(args.blind_bundle)],1800,300)
        assert restarted.ready["validation_count"]==1
        restarted.close()
    agent.stdin.write('{"command":"stop"}\n');agent.stdin.flush();agent.wait(timeout=10)
    assert agent.returncode==0
    print(json.dumps({"event":"r4-http-gate","blind_updates":2,"replay_rejected":True,
        "restart_validation_count":1,"agent_receipt":ready["checked_receipt_sha256"]},sort_keys=True))

if __name__=="__main__": main()
