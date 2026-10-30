#!/usr/bin/env python3
"""Real checked Joint Agent -> HTTP service -> resident verifier gate."""
import argparse, hashlib, http.client, json, os, subprocess, tempfile, threading
from pathlib import Path
from http.server import ThreadingHTTPServer
from service import App, ResidentCheckedVerifier, Store, canonical, handler_for

class Clock:
    def __init__(self,value): self.value=value
    def __call__(self): return self.value

def read(process):
    line=process.stdout.readline()
    if not line: raise RuntimeError(f"agent-exit-{process.poll()}")
    return json.loads(line)
def request(process,value):
    process.stdin.write(json.dumps(value,separators=(",",":"))+"\n");process.stdin.flush();return read(process)
def post(port,path,body,headers=None):
    connection=http.client.HTTPConnection("127.0.0.1",port,timeout=300)
    connection.request("POST",path,body,headers or {});response=connection.getresponse();data=response.read();connection.close()
    return response.status,json.loads(data)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--agent",type=Path,required=True);parser.add_argument("--core",type=Path,required=True)
    parser.add_argument("--blind-bundle",type=Path,required=True);parser.add_argument("--joint-bundle",type=Path,required=True)
    args=parser.parse_args(); now=150; audience="https://service.example"; body=b"payload"
    joint_vk_id=hashlib.sha256((args.joint_bundle/"vk.bin").read_bytes()).hexdigest()
    os.environ.update(PLAN_A_VK_ID=joint_vk_id,
        PLAN_A_L="3",PLAN_A_DS="20",PLAN_A_DRA="20",PLAN_A_DREV="32")
    # Config and configured-key failures occur before any checked-ready record.
    for variable,value,needle in [("PLAN_A_DS","19",b"unsupported-joint-profile"),("PLAN_A_VK_ID","00"*32,b"vk-id-mismatch")]:
        environment=dict(os.environ);environment[variable]=value
        failed=subprocess.run([str(args.core),"joint-only",str(args.joint_bundle)],env=environment,
            input=b"",stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=300)
        assert failed.returncode==2 and needle in failed.stderr
    agent=subprocess.Popen([str(args.agent),"resident-checked-fixture",str(args.joint_bundle),"2",audience,body.decode()],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    agent_ready=read(agent);assert agent_ready["ready"] and agent_ready["validation_count"]==1
    artifact=request(agent,{"nonce":101,"now":now});assert "error" not in artifact
    artifact2=request(agent,{"nonce":102,"now":now});assert "error" not in artifact2
    assert artifact2["bootstrap_admission"]==artifact["bootstrap_admission"]
    assert artifact2["bootstrap_ra_registration"]==artifact["bootstrap_ra_registration"]
    assert artifact2["snapshot"]==artifact["snapshot"]
    assert artifact2["envelope"]!=artifact["envelope"]
    deployment=artifact["bootstrap_admission"]["deployment_id"]
    os.environ.update(PLAN_A_REGISTRY_PK_B64=artifact["registry_pk_b64"],PLAN_A_DEPLOYMENT_ID=deployment)
    verifier=ResidentCheckedVerifier([str(args.core),"joint-only",str(args.joint_bundle)],1800,300)
    assert verifier.ready["validation_count"]==1
    receipt=verifier.ready["receipt_sha256"]
    with tempfile.TemporaryDirectory() as temporary:
        app=App(Store(Path(temporary)/"joint.sqlite"),verifier,30,audience,Clock(now),deployment)
        server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(app));thread=threading.Thread(target=server.serve_forever);thread.start()
        port=server.server_port
        try:
            assert post(port,"/admin/enroll",canonical(artifact["bootstrap_admission"]),{"Content-Type":"application/json"})[0]==201
            assert post(port,"/admin/ra-register",canonical(artifact["bootstrap_ra_registration"]),{"Content-Type":"application/json"})[0]==201
            assert post(port,"/admin/header",canonical(artifact["snapshot"]),{"X-PlanA-Header-Signature":artifact["header_signature_b64"]})[0]==201
            envelope=json.dumps(artifact["envelope"],separators=(",",":"))
            status,value=post(port,"/resource/read",body,{"X-PlanA-Authorization":envelope})
            print(json.dumps({"event":"joint-http-response","request":1,"status":status,"value":value},sort_keys=True),flush=True)
            assert status==200 and value.get("ok") is True
            envelope2=json.dumps(artifact2["envelope"],separators=(",",":"))
            status,value=post(port,"/resource/read",body,{"X-PlanA-Authorization":envelope2})
            print(json.dumps({"event":"joint-http-response","request":2,"status":status,"value":value},sort_keys=True),flush=True)
            assert status==200 and value.get("ok") is True
            assert post(port,"/resource/read",body,{"X-PlanA-Authorization":envelope2})[0]==409
        finally:
            server.shutdown();server.server_close();thread.join();verifier.close()
    restarted=ResidentCheckedVerifier([str(args.core),"joint-only",str(args.joint_bundle)],1800,300)
    assert restarted.ready["validation_count"]==1 and restarted.ready["receipt_sha256"]==receipt
    restarted.close();agent.stdin.close();agent.wait(timeout=10);assert agent.returncode==0
    print(json.dumps({"event":"r4-joint-http-gate","profile":"L3-g3-state20-ra20-rev32",
        "requests_verified":2,"same_agent_and_verifier_processes":True,
        "replay_rejected":True,"restart_validation_count":1,
        "agent_receipt":agent_ready["checked_receipt_sha256"],"verifier_receipt":receipt},sort_keys=True))

if __name__=="__main__":main()
