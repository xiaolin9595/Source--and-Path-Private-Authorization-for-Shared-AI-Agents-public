#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, http.client, json, os, sqlite3, subprocess, threading, time, uuid
from http.server import ThreadingHTTPServer
from pathlib import Path
import sys

SERVICE_DIR=Path(__file__).resolve().parents[1]/"service"
sys.path.insert(0,str(SERVICE_DIR))
from service import App, CoreVerifier, Store, canonical, encode_u64, handler_for  # noqa:E402

def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def sha_text(value:str)->str:return hashlib.sha256(value.encode()).hexdigest()
def emit(path:Path,row:dict)->None:
    with path.open("ab") as f:f.write(canonical(row)+b"\n");f.flush();os.fsync(f.fileno())
def readline(proc:subprocess.Popen)->dict:
    line=proc.stdout.readline()
    if not line:raise RuntimeError(f"agent exited {proc.poll()}")
    return json.loads(line)
def command(proc:subprocess.Popen,value:dict)->dict:
    proc.stdin.write(json.dumps(value,separators=(",",":"))+"\n");proc.stdin.flush();return readline(proc)

def chain(args,setup_id:int,setup_dir:Path,phase:str,count:int,out:Path,identities:dict)->dict:
    proc=subprocess.Popen([str(args.agent),"serve",str(setup_dir)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
    ready=readline(proc);assert ready["event"]=="ready"
    db_identity=uuid.uuid4().hex
    db_path=args.output/f"setup{setup_id:02d}-{phase}-{db_identity}.sqlite"
    store=Store(db_path);m=ready["metadata"]
    with store.connect() as db:
        db.execute("INSERT INTO admissions VALUES(?,?,?,?,?,?,?)",(m["deployment_id"],ready["owner_commitment"],ready["position"],ready["owner_public_key"],ready["registration_salt"],encode_u64(ready["expiry_cap"]),encode_u64(ready["admission_version"])))
        db.execute("INSERT INTO owner_states VALUES(?,?,?,?,?,?,?,?)",(m["deployment_id"],ready["owner_commitment"],ready["position"],encode_u64(ready["initial_version"]),encode_u64(ready["initial_epoch"]),1,ready["initial_leaf"],int(time.time())))
    os.environ.update({"PLAN_A_DEPLOYMENT_ID":m["deployment_id"],"PLAN_A_BLIND_CONFIG_DIGEST":m["config_digest"],"PLAN_A_BLIND_CIRCUIT_ID":m["circuit_id"],"PLAN_A_BLIND_UPDATE_VK_PATH":str(setup_dir/"vk.bin"),"PLAN_A_BLIND_UPDATE_VK_ID":m["vk_sha256"]})
    os.environ["PLAN_A_E2_TIMING"]="1"
    verifier=CoreVerifier([str(args.core)],args.verify_timeout);app=App(store,verifier,0,"e2",deployment_id=m["deployment_id"])
    server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(app));thread=threading.Thread(target=server.serve_forever);thread.start()
    initial={"leaf":ready["initial_leaf"],"version":ready["initial_version"],"epoch":ready["initial_epoch"]}
    owner_sha256=sha_text(ready["owner_commitment"]);db_sha256=sha_text(db_identity)
    try:
        for position in range(1,count+1):
            client_start=time.perf_counter_ns();produced=command(proc,{"command":"next"});wire=canonical(produced["request"])
            http_start=time.perf_counter_ns();conn=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=args.verify_timeout);conn.request("POST","/state/blind-update",wire,{"Content-Type":"application/json"});response=conn.getresponse();body=response.read();status=response.status;conn.close();http_ns=time.perf_counter_ns()-http_start;client_ns=time.perf_counter_ns()-client_start
            value=json.loads(body);accepted=status==201 and value.get("valid") is True
            statement=produced["request"]["statement"]
            persisted=store.blind_admission(statement["deployment_id"],statement["owner_commitment"],statement["position"])
            with store.connect() as db:
                stored=db.execute("SELECT leaf,state_version,state_epoch FROM owner_states WHERE deployment_id=? AND owner_commitment=? AND position=?",(statement["deployment_id"],statement["owner_commitment"],statement["position"])).fetchone()
            accepted=accepted and persisted is not None and stored is not None and stored["leaf"]==statement["new_leaf"] and int(stored["state_version"])==statement["new_version"] and int(stored["state_epoch"])==statement["new_epoch"]
            timings={**produced["timings_ns"],"pure_proof_verify":getattr(app,"last_blind_timing",{}).get("pure_proof_verify_ns"),"server_verify_external":getattr(app,"last_blind_timing",{}).get("server_verification_ns"),"atomic_replace":getattr(app,"last_blind_timing",{}).get("atomic_cas_ns"),"http_request_to_committed_response":http_ns,"client_prepare_to_response":client_ns,"publication":None}
            row={"schema":"e2-observation-v1","event":"update","phase":phase,"setup_id":setup_id,"position":position,"accepted":accepted,"error":None if accepted else {"status":status,"body":value},"old_leaf":statement["old_leaf"],"new_leaf":statement["new_leaf"],"old_version":statement["old_version"],"new_version":statement["new_version"],"old_epoch":statement["old_epoch"],"new_epoch":statement["new_epoch"],"proof_bytes":produced["proof_bytes"],"request_bytes":len(wire),"proof_sha256":produced["proof_sha256"],"request_sha256":hashlib.sha256(wire).hexdigest(),"matrix_sha256":m["matrix_sha256"],"config_sha256":m["config_sha256"],"config_digest":m["config_digest"],"deployment_id":m["deployment_id"],"circuit_id":m["circuit_id"],"pk_sha256":m["pk_sha256"],"vk_sha256":m["vk_sha256"],"owner_sha256":owner_sha256,"db_sha256":db_sha256,**identities,"timings_ns":timings}
            emit(out,row)
            if not accepted:raise RuntimeError(f"update failed: {row['error']}")
            committed=command(proc,{"command":"commit"});assert committed["leaf"]==statement["new_leaf"]
    finally:
        try:command(proc,{"command":"stop"})
        except Exception:pass
        proc.terminate();proc.wait(timeout=10);server.shutdown();server.server_close();thread.join()
    return {"ready":ready,"initial":initial,"owner_sha256":owner_sha256,"db_sha256":db_sha256,"db_artifact_sha256":sha(db_path)}

def main()->None:
    p=argparse.ArgumentParser();p.add_argument("--agent",type=Path,required=True);p.add_argument("--core",type=Path,required=True);p.add_argument("--output",type=Path,required=True);p.add_argument("--setups",type=int,default=10);p.add_argument("--updates",type=int,default=30);p.add_argument("--warmups",type=int,default=3);p.add_argument("--verify-timeout",type=float,default=120);p.add_argument("--source-manifest",type=Path,required=True);p.add_argument("--protocol",type=Path,required=True);p.add_argument("--analyzer",type=Path,required=True);p.add_argument("--gate-manifest",type=Path,required=True);a=p.parse_args()
    a.output.mkdir(parents=True,exist_ok=False);out=a.output/"observations.jsonl";driver=Path(__file__).resolve();identities={"source_manifest_sha256":sha(a.source_manifest),"driver_sha256":sha(driver),"analyzer_sha256":sha(a.analyzer),"protocol_sha256":sha(a.protocol),"gate_manifest_sha256":sha(a.gate_manifest)}
    for index in range(1,a.setups+1):
        setup_id=index;setup_dir=a.output/f"setup{index:02d}"
        setup_result=subprocess.run([str(a.agent),"setup",str(setup_dir)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,check=True);metadata=json.loads(setup_result.stdout)
        if index == 1:
            emit(out,{"schema":"e2-observation-v1","event":"collection","setups":a.setups,"updates":a.updates,"warmups":a.warmups,"config_sha256":metadata["config_sha256"],"matrix_sha256":metadata["matrix_sha256"],"config_digest":metadata["config_digest"],**identities})
        warm=chain(a,setup_id,setup_dir,"warmup",a.warmups,out,identities);formal=chain(a,setup_id,setup_dir,"formal",a.updates,out,identities)
        emit(out,{**metadata,"schema":"e2-observation-v1","event":"setup","setup_id":setup_id,"formal_initial_leaf":formal["initial"]["leaf"],"formal_initial_version":formal["initial"]["version"],"formal_initial_epoch":formal["initial"]["epoch"],"owner_sha256":formal["owner_sha256"],"db_sha256":formal["db_sha256"],"formal_db_artifact_sha256":formal["db_artifact_sha256"],"warmup_owner_sha256":warm["owner_sha256"],"warmup_db_sha256":warm["db_sha256"],"warmup_db_artifact_sha256":warm["db_artifact_sha256"],"timings_ns":{"setup":metadata["setup_ns"],"pk_load":formal["ready"]["pk_load_ns"],"vk_load_prepare":formal["ready"]["vk_load_prepare_ns"]},**identities})
    (a.output/"COMPLETE").write_text(f"setups={a.setups} formal={a.setups*a.updates} warmup={a.setups*a.warmups}\n")
if __name__=="__main__":main()
