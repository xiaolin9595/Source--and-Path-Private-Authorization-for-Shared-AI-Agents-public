#!/usr/bin/env python3
"""Ten warm Agent proofs followed by the real HTTP verification path."""
import argparse,base64,hashlib,json,subprocess,tempfile,time
from pathlib import Path
from real_http_trace import Clock,call,serve
from service import App,CoreVerifier,Store,canonical
def main():
 p=argparse.ArgumentParser();p.add_argument("--agent",required=True);p.add_argument("--core",required=True);p.add_argument("--pk",required=True);p.add_argument("--vk",required=True);p.add_argument("--out",type=Path,required=True);p.add_argument("--l",type=int,default=3);p.add_argument("--active",type=int,default=2);p.add_argument("--ds",type=int,default=10);p.add_argument("--dra",type=int,default=20);p.add_argument("--drev",type=int,default=32);p.add_argument("--delta-seconds",type=int,default=30);p.add_argument("--requests",type=int,default=10);p.add_argument("--fixture",choices=("fixed","two-source-a"),default="fixed");a=p.parse_args();assert a.requests>=10;aud="https://service.example";body=b"payload";now=150
 import os
 if a.fixture=="two-source-a":os.environ["PLAN_A_AGENT_FIXTURE"]="two-source-a"
 proc=subprocess.Popen([a.agent,"serve",a.pk,a.vk,str(a.l),str(a.active),str(a.ds),str(a.dra),str(a.drev),aud,body.decode()],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
 ready=json.loads(proc.stdout.readline());assert ready.get("ready") is True,ready;artifacts=[]
 for i in range(a.requests):proc.stdin.write(json.dumps({"nonce":1000+i,"now":now})+"\n");proc.stdin.flush();artifacts.append(json.loads(proc.stdout.readline()))
 first=artifacts[0];os.environ.update(PLAN_A_VK_PATH=a.vk,PLAN_A_VK_ID=first["vk_id"],PLAN_A_L=str(a.l),PLAN_A_DS=str(a.ds),PLAN_A_DRA=str(a.dra),PLAN_A_DREV=str(a.drev),PLAN_A_REGISTRY_PK_B64=first["registry_pk_b64"],PLAN_A_DEPLOYMENT_ID=first["bootstrap_admission"]["deployment_id"])
 deployment=first["bootstrap_admission"]["deployment_id"];clock=Clock(now)
 with tempfile.TemporaryDirectory() as td:
  app=App(Store(Path(td)/"resident.db"),CoreVerifier([a.core],180),a.delta_seconds,aud,clock,deployment);server=serve(app);port=server.server_port
  for admission in first.get("bootstrap_admissions",[first["bootstrap_admission"]]):st,_=call(port,"/admin/enroll",canonical(admission),{"Content-Type":"application/json"});assert st==201
  st,_=call(port,"/admin/header",canonical(first["snapshot"]),{"X-PlanA-Header-Signature":first["header_signature_b64"]});assert st==201
  rows=[]
  for i,x in enumerate(artifacts):
   env=x["envelope"];request={k:env[k] for k in ("protocol_version","deployment_id","audience","resource","action_onehot","nonce","request_time","expires_at","terminal_agent_pk","circuit_id","vk_id","snapshot_digest")};request.update(method="POST",path="/resource/read",body_sha256=hashlib.sha256(body).hexdigest());auth=json.dumps(env,separators=(",",":"));t=time.perf_counter_ns();st,val=call(port,"/resource/read",body,{"X-PlanA-Authorization":auth});wall=time.perf_counter_ns()-t;assert st==200,(i,st,val);rows.append({"index":i,"nonce":1000+i,"prove_ns":int(x["timing"]["prove_with_loaded_pk_ms"]*1_000_000),"http_ns":wall,"status":st,"canonical_request_bytes":len(canonical(request)),"nonce_decoded_bytes":len(base64.urlsafe_b64decode(env["nonce"]+"="*(-len(env["nonce"])%4))),"authorization_header_bytes":len(auth.encode()),"body_bytes":len(body),"response_bytes":len(canonical(val)),"proof_bytes":len(base64.b64decode(env["proof_b64"]))})
  server.shutdown();server.server_close()
 proc.stdin.close();proc.wait(timeout=10);same=a.fixture=="two-source-a";out={"schema":"plan-a-joint-http-warm-v2","ok":True,"profile":{"fixture":a.fixture,"fixture_provenance":first.get("fixture_provenance"),"L":a.l,"active":a.active,"DS":a.ds,"DRA":a.dra,"DRev":a.drev,"delta_seconds":a.delta_seconds,"body_utf8":"payload","method":"POST","path":"/resource/read","audience":aud,"warm_process_mode":"resident_agent_cached_pk; one-shot_public_verifier_per_HTTP"},"h0":{"snapshot":first["snapshot"],"snapshot_digest":first["snapshot_digest"],"terminal_agent_pk":first["envelope"]["terminal_agent_pk"],"resource":first["envelope"]["resource"],"action_onehot":first["envelope"]["action_onehot"],"request_time":first["envelope"]["request_time"],"expires_at":first["envelope"]["expires_at"]},"initialization":{"cold_pk_load_ms":ready["pk_load_ms"]},"comparison_notes":{"same_nonce_encoding_as_sr":True,"same_body_method_path_audience_time_window_as_sr":True,"canonical_request_schema_and_length_may_differ_due_to_scheme_config_fields":True,"same_h0_fixture_as_sr":same},"requests":rows};a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(out,indent=2)+"\n");print(json.dumps({"ok":True,"trace":str(a.out),"cold_pk_load_ms":ready["pk_load_ms"],"warm_requests":len(rows)}))
if __name__=="__main__":main()
