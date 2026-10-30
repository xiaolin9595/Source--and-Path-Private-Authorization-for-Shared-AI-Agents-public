#!/usr/bin/env python3
"""Runner-only H0/H1/H2 SR lifecycle plus ten warm real HTTP requests."""
import argparse,base64,concurrent.futures,hashlib,json,os,subprocess,tempfile,time
from pathlib import Path
from real_http_trace import Clock,call,serve
from service import App,CoreVerifier,Store,canonical
class FlipSRVerifier(CoreVerifier):
 def __init__(self,argv,timeout,clock,flip):super().__init__(argv,timeout);self.clock,self.flip=clock,flip
 def call(self,p):
  ok=super().call(p)
  if p.get("command")=="sr-terminal-verify":self.clock.n=self.flip
  return ok
def direct(argv,p):return json.loads(subprocess.run(argv,input=canonical(p)+b"\n",stdout=subprocess.PIPE,check=False).stdout)
def show(proc,request,seed,stale_epoch=None):
 payload={"request":request,"show_seed":seed}
 if stale_epoch is not None:payload["stale_credential_epoch"]=stale_epoch
 wire=canonical(payload);proc.stdin.write(wire.decode()+"\n");proc.stdin.flush();o=json.loads(proc.stdout.readline());assert "error" not in o,o
 env={k:request[k] for k in ("protocol_version","proof_scheme","config_id","deployment_id","audience","resource","action_onehot","nonce","request_time","expires_at","terminal_agent_pk","circuit_id","snapshot_digest")};env.update(showing_b64=o["showing_b64"],signature_b64=o["signature_b64"]);return env,o["timing"],len(wire)
def main():
 p=argparse.ArgumentParser();p.add_argument("--agent",required=True);p.add_argument("--setup",required=True);p.add_argument("--sr-verifier",required=True);p.add_argument("--joint-core",required=True);p.add_argument("--out",type=Path,required=True);p.add_argument("--requests",type=int,default=10);a=p.parse_args();assert a.requests>=10
 with tempfile.TemporaryDirectory() as td:
  cfg=Path(td)/"trusted.json";setup_started=time.perf_counter_ns();cfg.write_bytes(subprocess.check_output([a.setup]));setup_wall_ns=time.perf_counter_ns()-setup_started;describe_started=time.perf_counter_ns();desc=json.loads(subprocess.check_output([a.agent,"describe"],text=True));admin_artifacts_wall_ns=time.perf_counter_ns()-describe_started;headers=desc["headers"];h0,h1,h2=headers;aud="https://service.example";body=b"payload";now=150
  os.environ.update(PLAN_A_REGISTRY_PK_B64=desc["registry_pk_b64"],PLAN_A_DEPLOYMENT_ID=desc["deployment_id"],PLAN_A_DS="3",PLAN_A_DREV="4")
  proc=subprocess.Popen([a.agent,"serve",str(cfg)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1);ready=json.loads(proc.stdout.readline());assert ready.get("ready") is True
  def request(i,h=h0):
   raw=(1000+i).to_bytes(16,"big");return {"action_onehot":1,"audience":aud,"body_sha256":hashlib.sha256(body).hexdigest(),"circuit_id":desc["circuit_id"],"config_id":ready["config_id"],"deployment_id":desc["deployment_id"],"expires_at":now+30,"method":"POST","nonce":base64.urlsafe_b64encode(raw).decode().rstrip("="),"path":"/resource/read","proof_scheme":ready["proof_scheme"],"protocol_version":"plan-a-http-v1","request_time":now,"resource":"fr:"+(700).to_bytes(32,"big").hex(),"snapshot_digest":h["snapshot_digest"],"terminal_agent_pk":desc["terminal_agent_pk"]}
  sr=[a.sr_verifier,str(cfg)];clock=Clock(now);app=App(Store(Path(td)/"sr.db"),CoreVerifier([a.joint_core],180),0,aud,clock,desc["deployment_id"],CoreVerifier(sr,180));server=serve(app);port=server.server_port
  for admission in desc["bootstrap_admissions"]:assert call(port,"/admin/enroll",canonical(admission),{"Content-Type":"application/json"})[0]==201
  assert call(port,"/admin/header",canonical(h0["snapshot"]),{"X-PlanA-Header-Signature":h0["header_signature_b64"]})[0]==201
  rows=[]
  for i in range(a.requests):
   req=request(i);env,timing,agent_in=show(proc,req,0x5100+i);auth=json.dumps(env,separators=(",",":"));t=time.perf_counter_ns();status,val=call(port,"/resource/read",body,{"X-PlanA-Authorization":auth});http_ns=time.perf_counter_ns()-t;assert status==200,(i,status,val);rows.append({"index":i,"status":status,"show_ns":timing["show_ns"],"http_ns":http_ns,"showing_bytes":timing["showing_bytes"],"canonical_request_bytes":len(canonical(req)),"nonce_decoded_bytes":len(base64.urlsafe_b64decode(req["nonce"]+"="*(-len(req["nonce"])%4))),"agent_input_bytes":agent_in,"authorization_header_bytes":len(auth.encode()),"body_bytes":len(body),"response_bytes":len(canonical(val))})
  bad_req=request(90);bad,_,_=show(proc,bad_req,0x9900);good=dict(bad);raw=bytearray(base64.b64decode(bad["showing_b64"]));raw[len(raw)//2]^=1;bad["showing_b64"]=base64.b64encode(raw).decode();assert call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(bad,separators=(",",":"))})[0]==403;assert call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(good,separators=(",",":"))})[0]==200
  statement={"snapshot":h0["snapshot"],"request":bad_req,"canonical_request_sha256":hashlib.sha256(b"plan-a-request-v1\0"+canonical(bad_req)).hexdigest()};pkg={"command":"sr-verify","config_id":ready["config_id"],"proof_scheme":ready["proof_scheme"],"public_statement":statement,"showing_b64":good["showing_b64"]};assert direct(sr,pkg).get("valid") is True
  wrong=json.loads(json.dumps(pkg));wrong["public_statement"]["snapshot"]["state_root"]="00"*32;assert direct(sr,wrong).get("valid") is False;wrong=dict(pkg);wrong["config_id"]="other";assert direct(sr,wrong).get("valid") is False
  race_req=request(91);race,_,_=show(proc,race_req,0x9901);rh={"X-PlanA-Authorization":json.dumps(race,separators=(",",":"))}
  with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:statuses=list(ex.map(lambda _:call(port,"/resource/read",body,rh)[0],range(2)))
  assert sorted(statuses)==[200,409]
  mutations={}
  modulus="73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
  for j,(field,value) in enumerate((("nonce",base64.urlsafe_b64encode((9).to_bytes(16,"big")).decode().rstrip("=")),("resource","fr:"+(701).to_bytes(32,"big").hex()),("resource_alias","fr:"+modulus),("action_onehot",2),("circuit_id","00"*32),("config_id","other"),("deployment_id","00"*32))):
   env,_,_=show(proc,request(100+j),0xa000+j);actual="resource" if field=="resource_alias" else field;env[actual]=value;mutations[field]=call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(env,separators=(",",":"))})[0];assert mutations[field]!=200
  assert call(port,"/admin/revoke",canonical(desc["revoke_source_b"]),{"Content-Type":"application/json"})[0]==201;assert call(port,"/admin/header",canonical(h1["snapshot"]),{"X-PlanA-Header-Signature":h1["header_signature_b64"]})[0]==201
  refresh_started=time.perf_counter_ns();proc.stdin.write(json.dumps({"command":"refresh-h1"},separators=(",",":"))+"\n");proc.stdin.flush();h1_refresh=json.loads(proc.stdout.readline());refresh_client_wall_ns=time.perf_counter_ns()-refresh_started;assert h1_refresh.get("refreshed") is True,h1_refresh;h1_refresh["client_observed_wall_ns"]=refresh_client_wall_ns
  malicious_h0,_,_=show(proc,request(120,h1),0xb000,1);mh={"X-PlanA-Authorization":json.dumps(malicious_h0,separators=(",",":"))};assert call(port,"/resource/read",body,mh)[0]==403
  mr=request(120,h1);mstmt={"snapshot":h1["snapshot"],"request":mr,"canonical_request_sha256":hashlib.sha256(b"plan-a-request-v1\0"+canonical(mr)).hexdigest()};mp={"command":"sr-verify","config_id":ready["config_id"],"proof_scheme":ready["proof_scheme"],"public_statement":mstmt,"showing_b64":malicious_h0["showing_b64"]};assert direct(sr,mp).get("valid") is False
  mt={"command":"sr-terminal-verify","config_id":ready["config_id"],"proof_scheme":ready["proof_scheme"],"deployment_id":desc["deployment_id"],"circuit_id":desc["circuit_id"],"terminal_agent_pk":desc["terminal_agent_pk"],"canonical_request_sha256":mstmt["canonical_request_sha256"],"snapshot_digest":h1["snapshot_digest"],"showing_b64":malicious_h0["showing_b64"],"signature_b64":malicious_h0["signature_b64"]};assert direct(sr,mt).get("valid") is True
  h1env,_,_=show(proc,request(121,h1),0xb001);assert call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(h1env,separators=(",",":"))})[0]==200
  assert call(port,"/admin/state-update",canonical(desc["deactivate_source_a"]),{"Content-Type":"application/json"})[0]==201;assert call(port,"/admin/header",canonical(h2["snapshot"]),{"X-PlanA-Header-Signature":h2["header_signature_b64"]})[0]==201
  malicious_h1,_,_=show(proc,request(122,h2),0xb002,2);h2_status=call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(malicious_h1,separators=(",",":"))})[0];assert h2_status==403
  h2r=request(122,h2);h2stmt={"snapshot":h2["snapshot"],"request":h2r,"canonical_request_sha256":hashlib.sha256(b"plan-a-request-v1\0"+canonical(h2r)).hexdigest()};h2p={"command":"sr-verify","config_id":ready["config_id"],"proof_scheme":ready["proof_scheme"],"public_statement":h2stmt,"showing_b64":malicious_h1["showing_b64"]};assert direct(sr,h2p).get("valid") is False
  h2t=dict(mt);h2t.update(canonical_request_sha256=h2stmt["canonical_request_sha256"],snapshot_digest=h2["snapshot_digest"],showing_b64=malicious_h1["showing_b64"],signature_b64=malicious_h1["signature_b64"]);assert direct(sr,h2t).get("valid") is True
  server.shutdown();server.server_close()
  exp_clock=Clock(now);exp=App(Store(Path(td)/"exp.db"),CoreVerifier([a.joint_core],180),0,aud,exp_clock,desc["deployment_id"],FlipSRVerifier(sr,180,exp_clock,181));es=serve(exp);ep=es.server_port
  for admission in desc["bootstrap_admissions"]:assert call(ep,"/admin/enroll",canonical(admission),{"Content-Type":"application/json"})[0]==201
  assert call(ep,"/admin/header",canonical(h0["snapshot"]),{"X-PlanA-Header-Signature":h0["header_signature_b64"]})[0]==201;ee,_,_=show(proc,request(130),0xc000);expiry=call(ep,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(ee,separators=(",",":"))})[0];assert expiry==409;es.shutdown();es.server_close();proc.stdin.close();proc.wait(timeout=10)
  h0req=request(0);out={"schema":"plan-a-sr-http-lifecycle-v2","ok":True,"profile":{"fixture_provenance":"plan_a_joint_circuit::fixture::two_source_same_terminal","L":3,"DS":3,"DRA":3,"DRev":4,"delta_seconds":0,"body_utf8":"payload","method":"POST","path":"/resource/read","audience":aud,"warm_process_mode":"resident_agent_cached_prover_and_credentials; one-shot_public_verifier_per_HTTP","matched_e2_performance":False},"h0":{"snapshot":h0["snapshot"],"snapshot_digest":h0["snapshot_digest"],"terminal_agent_pk":h0req["terminal_agent_pk"],"resource":h0req["resource"],"action_onehot":h0req["action_onehot"],"request_time":h0req["request_time"],"expires_at":h0req["expires_at"]},"initialization":{"trusted_setup_process_wall_ns":setup_wall_ns,"admin_artifact_generation_wall_ns":admin_artifacts_wall_ns,"agent":ready["initialization"]},"credential_refresh":{"h1_after_revocation_and_header":h1_refresh,"issuer_model":"trusted issuer emulation colocated with benchmark Agent","production_network_delivery_measured":False},"warm_requests":len(rows),"requests":rows,"checks":{"invalid_show_no_nonce":True,"nonce_race":statuses,"mutations":mutations,"h0_stale_credential_fresh_h1_context_terminal_signature_valid":True,"h0_stale_credential_h1_anonymous_proof_rejected":True,"h1_surviving_credential_accepted":True,"h2_state_root_from_real_a_deactivation":True,"h1_stale_credential_fresh_h2_context_terminal_signature_valid":True,"h1_stale_credential_h2_anonymous_proof_status":h2_status,"expiry_at_commit":expiry}}
  a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(out,indent=2)+"\n");print(json.dumps({"ok":True,"trace":str(a.out)}))
if __name__=="__main__":main()
