#!/usr/bin/env python3
"""Run the real Agent -> HTTP service -> Rust verifier path and save a trace."""
from __future__ import annotations
import argparse, base64, copy, http.client, json, os, subprocess, tempfile, threading, time
from pathlib import Path
from service import App, CoreVerifier, Store, canonical, handler_for
from http.server import ThreadingHTTPServer

def call(port:int,path:str,body:bytes,headers:dict[str,str]):
    c=http.client.HTTPConnection("127.0.0.1",port,timeout=180);c.request("POST",path,body,headers);r=c.getresponse();data=r.read();c.close();return r.status,json.loads(data)
def corrupt(s:str)->str:
    b=bytearray(base64.b64decode(s));b[-1]^=1;return base64.b64encode(b).decode()
class Clock:
    def __init__(self,n:int):self.n=n
    def __call__(self):return self.n
class FlipVerifier(CoreVerifier):
    def __init__(self,argv,timeout,clock,flip):super().__init__(argv,timeout);self.clock=clock;self.flip=flip
    def call(self,payload):
        ok=super().call(payload)
        if payload.get("command")=="terminal-verify":self.clock.n=self.flip
        return ok
def serve(app):
    server=ThreadingHTTPServer(("127.0.0.1",0),handler_for(app));threading.Thread(target=server.serve_forever,daemon=True).start();return server
def main():
    p=argparse.ArgumentParser();p.add_argument("--agent",required=True);p.add_argument("--mutation",required=True);p.add_argument("--lifecycle",required=True);p.add_argument("--core",required=True);p.add_argument("--pk",required=True);p.add_argument("--vk",required=True);p.add_argument("--out",type=Path,required=True);p.add_argument("--l",type=int,default=3);p.add_argument("--active",type=int,default=2);p.add_argument("--ds",type=int,default=10);p.add_argument("--dra",type=int,default=20);p.add_argument("--drev",type=int,default=32);a=p.parse_args()
    now=150;audience="https://service.example";body=b"payload"
    cmd=[a.agent,a.pk,a.vk,str(a.l),str(a.active),"101",str(a.ds),str(a.dra),str(a.drev),str(now),audience,body.decode()]
    artifact=json.loads(subprocess.check_output(cmd,text=True));assert "error" not in artifact,artifact
    os.environ.update(PLAN_A_VK_PATH=a.vk,PLAN_A_VK_ID=artifact["vk_id"],PLAN_A_L=str(a.l),PLAN_A_DS=str(a.ds),PLAN_A_DRA=str(a.dra),PLAN_A_DREV=str(a.drev),PLAN_A_REGISTRY_PK_B64=artifact["registry_pk_b64"],PLAN_A_DEPLOYMENT_ID=artifact["bootstrap_admission"]["deployment_id"])
    core=[a.core];trace={"config":{"l":a.l,"active":a.active,"ds":a.ds,"dra":a.dra,"drev":a.drev,"vk_id":artifact["vk_id"],"circuit_id":artifact["circuit_id"]},"agent_timing":artifact.get("timing"),"checks":{}}
    with tempfile.TemporaryDirectory() as td:
        deployment=artifact["bootstrap_admission"]["deployment_id"]
        clock=Clock(now);app=App(Store(Path(td)/"main.db"),CoreVerifier(core,180),30,audience,clock,deployment);server=serve(app);port=server.server_port
        st,val=call(port,"/admin/enroll",canonical(artifact["bootstrap_admission"]),{"Content-Type":"application/json"});assert st==201,(st,val);trace["checks"]["fixture_state_bootstrap"]={"status":st,"body":val}
        st,val=call(port,"/admin/ra-register",canonical(artifact["bootstrap_ra_registration"]),{"Content-Type":"application/json"});assert st==201,(st,val);trace["checks"]["fixture_ra_bootstrap"]={"status":st,"body":val}
        bad=corrupt(artifact["header_signature_b64"]);st,val=call(port,"/admin/header",canonical(artifact["snapshot"]),{"X-PlanA-Header-Signature":bad,"Content-Type":"application/json"});assert st==403;(trace["checks"]).__setitem__("bad_header_signature",{"status":st,"body":val})
        st,val=call(port,"/admin/header",canonical(artifact["snapshot"]),{"X-PlanA-Header-Signature":artifact["header_signature_b64"],"Content-Type":"application/json"});assert st==201;(trace["checks"]).__setitem__("install_header",{"status":st,"body":val})
        base=artifact["envelope"]
        mutations={
          "protocol_version":"wrong","deployment_id":"00"*31+"0a","audience":"https://wrong.example","resource":"fr:"+"00"*32,"action_onehot":3,
          "nonce":base["nonce"][:-1]+("A" if base["nonce"][-1]!="A" else "B"),"request_time":149,"expires_at":181,
          "terminal_agent_pk":corrupt(base["terminal_agent_pk"]),"circuit_id":"wrong","vk_id":"00"*32,
          "snapshot_digest":"00"*32,"relation_request_digest":"00"*32,"proof_b64":corrupt(base["proof_b64"]),"signature_b64":corrupt(base["signature_b64"]),
        }
        field_results={}
        for field,value in mutations.items():
            altered=copy.deepcopy(base);altered[field]=value;st,val=call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(altered,separators=(",",":"))});assert st!=200,(field,val);field_results[field]={"status":st,"error":val.get("error")}
        trace["checks"]["field_mutations"]=field_results
        broken=copy.deepcopy(base);broken["signature_b64"]=corrupt(base["signature_b64"]);st,val=call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(broken,separators=(",",":"))});assert st==403;trace["checks"]["bad_terminal_signature"]={"status":st,"body":val}
        barrier=threading.Barrier(3);results=[]
        def worker():barrier.wait();results.append(call(port,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(base,separators=(",",":"))}))
        ts=[threading.Thread(target=worker) for _ in range(2)];[t.start() for t in ts];barrier.wait();[t.join() for t in ts];statuses=sorted(x[0] for x in results);assert statuses==[200,409],results;trace["checks"]["nonce_concurrency"]=[{"status":s,"body":v} for s,v in results]
        enroll=json.loads(subprocess.check_output([a.mutation,"enroll"],text=True));enroll_conflict=json.loads(subprocess.check_output([a.mutation,"enroll-position-conflict"],text=True));state=json.loads(subprocess.check_output([a.mutation,"state-update"],text=True));state_expiry=json.loads(subprocess.check_output([a.mutation,"state-update-expiry"],text=True));reactivate=json.loads(subprocess.check_output([a.mutation,"state-reactivate"],text=True));revoke=json.loads(subprocess.check_output([a.mutation,"revoke"],text=True))
        bad_state=copy.deepcopy(state);bad_state["signature_b64"]=corrupt(state["signature_b64"]);st,val=call(port,"/admin/state-update",canonical(bad_state),{"Content-Type":"application/json"});assert st in (403,404),(st,val);trace["checks"]["unregistered_or_bad_state"]={"status":st,"body":val}
        bad_enroll=copy.deepcopy(enroll);bad_enroll["signature_b64"]=corrupt(enroll["signature_b64"]);st,val=call(port,"/admin/enroll",canonical(bad_enroll),{"Content-Type":"application/json"});assert st==403,(st,val);trace["checks"]["bad_admission_signature"]={"status":st,"body":val}
        st,val=call(port,"/admin/enroll",canonical(enroll),{"Content-Type":"application/json"});assert st==201,(st,val);trace["checks"]["trusted_enrollment"]={"status":st,"body":val}
        st,val=call(port,"/admin/enroll",canonical(enroll_conflict),{"Content-Type":"application/json"});assert st==409,(st,val);trace["checks"]["cross_owner_position_conflict"]={"status":st,"body":val}
        bad_state=copy.deepcopy(state);bad_state["signature_b64"]=corrupt(state["signature_b64"]);st,val=call(port,"/admin/state-update",canonical(bad_state),{"Content-Type":"application/json"});assert st==403,(st,val);trace["checks"]["bad_owner_signature"]={"status":st,"body":val}
        roots_before_failed_update=app.verifier.response(app.store.materialization_inputs(deployment))
        st,val=call(port,"/admin/state-update",canonical(state_expiry),{"Content-Type":"application/json"});assert st==403,(st,val);trace["checks"]["state_expiry_cap"]={"status":st,"body":val}
        roots_after_failed_update=app.verifier.response(app.store.materialization_inputs(deployment));assert roots_before_failed_update==roots_after_failed_update;trace["checks"]["failed_update_not_in_root"]=True
        barrier=threading.Barrier(3);state_results=[]
        def state_worker():barrier.wait();state_results.append(call(port,"/admin/state-update",canonical(state),{"Content-Type":"application/json"}))
        ts=[threading.Thread(target=state_worker) for _ in range(2)];[t.start() for t in ts];barrier.wait();[t.join() for t in ts];assert sorted(x[0] for x in state_results)==[201,409],state_results;state_ack_observed_ns=time.time_ns();trace["checks"]["state_cas_concurrency"]=[{"status":s,"body":v} for s,v in state_results]
        st,val=call(port,"/admin/state-update",canonical(reactivate),{"Content-Type":"application/json"});assert st==403,(st,val);trace["checks"]["owner_cannot_reactivate"]={"status":st,"body":val}
        barrier=threading.Barrier(3);rev_results=[]
        def rev_worker():barrier.wait();rev_results.append(call(port,"/admin/revoke",canonical(revoke),{"Content-Type":"application/json"}))
        ts=[threading.Thread(target=rev_worker) for _ in range(2)];[t.start() for t in ts];barrier.wait();[t.join() for t in ts];assert sorted(x[0] for x in rev_results)==[201,409],rev_results;revocation_ack_observed_ns=time.time_ns();trace["checks"]["revocation_uniqueness"]=[{"status":s,"body":v} for s,v in rev_results]
        roots=app.verifier.response(app.store.materialization_inputs(deployment));assert roots and roots.get("valid") is True,roots
        successor=dict(artifact["snapshot"]);successor.update(tuple_version=2,state_root=roots["state_root"],revocation_root=roots["revocation_root"],revocation_epoch=10,issued_at=now)
        wrong=dict(successor);wrong["state_root"]="00"*32;wrong_sig=json.loads(subprocess.check_output([a.mutation,"sign-header",json.dumps(wrong,sort_keys=True,separators=(",",":"))],text=True))["signature_b64"]
        st,val=call(port,"/admin/header",canonical(wrong),{"X-PlanA-Header-Signature":wrong_sig});assert st==400 and val.get("error")=="header-root-does-not-match-registry",(st,val);trace["checks"]["signed_wrong_registry_root"]={"status":st,"body":val}
        successor_sig=json.loads(subprocess.check_output([a.mutation,"sign-header",json.dumps(successor,sort_keys=True,separators=(",",":"))],text=True))["signature_b64"]
        st,val=call(port,"/admin/header",canonical(successor),{"X-PlanA-Header-Signature":successor_sig});assert st==201,(st,val);successor_installed_observed_ns=time.time_ns();trace["checks"]["materialized_successor_header"]={"status":st,"body":val,"roots":roots,"state_ack_observed_ns":state_ack_observed_ns,"revocation_ack_observed_ns":revocation_ack_observed_ns,"successor_installed_observed_ns":successor_installed_observed_ns,"publication_delay_claimed":False}
        server.shutdown();server.server_close()
        expiry_clock=Clock(now);expiry_app=App(Store(Path(td)/"expiry.db"),FlipVerifier(core,180,expiry_clock,181),30,audience,expiry_clock,deployment);expiry_server=serve(expiry_app);ep=expiry_server.server_port
        st,_=call(ep,"/admin/enroll",canonical(artifact["bootstrap_admission"]),{"Content-Type":"application/json"});assert st==201
        st,_=call(ep,"/admin/header",canonical(artifact["snapshot"]),{"X-PlanA-Header-Signature":artifact["header_signature_b64"]});assert st==201
        st,val=call(ep,"/resource/read",body,{"X-PlanA-Authorization":json.dumps(base,separators=(",",":"))});assert st==409 and val.get("error")=="stale-after-verification",(st,val);trace["checks"]["expiry_at_commit"]={"status":st,"body":val}
        expiry_server.shutdown();expiry_server.server_close()
        lifecycle=json.loads(subprocess.check_output([a.lifecycle],text=True));life_clock=Clock(now);life_app=App(Store(Path(td)/"lifecycle.db"),CoreVerifier(core,180),0,audience,life_clock,deployment);life_server=serve(life_app);lp=life_server.server_port
        for admission in lifecycle["bootstrap_admissions"]:
            st,av=call(lp,"/admin/enroll",canonical(admission),{"Content-Type":"application/json"});assert st==201,(st,av)
        for registration in lifecycle["bootstrap_ra_registrations"]:
            st,av=call(lp,"/admin/ra-register",canonical(registration),{"Content-Type":"application/json"});assert st==201,(st,av)
        st,v0=call(lp,"/admin/header",canonical(lifecycle["h0"]),{"X-PlanA-Header-Signature":lifecycle["h0_signature_b64"]});assert st==201,(st,v0)
        assert lifecycle["revoke"]["sn"]==lifecycle["revoked_grant_serial"]
        st,rv=call(lp,"/admin/revoke",canonical(lifecycle["revoke"]),{"Content-Type":"application/json"});rev_ack_ns=time.time_ns();assert st==201 and rv.get("publication_status")=="pending",(st,rv)
        st,v1=call(lp,"/admin/header",canonical(lifecycle["h1"]),{"X-PlanA-Header-Signature":lifecycle["h1_signature_b64"]});h1_install_ns=time.time_ns();assert st==201,(st,v1);assert v0["snapshot_digest"]!=v1["snapshot_digest"]
        h0_current=life_app.store.accepted_snapshot(v0["snapshot_digest"],life_clock(),0);assert h0_current is None
        trace["checks"]["linked_revocation_header_lifecycle"]={"revoked_grant_serial":lifecycle["revoked_grant_serial"],"capability_serial":lifecycle["revoke"]["sn"],"h0":v0,"revoke":rv,"h1":v1,"h0_rejected_at_delta0":True,"revocation_ack_observed_ns":rev_ack_ns,"successor_installed_observed_ns":h1_install_ns,"publication_delay_claimed":False}
        life_server.shutdown();life_server.server_close()
    trace["ok"]=True;a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(trace,indent=2,sort_keys=True)+"\n");print(json.dumps({"ok":True,"trace":str(a.out),"checks":list(trace["checks"])}))
if __name__=="__main__":main()
