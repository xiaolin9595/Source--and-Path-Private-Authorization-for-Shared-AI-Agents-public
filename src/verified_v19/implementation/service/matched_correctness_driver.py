#!/usr/bin/env python3
"""Untimed same-process, same-SQLite t0 -> t1 -> t2 correctness gate."""
from __future__ import annotations
import argparse, copy, hashlib, json, os, subprocess, threading, time, urllib.error, urllib.request
from pathlib import Path
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def canonical(v):return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def cmd(v):
    x=json.loads(v)
    if not isinstance(x,list) or not x:return (_ for _ in ()).throw(ValueError("command JSON array required"))
    return x
def post(url,auth,body=b'{"operation":"read"}'):
    req=urllib.request.Request(url,data=body,method="POST",headers={"X-PlanA-Authorization":canonical(auth).decode(),"Content-Type":"application/json"})
    try:
        with OPENER.open(req,timeout=600) as r:return r.status,json.loads(r.read())
    except urllib.error.HTTPError as e:return e.code,json.loads(e.read())
def wait(url,process):
    for _ in range(600):
        if process.poll() is not None:raise RuntimeError(f"service exited before readiness: rc={process.returncode}")
        try:OPENER.open(url,timeout=.2)
        except urllib.error.HTTPError:return
        except Exception:time.sleep(.05);continue
    raise RuntimeError("service start timeout")
def require(label,status,value,allowed):
    if status not in allowed:raise RuntimeError(f"{label}: unexpected {status} {value}")
    return {"label":label,"status":status,"response":value}
def flip_hex(value):
    raw=bytearray.fromhex(value);raw[0]^=1;return raw.hex()
def main():
    p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True);p.add_argument("--case-plan",type=Path,required=True);p.add_argument("--joint-bundle",type=Path,required=True);p.add_argument("--dac-bundle",type=Path,required=True);p.add_argument("--joint-resident-cmd",required=True);p.add_argument("--dac-resident-cmd",required=True);p.add_argument("--service-script",type=Path,required=True);p.add_argument("--out",type=Path,required=True);p.add_argument("--port",type=int,default=18789);a=p.parse_args()
    manifest=json.loads(a.manifest.read_bytes());bundles={"joint-bls12-381":json.loads(a.joint_bundle.read_bytes()),"dac-bw6-761":json.loads(a.dac_bundle.read_bytes())};hashes={v["semantic_input_sha256"] for v in bundles.values()}
    def case(bundle,name):
        value=bundle["cases"][name];return value["envelope"],canonical(value["body"])
    if len(hashes)!=1:raise RuntimeError("semantic hash mismatch")
    case_plan=json.loads(a.case_plan.read_bytes());case_plan_sha=hashlib.sha256(a.case_plan.read_bytes()).hexdigest()
    if any(bundle.get("case_plan_sha256")!=case_plan_sha for bundle in bundles.values()):raise RuntimeError("case plan digest mismatch")
    if any(set(bundle["cases"])!=set(case_plan["cases"]) for bundle in bundles.values()):raise RuntimeError("case IDs mismatch")
    semantic_sha=hashes.pop();audience="https://matched.service.example";path="/resource/read"
    for bundle in bundles.values():
        base=manifest["request"]["nonce_u64"]
        for name,spec in case_plan["cases"].items():
            item=bundle["cases"][name]
            if item["update_index"]!=spec["update_index"] or item["body"]["nonce_u64"]!=base+spec["nonce_offset"]:raise RuntimeError(f"case plan mismatch: {name}")
    trusted={"schema":"plan-a-matched-service-config-v1","canonical_manifest":manifest,"semantic_input_sha256":semantic_sha,"audience":audience,"resource_path":path,"terminal_keys":{k:v["terminal_public_key"] for k,v in bundles.items()},"backend_profiles":{k:v.get("backend_profile") or v.get("trusted_config",{}).get("backend_profile") or {"vk_sha256":v["vk_sha256"]} for k,v in bundles.items()}}
    a.out.mkdir(parents=True,exist_ok=False);trusted_path=a.out/"trusted.json";trusted_path.write_bytes(canonical(trusted));clock=a.out/"clock";clock.write_text(str(manifest["request"]["now"]));env=os.environ.copy();env.update({"NO_PROXY":"127.0.0.1,localhost","no_proxy":"127.0.0.1,localhost","MATCHED_MANIFEST_PATH":str(a.manifest),"MATCHED_SEMANTIC_SHA256":semantic_sha,"MATCHED_JOINT_VK_PATH":str(bundles["joint-bls12-381"]["vk_path"]),"MATCHED_JOINT_VK_SHA256":bundles["joint-bls12-381"]["vk_sha256"],"MATCHED_REGISTRY_PK_HEX":bundles["joint-bls12-381"]["registry_public_key"],"MATCHED_JOINT_CIRCUIT_ID":"plan-a-matched-joint-l2-v1"})
    for bundle in bundles.values():
        resident_env=bundle.get("resident_env",{})
        if not isinstance(resident_env,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in resident_env.items()):raise ValueError("bad resident_env")
        if any(k.startswith("MATCHED_") for k in resident_env):raise ValueError("resident_env overwrites matched trusted config")
        env.update(resident_env)
    dac=bundles["dac-bw6-761"]
    if not dac.get("resident_env") or "trusted_config_sha256" not in dac:raise ValueError("DAC trusted resident config missing")
    dac_config=Path(dac["resident_env"]["DAC_TRUSTED_CONFIG_PATH"])
    if hashlib.sha256(dac_config.read_bytes()).hexdigest()!=dac["trusted_config_sha256"]:raise ValueError("DAC trusted config digest mismatch")
    bad_clock_config=copy.deepcopy(trusted);bad_clock_config["canonical_manifest"]["updates"][1]["issued_at"]=bad_clock_config["canonical_manifest"]["updates"][0]["issued_at"]-1;bad_clock_path=a.out/"trusted-bad-clock.json";bad_clock_path.write_bytes(canonical(bad_clock_config))
    bad_clock_service=[os.environ.get("PYTHON","python3"),str(a.service_script),"--db",str(a.out/"bad-clock.sqlite"),"--trusted-config",str(bad_clock_path),"--port",str(a.port+1),"--clock-file",str(clock),"--joint-cli",*cmd(a.joint_resident_cmd),"--dac-cli",*cmd(a.dac_resident_cmd)]
    bad_clock_run=subprocess.run(bad_clock_service,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);(a.out/"bad-clock.stdout").write_bytes(bad_clock_run.stdout);(a.out/"bad-clock.stderr").write_bytes(bad_clock_run.stderr)
    if bad_clock_run.returncode==0 or b"bad-trusted-clock-mapping" not in bad_clock_run.stderr:raise RuntimeError("tampered trusted clock mapping was not rejected")
    barrier=a.out/"read-barrier";env["MATCHED_READ_BARRIER_DIR"]=str(barrier)
    service=[os.environ.get("PYTHON","python3"),str(a.service_script),"--db",str(a.out/"correctness.sqlite"),"--trusted-config",str(trusted_path),"--port",str(a.port),"--clock-file",str(clock),"--joint-cli",*cmd(a.joint_resident_cmd),"--dac-cli",*cmd(a.dac_resident_cmd)];service_stdout=(a.out/"service.stdout").open("wb");service_stderr=(a.out/"service.stderr").open("wb");proc=subprocess.Popen(service,env=env,stdout=service_stdout,stderr=service_stderr);results=[]
    try:
      wait(f"http://127.0.0.1:{a.port}/not-found",proc)
      for phase_index in range(3):
        raced={};race_threads=[]
        if phase_index==1:
          barrier.mkdir(exist_ok=True);(barrier/"enabled").write_text("1")
          for race_backend,race_bundle in bundles.items():
            stale,stale_body=case(race_bundle,"old_ticket")
            thread=threading.Thread(target=lambda b=race_backend,e=stale,bo=stale_body:raced.__setitem__(b,post(f"http://127.0.0.1:{a.port}{path}",{"backend":b,"envelope":e},bo)));thread.start();race_threads.append(thread)
          for _ in range(3000):
            if all((barrier/f"reached-{backend}").exists() for backend in bundles):break
            time.sleep(.01)
          else:raise RuntimeError("read-ticket barrier not reached")
        for backend,bundle in bundles.items():
          phase=bundle["phases"][phase_index];status,value=post(f"http://127.0.0.1:{a.port}/admin/matched-header",{"backend":backend,"update_index":phase_index,"envelope":phase["header_envelope"]},b"");results.append(require(f"t{phase_index}-{backend}-header",status,value,{201}))
        if phase_index==1:
          (barrier/"release").write_text("1")
          for thread in race_threads:thread.join(30)
          if any(thread.is_alive() for thread in race_threads) or len(raced)!=len(bundles):raise RuntimeError("read-ticket race did not finish")
          for race_backend,(status,value) in raced.items():results.append(require(f"t0-ticket-after-t1-header-{race_backend}",status,value,{409}))
          (barrier/"enabled").unlink()
        if phase_index==0:
          for backend,bundle in bundles.items():
            for name in ("t0_a","t0_b","t0_c"):
              envelope,case_bytes=case(bundle,name);status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":envelope},case_bytes);results.append(require(f"{name}-{backend}",status,value,{200}))
            for name,target in (("negative_body","body"),("negative_proof","proof"),("negative_terminal","terminal_signature")):
              envelope,case_bytes=case(bundle,name);auth={"backend":backend,"envelope":copy.deepcopy(envelope)}
              if target=="body":case_bytes=canonical({"nonce_u64":json.loads(case_bytes)["nonce_u64"],"operation":"changed"});expected_status={400}
              else:auth["envelope"][target]=flip_hex(auth["envelope"][target]);expected_status={403}
              status,value=post(f"http://127.0.0.1:{a.port}{path}",auth,case_bytes);results.append(require(f"{name}-{backend}",status,value,expected_status));status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":envelope},canonical(bundle["cases"][name]["body"]));results.append(require(f"{name}-nonce-not-consumed-{backend}",status,value,{200}))
        elif phase_index==1:
          for backend,bundle in bundles.items():
            stale,stale_body=case(bundle,"removed_a");status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":stale},stale_body);results.append(require(f"removed-a-{backend}",status,value,{403}))
            for name in ("t1_b","t1_c"):
              envelope,case_bytes=case(bundle,name);status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":envelope},case_bytes);results.append(require(f"{name}-{backend}",status,value,{200}))
        else:
          for backend,bundle in bundles.items():
            stale,stale_body=case(bundle,"revoked_b");status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":stale},stale_body);results.append(require(f"revoked-b-{backend}",status,value,{403}))
            valid,valid_body=case(bundle,"t2_c");status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":valid},valid_body);results.append(require(f"t2-c-{backend}",status,value,{200}));status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":valid},valid_body);results.append(require(f"replay-{backend}",status,value,{409}))
      clock.write_text(str(manifest["request"]["interval_hi"]+1))
      for backend,bundle in bundles.items():
        envelope,case_bytes=case(bundle,"expired");status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":envelope},case_bytes);results.append(require(f"expired-{backend}",status,value,{403}))
      clock.write_text(str(manifest["request"]["now"]))
      for backend,bundle in bundles.items():
        envelope,case_bytes=case(bundle,"expired");status,value=post(f"http://127.0.0.1:{a.port}{path}",{"backend":backend,"envelope":envelope},case_bytes);results.append(require(f"expired-nonce-not-consumed-{backend}",status,value,{200}))
    finally:proc.terminate();proc.wait(timeout=10);service_stdout.close();service_stderr.close()
    (a.out/"correctness.json").write_text(json.dumps({"valid":True,"results":results},indent=2,sort_keys=True));print(json.dumps({"valid":True,"checks":len(results)}))
if __name__=="__main__":main()
