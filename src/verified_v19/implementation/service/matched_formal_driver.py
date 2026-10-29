#!/usr/bin/env python3
"""Balanced ten-setup Joint/DAC proof-to-HTTP driver for the benchmark-host gate."""
from __future__ import annotations
import argparse, hashlib, json, os, random, statistics, subprocess, time, urllib.error, urllib.request
from pathlib import Path
OPENER=urllib.request.build_opener(urllib.request.ProxyHandler({}))

def canonical(v): return json.dumps(v,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
def command(value: str) -> list[str]:
    result=json.loads(value)
    if not isinstance(result,list) or not result or not all(isinstance(x,str) and x for x in result): raise ValueError("command must be JSON string array")
    return result
def atomic_json(path, value):
    temporary=path.with_suffix(path.suffix+".tmp");temporary.write_bytes(json.dumps(value,indent=2,sort_keys=True).encode());temporary.replace(path)
def run(argv, env, raw_path, log_path, parsed_result_path=None):
    started=time.perf_counter(); p=subprocess.run(argv,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=False)
    wall=(time.perf_counter()-started)*1000
    raw_path.write_bytes(p.stdout);stderr_path=raw_path.with_suffix(".stderr.log");stderr_path.write_bytes(p.stderr)
    parsed_bytes = parsed_result_path.read_bytes() if parsed_result_path is not None and parsed_result_path.exists() else p.stdout
    atomic_json(log_path,{"argv":argv,"returncode":p.returncode,"wall_ms":wall,"stdout_path":str(raw_path),"stdout_sha256":hashlib.sha256(p.stdout).hexdigest(),"stderr_path":str(stderr_path),"stderr_sha256":hashlib.sha256(p.stderr).hexdigest(),"parsed_result_path":str(parsed_result_path) if parsed_result_path is not None else str(raw_path),"parsed_result_sha256":hashlib.sha256(parsed_bytes).hexdigest()})
    if p.returncode: raise RuntimeError(f"command failed rc={p.returncode}: {p.stderr.decode(errors='replace')[-2000:]}")
    value=json.loads(parsed_bytes)
    if not isinstance(value,dict) or value.get("valid") is False: raise RuntimeError(f"bad producer response: {value}")
    return value,wall
def post(url, auth, body=b""):
    request=urllib.request.Request(url,data=body,method="POST",headers={"Content-Type":"application/json","X-PlanA-Authorization":canonical(auth).decode()})
    started=time.perf_counter()
    try:
        with OPENER.open(request,timeout=600) as response: status=response.status; value=json.loads(response.read())
    except urllib.error.HTTPError as exc: status=exc.code; value=json.loads(exc.read())
    return status,value,(time.perf_counter()-started)*1000
def wait_ready(url):
    for _ in range(100):
        try: OPENER.open(url,timeout=.2)
        except urllib.error.HTTPError: return
        except Exception: time.sleep(.05); continue
        return
    raise RuntimeError("service did not start")
def percentile(values,p):
    ordered=sorted(values);return ordered[min(len(ordered)-1,max(0,round((len(ordered)-1)*p)))]
def paired_summary(cells,seed):
    rng=random.Random(seed);backends=("joint-bls12-381","dac-bw6-761");draws={b:[] for b in backends};diff_draws=[]
    for _ in range(10000):
        sample=[rng.choice(cells) for _ in cells]
        medians={b:statistics.median(v[b] for v in sample) for b in backends}
        for b in backends:draws[b].append(medians[b])
        diff_draws.append(statistics.median(v["dac-bw6-761"]-v["joint-bls12-381"] for v in sample))
    backend_values={b:[v[b] for v in cells] for b in backends};diffs=[v["dac-bw6-761"]-v["joint-bls12-381"] for v in cells]
    return {"pairs":len(cells),"backend_median_ms":{b:statistics.median(backend_values[b]) for b in backends},"backend_median_ci95_ms":{b:[percentile(draws[b],.025),percentile(draws[b],.975)] for b in backends},"paired_dac_minus_joint_median_ms":statistics.median(diffs),"paired_median_difference_ci95_ms":[percentile(diff_draws,.025),percentile(diff_draws,.975)],"bootstrap_resamples":10000,"resampling_unit":"paired setup index"}
def bootstrap(rows,key,seed):
    pairs={}
    for row in rows:pairs.setdefault((row["setup"],row["actual"]),{})[row["backend"]]=row[key]
    result={}
    for actual in (1,2):
        cells=[v for (setup,cell_actual),v in pairs.items() if cell_actual==actual and len(v)==2]
        result[f"actual{actual}"]=paired_summary(cells,seed)
    return result
def setup_bootstrap(rows,seed):
    unique={(row["setup"],row["backend"]):row["setup_ms"] for row in rows};pairs={}
    for (setup,backend),value in unique.items():pairs.setdefault(setup,{})[backend]=value
    cells=[v for v in pairs.values() if len(v)==2]
    return paired_summary(cells,seed)
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--manifest",type=Path,required=True);ap.add_argument("--joint-fixture-cmd",required=True);ap.add_argument("--dac-fixture-cmd",required=True);ap.add_argument("--joint-resident-cmd",required=True);ap.add_argument("--dac-resident-cmd",required=True);ap.add_argument("--service-script",type=Path,required=True);ap.add_argument("--out",type=Path,required=True);ap.add_argument("--setups",type=int,default=10);ap.add_argument("--port",type=int,default=18788);args=ap.parse_args()
    manifest=json.loads(args.manifest.read_bytes()); semantic_sha=hashlib.sha256(json.dumps(manifest,separators=(",",":"),ensure_ascii=False).encode()).hexdigest()
    # Producers/residents independently recompute the authoritative typed hash; this provisional value is replaced by producer output.
    body=canonical({"nonce_u64":manifest["request"]["nonce_u64"],"operation":"read"}); audience="https://matched.service.example"; path="/resource/read"; http={"audience":audience,"body_sha256":hashlib.sha256(body).hexdigest(),"method":"POST","path":path}
    args.out.mkdir(parents=True,exist_ok=False); (args.out/"http.json").write_bytes(canonical(http));rows=[];setup_records=[]
    base_env=os.environ.copy();base_env.update({"NO_PROXY":"127.0.0.1,localhost","no_proxy":"127.0.0.1,localhost","MATCHED_MANIFEST_PATH":str(args.manifest),"MATCHED_HTTP_JSON_PATH":str(args.out/"http.json"),"MATCHED_UPDATE_INDEX":"1","MATCHED_REGISTRY_SK_U64":"7001","MATCHED_JOINT_CIRCUIT_ID":"plan-a-matched-joint-l2-v1"})
    for setup in range(args.setups):
        setup_dir=args.out/f"setup-{setup:02d}";setup_dir.mkdir(); env=dict(base_env);env["MATCHED_JOINT_VK_OUT"]=str(setup_dir/"joint.vk");env["MATCHED_DAC_VK_OUT"]=str(setup_dir/"dac.vk");env["MATCHED_DAC_PRODUCER_MODE"]="formal-t1";env["MATCHED_DAC_PRODUCER_OUT"]=str(setup_dir/"producer-dac-bw6-761.result.json");env["MATCHED_DAC_TRUSTED_CONFIG_OUT"]=str(setup_dir/"dac.trusted-config.json");env["MATCHED_DAC_VERIFY_FAILURE_OUT"]=str(setup_dir/"dac.verify-failure.json");env["MATCHED_CASE_PLAN_PATH"]=str(args.service_script.parent/"matched_case_plan_v1.json")
        producers={};walls={}
        order=["joint-bls12-381","dac-bw6-761"] if setup%2==0 else ["dac-bw6-761","joint-bls12-381"]
        for backend in order:
            argv=command(args.joint_fixture_cmd if backend.startswith("joint") else args.dac_fixture_cmd)
            raw_path=setup_dir/f"producer-{backend}.stdout.json"
            parsed_result_path=Path(env["MATCHED_DAC_PRODUCER_OUT"]) if backend=="dac-bw6-761" else None
            producers[backend],walls[backend]=run(argv,env,raw_path,setup_dir/f"producer-{backend}.command.json",parsed_result_path)
            atomic_json(setup_dir/f"producer-{backend}.parsed.json",producers[backend])
        if producers["dac-bw6-761"].get("producer_mode") != "formal-t1" or len(producers["dac-bw6-761"].get("rows",[])) != 2: raise RuntimeError("DAC formal producer did not emit exactly two t1 proofs")
        hashes={p["semantic_input_sha256"] for p in producers.values()}
        if len(hashes)!=1: raise RuntimeError("producer semantic hash mismatch")
        semantic_sha=hashes.pop(); terminal_keys={b:p["terminal_public_key"] for b,p in producers.items()}
        trusted={"schema":"plan-a-matched-service-config-v1","canonical_manifest":manifest,"semantic_input_sha256":semantic_sha,"audience":audience,"resource_path":path,"terminal_keys":terminal_keys,"backend_profiles":{b:p.get("backend_profile") or p.get("trusted_config",{}).get("backend_profile") or {"vk_sha256":p["vk_sha256"]} for b,p in producers.items()}}
        trusted_path=setup_dir/"trusted.json";trusted_path.write_bytes(canonical(trusted))
        env.update({"MATCHED_SEMANTIC_SHA256":semantic_sha,"MATCHED_JOINT_VK_PATH":str(setup_dir/"joint.vk"),"MATCHED_JOINT_VK_SHA256":producers["joint-bls12-381"]["vk_sha256"],"MATCHED_REGISTRY_PK_HEX":producers["joint-bls12-381"]["registry_public_key"]})
        for produced in producers.values():
            resident_env=produced.get("resident_env",{})
            if not isinstance(resident_env,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in resident_env.items()):raise ValueError("bad resident_env")
            if any(k.startswith("MATCHED_") for k in resident_env):raise ValueError("resident_env overwrites matched trusted config")
            env.update(resident_env)
        dac=producers["dac-bw6-761"]
        if not dac.get("resident_env") or "trusted_config_sha256" not in dac:raise ValueError("DAC trusted resident config missing")
        dac_config=Path(dac["resident_env"]["DAC_TRUSTED_CONFIG_PATH"])
        if hashlib.sha256(dac_config.read_bytes()).hexdigest()!=dac["trusted_config_sha256"]:raise ValueError("DAC trusted config digest mismatch")
        depth_order=[1,2] if setup%2==0 else [2,1]
        # Each depth gets an isolated service lifecycle.  Both proofs retain the
        # same canonical nonce; sharing one nonce table would correctly classify
        # the second depth as a replay instead of measuring it.
        for actual in depth_order:
            db=setup_dir/f"service-actual-{actual}.sqlite"
            service=[os.environ.get("PYTHON","python3"),str(args.service_script),"--db",str(db),"--trusted-config",str(trusted_path),"--host","127.0.0.1","--port",str(args.port),"--fixed-now",str(manifest["request"]["now"]),"--joint-cli",*command(args.joint_resident_cmd),"--dac-cli",*command(args.dac_resident_cmd)]
            service_stdout=(setup_dir/f"service-actual-{actual}.stdout.log").open("wb");service_stderr=(setup_dir/f"service-actual-{actual}.stderr.log").open("wb");process=subprocess.Popen(service,env=env,stdout=service_stdout,stderr=service_stderr)
            try:
                wait_ready(f"http://127.0.0.1:{args.port}/not-found")
                for backend in order:
                    status,value,_=post(f"http://127.0.0.1:{args.port}/admin/matched-header",{"backend":backend,"update_index":1,"envelope":producers[backend]["header_envelope"]})
                    if status!=201: raise RuntimeError(f"header install failed {backend}: {status} {value}")
                    produced=next(r for r in producers[backend]["rows"] if r["actual"]==actual)
                    assembly_start=time.perf_counter();authorization={"backend":backend,"envelope":produced["envelope"]};authorization_assembly_ms=(time.perf_counter()-assembly_start)*1000
                    status,value,http_ms=post(f"http://127.0.0.1:{args.port}{path}",authorization,body)
                    if status!=200: raise RuntimeError(f"HTTP gate failed {backend}/{actual}: {status} {value}")
                    proof_hex=produced["envelope"]["proof"];header=producers[backend]["header_envelope"]["header"]
                    rows.append({"setup":setup,"backend":backend,"actual":actual,"semantic_input_sha256":semantic_sha,"setup_ms":producers[backend]["setup_ms"],"producer_wall_ms":walls[backend],"prove_ms":produced["prove_ms"],"internal_verify_ms":produced["verify_ms"],"authorization_assembly_ms":authorization_assembly_ms,"http_sqlite_ms":http_ms,"measured_component_sum_ms":produced["prove_ms"]+authorization_assembly_ms+http_ms,"component_sum_excludes":["setup","witness/input construction before producer prove timer","proof serialization","terminal signing","producer process startup/teardown","service startup/header installation"],"native_parameter_sha256":producers[backend].get("native_parameter_sha256") or producers[backend].get("deployment_parameter_sha256"),"pk_bytes":producers[backend].get("pk_bytes"),"pk_sha256":producers[backend].get("pk_sha256"),"vk_bytes":producers[backend]["vk_bytes"],"vk_sha256":producers[backend]["vk_sha256"],"proof_bytes":len(bytes.fromhex(proof_hex)),"proof_sha256":hashlib.sha256(bytes.fromhex(proof_hex)).hexdigest(),"native_header_sha256":hashlib.sha256(canonical(header)).hexdigest(),"producer_raw_sha256":hashlib.sha256((setup_dir/f"producer-{backend}.stdout.json").read_bytes()).hexdigest(),"header":header})
                    atomic_json(args.out/"raw_rows.partial.json",rows)
            finally:
                process.terminate();process.wait(timeout=10);service_stdout.close();service_stderr.close()
        setup_records.append({"setup":setup,"backend_order":order,"depth_order":depth_order,"producer_files":{b:str(setup_dir/f"producer-{b}.stdout.json") for b in producers}});atomic_json(args.out/"setups.partial.json",setup_records)
    summary={key:bootstrap(rows,key,0xB2) for key in ("prove_ms","http_sqlite_ms","measured_component_sum_ms")};summary["setup_ms"]=setup_bootstrap(rows,0xB2)
    cell_counts={f"{backend}/actual{actual}":sum(row["backend"]==backend and row["actual"]==actual for row in rows) for backend in ("joint-bls12-381","dac-bw6-761") for actual in (1,2)}
    backend_first=sum(record["backend_order"][0]=="joint-bls12-381" for record in setup_records);depth_first=sum(record["depth_order"][0]==1 for record in setup_records)
    unique_pk={backend:len({row["pk_sha256"] for row in rows if row["backend"]==backend}) for backend in ("joint-bls12-381","dac-bw6-761")};unique_vk={backend:len({row["vk_sha256"] for row in rows if row["backend"]==backend}) for backend in ("joint-bls12-381","dac-bw6-761")}
    unique_native_parameters={backend:len({row["native_parameter_sha256"] for row in rows if row["backend"]==backend and row["native_parameter_sha256"]}) for backend in ("joint-bls12-381","dac-bw6-761")};semantic_hashes={row["semantic_input_sha256"] for row in rows}
    formal_gate=args.setups==10 and len(rows)==40 and len(semantic_hashes)==1 and all(count==10 for count in cell_counts.values()) and backend_first==5 and depth_first==5 and all(count==10 for count in unique_pk.values()) and all(count==10 for count in unique_vk.values()) and unique_native_parameters["dac-bw6-761"]==10 and unique_native_parameters["joint-bls12-381"]==0
    scope={"timed_update_index":1,"requested_setups":args.setups,"formal_gate":formal_gate,"formal_gate_checks":{"cell_counts":cell_counts,"semantic_hash_count":len(semantic_hashes),"joint_backend_first_setups":backend_first,"actual1_depth_first_setups":depth_first,"unique_native_parameters_per_backend":unique_native_parameters,"unique_pk_per_backend":unique_pk,"unique_vk_per_backend":unique_vk},"fresh_per_setup":["Joint CRS/PK/VK/proofs","DAC CRS/deployment-native parameters/PK/VK/proofs"],"fixed_across_setups":["canonical semantic manifest","logical IDs","deterministically derived logical grant/terminal keys","registry test key","Joint fixed Poseidon/native constants"],"correctness_gate":"matched_correctness_driver.py must pass separately before timing"}
    atomic_json(args.out/"raw_rows.json",rows);atomic_json(args.out/"setups.json",setup_records);atomic_json(args.out/"bootstrap.json",summary);atomic_json(args.out/"scope.json",scope);print(json.dumps({"valid":formal_gate,"formal_gate":formal_gate,"smoke_completed":True,"rows":len(rows),"scope":scope,"summary":summary},sort_keys=True))
if __name__=="__main__":main()
