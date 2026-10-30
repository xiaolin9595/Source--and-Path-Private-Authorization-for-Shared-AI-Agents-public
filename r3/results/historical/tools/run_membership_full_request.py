#!/usr/bin/env python3
"""Frozen formal ten-pair full client-cycle runner."""
import argparse, base64, http.client, json, os, random, statistics, subprocess, tempfile, time
from pathlib import Path

NONCES=list(range(6001,6011)); ORDER=[["inline","lego"] if i%2==0 else ["lego","inline"] for i in range(10)]
COMMON=("protocol_version","deployment_id","audience","resource","action_onehot","nonce","request_time","expires_at","terminal_agent_pk","circuit_id","snapshot_digest")
def percentile(v,p):
    x=(len(v)-1)*p;lo=int(x);hi=min(lo+1,len(v)-1);w=x-lo;return v[lo]*(1-w)+v[hi]*w
def start(command):
    began=time.perf_counter_ns();p=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1);ready=json.loads(p.stdout.readline());wall=time.perf_counter_ns()-began
    if ready.get("ready") is not True: raise RuntimeError((command,ready));
    return p,ready,wall
def produce(p,request):
    p.stdin.write(json.dumps(request,separators=(",",":"))+"\n");p.stdin.flush();return json.loads(p.stdout.readline())
def producer_check(backend,t):
    if backend=="inline": keys=("parse_ns","fixture_canonical_ns","proof_generate_encode_ns","terminal_frame_sign_ns","artifact_finalize_ns","artifact_serialize_ns");reported=t["internal_component_sum_ns"]
    else: keys=("parse_ns","fixture_canonical_ns","proof_encode_ns","terminal_frame_sign_ns","artifact_serialize_ns");reported=t["component_sum_ns"]
    actual=sum(t[k] for k in keys);return {"keys":keys,"actual_sum_ns":actual,"reported_sum_ns":reported,"sum_matches":actual==reported}
def env_for(artifact,backend,a):
    e=os.environ.copy();e.update(PLAN_A_L="3",PLAN_A_DS="20",PLAN_A_DRA="20",PLAN_A_DREV="32",PLAN_A_DEPLOYMENT_ID=artifact["bootstrap_admission"]["deployment_id"],PLAN_A_REGISTRY_PK_B64=artifact["registry_pk_b64"],PLAN_A_VK_ID=artifact["vk_id"],PLAN_A_PROOF_BACKEND="native-inline" if backend=="inline" else "native-merkle-lego")
    if backend=="inline":e["PLAN_A_VK_PATH"]=a.inline_vk
    else:e.update(PLAN_A_LEGO_VERIFIER_BIN=a.lego_verifier,PLAN_A_LEGO_VERIFIER_ID=artifact["vk_id"],PLAN_A_LEGO_CORE_VK_PATH=a.lego_core_vk,PLAN_A_LEGO_MEMBERSHIP_VK_PATH=a.lego_membership_vk)
    return e
def http_accept(port,artifact):
    body=base64.b64decode(artifact["body_b64"]);authorization=json.dumps(artifact["envelope"],separators=(",",":"));connection=http.client.HTTPConnection("127.0.0.1",port,timeout=180);connection.request("POST","/resource/read",body,{"X-PlanA-Authorization":authorization});response=connection.getresponse();raw=response.read();status=response.status;connection.close();return status,json.loads(raw),{"body":len(body),"authorization_header":len(authorization.encode()),"proof":len(base64.b64decode(artifact["envelope"]["proof_b64"])),"response_wire":len(raw)}
def main():
    p=argparse.ArgumentParser()
    for n in ("agent","direct_lego","core","lego_verifier","inline_pk","inline_vk","lego_core_pk","lego_membership_pk","lego_core_vk","lego_membership_vk","ready_service"):p.add_argument("--"+n.replace("_","-"),dest=n,required=True)
    p.add_argument("--out",type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    schedule={"nonces":NONCES,"order":ORDER,"fresh_provisioned_service_and_db_per_request":True,"resident_producers_ready_before_t0":True};(a.out/"SCHEDULE.json").write_text(json.dumps(schedule,indent=2)+"\n")
    inline,ir,iw=start([a.agent,"serve",a.inline_pk,a.inline_vk,"3","3","20","20","32","https://service.example","payload"]);lego,lr,lw=start([a.direct_lego,"serve",a.lego_core_pk,a.lego_membership_pk])
    producers={"inline":inline,"lego":lego};templates={};pre=[]
    try:
        for backend in ("inline","lego"):
            value=produce(producers[backend],{"nonce":5999,"now":150});templates[backend]=value;path=a.out/f"prevalidation-{backend}-artifact.json";path.write_text(json.dumps(value,sort_keys=True,separators=(",",":"))+"\n")
            check=producer_check(backend,value["producer_timing"]);assert check["sum_matches"]
            with tempfile.TemporaryDirectory() as d:
                service_started=time.perf_counter_ns();service=subprocess.Popen([a.ready_service,"--bootstrap",str(path),"--core",a.core,"--db",str(Path(d)/"prevalidation.db")],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1,env=env_for(value,backend,a));sready=json.loads(service.stdout.readline());swall=time.perf_counter_ns()-service_started;assert sready.get("ready") is True
                status,response,_=http_accept(sready["port"],value);timing=response.pop("_service_timing",None);service.stdin.write('{"command":"shutdown"}\n');service.stdin.flush();service.stdout.readline();service.wait(timeout=30)
                assert status==200 and timing is not None and timing["sum_matches"]
            pre.append({"backend":backend,"producer_check":check,"service_status":status,"service_component_sum_matches":True,"service_process_to_provisioned_ns":sready["process_to_provisioned_ns"],"service_ready_client_wall_ns":swall})
        rows=[]
        for i,order in enumerate(ORDER):
            pair={}
            for backend in order:
                with tempfile.TemporaryDirectory() as d:
                    template=a.out/f"prevalidation-{backend}-artifact.json"
                    # The service inherits the trusted verifier environment and is fully provisioned before t0.
                    service_started=time.perf_counter_ns();service=subprocess.Popen([a.ready_service,"--bootstrap",str(template),"--core",a.core,"--db",str(Path(d)/"trial.db")],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1,env=env_for(templates[backend],backend,a));sready=json.loads(service.stdout.readline());swall=time.perf_counter_ns()-service_started
                    assert sready.get("ready") is True
                    t0=time.perf_counter_ns();artifact=produce(producers[backend],{"nonce":NONCES[i],"now":150});producer_received=time.perf_counter_ns();status,response,byte_counts=http_accept(sready["port"],artifact);t_end=time.perf_counter_ns()
                    timing=response.pop("_service_timing",None);service.stdin.write('{"command":"effects"}\n');service.stdin.flush();effects=json.loads(service.stdout.readline())["selected_db_effects"];service.stdin.write('{"command":"shutdown"}\n');service.stdin.flush();service.stdout.readline();service.wait(timeout=30)
                    if status!=200 or timing is None:raise RuntimeError((i,backend,status,response))
                    check=producer_check(backend,artifact["producer_timing"]);assert check["sum_matches"] and timing["sum_matches"]
                    path=a.out/f"pair-{i}-{backend}-artifact.json";path.write_text(json.dumps(artifact,sort_keys=True,separators=(",",":"))+"\n")
                    pair[backend]={"status":status,"full_client_cycle_ns":t_end-t0,"producer_client_roundtrip_ns":producer_received-t0,"http_after_producer_ns":t_end-producer_received,"t0_perf_counter_ns":t0,"producer_received_perf_counter_ns":producer_received,"t_end_perf_counter_ns":t_end,"producer_timing":artifact["producer_timing"],"producer_check":check,"service_timing":timing,"service_process_to_provisioned_ns":sready["process_to_provisioned_ns"],"service_ready_client_wall_ns":swall,"bytes":byte_counts,"selected_db_effects":effects,"response":response,"external":{k:artifact["envelope"][k] for k in COMMON},"body_b64":artifact["body_b64"],"snapshot":artifact["snapshot"]}
            if pair["inline"]["selected_db_effects"]!=pair["lego"]["selected_db_effects"]:raise RuntimeError((i,"db-effects"))
            if pair["inline"]["external"]!=pair["lego"]["external"] or pair["inline"]["body_b64"]!=pair["lego"]["body_b64"] or pair["inline"]["snapshot"]!=pair["lego"]["snapshot"]:raise RuntimeError((i,"contract"))
            x=pair["inline"]["full_client_cycle_ns"];y=pair["lego"]["full_client_cycle_ns"];rows.append({"pair":i,"nonce":NONCES[i],"order":order,"inline":pair["inline"],"lego":pair["lego"],"ratio_inline_over_lego":x/y,"difference_inline_minus_lego_ns":x-y,"external_contract_equal":True,"selected_db_effects_equal":True})
    finally:
        for q in (inline,lego):
            if q.poll() is None:q.stdin.close();q.wait(timeout=30)
    ratios=[x["ratio_inline_over_lego"] for x in rows];rng=random.Random(0xE8C12026);boot=sorted(statistics.median(ratios[rng.randrange(10)] for _ in ratios) for _ in range(100000))
    result={"schema":"plan-a-tertiary-full-client-cycle-formal-v1","schedule":schedule,"producer_startup":{"inline_ready":ir,"inline_client_wall_ns":iw,"lego_ready":lr,"lego_client_wall_ns":lw},"prevalidation":pre,"pairs":rows,"median_paired_ratio_inline_over_lego":statistics.median(ratios),"paired_bootstrap_95_percentile_interval":[percentile(boot,.025),percentile(boot,.975)],"bootstrap_resamples":100000,"bootstrap_seed":0xE8C12026,"all_20_status_200":all(x[b]["status"]==200 for x in rows for b in ("inline","lego")),"all_producer_component_sums":all(x[b]["producer_check"]["sum_matches"] for x in rows for b in ("inline","lego")),"all_service_component_sums":all(x[b]["service_timing"]["sum_matches"] for x in rows for b in ("inline","lego")),"all_external_contracts_equal":all(x["external_contract_equal"] for x in rows),"all_selected_db_effects_equal":all(x["selected_db_effects_equal"] for x in rows)}
    (a.out/"RESULTS.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
