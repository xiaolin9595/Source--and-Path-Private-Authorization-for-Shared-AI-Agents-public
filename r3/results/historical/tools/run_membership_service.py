#!/usr/bin/env python3
"""Frozen ten-pair secondary service runner."""
import argparse, json, os, random, statistics, subprocess, time
from pathlib import Path

NONCES=list(range(5001,5011))
ORDER=[["inline","lego"] if i%2==0 else ["lego","inline"] for i in range(10)]

def percentile(values,p):
    position=(len(values)-1)*p;lo=int(position);hi=min(lo+1,len(values)-1);w=position-lo
    return values[lo]*(1-w)+values[hi]*w

def main():
    p=argparse.ArgumentParser();p.add_argument("--agent",required=True);p.add_argument("--rewrap",required=True);p.add_argument("--core",required=True);p.add_argument("--lego-verifier",required=True);p.add_argument("--inline-pk",required=True);p.add_argument("--inline-vk",required=True);p.add_argument("--lego-core-pk",required=True);p.add_argument("--lego-membership-pk",required=True);p.add_argument("--lego-core-vk",required=True);p.add_argument("--lego-membership-vk",required=True);p.add_argument("--trial",required=True);p.add_argument("--out",type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    schedule={"schema":"plan-a-secondary-schedule-v1","nonces":NONCES,"order":ORDER,"pairs":10,"fresh_service_process_and_db_per_backend":True,"fresh_cryptographic_setup":False};(a.out/"SCHEDULE.json").write_text(json.dumps(schedule,indent=2)+"\n")
    artifacts=[];producer=[]
    inline_started=time.perf_counter_ns()
    inline_proc=subprocess.Popen([a.agent,"serve",a.inline_pk,a.inline_vk,"3","3","20","20","32","https://service.example","payload"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
    inline_ready=json.loads(inline_proc.stdout.readline()); inline_ready_ns=time.perf_counter_ns()-inline_started
    if inline_ready.get("ready") is not True: raise SystemExit("inline-resident-not-ready")
    rewrap_started=time.perf_counter_ns()
    rewrap_proc=subprocess.Popen([a.rewrap,"--jsonl",a.lego_core_pk,a.lego_membership_pk,"20","20","32"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
    rewrap_ready=json.loads(rewrap_proc.stdout.readline()); rewrap_ready_ns=time.perf_counter_ns()-rewrap_started
    if rewrap_ready.get("ready") is not True: raise SystemExit("lego-resident-not-ready")
    try:
        for i,nonce in enumerate(NONCES):
            inline=a.out/f"pair-{i}-inline-artifact.json";lego=a.out/f"pair-{i}-lego-artifact.json"
            started=time.perf_counter_ns();inline_proc.stdin.write(json.dumps({"nonce":nonce,"now":150})+"\n");inline_proc.stdin.flush();raw=inline_proc.stdout.readline();inline_ns=time.perf_counter_ns()-started
            value=json.loads(raw)
            if "error" in value: raise SystemExit(f"pair-{i}-inline-producer:{value['error']}")
            inline.write_text(json.dumps(value,separators=(",",":"))+"\n")
            started=time.perf_counter_ns();rewrap_proc.stdin.write(json.dumps({"inline_json":str(inline),"nonce":nonce})+"\n");rewrap_proc.stdin.flush();raw=rewrap_proc.stdout.readline();lego_ns=time.perf_counter_ns()-started
            value=json.loads(raw)
            if "error" in value: raise SystemExit(f"pair-{i}-lego-producer:{value['error']}")
            lego.write_text(json.dumps(value,separators=(",",":"))+"\n")
            artifacts.append({"inline":inline,"lego":lego});producer.append({"pair":i,"nonce":nonce,"inline_resident_roundtrip_ns":inline_ns,"lego_resident_roundtrip_ns":lego_ns,"inline_reported":json.loads(inline.read_text()).get("timing"),"lego_reported":json.loads(lego.read_text()).get("timing")})
    finally:
        for process in (inline_proc,rewrap_proc):
            if process.stdin: process.stdin.close()
            process.wait(timeout=30)
    producer_meta={"method":"resident-cached-key-preparation-not-part-of-service-timing","inline_ready":inline_ready,"inline_ready_wall_ns":inline_ready_ns,"lego_ready":rewrap_ready,"lego_ready_wall_ns":rewrap_ready_ns,"pairs":producer}
    (a.out/"PRODUCER.json").write_text(json.dumps(producer_meta,indent=2)+"\n")
    prevalidation=[]
    for i in range(10):
        for backend in ("inline","lego"):
            artifact=json.loads(artifacts[i][backend].read_text());env=os.environ.copy();env.update(PLAN_A_L="3",PLAN_A_DS="20",PLAN_A_DRA="20",PLAN_A_DREV="32",PLAN_A_DEPLOYMENT_ID=artifact["bootstrap_admission"]["deployment_id"],PLAN_A_REGISTRY_PK_B64=artifact["registry_pk_b64"],PLAN_A_VK_ID=artifact["vk_id"],PLAN_A_PROOF_BACKEND="native-inline" if backend=="inline" else "native-merkle-lego")
            if backend=="inline": env["PLAN_A_VK_PATH"]=a.inline_vk
            else: env.update(PLAN_A_LEGO_VERIFIER_BIN=a.lego_verifier,PLAN_A_LEGO_VERIFIER_ID=artifact["vk_id"],PLAN_A_LEGO_CORE_VK_PATH=a.lego_core_vk,PLAN_A_LEGO_MEMBERSHIP_VK_PATH=a.lego_membership_vk)
            output=a.out/f"pair-{i}-{backend}-prevalidation.json";subprocess.run([a.trial,"--artifact",str(artifacts[i][backend]),"--core",a.core,"--out",str(output),"--backend",backend],env=env,check=True);row=json.loads(output.read_text())
            if row["status"]!=200 or not row["service_timing"]["sum_matches"]: raise SystemExit(f"pair-{i}-{backend}-prevalidation-failed")
            prevalidation.append({"pair":i,"backend":backend,"status":row["status"],"proof_reverified_by_frozen_service":True})
    (a.out/"PREVALIDATION.json").write_text(json.dumps(prevalidation,indent=2)+"\n")
    pairs=[]
    for i,order in enumerate(ORDER):
        rows={}
        for backend in order:
            artifact=json.loads(artifacts[i][backend].read_text());env=os.environ.copy();env.update(PLAN_A_L="3",PLAN_A_DS="20",PLAN_A_DRA="20",PLAN_A_DREV="32",PLAN_A_DEPLOYMENT_ID=artifact["bootstrap_admission"]["deployment_id"],PLAN_A_REGISTRY_PK_B64=artifact["registry_pk_b64"],PLAN_A_VK_ID=artifact["vk_id"],PLAN_A_PROOF_BACKEND="native-inline" if backend=="inline" else "native-merkle-lego")
            if backend=="inline": env["PLAN_A_VK_PATH"]=a.inline_vk
            else: env.update(PLAN_A_LEGO_VERIFIER_BIN=a.lego_verifier,PLAN_A_LEGO_VERIFIER_ID=artifact["vk_id"],PLAN_A_LEGO_CORE_VK_PATH=a.lego_core_vk,PLAN_A_LEGO_MEMBERSHIP_VK_PATH=a.lego_membership_vk)
            output=a.out/f"pair-{i}-{backend}-trial.json";subprocess.run([a.trial,"--artifact",str(artifacts[i][backend]),"--core",a.core,"--out",str(output),"--backend",backend],env=env,check=True);rows[backend]=json.loads(output.read_text())
        if rows["inline"]["status"]!=200 or rows["lego"]["status"]!=200 or rows["inline"]["selected_db_effects"]!=rows["lego"]["selected_db_effects"]: raise SystemExit(f"pair-{i}-invariant-failed")
        inline_ns=rows["inline"]["service_timing"]["accept_ns"];lego_ns=rows["lego"]["service_timing"]["accept_ns"]
        pairs.append({"pair":i,"nonce":NONCES[i],"order":order,"inline":rows["inline"],"lego":rows["lego"],"ratio_inline_over_lego":inline_ns/lego_ns,"difference_inline_minus_lego_ns":inline_ns-lego_ns,"db_effects_equal":True})
    ratios=[row["ratio_inline_over_lego"] for row in pairs];rng=random.Random(0xE8_5E_2026);boot=sorted(statistics.median(ratios[rng.randrange(10)] for _ in ratios) for _ in range(100000))
    result={"schema":"plan-a-secondary-service-formal-v1","scope":"L3 active3 DS20 DRA20 DRev32 retained-key service acceptance; not engine G2","schedule":schedule,"pairs":pairs,"median_paired_ratio_inline_over_lego":statistics.median(ratios),"paired_bootstrap_95_percentile_interval":[percentile(boot,.025),percentile(boot,.975)],"bootstrap_resamples":100000,"bootstrap_seed":0xE8_5E_2026,"all_status_200":True,"all_component_sums_match":all(row[b]["service_timing"]["sum_matches"] for row in pairs for b in ("inline","lego")),"all_selected_db_effects_equal":True}
    (a.out/"RESULTS.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
