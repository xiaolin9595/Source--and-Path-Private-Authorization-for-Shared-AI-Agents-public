#!/usr/bin/env python3
"""Recompute the bounded historical main-result layer without rerunning trials."""
import hashlib,json,shutil,subprocess,sys,tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
H=ROOT/"results/historical"
def run(args,**kw):
    kw.setdefault("cwd",ROOT)
    return subprocess.run([sys.executable,*map(str,args)],check=True,**kw)
def same(a,b,label):
    if Path(a).read_bytes()!=Path(b).read_bytes(): raise SystemExit(f"historical mismatch: {label}")
def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

checks=[]
with tempfile.TemporaryDirectory(prefix="historical-recompute-") as td:
    t=Path(td)
    out=t/"grid.json"; run([H/"tools/recompute_scaling_grid_200.py","--root",H/"scaling_grid_200","--output",out]); same(out,H/"scaling_grid_200/RECOMPUTED_VALIDATION.json","grid200 validation"); checks.append("grid200 deterministic statistics")
    for name in ("depth20_repeat50","dac_matched"):
        work=t/name; shutil.copytree(H/name,work); run([work/"analyze_results.py"],cwd=work,stdout=subprocess.DEVNULL)
        same(work/"results/ANALYSIS.json",H/name/"results/ANALYSIS.json",name+" analysis"); same(work/"results/SUMMARY.csv",H/name/"results/SUMMARY.csv",name+" csv"); checks.append(name+" exact")
    warm=t/"warm.json"; run([H/"tools/analyze_membership_warm.py",H/"membership_warm/results.json",warm]); same(warm,H/"membership_warm/RECOMPUTED_ANALYSIS.json","membership warm")
    w=json.loads(warm.read_text()); wf=json.loads((H/"membership_warm/PAIRED_ANALYSIS.json").read_text())
    for key in ("raw_sha256","pairs","median_paired_ratio","paired_bootstrap_95_percentile_interval","bootstrap_resamples","bootstrap_seed","raw_paired_ratios"):
        if w[key]!=wf[key]: raise SystemExit("membership warm frozen-field mismatch: "+key)
    checks.append("membership warm frozen fields")
    svc=t/"service.json"; run([H/"tools/recompute_membership_service.py",H/"membership_service/RESULTS.json",svc]); same(svc,H/"membership_service/RECOMPUTED_ANALYSIS.json","membership service"); checks.append("membership service exact")
    tertiary=subprocess.run([sys.executable,str(H/"tools/analyze_membership_full_request.py"),str(H/"membership_full_request/RESULTS.json")],cwd=ROOT,check=True,capture_output=True)
    tertiary_out=t/"tertiary.json"; tertiary_out.write_bytes(tertiary.stdout); same(tertiary_out,H/"membership_full_request/RECOMPUTED_ANALYSIS.json","membership full request")
    tr=json.loads(tertiary.stdout); tf=json.loads((H/"membership_full_request/RESULTS.json").read_text())
    if tr["median_paired_ratio"]!=tf["median_paired_ratio_inline_over_lego"] or tr["bootstrap_95_percentile_interval"]!=tf["paired_bootstrap_95_percentile_interval"]: raise SystemExit("membership full-request frozen-field mismatch")
    checks.append("membership full request frozen fields")
    life=t/"lifecycle180"; shutil.copytree(H/"lifecycle180",life); run([life/"analyze_e4_real_lifecycle_formal.py","--result",life,"--bootstrap-reps","10000"],stdout=subprocess.DEVNULL)
    for name in ("E4_FORMAL_CELL_SUMMARY.json","E4_FORMAL_CELL_SUMMARY.csv","E4_FORMAL_GRID_VALIDATION.json"):
        same(life/name,H/"lifecycle180"/name,"lifecycle "+name)
    checks.append("lifecycle180 exact")

report={"schema":"historical-main-results-recompute-v1","status":"PASS","checks":checks,"important_limitation":"grid200 deterministic raw statistics and frozen CI metadata validate, but CI endpoints are retained rather than regenerated because the original per-cell/per-metric RNG stream derivation is absent","identities":{"grid_trials_sha256":digest(H/"scaling_grid_200/raw/TRIALS.jsonl"),"depth50_analysis_sha256":digest(H/"depth20_repeat50/results/ANALYSIS.json"),"dac_analysis_sha256":digest(H/"dac_matched/results/ANALYSIS.json"),"warm_analysis_sha256":digest(H/"membership_warm/PAIRED_ANALYSIS.json"),"service_results_sha256":digest(H/"membership_service/RESULTS.json"),"full_request_results_sha256":digest(H/"membership_full_request/RESULTS.json"),"lifecycle_trials_sha256":digest(H/"lifecycle180/TRIALS.jsonl")}}
print(json.dumps(report,indent=2,sort_keys=True))
