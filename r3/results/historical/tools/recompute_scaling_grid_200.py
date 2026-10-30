#!/usr/bin/env python3
"""Validate the 200 retained scaling observations against frozen summaries.

The original CI-generating program is not present in the frozen artifact.  The
saved metadata records seed 20261023, 10,000 percentile-bootstrap resamples of
the median, but not the per-cell/per-metric RNG stream derivation.  This script
therefore recomputes every deterministic statistic and validates CI metadata;
it deliberately does not invent an RNG schedule merely to reproduce endpoints.
"""
import argparse, hashlib, json, statistics
from collections import Counter, defaultdict
from pathlib import Path


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p=argparse.ArgumentParser(); p.add_argument("--root",type=Path,required=True); p.add_argument("--output",type=Path,required=True); a=p.parse_args()
    raw=a.root/"raw"; trials=[json.loads(x) for x in (raw/"TRIALS.jsonl").read_text().splitlines() if x.strip()]
    summary=json.loads((raw/"SUMMARY.json").read_text()); frozen=json.loads((raw/"E2_CELL_SUMMARY_CI.json").read_text())
    if len(trials)!=200 or summary.get("expected_trials")!=200 or summary.get("completed_trials")!=200: raise SystemExit("expected exactly 200 trials")
    counts=Counter(); reps=defaultdict(set); by=defaultdict(list)
    for row in trials:
        m=row.get("measurement",{}); key=(int(row["l_max"]),int(row["state_depth"])); counts[key]+=1; reps[key].add(int(row["repetition"])); by[key].append(m)
        if row.get("exit_code")!=0 or m.get("ok") is not True: raise SystemExit("failed/unverified trial")
        if (m.get("l_max"),m.get("state_depth"),m.get("ra_depth"),m.get("revocation_depth"))!=(key[0],key[1],20,32): raise SystemExit("shape mismatch")
    expected={(l,d) for l in range(1,6) for d in (10,16,20,24)}
    if set(counts)!=expected or any(counts[k]!=10 or reps[k]!=set(range(10)) for k in expected): raise SystemExit("grid/cardinality mismatch")
    stats=frozen.get("statistics",{})
    if stats.get("base_seed")!=20261023 or stats.get("resamples")!=10000 or stats.get("bootstrap")!="percentile bootstrap of median": raise SystemExit("unexpected frozen CI convention")
    cells=frozen.get("cells",[])
    if len(cells)!=20: raise SystemExit("expected 20 frozen cells")
    for cell in cells:
        key=(int(cell["l_max"]),int(cell["state_depth"])); rows=by[key]
        if int(cell["n"])!=10: raise SystemExit("bad frozen n")
        for metric in ("setup_ms","prove_ms","verify_ms"):
            vals=[float(x[metric]) for x in rows]
            if cell[f"{metric}_median"]!=statistics.median(vals) or cell[f"{metric}_min"]!=min(vals) or cell[f"{metric}_max"]!=max(vals): raise SystemExit(f"deterministic statistic mismatch: {key} {metric}")
            if not cell[f"{metric}_ci95_lo"]<=cell[f"{metric}_median"]<=cell[f"{metric}_ci95_hi"]: raise SystemExit("invalid retained interval")
        constants={(int(x["constraints"]),int(x["pk_bytes"])) for x in rows}
        if len(constants)!=1: raise SystemExit("within-cell constants vary")
        constraints,pk=constants.pop()
        if constraints!=int(cell["constraints"]) or pk!=int(cell["compressed_pk_bytes"]): raise SystemExit("frozen constants disagree with raw")
    out={"schema":"historical-grid200-validation-v1","status":"PASS","trials":200,"cells":20,"trials_per_cell":10,"all_exit_zero_and_verified":True,"deterministic_statistics_match":True,"frozen_ci_metadata":{"base_seed":20261023,"resamples":10000,"method":"percentile bootstrap of median"},"ci_endpoint_recomputation":"NOT_CLAIMED_ORIGINAL_RNG_STREAM_DERIVATION_NOT_RETAINED","input_sha256":{"TRIALS.jsonl":sha(raw/"TRIALS.jsonl"),"E2_CELL_SUMMARY_CI.json":sha(raw/"E2_CELL_SUMMARY_CI.json"),"SUMMARY.json":sha(raw/"SUMMARY.json")}}
    a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")

if __name__=="__main__": main()
