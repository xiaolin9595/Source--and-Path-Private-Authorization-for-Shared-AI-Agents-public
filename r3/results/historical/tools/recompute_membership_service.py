#!/usr/bin/env python3
"""Recompute the frozen secondary-service paired statistic from RESULTS.json."""
import argparse,json,random,statistics
from pathlib import Path

SEED=0xE8_5E_2026; N=100000
def pct(v,p):
    x=(len(v)-1)*p; lo=int(x); hi=min(lo+1,len(v)-1); w=x-lo; return v[lo]*(1-w)+v[hi]*w
def main():
    p=argparse.ArgumentParser();p.add_argument("results",type=Path);p.add_argument("output",type=Path);a=p.parse_args();r=json.loads(a.results.read_text());pairs=r["pairs"]
    if len(pairs)!=10 or r.get("bootstrap_seed")!=SEED or r.get("bootstrap_resamples")!=N: raise SystemExit("frozen design mismatch")
    if not all(x.get("db_effects_equal") is True and x["inline"]["status"]==200 and x["lego"]["status"]==200 and x["inline"]["service_timing"]["sum_matches"] is True and x["lego"]["service_timing"]["sum_matches"] is True for x in pairs): raise SystemExit("failed pair")
    ratios=[x["inline"]["service_timing"]["accept_ns"]/x["lego"]["service_timing"]["accept_ns"] for x in pairs]
    rng=random.Random(SEED); boot=sorted(statistics.median(ratios[rng.randrange(10)] for _ in ratios) for _ in range(N)); interval=[pct(boot,.025),pct(boot,.975)]; median=statistics.median(ratios)
    if median!=r["median_paired_ratio_inline_over_lego"] or interval!=r["paired_bootstrap_95_percentile_interval"]: raise SystemExit("recomputed statistic mismatch")
    out={"schema":"historical-membership-service-recompute-v1","status":"PASS","pairs":10,"median_paired_ratio_inline_over_lego":median,"paired_bootstrap_95_percentile_interval":interval,"bootstrap_resamples":N,"bootstrap_seed":SEED,"all_status_200":True,"all_component_sums_match":True,"all_selected_db_effects_equal":True}
    a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n")
if __name__=="__main__":main()
