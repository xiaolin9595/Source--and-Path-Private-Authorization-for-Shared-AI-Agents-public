#!/usr/bin/env python3
import argparse,json,random,statistics
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument("results",type=Path);a=p.parse_args();r=json.loads(a.results.read_text());pairs=r["pairs"]
ratios=[x["inline"]["full_client_cycle_ns"]/x["lego"]["full_client_cycle_ns"] for x in pairs]
rng=random.Random(0xE8C12026);boot=sorted(statistics.median(ratios[rng.randrange(10)] for _ in ratios) for _ in range(100000))
def pct(v,p):
 x=(len(v)-1)*p;lo=int(x);hi=min(lo+1,len(v)-1);w=x-lo;return v[lo]*(1-w)+v[hi]*w
out={"ratios":ratios,"differences_inline_minus_lego_ns":[x["inline"]["full_client_cycle_ns"]-x["lego"]["full_client_cycle_ns"] for x in pairs],"inline_median_ns":statistics.median(x["inline"]["full_client_cycle_ns"] for x in pairs),"lego_median_ns":statistics.median(x["lego"]["full_client_cycle_ns"] for x in pairs),"median_paired_ratio":statistics.median(ratios),"bootstrap_95_percentile_interval":[pct(boot,.025),pct(boot,.975)],"bootstrap_resamples":100000,"seed":0xE8C12026}
print(json.dumps(out,indent=2))
