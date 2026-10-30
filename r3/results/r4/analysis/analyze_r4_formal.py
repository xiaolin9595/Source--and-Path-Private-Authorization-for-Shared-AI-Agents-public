#!/usr/bin/env python3
import argparse, hashlib, json, math, re, statistics
from pathlib import Path

RELATIONS={
    "blind":{"relation":"blind-update","shape":(11427,15,8567,16384)},
    "joint":{"relation":"randomized-dummy-joint","shape":(187556,24,172232,262144)},
}
STAGES=("pk_decode_ns","vk_decode_ns","material_decode_ns","relation_ns","powers_ns",
        "reconstruction_ns","direct_query_ns","b_cross_ns","equation_ns","binding_ns","checker_total_ns")

def one_json(path):
    rows=[json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    if len(rows)!=1: raise ValueError(f"expected one JSON row: {path}")
    return rows[0]

def last_json(path):
    rows=[json.loads(x) for x in path.read_text().splitlines() if x.strip()]
    if not rows: raise ValueError(f"empty JSONL: {path}")
    return rows[-1]

def rss(path):
    m=re.search(r"Maximum resident set size \(kbytes\): (\d+)",path.read_text())
    if not m: raise ValueError(f"missing RSS: {path}")
    return int(m.group(1))

def wall_ns(path):
    m=re.search(r"Elapsed \(wall clock\) time \(h:mm:ss or m:ss\): ([0-9:.]+)",path.read_text())
    if not m: raise ValueError(f"missing wall time: {path}")
    parts=m.group(1).split(":")
    if len(parts)==2: seconds=float(parts[0])*60+float(parts[1])
    elif len(parts)==3: seconds=float(parts[0])*3600+float(parts[1])*60+float(parts[2])
    else: raise ValueError(f"bad wall time: {path}")
    return round(seconds*1_000_000_000)

def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
    return h.hexdigest()

def finite_nonnegative(value,name):
    if not isinstance(value,(int,float)) or isinstance(value,bool) or not math.isfinite(value) or value<0:
        raise ValueError(f"invalid {name}: {value!r}")
    return value

def finite(value,name):
    if not isinstance(value,(int,float)) or isinstance(value,bool) or not math.isfinite(value):
        raise ValueError(f"invalid {name}: {value!r}")
    return value

def checked_derived(checked):
    nonoverlap=("pk_decode_ns","vk_decode_ns","material_decode_ns","relation_ns","powers_ns",
                "reconstruction_ns","direct_query_ns","b_cross_ns","equation_ns","binding_ns")
    stage_sum=sum(checked["metrics"][k] for k in nonoverlap)
    return {
        "checked_structural_ns":sum(checked["metrics"][k] for k in
            ("relation_ns","powers_ns","reconstruction_ns","direct_query_ns","b_cross_ns","equation_ns","binding_ns")),
        "checked_internal_unallocated_ns":checked["metrics"]["checker_total_ns"]-stage_sum,
        "checked_total_unallocated_ns":checked["full_load_ns"]-checked["file_read_ns"]-stage_sum,
        "checked_external_wrapper_ns":checked["full_load_ns"]-checked["file_read_ns"]-checked["metrics"]["checker_total_ns"],
    }

def summary(values):
    if len(values)!=5: raise ValueError(f"expected five observations, got {len(values)}")
    return {"median":statistics.median(values),"min":min(values),"max":max(values),"unit":"ns"}

def collect(root, label):
    spec=RELATIONS[label]; rows=[]; pk_hashes=set(); vk_hashes=set(); material_hashes=set()
    for index in range(1,6):
        cell=root/label/f"setup_{index:02d}"
        if not (cell/"COMPLETE").is_file(): raise ValueError(f"incomplete cell: {cell}")
        expected="checked,ordinary" if index%2 else "ordinary,checked"
        if (cell/"order.txt").read_text().strip()!=expected: raise ValueError(f"wrong order: {cell}")
        setup=one_json(cell/"setup.jsonl"); checked=last_json(cell/"checked.jsonl"); ordinary=one_json(cell/"ordinary.jsonl")
        c,i,w,d=spec["shape"]
        if (setup["constraints"],setup["instances"],setup["witnesses"],setup["domain"])!=(c,i,w,d): raise ValueError(f"wrong shape: {cell}")
        if checked.get("event")!="gate" or checked.get("relation")!=spec["relation"] or checked.get("verified") is not True: raise ValueError(f"bad checked row: {cell}")
        if ordinary.get("event")!="ordinary_load" or ordinary.get("relation")!=spec["relation"] or ordinary.get("canonical_exact") is not True or ordinary.get("embedded_vk_equal") is not True: raise ValueError(f"bad ordinary row: {cell}")
        actual={name:digest(cell/"bundle"/name) for name in ("pk.bin","vk.bin","checking.bin")}
        if actual["pk.bin"]!=setup["pk_sha256"] or actual["vk.bin"]!=setup["vk_sha256"] or actual["checking.bin"]!=setup["material_sha256"]: raise ValueError(f"bundle digest mismatch: {cell}")
        pk_hashes.add(actual["pk.bin"]);vk_hashes.add(actual["vk.bin"]);material_hashes.add(actual["checking.bin"])
        metrics={
            "setup_ns":setup["setup_ns"],"power_construction_ns":setup["power_construction_ns"],
            "serialization_write_ns":setup["serialization_write_ns"],
            "setup_process_wall_ns":wall_ns(cell/"setup.time"),
            "checked_full_load_ns":checked["full_load_ns"],"ordinary_full_load_ns":ordinary["full_load_ns"],
            "paired_extra_checked_ns":checked["full_load_ns"]-ordinary["full_load_ns"],
            "prove_ns":checked["prove_ns"],"verify_ns":checked["verify_ns"],
            "setup_peak_rss_kib":rss(cell/"setup.time"),"checked_peak_rss_kib":rss(cell/"checked.time"),
            "ordinary_peak_rss_kib":rss(cell/"ordinary.time"),
        }
        metrics.update({f"checked_{k}":checked["metrics"][k] for k in STAGES})
        metrics.update(checked_derived(checked))
        for name,value in metrics.items():
            if name=="paired_extra_checked_ns": finite(value,name)
            else: finite_nonnegative(value,name)
        rows.append({"index":index,"order":expected,"pk_sha256":actual["pk.bin"],"vk_sha256":actual["vk.bin"],"material_sha256":actual["checking.bin"],
                     "serialized_bytes":setup["bytes"],"metrics":metrics})
    if len(pk_hashes)!=5 or len(vk_hashes)!=5 or len(material_hashes)!=5: raise ValueError(f"fresh-key digest collision: {label}")
    names=rows[0]["metrics"]
    summaries={name:summary([r["metrics"][name] for r in rows]) for name in names}
    for name in ("setup_peak_rss_kib","checked_peak_rss_kib","ordinary_peak_rss_kib"):
        summaries[name]["unit"]="KiB"
    return {"completed_bundles":5,"verified_proofs":5,"fresh_pk_vk_material":True,"observations":rows,"summaries":summaries}

def main():
    p=argparse.ArgumentParser();p.add_argument("--run",type=Path,required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    if not (a.run/"COMPLETE").is_file(): raise SystemExit("formal run is not COMPLETE")
    out={"schema":"r4-formal-analysis-v1","descriptive_only":True,"stable_speedup_inference":False,
         "relations":{label:collect(a.run,label) for label in RELATIONS}}
    a.output.write_text(json.dumps(out,sort_keys=True,indent=2)+"\n")

if __name__=="__main__": main()
