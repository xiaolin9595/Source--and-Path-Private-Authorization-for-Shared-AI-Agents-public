#!/usr/bin/env python3
import csv, hashlib, json, random, re, statistics
from pathlib import Path

ROOT = Path(__file__).resolve().parent
RES = ROOT / "results"
SEED = 2026102704
N_BOOT = 10_000
METRICS = ["setup_ms", "prove_ms", "verify_ms", "serialize_ms"]

def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def percentile(xs, q):
    ys = sorted(xs)
    x = (len(ys) - 1) * q
    lo, hi = int(x), min(int(x) + 1, len(ys) - 1)
    return ys[lo] + (ys[hi] - ys[lo]) * (x - lo)

def median_ci(values, rng):
    n = len(values)
    boots = [statistics.median(rng.choices(values, k=n)) for _ in range(N_BOOT)]
    return [percentile(boots, .025), percentile(boots, .975)]

rows = [json.loads(line) for line in (RES / "TRIALS.jsonl").read_text().splitlines() if line.strip()]
assert len(rows) == 50
assert sorted(r["order"] for r in rows) == list(range(50))
assert all(r["exit_code"] == 0 and r["measurement"]["ok"] is True for r in rows)
assert all(r["measurement"]["pk_load_ms"] is None for r in rows)
assert all(r["length"] == r["measurement"]["l_max"] == r["measurement"]["active"] for r in rows)
assert all((r["measurement"]["ra_depth"], r["measurement"]["state_depth"], r["measurement"]["revocation_depth"], r["measurement"]["grant_depth"]) == (20,20,32,3) for r in rows)
for length in range(1, 6):
    rs = [r for r in rows if r["length"] == length]
    assert len(rs) == 10 and sorted(r["rep"] for r in rs) == list(range(10))
for name in ["proof.bin", "pk.bin", "vk.bin"]:
    hashes = [r["artifacts"][name]["sha256"] for r in rows]
    assert len(set(hashes)) == 50, (name, len(set(hashes)))
for r in rows:
    d = RES / "artifacts" / f"L{r['length']}-rep{r['rep']:02d}"
    for name in ["proof.bin", "public.bin", "vk.bin"]:
        assert sha256(d / name) == r["artifacts"][name]["sha256"]

summary = {"schema": "r14_shared_remeasurement_analysis_v1", "seed": SEED, "bootstrap_replicates": N_BOOT,
           "trial_count": len(rows), "all_exit_zero": True, "all_verify_ok": True,
           "all_proofs_unique": len({r['artifacts']['proof.bin']['sha256'] for r in rows}) == 50,
           "all_fresh_pk_unique": len({r['artifacts']['pk.bin']['sha256'] for r in rows}) == 50,
           "pk_files_retained_remote_only": True, "configs": []}
rng = random.Random(SEED)
flat = []
for length in range(1, 6):
    rs = [r for r in rows if r["length"] == length]
    m0 = rs[0]["measurement"]
    cfg = {"length": length, "n": len(rs)}
    for metric in METRICS:
        vals = [r["measurement"][metric] for r in rs]
        cfg[metric] = {"median": statistics.median(vals), "bootstrap_95_ci": median_ci(vals, rng)}
    for key in ["pk_bytes","proof_bytes","public_bytes","vk_bytes","constraints","witnesses","instances","qap_domain","a_nnz","b_nnz","c_nnz"]:
        vals = {r["measurement"][key] for r in rs}; assert len(vals) == 1; cfg[key] = vals.pop()
    rss=[]; procwall=[]
    for r in rs:
        d=RES/"artifacts"/f"L{length}-rep{r['rep']:02d}"/"PROCESS.time"
        txt=d.read_text()
        rss.append(int(re.search(r"Maximum resident set size \(kbytes\): (\d+)",txt).group(1)))
        procwall.append(r["outer_wall_s"])
    cfg["peak_rss_kib"]={"median":statistics.median(rss),"max":max(rss)}
    cfg["process_wall_s"]={"median":statistics.median(procwall),"bootstrap_95_ci":median_ci(procwall,rng)}
    summary["configs"].append(cfg)
    flat.append(cfg)

(RES / "ANALYSIS.json").write_text(json.dumps(summary, indent=2) + "\n")
with (RES / "SUMMARY.csv").open("w", newline="") as f:
    w=csv.writer(f); w.writerow(["length","n","setup_median_ms","setup_ci_low","setup_ci_high","prove_median_ms","prove_ci_low","prove_ci_high","verify_median_ms","verify_ci_low","verify_ci_high","serialize_median_ms","serialize_ci_low","serialize_ci_high","pk_bytes","constraints","witnesses","instances","qap_domain","peak_rss_median_kib","peak_rss_max_kib","process_wall_median_s"])
    for c in flat:
        w.writerow([c["length"],c["n"],*[x for m in METRICS for x in [c[m]["median"],*c[m]["bootstrap_95_ci"]]],c["pk_bytes"],c["constraints"],c["witnesses"],c["instances"],c["qap_domain"],c["peak_rss_kib"]["median"],c["peak_rss_kib"]["max"],c["process_wall_s"]["median"]])
print(json.dumps(summary, indent=2))
