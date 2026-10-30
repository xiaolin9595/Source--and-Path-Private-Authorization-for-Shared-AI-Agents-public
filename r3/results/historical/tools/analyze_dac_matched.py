#!/usr/bin/env python3
import csv, hashlib, json, random, statistics
from pathlib import Path

ROOT=Path(__file__).resolve().parent; RES=ROOT/'results'; SEED=2026102704; N=10_000
rows=[json.loads(x) for x in (RES/'TRIALS.jsonl').read_text().splitlines() if x]
assert len(rows)==20
by={(r['rep'],r['backend']):r for r in rows}; assert len(by)==20
assert not (RES/'FAILED_ATTEMPT').exists() and (RES/'FINISHED').exists() and (RES/'MEASUREMENTS_COMPLETE').exists()
schedule=json.loads((ROOT/'inputs/FROZEN_SCHEDULE.json').read_text())
all_proofs=[]
for s in schedule:
    rep=s['rep']; expected=[int(x) for x in s['length_order'].split(',')]
    assert [r['backend'] for r in rows if r['rep']==rep]==s['backend_order']
    for backend in ('joint','dac'):
        r=by[rep,backend]; assert r['exit_code']==0 and r['length_order']==s['length_order']
        ps=r['result']['rows' if backend=='joint' else 'proofs']
        labels=[p['actual' if backend=='joint' else 'active'] for p in ps]
        assert labels==expected and set(labels)=={1,2,3}
        flag='changed_public_rejected' if backend=='joint' else 'mutated_public_rejected'
        assert all(p['verified'] is True and p[flag] is True for p in ps)
        assert len(r['proof_fingerprints'])==3 and len(set(r['proof_fingerprints']))==3
        all_proofs.extend((backend,x) for x in r['proof_fingerprints'])
assert len(set(all_proofs))==60
assert len({by[i,'joint']['proving_key_sha256'] for i in range(10)})==10
assert len({by[i,'dac']['proving_key_sha256'] for i in range(10)})==10

def pct(a,q):
    s=sorted(a); x=(len(s)-1)*q; lo=int(x); hi=min(lo+1,len(s)-1); return s[lo]+(s[hi]-s[lo])*(x-lo)
def stat(values, salt):
    rng=random.Random(SEED+salt); boots=[statistics.median(rng.choices(values,k=len(values))) for _ in range(N)]
    return {'n':len(values),'median':statistics.median(values),'bootstrap_95_ci':[pct(boots,.025),pct(boots,.975)]}
def proofmap(r): return {p['actual' if r['backend']=='joint' else 'active']:p for p in r['result']['rows' if r['backend']=='joint' else 'proofs']}

paired=[]; lengths=[]; salt=0
for length in (1,2,3):
    per=[]
    for rep in range(10):
        j=proofmap(by[rep,'joint'])[length]; d=proofmap(by[rep,'dac'])[length]
        item={'rep':rep,'length':length,'joint_prove_ms':j['prove_ms'],'dac_prove_ms':d['prove_ms'],'prove_difference_ms':d['prove_ms']-j['prove_ms'],'prove_direct_ratio_dac_over_joint':d['prove_ms']/j['prove_ms'],'joint_verify_ms':j['verify_ms'],'dac_verify_ms':d['verify_ms'],'verify_difference_ms':d['verify_ms']-j['verify_ms'],'verify_direct_ratio_dac_over_joint':d['verify_ms']/j['verify_ms']}
        per.append(item); paired.append(item)
    out={'length':length}
    for key in ['joint_prove_ms','dac_prove_ms','prove_difference_ms','prove_direct_ratio_dac_over_joint','joint_verify_ms','dac_verify_ms','verify_difference_ms','verify_direct_ratio_dac_over_joint']:
        salt+=1; out[key]=stat([x[key] for x in per],salt)
    lengths.append(out)

backend_level=[]
for rep in range(10):
    j=by[rep,'joint']; d=by[rep,'dac']; jr=j['result']; dr=d['result']
    backend_level.append({'rep':rep,'joint_setup_ms':jr['setup_ms'],'dac_setup_ms':dr['setup_ms'],'setup_difference_ms':dr['setup_ms']-jr['setup_ms'],'setup_direct_ratio_dac_over_joint':dr['setup_ms']/jr['setup_ms'],'joint_wall_s':j['wall_s'],'dac_wall_s':d['wall_s'],'wall_difference_s':d['wall_s']-j['wall_s'],'wall_direct_ratio_dac_over_joint':d['wall_s']/j['wall_s'],'joint_pk_bytes':jr['pk_bytes'],'dac_pk_bytes':dr['pk_bytes'],'joint_proof_bytes':len(bytes.fromhex(jr['rows'][0]['envelope']['proof'])),'dac_proof_bytes':dr['proofs'][0]['proof_bytes'],'dac_peak_rss_kib':dr['peak_rss_kib']})
backend_summary={}
for key in backend_level[0]:
    if key!='rep': salt+=1; backend_summary[key]=stat([x[key] for x in backend_level],salt)

analysis={'schema':'r13_main_matched_formal_attempt02_analysis_v1','seed':SEED,'bootstrap_replicates':N,'backend_rows':20,'pairs':10,'all_exit_zero':True,'all_60_standard_verify':True,'all_60_changed_public_rejected':True,'all_60_proofs_unique_within_backend_fingerprint_scheme':True,'all_20_fresh_keys_unique_within_backend':True,'lengths':lengths,'backend_level':backend_summary,'joint_process_peak_rss_kib':None,'joint_process_peak_rss_limitation':'not captured by the frozen runner; no rerun performed','dac_process_peak_rss_kib':backend_summary['dac_peak_rss_kib'],'timer_boundaries':{'joint':'fixture/projection construction precedes timer; setup_ms is Groth16 circuit_specific_setup only; prove_ms and standard verify_ms are separate; outer wall includes fixture construction, setup, three prove/verify operations, serialization and runner overhead','dac':'fixture/native credential/accumulator construction precedes pilot_start and setup timer; setup_ms is Groth16 setup only; prove_ms and standard verify_ms are separate; total_after_fixture_ms and outer wall exclude/include runner overhead respectively; key serialization is separately reported'}}
(RES/'ANALYSIS.json').write_text(json.dumps(analysis,indent=2)+'\n')
with (RES/'PAIRED_BY_REP.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=paired[0]); w.writeheader(); w.writerows(paired)
with (RES/'BACKEND_BY_REP.csv').open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=backend_level[0]); w.writeheader(); w.writerows(backend_level)
with (RES/'SUMMARY.csv').open('w',newline='') as f:
    w=csv.writer(f); w.writerow(['scope','length','metric','n','median','ci_low','ci_high'])
    for x in lengths:
        for k,v in x.items():
            if k!='length': w.writerow(['length',x['length'],k,v['n'],v['median'],*v['bootstrap_95_ci']])
    for k,v in backend_summary.items(): w.writerow(['backend','',k,v['n'],v['median'],*v['bootstrap_95_ci']])
print(json.dumps(analysis,indent=2))
