#!/usr/bin/env python3
import argparse, hashlib, json, os, random, re, subprocess, time
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--bin',type=Path,required=True); p.add_argument('--out',type=Path,required=True); p.add_argument('--repetitions',type=int,default=10); a=p.parse_args(); a.out.mkdir(parents=True,exist_ok=True)
seed=20261023; jobs=[(l,ds,r) for l in range(1,6) for ds in (10,16,20,24) for r in range(a.repetitions)]; random.Random(seed).shuffle(jobs)
jsonl=a.out/'TRIALS.jsonl'; completed=set()
if jsonl.exists():
 for line in jsonl.read_text().splitlines():
  x=json.loads(line); completed.add((x['l_max'],x['state_depth'],x['repetition']))
def resource():
 m={}
 for line in Path('/proc/meminfo').read_text().splitlines():
  if line.startswith(('MemAvailable:','SwapFree:')): k,v,*_=line.split();m[k[:-1]]=int(v)
 load=Path('/proc/loadavg').read_text().split()[:3]
 vm={}
 for line in Path('/proc/vmstat').read_text().splitlines():
  k,v=line.split()
  if k in ('pswpin','pswpout'):vm[k]=int(v)
 return {'load':load,**m,**vm}
def sha(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for chunk in iter(lambda:f.read(1024*1024),b''):h.update(chunk)
 return h.hexdigest()
def parse_time(path):
 text=path.read_text(); out={}
 for key,name in [('Elapsed (wall clock) time','elapsed'),('Maximum resident set size (kbytes)','max_rss_kib')]:
  match=re.search(r'^\s*'+re.escape(key)+r'.*?:\s*(.+)$',text,re.M)
  if match: out[name]=match.group(1)
 return out
for order,(l,ds,rep) in enumerate(jobs):
 if (l,ds,rep) in completed: continue
 tag=f'L{l}-dS{ds}-rep{rep}'; d=a.out/'artifacts'/tag; d.mkdir(parents=True,exist_ok=True)
 pk,vk,proof,public=[d/x for x in ('pk.bin','vk.bin','proof.bin','public.bin')]; tf=d/'time.txt'
 cmd=['/usr/bin/time','-v','-o',str(tf),'env','PLAN_A_SKIP_PK_LOAD=1',str(a.bin),'trial',str(pk),str(vk),str(proof),str(public),str(l),str(l),str(100000+order),str(ds),'20','32',tag]
 before=resource(); t=time.monotonic(); cp=subprocess.run(cmd,text=True,capture_output=True); wall=time.monotonic()-t; after=resource()
 (d/'stdout').write_text(cp.stdout); (d/'stderr').write_text(cp.stderr)
 row={'schema':'plan-a-e2-trial-v1','random_seed':seed,'order':order,'l_max':l,'state_depth':ds,'ra_depth':20,'revocation_depth':32,'repetition':rep,'exit_code':cp.returncode,'outer_wall_s':wall,'resource_before':before,'resource_after':after,'time':parse_time(tf)}
 if cp.returncode==0:
  payload=json.loads(cp.stdout); assert payload['pk_load_ms'] is None; row['measurement']=payload; row['artifacts']={x.name:{'bytes':x.stat().st_size,'sha256':sha(x)} for x in (pk,vk,proof,public)}
 with jsonl.open('a') as f:f.write(json.dumps(row,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'order':order,'l':l,'ds':ds,'rep':rep,'exit':cp.returncode,'wall_s':wall}),flush=True)
 if cp.returncode: raise SystemExit(cp.returncode)
 for x in (pk,vk,proof,public): x.unlink()
(d:=json.loads(jsonl.read_text().splitlines()[0]))
summary={'schema':'plan-a-e2-raw-v1','random_seed':seed,'expected_trials':len(jobs),'completed_trials':len(jsonl.read_text().splitlines()),'note':'Each trial is an independent OsRng setup, in-memory proof and verification; pk_load_ms is null. Process RSS includes setup, proving, verification and serialization.'}
(a.out/'SUMMARY.json').write_text(json.dumps(summary,indent=2)+'\n')
