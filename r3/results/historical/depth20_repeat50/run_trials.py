from pathlib import Path
import subprocess,os,json,time,hashlib,re,resource
root=Path(__file__).parent; out=root/'results'; out.mkdir(exist_ok=True); binary=root.parent/'build/release/plan_a_proof_cli'
def sha(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  for b in iter(lambda:f.read(1024*1024),b''):h.update(b)
 return h.hexdigest()
def envstate():
 m={l.split(':',1)[0]:int(l.split()[1]) for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith(('MemAvailable:','SwapFree:'))};m['loadavg']=Path('/proc/loadavg').read_text().split()[:3];m['vmstat']={l.split()[0]:int(l.split()[1]) for l in Path('/proc/vmstat').read_text().splitlines() if l.startswith(('pswpin ','pswpout '))};return m
jobs=[]
for rep in range(10):
 base=[1,2,3,4,5] if rep<5 else [5,4,3,2,1];k=rep%5
 for length in base[k:]+base[:k]:jobs.append({'order':len(jobs),'rep':rep,'length':length})
(out/'FROZEN_SCHEDULE.json').write_text(json.dumps(jobs,indent=2)+'\n')
assert not (out/'TRIALS.jsonl').exists(), 'refuse overwrite or implicit resume'
for job in jobs:
 p=out/'artifacts'/f"L{job['length']}-rep{job['rep']:02d}";p.mkdir(parents=True)
 files=[p/name for name in ['pk.bin','vk.bin','proof.bin','public.bin']]
 cmd=['/usr/bin/time','-v','-o',str(p/'PROCESS.time'),'timeout','180',str(binary),'trial',*[str(f) for f in files],str(job['length']),str(job['length']),str(200000+job['order']),'20','20','32','v17-r14']
 before=envstate();started=time.monotonic()
 r=subprocess.run(cmd,capture_output=True,text=True,env=dict(os.environ,PLAN_A_SKIP_PK_LOAD='1'),preexec_fn=lambda:resource.setrlimit(resource.RLIMIT_AS,(8*1024**3,8*1024**3)))
 row=dict(job,command=cmd,resource_before=before,resource_after=envstate(),outer_wall_s=time.monotonic()-started,exit_code=r.returncode)
 (p/'stdout').write_text(r.stdout);(p/'stderr').write_text(r.stderr)
 if r.returncode==0:
  d=json.loads(r.stdout);assert d['pk_load_ms'] is None and d['ok'];row['measurement']=d;row['artifacts']={f.name:{'bytes':f.stat().st_size,'sha256':sha(f)} for f in files}
 with (out/'TRIALS.jsonl').open('a') as f:f.write(json.dumps(row,sort_keys=True)+'\n');f.flush();os.fsync(f.fileno())
 print(json.dumps({'order':job['order'],'length':job['length'],'rep':job['rep'],'exit':r.returncode,'wall_s':row['outer_wall_s']}),flush=True)
 if r.returncode:raise SystemExit(r.returncode)
(out/'MEASUREMENTS_COMPLETE').write_text('50/50 processes completed\n')
