#!/usr/bin/env python3
import fcntl, hashlib, json, os, shutil, subprocess, sys, time
from pathlib import Path

BASE=Path('${REMOTE_DATA}/pets2027/checklist_experiments_v17_2026_10_27')
E=BASE/'r13_main_matched_formal_attempt02'; R=E/'results'; BIN=BASE/'build_attempt02/release'
schedule=json.loads((E/'inputs/FROZEN_SCHEDULE.json').read_text())
ALL_PROOF_FINGERPRINTS=set()
ALL_KEY_FINGERPRINTS={'joint':set(),'dac':set()}
def fail_hook(kind,value,tb):
    R.mkdir(exist_ok=True); (R/'FAILED_ATTEMPT').write_text(f'{time.strftime("%Y-%m-%dT%H:%M:%S%z")} {kind.__name__}: {value}\n')
    sys.__excepthook__(kind,value,tb)
sys.excepthook=fail_hook
def snapshot():
    mem={}
    for line in Path('/proc/meminfo').read_text().splitlines():
        if line.startswith(('MemAvailable:','SwapFree:')): mem[line.split(':')[0]]=int(line.split()[1])
    vm={}
    for line in Path('/proc/vmstat').read_text().splitlines():
        k,v=line.split()
        if k in ('pswpin','pswpout'): vm[k]=int(v)
    return {'time':time.time(),'loadavg':Path('/proc/loadavg').read_text().split()[:3],**mem,**vm}
def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for b in iter(lambda:f.read(1<<20),b''):h.update(b)
    return h.hexdigest()
def run(rep,backend,length_order):
    d=R/f'rep{rep:02d}'/backend; d.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy(); env.update(RAYON_NUM_THREADS='10',OMP_NUM_THREADS='1',MATCHED_MANIFEST_PATH=str(E/f'inputs/manifest-{rep:02d}.json'),MATCHED_LENGTH_ORDER=length_order)
    before=snapshot()
    if backend=='joint':
        env.update(MATCHED_HTTP_JSON_PATH=str(E/'inputs/canonical_http.json'),MATCHED_UPDATE_INDEX='0',MATCHED_JOINT_VK_OUT=str(d/'vk.bin'),MATCHED_REGISTRY_SK_U64='71',MATCHED_JOINT_CIRCUIT_ID='r13-main-matched-formal')
        cmd=['taskset','-c','0-9','timeout','1800',str(BIN/'formal_joint')]
    else:
        cmd=['taskset','-c','0-9','prlimit','--as=68719476736','timeout','1800',str(BIN/'v17_main_feasibility'),str(d)]
    started=time.monotonic()
    with open(d/'stdout','wb') as out,open(d/'stderr','wb') as err:
        p=subprocess.run(cmd,env=env,stdout=out,stderr=err)
    after=snapshot(); wall=time.monotonic()-started
    stdout=(d/'stdout').read_text().strip().splitlines()
    parsed=json.loads(stdout[-1]) if stdout else None
    record={'rep':rep,'backend':backend,'length_order':length_order,'exit_code':p.returncode,'wall_s':wall,'resource_before':before,'resource_after':after,'result':parsed,'files':{}}
    for path in sorted(d.iterdir()):
        if path.is_file(): record['files'][path.name]={'bytes':path.stat().st_size,'sha256':sha(path)}
    if p.returncode or parsed is None or parsed.get('valid') is False: raise RuntimeError(f'{backend} rep{rep} failed')
    manifest=json.loads((E/f'inputs/manifest-{rep:02d}.json').read_text())
    semantic_sha=hashlib.sha256(json.dumps(manifest,separators=(',',':')).encode()).hexdigest()
    if parsed.get('semantic_input_sha256')!=semantic_sha: raise RuntimeError(f'{backend} rep{rep} semantic manifest mismatch')
    proofs=parsed.get('rows') if backend=='joint' else parsed.get('proofs')
    labels=[int(x['actual'] if backend=='joint' else x['active']) for x in proofs]
    expected=[int(x) for x in length_order.split(',')]
    if len(proofs)!=3 or labels!=expected or set(labels)!={1,2,3}: raise RuntimeError(f'{backend} rep{rep} incomplete labels {labels}')
    if backend=='joint':
        if not all(x.get('verified') is True and x.get('changed_public_rejected') is True for x in proofs): raise RuntimeError(f'{backend} rep{rep} correctness gate')
        proof_hashes=[hashlib.sha256(bytes.fromhex(x['envelope']['proof'])).hexdigest() for x in proofs]
    else:
        if not all(x.get('verified') is True and x.get('mutated_public_rejected') is True for x in proofs): raise RuntimeError(f'{backend} rep{rep} correctness gate')
        proof_hashes=[x['proof_blake2s'] for x in proofs]
    if len(set(proof_hashes))!=3: raise RuntimeError(f'{backend} rep{rep} duplicate proofs')
    if ALL_PROOF_FINGERPRINTS.intersection(proof_hashes): raise RuntimeError(f'{backend} rep{rep} proof reused across trials')
    ALL_PROOF_FINGERPRINTS.update(proof_hashes)
    record['proof_fingerprints']=proof_hashes
    key_fingerprint=parsed['pk_sha256'] if backend=='joint' else record['files']['pk.bin']['sha256']
    if key_fingerprint in ALL_KEY_FINGERPRINTS[backend]: raise RuntimeError(f'{backend} rep{rep} proving key reused')
    ALL_KEY_FINGERPRINTS[backend].add(key_fingerprint); record['proving_key_sha256']=key_fingerprint
    with open(R/'TRIALS.jsonl','a') as f: f.write(json.dumps(record,separators=(',',':'))+'\n'); f.flush(); os.fsync(f.fileno())

R.mkdir(exist_ok=True); lock=open('${REMOTE_DATA}/pets2027/results/.experiment.lock','w'); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
if (R/'TRIALS.jsonl').exists(): raise SystemExit('refuse existing TRIALS.jsonl')
if snapshot()['MemAvailable'] < 100*1024*1024: raise SystemExit('MemAvailable gate')
if shutil.disk_usage('/mnt').free < 10*1024**3: raise SystemExit('/mnt free gate')
(R/'STARTED').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z')+'\n')
subprocess.run(['bash','-lc','date -Ins; hostname; lscpu; free -k; df -h /mnt; uptime; ps -eo user,pid,pcpu,pmem,etime,args --sort=-pcpu | head -n 40'],stdout=open(R/'HOST_BEFORE.txt','wb'),check=True)
for item in schedule:
    for backend in item['backend_order']: run(item['rep'],backend,item['length_order'])
subprocess.run(['bash','-lc','date -Ins; free -k; df -h /mnt; uptime'],stdout=open(R/'HOST_AFTER.txt','wb'),check=True)
(R/'MEASUREMENTS_COMPLETE').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z')+'\n')
(R/'FINISHED').write_text(time.strftime('%Y-%m-%dT%H:%M:%S%z')+'\n')
