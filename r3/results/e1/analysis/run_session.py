#!/usr/bin/env python3
"""Frozen-shape E1 session orchestrator; formal invocation requires root approval."""
import argparse,json,random,subprocess,hashlib
from pathlib import Path

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def call_setup(binary,out):
    return json.loads(subprocess.run([binary,"setup",str(out)],check=True,text=True,capture_output=True).stdout)
def start(binary,pk,relation_sha):
    p=subprocess.Popen([binary,"serve",str(pk),relation_sha],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,bufsize=1)
    ready=json.loads(p.stdout.readline()); assert ready["event"]=="ready"; return p,ready
def request(p,row):
    p.stdin.write(json.dumps(row,separators=(",",":"))+"\n");p.stdin.flush();return json.loads(p.stdout.readline())
def schedule(session):
    rng=random.Random(2026102900+session); cells=[(n,l) for n in (1,2,3) for l in ("o","aA","aB")];rows=[]
    warm=cells[:];rng.shuffle(warm)
    for i,(length,label) in enumerate(warm): rows.append({"command":"request","session":session,"block":-1,"length":length,"label":"gate" if label=="o" else label,"nonce":session*10_000_000+i,"measured":False,"route":"o" if label=="o" else "a"})
    for block in range(125):
        order=cells[:];rng.shuffle(order)
        for position,(length,label) in enumerate(order):rows.append({"command":"request","session":session,"block":block,"length":length,"label":label,"nonce":session*10_000_000+1000+block*9+position,"measured":True,"route":"o" if label=="o" else "a"})
    return rows
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--session",type=int,required=True,choices=range(1,5));ap.add_argument("--original-bin",required=True);ap.add_argument("--dummy-bin",required=True);ap.add_argument("--original-relation-sha",required=True);ap.add_argument("--dummy-relation-sha",required=True);ap.add_argument("--output",required=True);ap.add_argument("--dry-run",action="store_true");a=ap.parse_args();rows=schedule(a.session)
    assert len(rows)==1134 and sum(r["measured"] for r in rows)==1125
    if a.dry_run: print(json.dumps({"event":"schedule_valid","session":a.session,"rows":len(rows),"measured":1125,"sha256":hashlib.sha256((json.dumps(rows,sort_keys=True,separators=(",",":"))+"\n").encode()).hexdigest()}));return
    out=Path(a.output);assert not out.exists();out.mkdir();po=pa=None
    schedule_bytes=(json.dumps(rows,sort_keys=True,separators=(",",":"))+"\n").encode();schedule_sha=hashlib.sha256(schedule_bytes).hexdigest();(out/"schedule.json").write_bytes(schedule_bytes)
    log=(out/"records.jsonl").open("x",encoding="utf-8")
    try:
        setup_o=call_setup(a.original_bin,out/"original_setup");setup_a=call_setup(a.dummy_bin,out/"dummy_setup")
        po,ready_o=start(a.original_bin,out/"original_setup/pk.compressed",a.original_relation_sha);pa,ready_a=start(a.dummy_bin,out/"dummy_setup/pk.compressed",a.dummy_relation_sha)
        log.write(json.dumps({"event":"session","session":a.session,"schedule_sha256":schedule_sha,"schedule_rows":len(rows),"original_binary_sha256":sha(a.original_bin),"dummy_binary_sha256":sha(a.dummy_bin),"setup_o":setup_o,"setup_a":setup_a,"ready_o":ready_o,"ready_a":ready_a},sort_keys=True)+"\n");log.flush()
        for position,row in enumerate(rows):
            route=row["route"];payload={key:value for key,value in row.items() if key!="route"};event=request(po if route=="o" else pa,payload);event.update({"schedule_sha256":schedule_sha,"schedule_position":position,"route":route});log.write(json.dumps(event,sort_keys=True)+"\n");log.flush()
        po.stdin.close();pa.stdin.close();assert po.wait()==0 and pa.wait()==0;po=pa=None
        (out/"COMPLETE").write_text(schedule_sha+"\n",encoding="utf-8")
    finally:
        log.close()
        for child in (po,pa):
            if child is not None and child.poll() is None: child.terminate();child.wait(timeout=10)
if __name__=="__main__":main()
