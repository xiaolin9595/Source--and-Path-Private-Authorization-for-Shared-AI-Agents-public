#!/usr/bin/env python3
"""Frozen R2 session driver. Creates schedules and joins private control with receiver evidence."""
from __future__ import annotations

import argparse, hashlib, json, os, random, select, subprocess, sys, time
from pathlib import Path
from typing import Any, TextIO

SCHEMA = "r2-observation-v1"

def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()

def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""): h.update(chunk)
    return h.hexdigest()

def schedule(phase: str, session: int) -> tuple[list[dict[str, Any]], str]:
    blocks = 100 if phase == "calibration" else 125
    seed = (2026102960 if phase == "calibration" else 2026102970) + session
    rng = random.Random(seed); rows: list[dict[str, Any]] = []
    for block in range(1, blocks + 1):
        cells = ([(length, "u") for length in range(1, 4)] if phase == "calibration"
                 else [(length, arm) for length in range(1, 4) for arm in ("u", "pA", "pB")])
        rng.shuffle(cells)
        rows.extend({"block": block, "length": length, "arm": arm, "schedule_position": pos}
                    for pos, (length, arm) in enumerate(cells))
    return rows, hashlib.sha256(canonical(rows)).hexdigest()

def read_json_line(stream: TextIO, timeout: float) -> dict[str, Any]:
    ready, _, _ = select.select([stream], [], [], timeout)
    if not ready: raise TimeoutError("subprocess JSON timeout")
    line = stream.readline()
    if not line: raise RuntimeError("subprocess EOF")
    return json.loads(line)

def main() -> None:
    p=argparse.ArgumentParser(); p.add_argument("--phase",choices=("calibration","formal"),required=True)
    p.add_argument("--session",type=int,required=True); p.add_argument("--binary",type=Path,required=True)
    p.add_argument("--pk",type=Path,required=True); p.add_argument("--vk",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True); p.add_argument("--setup-id",required=True)
    p.add_argument("--config-sha256",required=True); p.add_argument("--gate-manifest-sha256",required=True)
    p.add_argument("--source-manifest-sha256",required=True)
    p.add_argument("--tpad-ms",type=int,default=0); p.add_argument("--gate-rows",type=int,default=0)
    a=p.parse_args()
    if a.phase=="formal" and a.tpad_ms<=0: raise SystemExit("formal requires frozen positive Tpad")
    if a.output.exists(): raise SystemExit("refusing existing output directory")
    a.output.mkdir(parents=True); rows,schedule_sha=schedule(a.phase,a.session)
    (a.output/"schedule.json").write_bytes(canonical(rows)+b"\n")
    identities={"pk_sha256":sha_file(a.pk),"vk_sha256":sha_file(a.vk),
                "config_sha256":a.config_sha256,"implementation_sha256":sha_file(a.binary),
                "gate_manifest_sha256":a.gate_manifest_sha256,
                "source_manifest_sha256":a.source_manifest_sha256,"provenance":"measured"}
    env=os.environ.copy(); env.update(RAYON_NUM_THREADS="10",OMP_NUM_THREADS="1")
    agent=subprocess.Popen(["taskset","-c","0-9",str(a.binary),"agent-serve",str(a.pk)],
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=(a.output/"agent.stderr").open("w"),text=True,bufsize=1,env=env)
    assert agent.stdin and agent.stdout
    ready=read_json_line(agent.stdout,180); assert ready["event"]=="agent_ready"
    selected=rows[:a.gate_rows] if a.gate_rows else rows
    records=(a.output/"records.jsonl").open("x",buffering=1)
    gates=(a.output/"gates.jsonl").open("x",buffering=1)
    active_receiver: subprocess.Popen[str] | None = None

    def observe(length: int, arm: str, ordinal: int) -> tuple[dict[str, Any],dict[str, Any]]:
        nonlocal active_receiver
        receiver=subprocess.Popen(["taskset","-c","0-9",str(a.binary),"receiver","127.0.0.1:0",str(a.vk),"normal"],
            stdout=subprocess.PIPE,stderr=(a.output/f"receiver-{ordinal:05d}.stderr").open("w"),text=True,bufsize=1,env=env)
        active_receiver=receiver
        try:
            assert receiver.stdout; ready_receiver=read_json_line(receiver.stdout,30)
            assert ready_receiver["event"]=="receiver_ready"
            control={"addr":ready_receiver["addr"],"length":length,"tpad_ms":a.tpad_ms,
                     "padded":arm!="u","slow_ms":0}
            agent.stdin.write(json.dumps(control,separators=(",",":"))+"\n"); agent.stdin.flush()
            ar=read_json_line(agent.stdout,60); rr=read_json_line(receiver.stdout,60)
            if receiver.wait(timeout=5)!=0: raise RuntimeError("receiver failed")
            for field in ("challenge_sha256","proof_sha256","envelope_sha256"):
                if ar[field] != rr[field]: raise RuntimeError(f"agent/receiver {field} mismatch")
            if not (rr.get("verified") and rr.get("proof_verified") and rr.get("signature_verified")
                    and rr.get("arrival_recorded_before_verification")):
                raise RuntimeError("receiver correctness gate failed")
            if ar["frame_bytes"] != rr["frame_bytes"]: raise RuntimeError("frame length mismatch")
            return ar,rr
        finally:
            if receiver.poll() is None:
                receiver.terminate()
                try: receiver.wait(timeout=5)
                except subprocess.TimeoutExpired: receiver.kill(); receiver.wait(timeout=5)
            active_receiver=None
    try:
        gate_cells = ([(length, arm) for length in range(1,4) for arm in ("u","pA","pB")]
                      if a.phase=="formal" else [(length,"u") for _ in range(3) for length in range(1,4)])
        for gate_index,(length,arm) in enumerate(gate_cells):
            ar,rr=observe(length,arm,-gate_index-1)
            gates.write(json.dumps({"event":"gate","gate_index":gate_index,"length_private":length,
                "arm_private":arm,"agent":ar,"receiver":rr},sort_keys=True,separators=(",",":"))+"\n")
        for ordinal, cell in enumerate(selected):
            ar,rr=observe(cell["length"],cell["arm"],ordinal)
            joined={"schema":SCHEMA,"phase":a.phase,"session":a.session,"setup_id":a.setup_id,
                    "block":cell["block"],"length":cell["length"],"arm":cell["arm"],
                    "schedule_position":cell["schedule_position"],"schedule_sha256":schedule_sha,
                    **identities,"event_agent":ar.pop("event"),"event_receiver":rr.pop("event"),
                    **ar,**{("receiver_frame_bytes" if k=="frame_bytes" else k):v for k,v in rr.items()}}
            # Split the independently computed digests after the flattened merge.
            for side in ("challenge_sha256","proof_sha256","envelope_sha256"):
                joined[f"agent_{side}"]=ar[side]; joined[f"receiver_{side}"]=rr[side]
                joined.pop(side, None)
            joined.pop("mutation_gate",None)
            records.write(json.dumps(joined,sort_keys=True,separators=(",",":"))+"\n")
    except BaseException:
        (a.output/"FAILED").write_text("failed\n"); raise
    finally:
        records.close(); gates.close()
        if active_receiver is not None and active_receiver.poll() is None: active_receiver.terminate()
        agent.stdin.close()
        try: agent.wait(timeout=5)
        except subprocess.TimeoutExpired: agent.terminate(); agent.wait(timeout=5)
    (a.output/"COMPLETE").write_text(f"rows={len(selected)} schedule_sha256={schedule_sha}\n")

if __name__=="__main__": main()
