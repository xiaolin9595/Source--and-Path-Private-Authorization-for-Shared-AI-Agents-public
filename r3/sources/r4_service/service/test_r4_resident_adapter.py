import json
import sys
import time
from pathlib import Path

from service import ResidentCheckedVerifier


def write_child(path: Path, ready: dict, response: dict) -> None:
    path.write_text(
        "import json,sys\n"
        f"print({json.dumps(json.dumps(ready))}, flush=True)\n"
        "for line in sys.stdin:\n"
        f" print({json.dumps(json.dumps(response))}, flush=True)\n"
    )


def test_resident_checked_ready_reuse_and_receipt(tmp_path):
    receipt = "12" * 32
    child = tmp_path / "child.py"
    write_child(child,
        {"event":"ready", "profile":"r4-checked-v5", "receipt_sha256":receipt,
         "relations":["blind-update"], "validation_count":1},
        {"valid":True, "_r4_receipt_sha256":receipt})
    verifier = ResidentCheckedVerifier([sys.executable, str(child)], 2, 2)
    try:
        assert verifier.call({"command":"one"})
        assert verifier.call({"command":"two"})
        assert verifier.process.poll() is None
    finally:
        verifier.close()


def test_resident_checked_rejects_response_receipt_change(tmp_path):
    receipt = "34" * 32
    child = tmp_path / "child.py"
    write_child(child,
        {"event":"ready", "profile":"r4-checked-v5", "receipt_sha256":receipt,
         "relations":["blind-update"], "validation_count":1},
        {"valid":True, "_r4_receipt_sha256":"56" * 32})
    verifier = ResidentCheckedVerifier([sys.executable, str(child)], 2, 2)
    assert verifier.response({"command":"one"}) is None
    assert verifier.process.poll() is not None


def test_resident_checked_rejects_unchecked_ready_record(tmp_path):
    child = tmp_path / "child.py"
    write_child(child, {"event":"ready", "profile":"unchecked"}, {"valid":True})
    try:
        ResidentCheckedVerifier([sys.executable, str(child)], 2, 2)
    except RuntimeError as error:
        assert str(error) == "invalid-checked-verifier-ready-record"
    else:
        raise AssertionError("unchecked child was accepted")


def test_resident_checked_partial_ready_line_honors_deadline_and_reaps(tmp_path):
    child = tmp_path / "partial.py"
    child.write_text("import sys,time\nsys.stdout.write('{\\\"event\\\":\\\"ready\\\"');sys.stdout.flush()\ntime.sleep(10)\n")
    started=time.monotonic()
    try:
        ResidentCheckedVerifier([sys.executable,str(child)],0.05,1)
    except TimeoutError as error:
        assert str(error)=="verifier-startup-timeout"
    else:
        raise AssertionError("partial line bypassed startup deadline")
    assert time.monotonic()-started < 3


def test_resident_checked_nonreading_child_bounds_write_and_reaps(tmp_path):
    child=tmp_path/"nonreader.py";receipt="78"*32
    ready={"event":"ready","profile":"r4-checked-v5","receipt_sha256":receipt,
           "relations":["blind-update"],"validation_count":1}
    child.write_text("import time\n"+f"print({json.dumps(json.dumps(ready))},flush=True)\n"+"time.sleep(10)\n")
    verifier=ResidentCheckedVerifier([sys.executable,str(child)],1,0.05)
    started=time.monotonic()
    assert verifier.response({"padding":"x"*(2*1024*1024)}) is None
    assert time.monotonic()-started<3
    assert verifier.process.poll() is not None
