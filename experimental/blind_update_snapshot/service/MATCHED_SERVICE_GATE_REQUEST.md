# 206160G matched service gate request

Executor: `/root/gap_runtime_56` only.  Do not overwrite any retained/frozen
output.  Create a new timestamped result directory.

1. Freeze source and lock digests, Rust/Python/toolchain versions, CPU/OS, and
   the canonical manifest plus `semantic_input_sha256`.
2. Format/check/build the paired manifest, DAC wrapper, Joint circuit, both
   resident adapters, and `matched_service.py` integration package offline.
3. Run `matched_correctness_driver.py` first on one resident service and one
   SQLite database through t0 ABC, t1 delete-A/retain-B-C, and t2 revoke-B/retain-C.
   Require stale header/proof/read-ticket, body, terminal, proof-byte, clock and
   nonce negatives. Preserve its complete response log.
4. Require projection equality and one successful real proof plus HTTP commit
   for Joint actual 1, Joint actual 2, DAC actual 1, and DAC actual 2.
5. Run negatives for stale header, changed method/path/body/resource/action,
   wrong terminal/logical mapping, nonce replay and race, proof/VK/header or
   terminal-signature byte mutation, and expiry between read and commit.
   Failed attempts must leave the SQLite nonce reusable.
6. Only after correctness passes, run the balanced 10-fresh-setup t1 design in
   `MATCHED_SERVICE_CONTRACT.md`; retain raw rows and the 10,000-resample paired
   bootstrap output.

Completion requires all four real proof-to-HTTP paths.  Native root/projection
audit alone does not satisfy this request.
