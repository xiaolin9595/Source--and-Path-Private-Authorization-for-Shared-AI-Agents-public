# Pinned Poseidon reference gate

Run only on `benchmark-host` under the shared experiment lock. Preserve every command,
stdout/stderr, exit code, byte digest, and repository provenance.

1. Do not retry the Git endpoint after the retained v1 connection-reset
   evidence. Transfer the two locally downloaded primary-source resources:
   the authors' official commit archive
   `offline_resources/poseidon_hadeshash_9d80ec0473ad7cde5a12f3aac46439ad0da68c0a/hadeshash-9d80ec0473ad7cde5a12f3aac46439ad0da68c0a.tar.gz`
   and the independently downloaded official raw
   `calc_round_numbers.py` from the same commit. Run:

   ```text
   python3 tools/prefetch_poseidon_reference.py \
     --out NEW_DIRECTORY \
     --official-archive ABSOLUTE_ARCHIVE_PATH \
     --official-raw-script ABSOLUTE_RAW_SCRIPT_PATH
   ```

   The script requires archive SHA-256
   `e27359cc8bf5c38cd74776ab995b793a86fdeafe7c88aca7653041b9a1eaeac4`,
   raw/script SHA-256
   `b850ecf8d403c3ac3fced726deff540574ec3ca713f1f19cad55beff4ea1d094`,
   exact archive root
   `hadeshash-9d80ec0473ad7cde5a12f3aac46439ad0da68c0a`, safe member paths, no
   links, and byte equality between the archive calculator and independent raw
   response. Retain the resources and `PROVENANCE.json`. No server network
   access is used in this mode.
2. Record the exact official archive/raw URLs, the two resource SHA-256 values,
   archive root name, and SHA-256 of the extracted
   `code/scripts/calc_round_numbers.py`. An HTTP archive cannot independently
   establish a Git object identity, so provenance must state
   `git_head_claimed=false`; the commit binding is the official URL path,
   archive root, and independent raw URL at the same 40-hex revision. Do not
   patch or execute the reference file before the server gate.
3. Run the standard-library-only wrapper:

   ```text
   python3 tools/poseidon_reference_gate.py \
     --script /absolute/path/to/hadeshash/code/scripts/calc_round_numbers.py \
     --commit 9d80ec0473ad7cde5a12f3aac46439ad0da68c0a \
     --compatibility-dir /fresh/result/path/python2-compatibility \
     --implementation-source /absolute/path/to/src/fixed_policy.rs
   ```

   The retained v2 inventory proves that `python2`, `python2.7`, and `pypy2`
   are absent on benchmark-host. The untouched official file is Python 2 syntax. The
   wrapper therefore requires its exact SHA-256, writes a retained temporary
   compatibility copy that changes only Python 2 `print` statements, and saves
   the complete unified patch, translated-file hash, and compatibility JSON.
   It audits every `/` operator in the pinned file: all eleven divisions use
   explicit floating operands, so Python 2 integer division is not involved.
   It also records the range/ceil semantic audit. The original bytes remain
   unchanged and are not described as executed; the translated compatibility
   copy is the executed program.

4. Require exit zero and JSON values: decimal modulus exactly matches
   `POSEIDON_PARAMETERS.md`, `field_modulus_bits=377`,
   `gcd_alpha_p_minus_one=1`, `width=3`, `alpha=5`,
   `security_bits=128`, `security_margin=true`,
   `recommended_full_rounds=8`, `recommended_partial_rounds=55`,
   `implemented_full_rounds=8`, `implemented_partial_rounds=57`,
   `implementation_extra_partial_rounds=2`, the frozen implementation-source
   SHA-256, and `gate_passed=true`.
   The official calculator's CLI `N` is the total state bit width, so this gate
   passes `N=t*n=3*377=1131`; it is distinct from the separately reported
   field-element bit length `n=377`. If the untouched algorithm executed via
   the disclosed compatibility patch recommends rounds other than 8/55, or
   the frozen implementation source does not contain the audited 8/57
   schedule, preserve that real stdout and fail closed. Do not coerce the
   output.
5. Retain the calculator's own target stdout embedded in the JSON. Output after
   the target recommendation comes from the script's hard-coded challenge
   table and is preserved separately in `reference_import_stdout`; it is not
   evidence for BLS12-377 Fq.
6. The Poseidon paper describes this calculator as deprecated in favor of its
   newer parameter generator. Therefore this gate establishes only that the
   pinned calculator recommends 8/55 and the frozen implementation retains
   8/57, two additional partial rounds, as checked through the disclosed
   Python 2 print-only compatibility patch. It does not validate the arkworks
   constants/MDS arrays, the wrapper's curve security, or the complete B2
   relation.

Primary source: Grassi et al., *POSEIDON*, USENIX Security 2021 / IACR ePrint
2019/458, Appendix B and the authors' linked repository.
