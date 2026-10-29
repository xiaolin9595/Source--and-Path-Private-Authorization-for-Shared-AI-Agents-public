# Paired Joint/SR review resolution

This checklist records the static review boundary before the first benchmark-host
gate. A checked item describes source that must still pass the remote
format/check/run/analysis gate; it is not a measured result by itself.

1. **Current Joint public inputs.** `current_profile_paired.rs` imports the
   main crate's `fixture` module and calls `fixture::public_inputs` for both
   Joint proofs. The server `cargo check` is the structural gate.
2. **Old credential under the successor statement.** `measure_refresh_sr`
   performs two distinct negatives: it submits the retained old showing under
   the successor context, and it creates a fresh showing from the old
   credential using that successor context. Both must fail against the
   successor public fields, and both booleans are required by the analyzer.
3. **Canonical Q16 request mapping.** `request_context` constructs all sixteen
   typed fields, calls `encode_complete_q` and `RequestContext::from_q16`, and
   asserts the mapped `(system, circuit_version, resource, action)` and
   `(tq, te)` equal the compiler output and request. Exact header and external
   request SHA-256 values are retained. Initial and successor phases must keep
   the exact external request digest while changing the signed header tuple.
4. **Freshness claim.** Output uses
   `old_showing_rejected_under_successor_context`; it does not call the
   cryptographic backend a header-history checker. Current-header selection is
   a service responsibility outside this component gate.
5. **Artifact names and storage boundary.** The private file is explicitly a
   two-source synthetic experiment bundle. The combined proof, credential,
   ledger, public-file reference bundle is explicitly an experiment audit
   bundle. Neither is called a holder wallet or a production credential store.
6. **Timing boundaries.** Initial timing is named
   `synthetic_fixture_and_private_records_build`. Successor timing includes the
   exact registry batch, dense root rebuild, and both source witness refreshes.
   Publication timing includes header signing and public JSON serialization
   only; durable install, transaction, HTTP, delivery, and production network
   time remain unmeasured.
7. **Paired differences.** The analyzer bootstraps signed per-trial differences
   for Joint prove minus SR show and Joint verify minus SR verify, for initial
   and successor phases. The output labels these component comparisons and
   does not report an end-to-end break-even.
8. **Scheme order.** Each configuration alternates Joint-first and SR-first by
   seed and update batch. The analyzer requires exactly five trials in each
   order for each ten-trial configuration.
9. **Trial independence.** The result declares one shared SR parameter setup
   and one audited Joint key. Ten seeds vary workload keys, records, paths,
   witnesses, and proof randomness. Confidence intervals describe workload
   trials only and do not claim fresh setups or deployment generalization.
10. **Database signature consistency.** Every current RA signature is verified
    against the recomputed current leaf. For each changed state row, the
    expected previous version is retained, the owner update digest is
    recomputed from the current row and expected version, the current version
    must be exactly one greater, and the owner signature is verified over the
    recomputed digest. The analyzer also requires exactly `u` updated rows.

## Remaining boundary

This gate is a same-profile component experiment. It does not yet exercise the
HTTP service with both backends and therefore cannot produce a numeric
end-to-end break-even. The production network and SR credential delivery path
remain unknown. A later HTTP bridge gate must preserve this distinction.
