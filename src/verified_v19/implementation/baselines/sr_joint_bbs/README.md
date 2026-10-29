# Joint SR BBS23-CDL adapter

This independent comparator first runs the native Joint validator over original signed grants and RA/state/revocation witnesses. It then compiles source-neutral atomic maximal intervals into the existing Dock BBS23 plus LegoGroth16 closed-interval credential backend. The SR-private ledger retains source indexes and every grant serial.

The adapter expands SR trust and observation. It is not a DAC, OAuth, UCAN, or the older `AuthCircuit` comparator. `system=0` is an explicit deployment constant because the current Joint request has no system field. The legacy BBS backend has only a `u64` circuit-version message, while Joint uses a full field element; the adapter first requires exact equality of the full Joint `circuit_id` across all supports, then uses trusted deployment registry value `1` in that legacy slot. This is an adapter mapping rather than a collision-resistant encoding. It is safe only when the issuer and verifier configuration uniquely fixes `(deployment, full circuit_id, full BBS parameter digest)` and refuses credentials or showings under any other mapping. Likewise, the legacy global epoch is only the tuple version, so the service must resolve it to one exact complete snapshot. The final service bridge must bind the full Joint circuit id, exact canonical request and atomic snapshot digest before any performance result is called matched.

The executable's positive portfolio uses two distinct owners and independently signed grant chains under one shared RA root, state root, revocation root, terminal and complete Joint request. Its successor inserts one source's serial into a new revocation tree, refreshes the other source's nonmembership witnesses, and checks that compilation retains the surviving source. Merely combining fixtures that share a terminal is rejected because their atomic snapshots differ.

Compilation derives each support's full effective interval first, then runs the native Joint validator with an internal request spanning exactly that interval. This prevents an unrelated external request from filtering otherwise valid supports before containment compilation. The internal request reuses the fixture's canonical-request limbs and therefore establishes the Joint policy relation only; it does not establish a canonical HTTP business-request encoding. The eventual matched service bridge must perform that encoding check separately. External requests enter the BBS presentation and verification step.

Each input support compiles exactly the one public `action_onehot` atom carried by its candidate request. It does not enumerate every action bit authorized by an entitlement or grant mask. A full-permission compilation must explicitly supply and validate one candidate per desired atom.

The canonical showing encoding contains the variable-length `complete_q` context and verifier nonce. The repeated-show component batch and fresh-setup batch currently use different context strings, which explains their different 1673-byte and 1664-byte observations. Those sizes and their latency batches are separate diagnostics. A matched result must use the same canonical HTTP request bytes and nonce framing in every scheme and must not merge these batches.

## Portfolio sweep profile

`portfolio_sweep` crosses portfolio sizes 2, 8, and 32 with duplicate,
strictly contained, and overlapping noncontained effective intervals. Every
support is a real, separately admitted owner with a separately signed path.
All supports in a cell share one exact RA/state/revocation snapshot, terminal,
resource, and one-hot action atom.

The sweep uses the fixed circuit capacity `Lmax=3`, but each support has
`actual_grants=1`: it is a root-only signed path. For each issued maximal
interval, the primary request is the whole interval represented by that
credential. Thus the positive show tests exact whole-interval authority. The
noncontained cell also attempts one request from the first lower bound through
the last upper bound and requires presentation or verification to reject it.
No unrequested action atom is presented.

This root-only profile is a component scaling experiment. Its compilation,
ledger, issuance, and refresh measurements must not be paired as the same
instance with an `E2` result whose path has `actual_grants=3`. A later component
lifecycle model must use the same `(Lmax, actual_grants)` profile on both sides,
or report separate profiles. The JSON records the profile and per-trial
exposure counts, including compiler invocations, native support validations,
issuance calls, presentation attempts, and verification calls.

The maximal-interval implementation sorts distinct intervals by lower endpoint
ascending and upper endpoint descending, then performs one linear scan. This is
`O(n log n)` including sorting. The private dependency ledger still retains all
duplicate and dominated supports. A test-only exhaustive naive oracle checks
the optimized scan over every subset of all closed intervals with endpoints
from 0 through 3; the production compiler has only the optimized path.
