# B2 completion matrix

Status vocabulary:

- **retained evidence**: an earlier artifact exists and is not overwritten;
- **implemented, runner pending**: source expresses the relation or gate, but
  `benchmark-host` has not yet returned a successful gate for this revision;
- **gated**: reserved for a successful retained runner artifact;
- **outstanding**: code or matched experiment evidence is still missing.

No row below marked runner pending is a completed B2 result. The native DAC,
partial wrapper relations, and full adapter are reported separately.

Retained stage evidence: `dac_fixed_wrapper_stage1_v18` passed locked compile
and the then-current synthesis gate with 887,682 constraints. A/B/C (including
actual-depth-one signed padding), D (alternate owner and independent issuer
key), and a legal request variant had exact public-input allocation and full
finalized-matrix digest equality. The run took 8:28.80 and peaked at
15,059,964 KB RSS. It did not run Groth16 setup/prove/verify. The frozen latest
candidate adds five time/cap negatives after that copy, so those negatives and
the full phase remain runner pending.

| Layer | Obligation | Current status | Executable or evidence | Completion gate |
|---|---|---|---|---|
| Native Mir-DAC | Root issuance, offline delegation, holder-key conversion, and native verification on BLS12-377 | Implemented, runner pending for this revision | `src/bin/fixed_policy_gate.rs` constructs paths A, B, and the one-level path C with padding | Native constructors and `Credential::verify` return success before circuit synthesis |
| Partial wrapper | Root SPSEQ-UC signature, exact KZG opening, holder binding, adversarial pairing-point subgroup and nonidentity checks | Retained failures v1-v6; fixes implemented, runner pending | `src/lib.rs`, default binary; prior logs remain under `dac_fixed_wrapper_stage1_v1` through `v6` on `benchmark-host` | Default JSON accepts the real credential and rejects mutated public input, identity, and sampled non-subgroup G2 witness |
| Partial native linkage | Randomized hidden-message show linked to VB nonmembership | Implemented, runner pending | `src/hidden_serial.rs`, `src/bin/hidden_serial_gate.rs` | Positive transcript plus commitment, context, and successor-accumulator negatives |
| Full relation | Exact 16-member quotient chain with no duplicate-tag or extra-member remainder | Implemented, runner pending | `fixed_policy.rs`: `record_members`, `enforce_typed_membership`, final quotient equality | Positive synthesis plus `hidden_field_mutation_rejected=true` |
| Full relation | Lossless parent-record digest in BLS12-377 Fq, encoded as 2x192 bits with the upper seven bits zero | Implemented, runner pending | `record_digest`, `split_record_digest`, `record_digest_var` | Native/R1CS positive and mutated parent limb negative |
| Full relation | Source and per-source issuer key remain private but are authenticated by the RA root | Implemented, runner pending | Private `issuer_pk`; `IssuerKey`, `OwnerCommitment`, and `RaLeaf` Poseidon domains; alternate owner D uses an independent issuer key | Both legal owners synthesize with identical constraint count; source mutation rejects; JSON reports `issuer_key_verifier_visible=false` |
| Full relation | Public RA/state leaves resist a low-entropy owner dictionary | Implemented, runner pending | Random 128-bit registration salt in owner commitment and random 128-bit state salt | RA/state positive synthesis and source/state mutation negatives |
| Full relation | Same owner can hold multiple independent root grants | Implemented, runner pending | Fixed-depth private root-grant tree containing A, B, and C | A/B/C membership succeeds under one public state root |
| Lifecycle | Delete A while preserving B and C, without reissuing B | Implemented, runner pending | Successor grant tree replaces A by zero; B proof is regenerated from unchanged DAC credential | A relation rejects, B relation/proof accepts, serialized B DAC signature is byte-identical |
| Policy | 16-bit action, 8-bit depth, attenuation, canonical intervals, not-before/expiry, entitlement and state caps, whole-request coverage | Implemented, runner pending | `FixedPolicyCircuit::generate_constraints` and negative matrix | All named policy/time/range/depth negatives are true |
| Revocation | Every enabled signed 128-bit serial is the accumulator element; disabled padding creates no authority | Implemented, runner pending | Conditional VB nonmembership equations; zero padding serial | Successor accumulator rejects A and leaves independent B usable |
| Depth privacy | Fixed `L_max=2`, private enabled prefix, legal one-level path plus signed no-op padding | Implemented, runner pending | Path C has one enabled root and one disabled self-delegated padding record | Both depth-two path A and depth-one path C satisfy the same relation; padding widening rejects |
| Header binding | Public typed header binds deployment, tuple, RA/state roots, accumulator, epochs, issue time, mapping, policy, and schema | Implemented, runner pending | `compute_header_digest` and matching R1CS Poseidon call | Stale field with unchanged digest rejects |
| Request binding | Two canonical 128-bit digest limbs, service IDs, policy atom, interval/time, nonce/context, terminal logical ID/key, and header digest | Implemented, runner pending | `compute_request_digest` and matching R1CS Poseidon call | Stale nonce or request field with unchanged digest rejects |
| Fixed shape and public input encoding | Groth16 verifier uses exact R1CS allocation order, including projective `(x,y,z=1)` for both public G1 points; legal witness/public variants have identical finalized matrices | Implemented, runner pending | `assert_positive_synthesis` compares the encoder to `instance_assignment[1..]`, then hashes full finalized A/B/C matrices with metadata, row/entry order, column indices, and canonical coefficients | Public-input equality and exact matrix-digest equality hold for A/B, one-level padding C, alternate-owner D, and a legal request variant; one PK proves and verifies all five; public mutations reject |
| Terminal PoP extension | Terminal Schnorr signature binds relation version, full request/header digest, nonce, terminal key, and exact canonical proof bytes | Implemented, runner pending | `service_adapter.rs` | Good signature accepts; changed signature and noncanonical proof bytes reject |
| Header registry extension | Signed headers advance monotonically and cannot be reinstalled | Implemented, runner pending | `DeltaZeroAdapter::install_header` | Repeated or non-increasing tuple is rejected |
| Delta=0 service boundary | Verify current proof at read; atomically recheck header, request, clock, proof-byte ticket, terminal signature, and nonce at commit | Implemented as reusable in-memory adapter, runner pending | `DeltaZeroAdapter::{verify_at_read,commit}` | Old-header ticket, bad signature, and nonce replay reject; successor B commits |
| Poseidon parameters | Native/R1CS use the same BLS12-377 Fq parameters and alpha field guards | Implemented; calculator observes RF=8/RP=55 while frozen source uses RF=8/RP=57 | `POSEIDON_PARAMETERS.md`, source fingerprint, retained calculator output | Machine gate binds recommendation and implemented schedule; no overall security claim |
| Paired semantics | Same canonical raw RA/state/revocation records, logical IDs, policy, request, terminal, and update sequence feed Joint381 and DAC377 encodings | Outstanding artifact | Contract is specified in `ADAPTER_CONTRACT.md` | Versioned paired raw-record manifest with independently recomputed roots and per-update membership outcomes |
| Complete proof | Fresh-`OsRng` circuit setup, same-PK A/B/C/D/request-variant proofs, B successor proof, verification, sizes, and timing | Implemented, deferred until synthesis gate passes | Full `fixed_policy_gate` phase | Retained successful full JSON and raw logs |
| Main service | Reuse adapter in the main service and run matched HTTP/lifecycle timing | Outstanding; owned by runtime integration | Adapter interface is ready; this crate does not modify the main service | Same workload, Delta=0, terminal request and update sequence as Joint; raw request/response and timing evidence |
| Security label | Curve pair is a nominal design target; wrapper adds CRS, circuit soundness, setup and proof cost | Documented | `README.md`, `POSEIDON_PARAMETERS.md`, primary sources ePrint 2020/351 and 2022/1145 | T6 assessment uses actual CRS/circuit and does not claim strict BLS12-381-equivalent 128-bit security |

## Stable runner phases

1. **Compile phase:** format check and locked offline release check.
2. **Relation phase:** run `fixed_policy_gate` with
   `DAC_FIXED_GATE_PHASE=synthesis`; require every positive and negative in its
   JSON. This performs no Groth16 setup or proof generation.
3. **Proof/lifecycle smoke phase:** only after phase 2 passes, run one full gate
   and retain setup/prove/verify, A/B lifecycle, adapter, size, and trust-role
   data. This remains an `n=1` exploratory stage artifact.
4. **Matched experiment phase:** only after phase 3 passes, integrate the
   adapter into the common service workload. Every final timing configuration
   uses at least ten independent fresh setups/trials where setup applies,
   retained paired trial rows, and a 95% bootstrap confidence interval. The
   Joint comparator must be freshly run at the same `L_max=2`, with matched
   actual depth 1 or 2, semantic tree capacities, raw records, request, and
   update sequence. Existing Joint `L_max=3` measurements remain the main E2
   result and are not a paired B2 timing comparator.

`scope_complete` remains `false` until the paired raw-record artifact, pinned
Poseidon calculator evidence, full proof/lifecycle gate, and matched service
experiment all pass.
