# Mir-DAC + fixed-shape ZK wrapper

This independent crate is the implementation path for a same-functionality,
same-verifier-view B2 comparator.  It changes the Dock Mir-DAC instantiation
from BLS12-381 to BLS12-377 and wraps it in Groth16 over BW6-761 so that the
lower pairing equations are native to the wrapper constraint field. The pair
has a nominal 128-bit generic-security design target. This is not a claim of a
strict 128-bit lower bound or equivalence to BLS12-381. El Housni and Guillevic
report at least 126 bits for BW6-761 in their analyzed proof-composition use,
while their auxiliary-input estimates for BLS12-377 fall to about 113--116 bits
for the two cited large setups. A separate rough finite-field estimate reports
122 bits for BLS12-377 and 123 bits for BW6-761. The final circuit-specific CRS
size must therefore be included in the security assessment before T6 can pass.
Primary sources: [ePrint 2020/351](https://eprint.iacr.org/2020/351) and
[ePrint 2022/1145](https://eprint.iacr.org/2022/1145).

The curve change and wrapper are public comparison differences.  The wrapper
adds a circuit-specific trusted setup, much larger prover work, and new circuit
soundness/composition obligations.  Results must be named **Mir-DAC +
fixed-shape ZK wrapper** and must not be described as native DAC performance.

## Implemented stage gate

`mir_dac_root_signature_and_singleton_commitment_v1` uses Dock to issue a real
SPSEQ-UC root credential on a singleton attribute set, verifies it natively,
and proves in the wrapper circuit:

1. the KZG singleton commitment opens to the public bounded business
   attribute;
2. both Mercurial signature pairing-product equations hold; and
3. the SPSEQ-UC holder-key binding equation holds.

All private G1/G2 signature points are constrained to the correct prime-order
subgroup and to be non-identity. In particular, the circuit does not rely on
ark-r1cs-std 0.4's local BLS12-377 G2 witness allocation branch: it allocates
both the claimed on-curve point and a cofactor preimage, computes the full
cofactor multiple, and requires exact equality to the claimed point. Retained
all-identity and sampled on-curve non-subgroup witness gates must reject. This
is a version-specific construction audit; it does not claim a general upstream
vulnerability.

The issuer public key and set-commitment SRS are fixed into the wrapper proving
and verifying keys.  The business attribute is a public input.  The credential
commitment, opening, signature, and holder public key stay private.  A retained
negative gate verifies that changing the public attribute rejects the proof.

This stage is not the complete B2 gate.  `scope_complete=false` is emitted on
purpose.  It does not yet prove delegation, fixed `L_max`, policy attenuation,
expiry/range predicates, per-grant non-revocation, terminal/full-request/header
binding, or the Joint service commit contract.

The stage-1 binary uses a fixed `StdRng` seed only for a reproducible smoke
test. Its SRS trapdoor and Groth16 setup are therefore not deployment-safe and
its timings are not a final comparison row. `fixed_policy_gate` uses fresh
`OsRng`, reports public/proving/verifying parameter byte sizes and public
parameter digests, and separately accounts for the DAC issuer, SRS ceremony,
accumulator manager, and Groth16 ceremony roles.

## Hidden serial linkage gate

`hidden_serial_gate` constructs a real randomized Mir-DAC credential show with
no disclosed attributes and a dynamic VB accumulator non-membership proof. A
KZG singleton-subset proof shows that an undisclosed scalar belongs to the
signed randomized commitment. Its Schnorr response for that scalar is reused
as the omitted element response of the non-membership proof. The joint
Fiat--Shamir transcript binds the signed commitment, accumulator value and a
domain-separated public service context.

The retained negative gates reject a different set commitment, a mutated
public context, and the successor accumulator after adding the hidden serial.
The show still exposes the number of DAC commitments, and the context in this
binary is only a fixed test encoding rather than the complete Joint header and
request relation. It therefore emits `scope_complete=false` and cannot replace
the fixed-shape wrapper.

## Full relation and adapter implementation

`fixed_policy_gate` is the executable relation and lifecycle gate. For fixed
`L_max=2` it creates real two-level Dock credentials A and B plus a one-level
credential C with a signed no-op padding slot. It proves the fixed-size
SPSEQ-UC signature, proves an exact chained
KZG opening to all 16 domain-separated typed fields in each hidden set,
enforces issuer/subject and native-Fq Poseidon parent-record-digest links,
16-bit action, range/time, and 8-bit depth attenuation, terminal and
whole-request coverage, and checks the same private
128-bit serial in a VB accumulator non-membership equation. The public
terminal key is explicitly constrained to the prime-order subgroup and is the
key bound by the final credential signature. A successor accumulator and a
mutated request must reject the retained proof. Separate allocation-level
negatives cover a mutated hidden field, a non-prefix enabled pattern, an
invalid depth decrement, and noncanonical `not_before > expiry`.

For each canonical member the circuit verifies the next KZG quotient, then
requires the quotient after all 16 members to equal the proved commitment
opening scalar times `P1`. This rules out duplicate tags and extra members
without a non-native characteristic-polynomial computation or an honest-issuer
premise. Parent links use a versioned Poseidon digest of the complete previous
record, split into two 192-bit typed limbs; random revocation serials stay
independent and delegation does not require an online global serial registry.
The parent digest uses a versioned Poseidon instance over BLS12-377 `Fq`; the
gate emits the parameter fingerprint. Primary primitive source:
[Poseidon](https://eprint.iacr.org/2019/458).

The relation now authenticates salted private-source RA/state Poseidon paths,
a fixed-depth private tree of independent root grants, the complete typed
header/request digest, and a custom Schnorr terminal proof-of-possession over
the exact canonical Groth16 proof bytes. The reusable in-memory adapter
performs monotonic signed-header installation and a Delta=0 atomic nonce
commit. These are deployment extensions around Mir-DAC and add their own keys,
checks, and costs; they are not native DAC features.

`service_wire` exports the exact verifier-visible statement, proof, verifying
key, signed header and terminal signature as canonical compressed bytes for a
runtime-owned adapter. `fixed_policy_adapter_cli` is a synthetic JSON/stdin
gate for that envelope. The service must independently derive the expected
request/terminal/policy values before comparison and must retain one
`DeltaZeroAdapter` across calls so nonce replay state survives. The precise
field and negative-test contract is in `SERVICE_WIRE_CONTRACT.md`.

The gate still emits `scope_complete=false`. Runner validation, the paired
raw-record mapping artifact, the pinned official Poseidon calculator output,
and main-service matched workload evidence remain outstanding. Exact status is
tracked in `B2_COMPLETION_MATRIX.md`.

For compile-time `L_max`, the final wrapper proves knowledge of a Dock DAC
credential chain and private per-level data such that:

* every one of the `L_max` slots verifies the SPSEQ-UC update/signature
  relation; unused suffix slots are legal holder-generated padding whose
  enabled bit is monotone and whose attributes cannot add authority;
* every enabled level binds one typed grant record containing issuer/subject,
  parent digest, resource, action mask, interval, `not_before`, expiry,
  remaining depth, and a uniformly random grant serial;
* issuer/subject and parent links hold, resource is equal, action masks and
  intervals attenuate, depth decrements, and time/range values are canonical;
* every enabled grant serial has a privacy-preserving non-membership proof
  under the revocation accumulator committed by the exact accepted header;
* the final enabled subject equals the public terminal, one public action is
  selected, one effective interval covers the whole public request interval,
  and the complete canonical request plus terminal signature is bound;
* the exact deployment/schema, DAC-side RA/state/revocation roots, epochs and
  policy version equal the accepted atomic header. The wrapper verifies typed
  BLS12-377-native Poseidon leaves and paths. Comparison to Joint uses the same
  canonical raw records, logical identities, policy, request, terminal and
  update sequence with separately versioned native encodings and roots;
  retained paired inputs/mappings are audit evidence, not a trusted mapper or
  a substitute for the authenticated-state relation.

The wrapper exposes only the same logical terminal, request atom and interval,
accepted header, and decision required by the Joint verifier view.  Source,
support identity, actual depth, grant serials, per-level policy values and
padding position remain private.  Issuance/delegation traffic and timing remain
part of the auxiliary view and require separate measurement.

## Runner-only command

Compilation and execution are restricted to `benchmark-host` by the experiment
coordination policy:

```text
cargo run --release --bin plan-a-dac-fixed-wrapper
cargo run --release --bin hidden_serial_gate
DAC_FIXED_GATE_PHASE=synthesis cargo run --release --bin fixed_policy_gate
# only after the synthesis/negative matrix passes:
cargo run --release --bin fixed_policy_gate
```

The required first-stage gate is `accepted=true`,
`mutated_public_attribute_rejected=true`, `identity_witness_rejected=true`,
`non_subgroup_g2_rejected=true`, and `scope_complete=false`. The reported
128-bit field is explicitly a nominal generic target rather than an achieved
circuit-specific security estimate.

