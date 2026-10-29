# DAC wrapper adapter and verification contract

Status: executable relation and reusable in-memory adapter implemented, with
runner validation and matched service integration pending. See
`B2_COMPLETION_MATRIX.md` for the evidence boundary of every obligation.

## Deployment parameters

The following tuple is immutable for one wrapper proving/verifying key:

```text
WrapperParams = (
  relation_version, L_max,
  DAC curve and SPSEQ-UC issuer verification key,
  set-commitment SRS,
  revocation-accumulator parameters and verification key,
  DAC-side BLS12-377-base-field Poseidon parameter identifiers,
  paired-record mapping/schema identifiers,
  canonical grant/request/header encodings,
  Groth16 wrapper curve and verification key
)
```

The implementation route uses BLS12-377 for Mir-DAC and BW6-761 for the
Groth16 wrapper.  This makes the lower pairing base field the wrapper scalar
field. The DAC comparator builds its authenticated RA and state roots with a
separately versioned Poseidon instance over the BLS12-377 base field. It does
not reproduce the Joint prototype's BLS12-381 root bytes inside this wrapper.

Comparison uses paired semantic roots: both backends ingest the same canonical
raw RA/state/revocation records, policy and schema version, request, terminal,
and ordered update sequence, while each backend deterministically builds its
own native authenticated encoding. The artifact retains the paired raw input,
mapping versions, domain tags, per-update roots, and independently recomputed
membership outcomes. A canonical audit digest identifies the paired raw input;
it is not a trusted mapping oracle and does not replace typed in-circuit leaf
fields or Merkle paths. Logical identities map to separately authenticated
backend keys, with that mapping treated as part of RA/state soundness.

The set-commitment trapdoor and accumulator manager secret must be generated
under a declared ceremony/manager model.  The Groth16 wrapper adds a separate
circuit-specific CRS.  No result may reuse Joint's setup time or security
statement for these parameters.

## Public verifier statement

```text
DacWrapperStatement = {
  deployment_id,
  relation_version,
  terminal,
  resource,
  one_hot_action,
  request_lo,
  request_hi,
  canonical_request_digest,
  terminal_signature,
  header: {
    ra_root,
    state_root,
    revocation_root_or_accumulator,
    ra_epoch,
    state_epoch,
    revocation_epoch,
    policy_version,
    schema_version
  }
}
```

The service reconstructs the canonical request and statement independently.
The proof bytes do not supply authoritative request fields.  A compact version
is accepted only if trusted service configuration maps it uniquely to every
field above.

## Private witness

```text
DacWrapperWitness = {
  fixed_slots[L_max],
  DAC credential/signature/openings/final holder key,
  RA and state leaves plus Merkle authentication paths,
  root-grant ownership/signature material and its digest,
  per-enabled-slot typed DAC grant fields,
  per-enabled-slot revocation serial and fresh non-membership witness,
  enabled prefix bits and padding material
}
```

Every `fixed_slots[i]` commits a typed record, not an unordered bag with
ambiguous field roles.  Each scalar is domain-separated by field name and slot
index before entering the set commitment, or its exact typed encoding is
proved in the wrapper.  Duplicate encodings and cross-field substitution are
rejected.

## Circuit predicate

The complete circuit accepts exactly when all conditions hold:

1. `enabled[0]=1`; enabled bits form a prefix; disabled slots form a suffix.
2. The fixed-size SPSEQ-UC credential verifies for all `L_max` commitments and
   the final holder key.  Every commitment opens to the typed private record
   used by the remaining checks.
3. The RA leaf and active state leaf authenticate under the exact public
   DAC-side BLS12-377-native Poseidon roots. The typed leaves include the
   paired-record mapping/schema identifiers and authenticated logical identity
   to DAC-key mapping. The state leaf epoch is at most the public state epoch,
   and the admitted owner controls the root grant bound by the state.
4. The first DAC record contains the same root-grant digest authenticated by
   the Joint state leaf.  For every enabled downstream slot, authorized
   SPSEQ-UC extension plus issuer/subject link, parent digest, common resource,
   action-mask attenuation, interval containment, `not_before`, expiry,
   remaining-depth decrement, and canonical encoding are valid.  The first
   slot links to the admitted owner/root grant; the DAC update relation is the
   downstream delegation authenticator rather than a redundant second grant
   signature scheme.
5. Every enabled slot's signed serial is the same hidden scalar consumed by a
   non-membership proof under the revocation value and epoch committed by the
   public header.  Disabled slots use a distinguished padding serial and do
   not create authority.
6. Padding is a legal no-op continuation: issuer equals subject equals the
   preceding subject, parent digest continues canonically, resource/action and
   effective interval do not widen, and the padding marker is signed/committed.
7. The last enabled subject, equivalently the padded final holder, equals the
   public terminal.  One enabled path authorizes the public one-hot action and
   one effective closed interval covers the entire public
   `[request_lo,request_hi]`.
8. The complete canonical request digest and terminal signature verify, and
   every header field equals the values used by admission, state, revocation,
   policy, and schema checks.

Disabled padding does not require a live revocation entry and cannot be chosen
as the authority-bearing terminal.  The circuit shape, proof size, and verifier
work are independent of the enabled prefix length.  Prover timing still needs
an E5-style measurement and mitigation claim before it can be called
length-hiding against an observing prover host.

## Service adapter

```text
prepare(statement, witness) -> wrapper_proof
verify_at_read(statement, wrapper_proof, accepted_header_history, now) -> ticket
commit(ticket, canonical_request, terminal_signature, nonce) -> resource_result
```

`verify_at_read` checks the complete statement and proof against the current
monotonic header, requires the caller's proof bytes to equal the canonical
serialization of the proof object, and verifies the terminal signature over
those exact bytes. `commit` re-reads the trusted clock and current header
inside the nonce/resource transaction, rechecks request expiry, proof-byte
ticket and terminal signature, and consumes the nonce atomically with the
effect.

The first matched comparison uses `Delta=0`: any retired header rejects.  This
must match the Joint gate before measuring request cost.  A later positive
`Delta` uses the same inclusive retirement boundary as Joint and is reported
separately.

## Revocation lifecycle gate

The retained fixture contains at least two independent paths for the same
terminal/atom.  Revoke one intermediate grant serial and install the successor
header/accumulator.  Required observations are:

1. every proof/witness dependent on the revoked grant rejects under the
   successor header;
2. an independently supported path continues to produce and verify a proof;
3. original DAC credentials/grant signatures on the independent path remain
   byte-for-byte unchanged;
4. old-header proofs reject immediately at `Delta=0` without consuming the
   request nonce;
5. request/header/terminal mutations reject; and
6. measured refresh accounting includes accumulator update, witness refresh,
   path selection, proof generation/delivery, and service commit work.

## Trust and cost labels

The B2 row reports Dock DAC issuance/delegation, accumulator update and witness
refresh, wrapper setup/prove/verify, proof/key sizes, delivery, and service
commit costs separately.  The wrapper CRS and accumulator manager are added
trust assumptions.  The root issuer is a DAC trust anchor; it is not permitted
to accept unauthenticated state or compile arbitrary effective authority. The
paired semantic comparison permits different curve, hash, key and root bytes;
these are public implementation differences and never relax source/depth/serial
privacy or revocation behavior.

The verifier-visible privacy target hides source identity, support identity,
actual enabled depth, per-grant serials, and per-level private policy values.
The model still exposes public terminal/request/header/decision and includes
issuance, delegation, update timing, resolver/manager interaction, and prover
timing in the auxiliary view when those observers are in scope.

