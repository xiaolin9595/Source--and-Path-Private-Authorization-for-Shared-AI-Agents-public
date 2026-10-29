# Version-specific point-allocation audit

Scope: `ark-r1cs-std 0.4.0`, `ark-bls12-377 0.4.0`, and this crate's
`RootCredentialCircuit`. This note records a local construction dependency and
does not assert a general upstream vulnerability.

## Exact dependency behavior

In the frozen `ark-r1cs-std-0.4.0` source,
`groups/curves/short_weierstrass/mod.rs`:

* the witness allocator chooses between cofactor clearing and a scalar-order
  route using the two Hamming weights (approximately lines 828--874 in the
  crates.io source);
* the scalar-order route ends with `ge.enforce_equal(&ge)` rather than an
  equality involving the computed multiple (approximately line 881); and
* the separate `enforce_prime_order` method is explicitly unimplemented
  (approximately lines 430--447).

For `ark-bls12-377-0.4.0`, G1's cofactor after removing powers of two has
Hamming weight 16, below the scalar-modulus-minus-one weight 87, so the generic
allocator uses its cofactor-clearing route. G2's cofactor has Hamming weight
197 and is odd, so the local dependency selects the other route. These branch
facts are specific to these source versions and parameters.

## Circuit response

Constants `P1`, `P2`, `sP1`, the issuer verification key, and the
set-commitment SRS are trusted deployment parameters fixed into the wrapper
key. They must be validated as canonical, on-curve, prime-subgroup,
non-identity points before wrapper setup.

Every prover-controlled G1 and G2 pairing point uses this crate's explicit
cofactor-image allocator and is separately constrained non-identity. For each
such point, this crate:

1. allocates the claimed point with an on-curve check;
2. allocates its native cofactor inverse image with an on-curve check;
3. computes the full group cofactor multiplication in the circuit;
4. constrains that result equal to the exact claimed point; and
5. constrains the claimed point non-identity.

The equality in step 4 prevents silent projection of an attacker-supplied
point. The image of full-cofactor multiplication is the prime-order subgroup
for this curve because the group order is `h*r` with coprime `h` and prime
`r`.

## Retained negative allocation gates

The stage-1 binary constructs and synthesizes two separate negative witnesses:

* all prover-controlled signature/commitment/holder points are the identity;
* `Y_tilde` is a sampled on-curve point that fails the native prime-subgroup
  predicate.

Both constraint systems must be unsatisfied, reported as
`identity_witness_rejected=true` and `non_subgroup_g2_rejected=true`. These are
allocation/constraint checks. The normal positive gate still requires a real
Groth16 proof and verification, plus rejection under a mutated public input.

## Remaining composition obligations

This audit covers only points already present in stage 1. Every later
attacker-controlled pairing point added for delegation, accumulator linkage,
Joint admission/state bridges, or padding needs the same explicit inventory.
It does not establish the complete B2 relation, fixed-shape depth privacy, or
binding of hidden DAC messages to Joint RA/state witnesses.

## Version-specific set-SRS boundary observation

Scope: the pinned `delegatable_credentials` checkout at commit
`730fa8780168645222a62b543dda4555deba294b`; the audited
`src/set_commitment.rs` has SHA-256
`2ab12d5c919248160ba1c7afaaf41af4ce86fdad5272a7b7768ef116f5d9ee4b`.
This is a retained construction observation, not a claim about other Dock
versions or a general upstream vulnerability.

The v14 and v17 runners issued a root credential and then delegated a
canonical record set with exactly 16 distinct members. Delegation panicked at
the macro expansion reported as `set_commitment.rs:149` with `range end index
16 out of range for slice of length 16`. The expanded operation is `eval` at
line 95, which takes `powers[0..=set_size]`; a degree-16 characteristic
polynomial therefore needs 17 basis points. The v17 backtrace localizes the
short slice to `Credential::delegate_with_new_attributes` and
`Signature::change_rel`: `sps_eq_uc_sig.rs` line 528 builds the update key from
`srs.P1[0..max_attributes_per_commitment]`, while lines 275--278 evaluate the
16-member set over that slice. Increasing only the outer SRS size therefore
does not enlarge the update-key slice. This call sequence is the retained
minimal reproduction:

1. generate an SRS, then call `Credential::issue_root` with
   `max_attributes_per_commitment=16` and request an update key;
2. call `delegate_with_new_attributes` with a 16-member set; `change_rel`
   evaluates the set over the 16-point update-key slice.

The fixture now defines the signed record width separately as 16 and passes
`max_attributes_per_commitment=17` to both the SRS constructor and every root
issuance. It immediately asserts that both realized SRS vectors have at least
17 points before issuance. Thus the update key contains the 17 powers needed
to delegate a 16-member record. The larger SRS and update keys are still
counted in the artifact; this effective-API workaround does not add a signed
field, relax exact 16-member opening checks, or change trust assumptions.
