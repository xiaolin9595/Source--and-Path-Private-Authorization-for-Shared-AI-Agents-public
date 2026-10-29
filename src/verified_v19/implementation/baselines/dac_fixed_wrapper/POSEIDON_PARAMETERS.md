# DAC wrapper Poseidon parameter manifest

Status: parameters are fixed in the relation source and await the sole benchmark-host
runner's native/R1CS equality and negative gates.  This manifest does not turn
the unfinished RA/state bridge into a complete B2 result.

## Field roles

| Role | Field | Exact modulus | Bit size | Poseidon? |
|---|---|---:|---:|---|
| BW6-761 Groth16 constraint field; record hash | BLS12-377 `Fq` | `258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458177` | 377 | yes |
| Dock SPSEQ/KZG/VB-accumulator scalar field; typed set members | BLS12-377 `Fr` | `8444461749428370424248824938781546531375899335154063827935233455917409239041` | 253 | no |

The record hash is an `Fq` Poseidon sponge inside the `Fq` R1CS.  Typed Dock
members are injective bit encodings in `Fr`; they do not evaluate Poseidon in
`Fr`.  This distinction is required because:

- `Fq mod 5 = 2`, hence `gcd(5, Fq - 1) = 1` and `x -> x^5` is a permutation;
- `Fr mod 5 = 1`, hence `gcd(5, Fr - 1) = 5` and `x -> x^5` is not a
  permutation.

The gate computes both facts from the arkworks modulus limbs and requires the
first to be true and the second to be false.  This prevents a future field
alias from silently reusing the `alpha=5` instance over `Fr`.

## Permutation and constant generation

- profile: `plan-a-dac-record-poseidon-v1`
- security input to round-number selection: `M=128`
- prime field: BLS12-377 `Fq`, 377 bits
- width `t=3`, rate `2`, capacity `1`
- S-box exponent `alpha=5`
- full rounds `R_F=8`
- partial rounds `R_P=57`
- arkworks dependency: `ark-crypto-primitives=0.4`
- constants/MDS constructor: `find_poseidon_ark_and_mds::<Fq>(377, 2, 8, 57, 0)`
- constant generator family: the arkworks 0.4 Grain LFSR constructor, zero
  skipped matrices
- deployed constants: bound by the Blake2s fingerprint emitted by the gate

The pinned authors' calculator was executed for `N=3*377=1131`, `t=3`,
`M=128`, the prime-field case, and `x^5`; it recommends `(R_F,R_P)=(8,55)`.
The frozen implementation uses `(8,57)`, adding two partial rounds. The gate
checks both the observed recommendation and exact schedule markers in the
frozen implementation source. `find_poseidon_ark_and_mds` generates constants
and the MDS matrix; neither that constructor nor this calculator result proves
the constants/MDS construction or end-to-end wrapper security.

Primary sources:

- Grassi et al., *POSEIDON: A New Hash Function for Zero-Knowledge Proof
  Systems*, USENIX Security 2021 / IACR ePrint 2019/458, especially Sections
  2.3 and 5 plus Appendix C: <https://eprint.iacr.org/2019/458>
- Poseidon authors' pinned `calc_round_numbers.py` reference implementation:
  <https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/9d80ec0473ad7cde5a12f3aac46439ad0da68c0a/code/scripts/calc_round_numbers.py>
- arkworks 0.4 source used for native and R1CS Poseidon:
  <https://docs.rs/crate/ark-crypto-primitives/0.4.0/source/src/sponge/poseidon/>

The 128-bit number here is the Poseidon parameter target.  It is not a claim
that the complete heterogeneous BLS12-377/BW6-761 wrapper has a strict
128-bit end-to-end security level; pairing estimates and the additional
Groth16 CRS trust are reported separately.

## Record preimage and lossless parent binding

The fixed preimage is domain separated by relation version, record domain,
field count, and slot index, followed by the complete canonical record:
enabled, issuer, subject, resource, 16-bit actions, interval bounds,
not-before, expiry, 8-bit remaining depth, 128-bit random revocation serial,
the previous digest container, schema version, and policy version.

The `Fq` digest is converted to an exact 384-bit little-endian container:

- `parent_digest_lo = bits 0..191`, stored as three `u64` limbs;
- `parent_digest_hi = bits 192..383`, stored as three `u64` limbs;
- because `Fq` is 377 bits, bits 377..383 are zero.

Both halves are separate 192-bit typed Dock members.  The field tag (8 bits)
and slot tag (16 bits) make each full encoding 216 bits, below the 253-bit
`Fr` modulus, so `Fr::from_le_bytes_mod_order` is injective for this layout.
The circuit recomputes the preceding record's `Fq` digest, expands all 377
bits, appends seven zero bits, and equates all 384 bits to the child record.
No 256-bit truncation or trusted off-circuit mapper is used.
