# Poseidon-Merkle parameter provenance and relation

This module implements the original Poseidon permutation, not Poseidon2, over
BLS12-381 Fr (modulus
`0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`).
It uses width 3, exponent 5, 8 full rounds split 4+4, and 57 partial rounds on
state word 0. The MDS multiplies a column vector, with no transpose.

The primary source is the authors' [Sage reference instance](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/raw/master/code/poseidonperm_x5_255_3.sage),
retrieved 2026-09-08 and preserved byte-for-byte as
`hrada_poseidon_reference.sage`. This source declares `M=128`, `n=255`, `t=3`,
`R_F=8`, `R_P=57`, the exact field, 195 round constants and the 3x3 MDS.
See also [Poseidon, USENIX Security 2021, Table 2](https://www.usenix.org/system/files/sec21-grassi.pdf).
The mutable upstream URL is anchored by the committed file SHA-256; the module
also binds Blake2s of all constants encoded canonically as little-endian 32-byte
field elements, in round-constant then row-major MDS order. Both hashes are in
`hrada_poseidon_parameters.rs` and its runtime descriptor.

`hrada_poseidon_reference_check.py` independently evaluates the author Sage
round function using Python integer modular arithmetic. Its output for
`[0,1,2]` is preserved in `hrada_poseidon_reference_output.json`, and compared
against the native Rust permutation. This is a vector independently evaluated
from the author reference, **not an author-published literal known-answer test**.
Native Rust and R1CS outputs are tested for agreement. The locked arkworks 0.1
Poseidon helper cannot supply this instance: its setup returns empty constants
and its hash helper assumes width 6. Hence the small implementation here uses
existing locked field and R1CS APIs, without adding another arkworks version.

The application uses fixed-length domain-separated compression:
`H(tag,a,b)=PoseidonPermutation([tag,a,b])[0]`. This is a fixed 2-to-1 field
compression convention, not an arbitrary-length sponge API. Occupied leaves
are `H(145,index,prime)`, empty leaves are `H(146,0,0)`, and internal nodes are
`H(147,left,right)`. A root is the canonical scalar encoded LE32, exposed as
its low and high 128-bit limbs. The circuit canonically decomposes the computed
root and enforces each limb separately, rejecting `root+Fr_modulus` aliases.
The hidden prime must be exactly 252 bits. SR checks probable primality before
insertion; primality and state freshness are not claims of this circuit.

The public instance order remains `[1, prime, root_low128, root_high128]`;
the link layer hides the prime using the existing commitment. A setup fixes
its depth to one of 4/8/12/16/20. The parameter descriptor specifies the complete
hash semantics and provenance; the caller should append the configured depth
when binding metadata (depth is also bound by the concrete R1CS/VK).

Occupied leaf indices are stable, and the same private index bits both enter
the leaf hash and choose sibling ordering. Empty leaves no longer include their
index, allowing default-subtree sharing. The state uses a sparse map of occupied
nodes and default nodes per level; initial construction uses O(N*depth) hashes,
replacement O(depth) hashes plus linear duplicate detection, and path extraction
O(depth) map lookups. Therefore update/construction differences against the old
dense Blake2s baseline combine **hash changes and sparse/incremental data
structure changes**. Do not attribute that entire speedup to Poseidon alone.

The source's M=128 parameter selection is not a new cryptanalysis or a security
certification. A one-field-element digest over this 255-bit field has generic
collision work around 127 bits; the full protocol retains its existing weaker
components and assumptions. This baseline adds the stated Poseidon collision
resistance assumption rather than claiming greater security than Blake2s.
