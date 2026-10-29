# E8 current-Joint two-backend gate request

## Scope

This independent crate compares the retained native 23-field
`JointCircuit<3>` with a current-stack LegoGroth16 composition whose union is
the full logical Joint relation. The split relation keeps RA membership,
typed state derivation, root-grant membership, grant signatures, policy,
indexed revocation, complete request binding, fixed padding and terminal
equality in `JointCoreCircuit`; a second circuit proves Poseidon state-tree
membership. Both Lego proofs commit to their first two witnesses in the exact
order `(state_leaf, position)`. They use the same link generators and link
blinding, and verification requires equal external link commitments plus both
internal CP-link proofs.

The native proof remains the retained relation reference. The split backend is
an independently named composition backend. This gate does not contain the
CP/RSA backend or the planned common certified-state-map augmented relation,
and no output may be substituted for the retained 179,708 native-Joint count.

The crate also contains a separately tested certified-map service primitive.
Its message-level certificates bind deployment, owner, state leaf, position,
generation, an exact 252-bit prime and mapping version. The service never
reuses a prime and rejects nonadvancing replacements and retired-generation
replay. Generation identity is the full
`(deployment,owner,position,state_version,state_epoch)` tuple. The issuer
derives odd exact-252-bit candidates from domain-separated SHA-256 and checks
each with small-prime division plus 64 strong Miller--Rabin rounds; native
verification repeats that test. The stated composite false-accept bound is
`4^-64 = 2^-128` for each fixed odd composite and independent uniform bases;
treating SHA-256-derived bases as such requires a random-oracle model, while
adaptive candidates and repeated issuance incur union loss. The circuit's
252-bit range check is not called a primality proof. This source is scaffolding for the later augmented three-backend
relation. It is excluded from the two-backend timings and does not claim that
the CP adapter or full augmented circuit is complete.

## Fail-closed checks

- both circuits are satisfied for one canonical fixture;
- one CRS per backend accepts enabled lengths 1, 2 and 3;
- all 23 public Joint fields are mutation-tested for both backends;
- the split membership root is mutation-tested, and the composition verifier
  rejects unequal core and membership state-root inputs before proof checks;
- mixing core and membership proofs from different presentations is rejected
  before cryptographic verification because their hidden-state commitments
  differ;
- raw CRS and proof artifacts, relation metrics and component/total timings
  are retained per repetition.
- certified-map tests reject a correctly ranged composite, distinguish the
  complete generation key, confirm old-prime removal and successor admission
  before replacement commits, preserve the old live mapping when that gate
  fails, and reject any retired-prime reuse.

The initial gate uses three fresh setups for bring-up. It is not
publication-grade scaling. A later retained run may raise the count after the
correctness gate passes.

## Server-only command

Run only through the coordinated benchmark-host runner and global experiment lock:

```sh
cd ${REMOTE_DATA}/pets2027/M3-min/work/plan_a_2026_10_23/implementation/baselines/joint_backend_matched
bash run_on_benchmark-host.sh
```

Do not compile or execute on another host. Preserve failed output directories.
