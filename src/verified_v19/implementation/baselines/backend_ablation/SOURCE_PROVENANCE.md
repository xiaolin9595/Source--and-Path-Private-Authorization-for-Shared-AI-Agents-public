# Source provenance

The standalone driver is based on
`zk-hrada-m3-backend/src/bin/hrada_poseidon_e2e.rs` from repository base commit
`730fa8780168645222a62b543dda4555deba294b`. The copied file is byte-identical
to that commit at SHA-256
`592e2012cfbe3abcac708cfa73ece26d1571e4590a6e83ec79faea3a9b72199c`.
The repository `LICENSE` applies.

`src/main.rs` retains the original CP membership, Auth Lego, Poseidon
Merkle--Lego, update, witness, and explicit CP component-codec routines. Its E8
entry point adds only the three-repetition orchestration, the Inline Groth16
wrapper, raw artifact retention, byte/timing fields, and targeted mutation
gates. The old copied full-flow entry point remains source-only and is not
called by `main`. Cryptographic primitives, Poseidon constants, Auth
constraints, CP membership, and Lego proof implementations remain in the
`cpsnarks-set` path dependency and were not copied or rewritten.

The current E8 source additionally depends on the uncommitted, review-visible
composition API in
`zk-hrada-m3-backend/src/protocols/hrada_poseidon_baseline.rs`:
`PoseidonMerkleCircuit::synthesize_with_allocated_prime`. The ordinary
`ConstraintSynthesizer` implementation delegates to that method after
allocating its original public prime, preserving the standalone Lego relation's
allocation order and checks. Inline Groth16 instead receives the private
`FpVar` returned by
`AuthCircuit::synthesize_with_prime_visibility(cs, true)` and passes the same
variable to this method.

Ordinary Inline Groth16 is pinned to commit
`681c0f1312cebf96b9664884ec32347a47f489de` from the same repository that was
later forked into LegoGroth16. That commit is the standard `ark-groth16` 0.1.0
implementation and exposes the exact pre-0.2 arkworks types and
`generate_random_parameters` / `create_random_proof` / public-input
`verify_proof` APIs used by the legacy backend. The separate `legogro16`
dependency continues to resolve from the reviewed backend lock at
`4df487bafaf542f0d07d2893aa646bbc4aac42a2`.

Local hashes at static handoff time were:

- `zk-hrada-m3-backend/src/protocols/hrada_auth.rs`:
  `b9c2c0607a212812b7eff5e938c97780a4ac5fe0fd9d51b2e993a952084cac27`
- `zk-hrada-m3-backend/src/protocols/hrada_poseidon_baseline.rs`:
  `ed43511ec7e49b24d4691df8859977ec124f89696d6d8be6f6b372e3dcce0010`
- `backend_ablation/src/main.rs`:
  `623f1a6da398e9f3975cc681ae01c30b5876e94fe92690e335981b97bc9ca5d5`
- `backend_ablation/Cargo.toml`:
  `4ffeb1e51f52fbc201f55bd29e15c16b058ec53e1496120e24da04e8fbeef737`

These hashes identify the static handoff, not a successful build or experiment.
The benchmark-host runner must create before/after manifests that also include the
generated `Cargo.lock`, Git status/diff, toolchain, executable hash, and all raw
CRS/proof/results files. Existing bins and prior raw results are outside this
crate and must remain unchanged.

The complete raw CRS/proving-key set is private retained evidence. Anonymous
artifact assembly exports its hashes, regeneration source/command, VKs and
proofs while excluding the large `cp-parameters.bin` and `*-pk.bin` files.
