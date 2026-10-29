# DAC-from-EQS + disclosed grant revocation baseline

This is an executable **partial B2 baseline** built on Dock's Apache-2.0 Rust implementation of Mir et al.'s PoPETs 2023 DAC (`delegatable_credentials::msbm`). It does not modify the Plan A core crate.

It implements root issuance, one delegated credential, randomized presentation, Fiat–Shamir request binding, and a dynamic accumulator non-membership check for a grant serial embedded as a signed final-layer attribute. The verifier checks the serial against the current revocation accumulator.

The serial is intentionally disclosed because the available DAC show and accumulator proof APIs do not supply a proof that a hidden signed attribute equals the hidden accumulator non-member. Consequently this baseline leaks the grant serial and actual number of commitment layers. It is a measurable component reference / partial-contract baseline, not a same-leakage implementation and must never be reported as equivalent to Plan A or as a cost lower bound for such an implementation.

`source_revision.txt` records the locally frozen Dock source revision. The runner should execute only on `benchmark-host`:

```text
cargo run --release -- --trials 30
```

Expected output is CSV on stdout. Required negative cases run before measurements: request mutation, revoked serial, wrong serial, and an old non-membership witness after revocation must all reject.

