# Narrow synthesis witness regularization patch

This directory vendors the frozen `ark-r1cs-std 0.4.0` crate and changes only
five witness-value closure families: `AllocatedFp::is_neq`'s multiplier and the
twisted-Edwards affine add-x/add-y and double-x/double-y denominator inversions.
Constraints, namespaces, allocation order and variable order are unchanged.

Integration from the sibling implementation:

```toml
[patch.crates-io]
ark-r1cs-std = { path = "../synthesis_patch/ark-r1cs-std" }
```

Enable dependency feature `synthesis-patch`. Native behavior remains the
default. Select the public mode for one prover thread with a nestable guard:

```rust
use ark_r1cs_std::synthesis_patch::{enter, Mode};
let _guard = enter(Mode::FixedWitness);
// synthesize on this same thread
```

The guard restores the prior mode on drop and is deliberately `!Send`. Modes
are thread-local, so parallel provers cannot mutate a shared global switch.

The fixed path is restricted to the exact BLS12-381 scalar modulus. It converts
canonical arkworks limbs to/from `bls12_381 0.7.1` `Scalar` little-endian bytes and uses
that crate's reviewed fixed addition-chain `Scalar::invert`, `subtle::Choice`
zero test and conditional selection. Inputs zero, one and general all execute
the inversion chain. Equality selects multiplier one for zero difference;
Edwards inversion makes the zero/error decision only after the chain and still
returns `None`, preserving `DivisionByZero`. Other moduli retain native behavior.

Feature `synthesis-patch-diagnostics` adds thread-local zero/one/general counters
for equality and each Edwards family. Do not enable it in timed binaries.

This regularizes the explicit inversion control flow. It is not a claim that
the entire synthesis pipeline, compiler output, memory hierarchy or all field
arithmetic is constant-time.
