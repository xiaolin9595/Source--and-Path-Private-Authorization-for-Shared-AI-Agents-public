# Synthesis witness patch implementation report

## Scope

The local crate is a complete vendor copy of frozen `ark-r1cs-std 0.4.0`.
The functional diff is restricted to an exported mode module and the five
requested witness-value closure families. No constraint expression, namespace,
allocation call, or variable ordering was changed.

`Mode::Native` is default. `enter(Mode::FixedWitness)` is a thread-local,
nestable RAII guard and is deliberately not transferable between threads.
The four-arm driver can therefore choose its public mode per synthesis call
without mutable process-global state.

## Primitive and semantics

For the exact BLS12-381 scalar modulus, the patch converts canonical arkworks
little-endian limbs to `bls12_381 0.7.1::Scalar`, executes its fixed
addition-chain `invert` for zero, one and general inputs alike, then converts
back. The same `0.7.1` version is used by the MSM candidate. Equality uses
`subtle` conditional selection to restore zero-difference multiplier `1`.
Edwards denominator zero is decided only after the inversion chain and remains
`None`, so the existing closure still yields `DivisionByZero`. Other moduli use
the original native behavior.

This is fixed-schedule inversion control flow, not a claim that all synthesis
or compiled field arithmetic is constant-time.

## Diagnostics and verification

`synthesis-patch-diagnostics` adds thread-local zero/one/general counters for
equality and add-x/add-y/double-x/double-y. The timed binary must not enable it.

Local commands using Rust 1.95.0:

```text
cargo +1.85.1 check --features synthesis-patch --lib
cargo +1.85.1 test --features synthesis-patch synthesis_patch::tests
cargo +1.85.1 test --features synthesis-patch-diagnostics synthesis_patch::tests
```

Results: compile check passed; native/fixed guard, zero/one/general semantics,
non-target-modulus fallback, nested restoration and diagnostic counter tests
passed (3/3 normal, 4/4 diagnostic). Three pre-existing redundant `borrow()`
calls flagged by the remote Rust 1.85.1 `noop_method_call` lint were mechanically
removed at the compiler-suggested locations (short-Weierstrass line family 841;
twisted-Edwards line families 340 and 626). This compatibility edit changes no
value, relation or allocation behavior and allows `deny(warnings)` without a
lint suppression.

Full Joint assignment/matrix, extreme witnesses, zero-error semantics and
exact-r,s proof equivalence remain integration gates owned by the execution
driver and must pass before any timing.
