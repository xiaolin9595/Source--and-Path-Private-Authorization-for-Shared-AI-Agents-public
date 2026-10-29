# B2 candidate source freeze — 2026-10-24

This is the frozen candidate after the v18 synthesis success, the 16-member
record/17-power update-key correction, and the five additional time/cap
negative relations. Further edits are limited to a concrete compiler or gate
failure. A format-only runner copy may change the affected file hash and must
be recorded as a new manifest without overwriting this one.

The v18 retained artifact predates the five additional negatives and therefore
does not validate this exact snapshot. It remains evidence that the fixed-shape
matrix and public-input checks work for A/B/C/D/request variants.

## SHA-256

```text
6f79641acf5a8fbca9d528cc7b6c9f269de9f9a3d90ab374be1097586ae4239b  Cargo.toml
063594a48902ba97a08286f502723ffa6ea68e223ed78388414e0813d459c840  src/lib.rs
1abd68a5b6f3a5328e087e276b6fe11882e17842addcafef2b75252ef830f4e4  src/main.rs
e9a15c8d000439140a9b680cb50bd74e5f75dfe7ac5c6343a71394ac3d2107f5  src/hidden_serial.rs
8ee5f80d3e1582ffff55dca1f817717faba84cdf1f7bf329b70a535bab18f336  src/fixed_policy.rs
f5452e796ffed71d705fc3000b14e9734d7470b3a11a1225e417c2863d46d821  src/service_adapter.rs
1fdc42736a6cb321889cb1ff5b328a23e48beb406f7fc18418b2e87c511029c9  src/bin/hidden_serial_gate.rs
92003162a363a99d870fe2033f507664298d100f04697b67455368e059aa4dc7  src/bin/fixed_policy_gate.rs
```

## Required next evidence

1. Locked release compile of this candidate.
2. Synthesis JSON including the five new boundary negatives and exact matrix
   equality.
3. Only after item 2, a full same-PK A/B/C/D/request proof/lifecycle run.
4. The separate official Poseidon round calculator gate.

`scope_complete` remains false after any single item above.
