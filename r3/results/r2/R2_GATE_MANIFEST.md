# R2 calibration-release gate manifest

Status: gate candidate complete; no calibration or formal R2 sample is included here.

## Frozen design and implementation identities

- `R2_PROTOCOL_FROZEN.md`: `7ca99dc4cdf62478097df0ffca395a30ed73112126b50e163f5356551768d468`
- `implementation/src/bin/r2_loopback.rs`: `6cb6901fd04caf7d419956813af0b1e40ba8abdbaea160912e88c9d1c223a89a`
- `run_r2_session.py`: `820ea3661b0dff165ffcee3466f23f84764622f5b25e4efff39de53f006ae172`
- `run_r2_calibration.sh`: `3a4c134c4a50905db4fcd848875e2a2c4ee688dd2f433d521f9019c8e05df837`
- `run_r2_formal.sh`: `5d227262b257a122012a6302cadbd7c3eb266505dc310dcaab528707cef9269b`
- `run_r2_all.sh`: `4c0fffa9201f31de55134294471a4f76cad6507c5527dd4e696fcecf0ecde219`
- `analyze_r2.py`: `1ddaa5990934fde6157bf061a44377189f0a7524781c5dfff97b5258104a4269`
- `test_analyze_r2.py`: `d2d38efdb9d0fbba26842a4c7ea39f025fb1afcbbefbea3e047bd9f09b369e87`
- `R2_ANALYZER_SCHEMA.md`: `8f45dcb499ca61fee71ceb1f9127c12e66aec6fa3effb62c032748131ef86565`
- Remote release binary: `c6fb4adebca413473c165ef4540a24cc549028f4f8d26d6bbd0775b5cc180d11` (3,059,728 bytes).

The R1 library, relation and fixtures are byte-for-byte identical to the isolated R1 source after excluding only `Cargo.toml`, the new `r2_loopback.rs`, build output and macOS metadata. The production relation remains 187,556 constraints, 24 instance variables and 172,232 witness variables, with frozen matrix digest `4e367d59484693a6d0b33345ae41c377976039b803379c8717751fd64dc67453`.

## Gate evidence

- Three-length same-challenge equality: `gates/WIRE_EQUALITY_GATE.jsonl`, SHA-256 `b897a27f5b50f88ba3e4cdd8f23a89b55f67a4eac3ad2bec23a674ec660f0a7a`. Canonical request, snapshot and public-input bytes were identical; all receiver frames were 2,567 bytes; forbidden experimental metadata was absent.
- Legal alternate presentations rejected against pinned configuration: `gates/PINNED_CONFIG_NEGATIVE_GATE.jsonl`, SHA-256 `855dd3bf0fcfc3ddf76eebf5d19c20a8573ee8a7b764d5faa3c7fe672ee29c68`. Independently valid proof and terminal signature for altered request context, snapshot and circuit-field configuration were all rejected.
- Actual loopback, mutation and forced overflow: receiver evidence SHA-256 `aef0cc3fb5579345e309ec9f6f5003d58b059151f906ba0c8b7fbc6a4d539786`; agent evidence SHA-256 `41a9fbb7f7eacbc79485567339dae492546c4989a31506ce488760dcff87e8c6`. Complete arrival preceded verification; proof/signature passed; replay and challenge/request/snapshot/signature/proof/circuit mutations were rejected; deliberate slow handling produced `k=35`, `overflow=true` and no early send.
- Framing: oversize declaration, truncated body and malformed JSON each terminated the receiver attempt with nonzero status and retained stderr under remote `FRAMING_GATES/`.
- Nine-cell resident-driver integration: `gates/records.jsonl`, SHA-256 `9ea178ea785029ede63699a1f879a880d6df77a2af1706367cbc9f9bce41f67c`; separate nine gates `gates/gates.jsonl`, SHA-256 `e289264c3b36eecca6b7befae833fa0761ac28c893e27c0da5ec48faf310ee53`. All three lengths and `u/pA/pB` were present, all independent challenge/proof/envelope digest pairs matched, all verification flags passed, frame length stayed 2,567, and arrival ordering passed.
- Analyzer: 13/13 fail-closed tests passed, including cardinality, schedules, identities, missing/duplicate/wrong-arm rows, timing order, early release, overflow semantics, independent digest pairs, calibration formula, formal screen, A/A, Wilson and bootstrap behavior. The real nine-row driver gate also passed `validate_gate_rows`.

The R1 fixtures retain their documented synthetic self-delegation pattern; the gate does not reinterpret them as sampled deployment paths. No 600-row calibration or 4,500-row formal R2 collection has started.
