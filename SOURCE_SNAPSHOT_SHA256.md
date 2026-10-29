# Experimental source snapshot hashes

Deterministic aggregate hashes were computed by hashing every non-AppleDouble,
non-`target` file by relative path and SHA-256, sorting those records bytewise,
then hashing the record stream.

| Source snapshot | Aggregate SHA-256 |
|---|---|
| `blind_update_impl` | `6b71519ac491359d91f75ccad62d9663b8ba1201999873ebd28a5b0d30176bd7` |
| `implementation_r3` | `747722ec6e32f77c00fd7f8d90c06adfcab2733945dd4d00af60b515c6578bce` |

Selected corrected blind-update files:

| File | SHA-256 |
|---|---|
| `service/test_blind_update_service.py` | `b709b5bdfccbba1aa9aa02ce5c4602658f6a565e91fa435c6aa9164b2cc01142` |
| `service/service.py` | `e9cda6231a7e82d6c74470ce95316a3aef9b52b1fb1fe3def91d2cb2b9c8c977` |
| `implementation/src/blind_update.rs` | `c1beb0cd61ba22c7aa428f9671b6b0870a8c065658ad63540b1d0daeb6f480d9` |
