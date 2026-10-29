# Pre-measurement review of the first implementation

Review status: the initial `joint.rs` is not an accepted authorization relation. The implementation owner has acknowledged the findings and is replacing it with single-allocation typed variables. The initial snapshot may be used to locate compilation errors; no joint-circuit performance or correctness claim may use it.

## Required corrections

1. Runtime request fields and snapshot metadata were allocated as circuit constants. This specializes the proving key to a particular fixture. Allocate public inputs or linked witnesses, and demonstrate multiple requests, sources and active lengths with one setup.
2. Fields hashed into registration/state/grant leaves were independently reallocated for range, signature and attenuation checks. All checks must refer to the same constrained variables. Native fixture values are not constraints connecting those allocations.
3. Parent hashes were absent. Sign and constrain the parent digest for each enabled child, and bind its issuer to the preceding subject using variable equality.
4. Active status and expiry were not fully constrained to the hashed state. Enforce active status, registration expiry, state expiry and every enabled grant's interval coverage on the actual committed variables.
5. Padding points need the Edwards identity coordinates and canonical zero scalar, with constraints covering every disabled field and path. Generic all-zero coordinates do not represent the identity.
6. The application contract uses a terminal signature over the full proof and statement. Implement that check and remove the unintended in-circuit holder secret requirement from the advertised relation.
7. Scheme A places only the root grant in the owner's active grant tree. Lower grants use signed parent links and per-grant revocation; do not require every descendant to be a member of the owner's tree.
8. Indexed revocation must use sparse trees and stable physical indices. Rebuilding a sorted dense tree at depth 32 is not feasible. Value-order adjacency is not physical index adjacency.
9. State updates must validate owner/leaf bindings and one-position-per-owner enrollment, with real authentication and checked version transitions. An unimplemented authenticator trait is not an authenticated service.
10. Signature scalar canonicality needs circuit constraints. Transcript encoding needs exact byte length and a separate terminal-signature domain.

## Re-entry checks

The server gate must include satisfiable positive fixtures, targeted mutations rejected as unsatisfied or failed verification, and a reusable proving key across varying public requests. Fixed-size matrices must be compared across different private witnesses, not only by total constraint count. Tests and measurements run only on benchmark-host.
