use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::Fr as Scalar;
use plan_a_joint_circuit::{
    signature::{public_key, sign, SecretKey},
    state_registry::*,
};

#[test]
fn cross_owner_deployment_expiry_and_stale_cas_are_rejected() {
    let deployment = Fr::from(500u64);
    let a = SecretKey(Scalar::from(21u64));
    let b = SecretKey(Scalar::from(22u64));
    let apk = public_key(&a).unwrap();
    let bpk = public_key(&b).unwrap();
    let salt = Fr::from(7u64);
    let oa = owner_commitment(apk.0.x, apk.0.y, salt);
    let ob = owner_commitment(bpk.0.x, bpk.0.y, salt);
    let mut registry = StateRegistry::new(deployment);
    let initial = StateLeafOpening {
        grant_root: Fr::from(1u64),
        state_expiry: 90,
        active: true,
        salt: Fr::from(2u64),
    };
    registry.enroll(apk, salt, oa, 7, 100, 8, initial).unwrap();
    let opening = StateLeafOpening {
        grant_root: Fr::from(77u64),
        state_expiry: 100,
        active: true,
        salt: Fr::from(9u64),
    };
    let wrong = OwnerAuthentication {
        signature: sign(
            &b,
            update_digest(deployment, oa, 7, 0, 9, &opening),
            [1; 32],
        )
        .unwrap(),
    };
    assert_eq!(
        registry
            .update(&wrong, oa, 7, 0, 9, opening.clone())
            .unwrap_err(),
        UpdateError::Authentication
    );
    let copied = OwnerAuthentication {
        signature: sign(
            &b,
            update_digest(deployment, ob, 7, 0, 9, &opening),
            [2; 32],
        )
        .unwrap(),
    };
    assert_eq!(
        registry
            .update(&copied, ob, 7, 0, 9, opening.clone())
            .unwrap_err(),
        UpdateError::Ownership
    );
    let over = StateLeafOpening {
        state_expiry: 101,
        ..opening.clone()
    };
    let sig = sign(&a, update_digest(deployment, oa, 7, 0, 9, &over), [3; 32]).unwrap();
    assert_eq!(
        registry
            .update(&OwnerAuthentication { signature: sig }, oa, 7, 0, 9, over)
            .unwrap_err(),
        UpdateError::Expiry
    );
    let sig = sign(
        &a,
        update_digest(deployment, oa, 7, 0, 9, &opening),
        [4; 32],
    )
    .unwrap();
    registry
        .update(
            &OwnerAuthentication { signature: sig },
            oa,
            7,
            0,
            9,
            opening.clone(),
        )
        .unwrap();
    let stale = OwnerAuthentication {
        signature: sign(
            &a,
            update_digest(deployment, oa, 7, 0, 10, &opening),
            [5; 32],
        )
        .unwrap(),
    };
    assert_eq!(
        registry.update(&stale, oa, 7, 0, 10, opening).unwrap_err(),
        UpdateError::Version
    );
}
