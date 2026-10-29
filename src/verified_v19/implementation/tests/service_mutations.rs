use ark_bls12_381::Fr;
use plan_a_joint_circuit::indexed_revocation::{
    derive_serial, revoke_by_capability, IndexedRevocationTree,
};

#[test]
fn revocation_requires_matching_capability_preimage() {
    let rk = [42u8; 32];
    let serial = derive_serial(rk, 7).unwrap();
    let mut tree = IndexedRevocationTree::new(32).unwrap();
    assert!(revoke_by_capability(&mut tree, [41u8; 32], 7, serial).is_err());
    let before = tree.root();
    let after = revoke_by_capability(&mut tree, rk, 7, serial).unwrap();
    assert_ne!(before, after);
    assert!(revoke_by_capability(&mut tree, rk, 7, serial).is_err());
    assert!(revoke_by_capability(&mut tree, rk, 8, Fr::from(1u64)).is_err());
}
