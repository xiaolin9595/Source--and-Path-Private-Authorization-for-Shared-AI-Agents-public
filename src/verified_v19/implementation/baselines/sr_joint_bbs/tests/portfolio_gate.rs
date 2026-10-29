use plan_a_joint_circuit::joint::{grant_digest, snapshot_digest};
use plan_a_sr_joint_bbs::{
    compile,
    portfolio::{
        build, revoke_support, unique_owner_count, unique_signed_path_count, IntervalShape,
    },
};

#[test]
fn duplicate_rows_are_distinct_authorized_sources() {
    let p = build(8, IntervalShape::Duplicate);
    assert_eq!(unique_owner_count(&p.sources), 8);
    assert_eq!(unique_signed_path_count(&p.sources), 8);
    assert!(p
        .sources
        .iter()
        .all(|c| snapshot_digest(&c.snapshot) == snapshot_digest(&p.sources[0].snapshot)));
    let c = compile(&p.sources).unwrap();
    assert_eq!((c.scanned_paths, c.valid_paths, c.invalid_paths), (8, 8, 0));
    assert_eq!(c.exact_duplicates, 7);
    assert_eq!(c.issuance.credentials.len(), 1);
    assert_eq!(c.dependencies.values().next().unwrap().len(), 8);
}

#[test]
fn revoking_widest_contained_support_exposes_next_maximal_support() {
    let p = build(8, IntervalShape::Contained);
    let before_digests = p
        .sources
        .iter()
        .map(|c| grant_digest(&c.grants[0].grant))
        .collect::<Vec<_>>();
    let before = compile(&p.sources).unwrap();
    assert_eq!(before.issuance.credentials.len(), 1);
    assert_eq!(before.issuance.credentials[0].not_before, 100);
    assert_eq!(before.issuance.credentials[0].upper(), 300);
    let successor_sources = revoke_support(&p, 0);
    assert_eq!(
        before_digests,
        successor_sources
            .iter()
            .map(|c| grant_digest(&c.grants[0].grant))
            .collect::<Vec<_>>()
    );
    let successor = compile(&successor_sources).unwrap();
    assert_eq!((successor.valid_paths, successor.invalid_paths), (7, 1));
    assert_eq!(successor.issuance.credentials.len(), 1);
    assert_eq!(successor.issuance.credentials[0].not_before, 101);
    assert_eq!(successor.issuance.credentials[0].upper(), 299);
}

#[test]
fn noncontained_intervals_are_never_convex_hulled() {
    let p = build(32, IntervalShape::Noncontained);
    let c = compile(&p.sources).unwrap();
    assert_eq!(c.issuance.credentials.len(), 32);
    assert_eq!((c.exact_duplicates, c.dominated), (0, 0));
    assert_eq!(c.issuance.credentials.first().unwrap().not_before, 100);
    assert_eq!(c.issuance.credentials.last().unwrap().upper(), 300);
    assert!(!c
        .issuance
        .credentials
        .iter()
        .any(|x| x.not_before <= 100 && x.upper() >= 300));
    let successor = compile(&revoke_support(&p, 0)).unwrap();
    assert_eq!((successor.valid_paths, successor.invalid_paths), (31, 1));
    assert_eq!(successor.issuance.credentials.len(), 31);
}
