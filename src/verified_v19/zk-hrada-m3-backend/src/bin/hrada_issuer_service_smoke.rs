//! Small actual-process lifecycle smoke test, no zero-knowledge setup.
use cpsnarks_set::protocols::{
    hrada_auth::AuthFixture,
    hrada_issuer_service::{serve_child, IssuerCluster},
};
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--issuer-child") {
        if serve_child().is_err() {
            std::process::exit(1);
        }
        return;
    }
    let mut fixture = AuthFixture::new(8001);
    let mut cluster = IssuerCluster::spawn(&fixture).unwrap();
    assert!(cluster.check_live().unwrap().iter().all(|x| *x));
    cluster.sign(0, [9; 32]).unwrap();
    fixture.close_issuers();
    cluster.stop_one(2).unwrap();
    assert_eq!(
        cluster.check_live().unwrap(),
        vec![true, true, false, true, true]
    );
    assert!(cluster.sign(2, [7; 32]).is_err());
    cluster.stop_all().unwrap();
    assert_eq!(cluster.check_live().unwrap(), vec![false; 5]);
    let counts = cluster.counters();
    assert!(counts
        .iter()
        .all(|c| c.process_exit_confirmed && c.offline_io_rejections >= 1));
    assert_eq!(counts[0].protocol_signatures, 1);
    println!("{}", serde_json::to_string_pretty(&counts).unwrap());
    drop(cluster);
    // A second cluster exercises Drop without explicit stop_all.
    let second = IssuerCluster::spawn(&AuthFixture::new(8002)).unwrap();
    let ids = second.counters().iter().map(|c| c.pid).collect::<Vec<_>>();
    drop(second);
    for pid in ids {
        let out = std::process::Command::new("ps")
            .args(&["-p", &pid.to_string(), "-o", "pid="])
            .output()
            .unwrap();
        assert!(!out.status.success() && out.stdout.is_empty());
    }
    println!("PASS real IPC signatures, one/all exits, offline pipe rejection, Drop reaping");
}
