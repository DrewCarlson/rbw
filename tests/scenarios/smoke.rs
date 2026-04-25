use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn register_login_unlock_list() {
    let server = skip_if_no_vaultwarden!();

    let email = "smoke@example.test";
    let password = "correct horse battery staple";

    register_user(&server, email, password)
        .expect("failed to register user against vaultwarden");

    let harness = BwxHarness::new(&server, email, password);

    // `bwx login` — needs the pinentry to answer with the master password.
    let out = harness
        .cmd()
        .arg("login")
        .output()
        .expect("spawn bwx login");
    assert!(
        out.status.success(),
        "bwx login failed: status={:?}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // `bwx unlock` — idempotent after login but we exercise it explicitly.
    let out = harness
        .cmd()
        .arg("unlock")
        .output()
        .expect("spawn bwx unlock");
    assert!(
        out.status.success(),
        "bwx unlock failed: status={:?}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // `bwx list` — should succeed and emit nothing (brand new vault).
    let out = harness.cmd().arg("list").output().expect("spawn bwx list");
    assert!(
        out.status.success(),
        "bwx list failed: status={:?}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.trim().is_empty(),
        "expected empty vault listing, got: {stdout:?}"
    );
}
