use crate::common::{register_user, RbwHarness, VaultwardenServer};

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn register_login_unlock_list() {
    let server = match VaultwardenServer::start() {
        Some(s) => s,
        None => {
            eprintln!(
                "skipping: vaultwarden binary not found. \
                 Install it or set VAULTWARDEN_BIN. \
                 See tests/e2e.rs for instructions."
            );
            return;
        }
    };

    let email = "smoke@example.test";
    let password = "correct horse battery staple";

    register_user(&server, email, password)
        .expect("failed to register user against vaultwarden");

    let harness = RbwHarness::new(&server, email, password);

    // `rbw login` — needs the pinentry to answer with the master password.
    let out = harness.cmd().arg("login").output().expect("spawn rbw login");
    assert!(
        out.status.success(),
        "rbw login failed: status={:?}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // `rbw unlock` — idempotent after login but we exercise it explicitly.
    let out = harness.cmd().arg("unlock").output().expect("spawn rbw unlock");
    assert!(
        out.status.success(),
        "rbw unlock failed: status={:?}\nstdout={}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    // `rbw list` — should succeed and emit nothing (brand new vault).
    let out = harness.cmd().arg("list").output().expect("spawn rbw list");
    assert!(
        out.status.success(),
        "rbw list failed: status={:?}\nstdout={}\nstderr={}",
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
