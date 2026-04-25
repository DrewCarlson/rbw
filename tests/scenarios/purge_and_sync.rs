use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn purge_clears_cache_sync_refetches() {
    let server = skip_if_no_vaultwarden!();

    let email = "purge@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness
        .run_with_stdin(&["add", "preserved.entry"], b"secret\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add failed");

    let before = harness.check(&["list"]);
    assert!(
        before.lines().any(|l| l.trim() == "preserved.entry"),
        "entry missing pre-purge:\n{before}"
    );

    // purge removes the local cached db and stops the agent.
    assert!(
        harness.run(&["purge"]).status.success(),
        "purge exited nonzero"
    );

    // Log in + sync must repopulate the local cache from the server.
    harness.check(&["login"]);
    harness.check(&["unlock"]);
    harness.check(&["sync"]);

    let after = harness.check(&["list"]);
    assert!(
        after.lines().any(|l| l.trim() == "preserved.entry"),
        "entry not recovered after purge+sync:\n{after}"
    );
}
