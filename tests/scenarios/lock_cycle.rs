use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn lock_then_unlock_again() {
    let server = skip_if_no_vaultwarden!();

    let email = "lock@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Populate one entry so we can verify the vault round-trips across locks.
    let out =
        harness.run_with_stdin(&["add", "before.lock"], b"pre-lock-pw\n\n\n");
    assert!(out.status.success(), "pre-lock add failed");

    // unlocked exits 0 when the agent is unlocked.
    assert!(harness.run(&["unlocked"]).status.success());

    // Lock: the vault should be sealed but the agent keeps running.
    assert!(harness.run(&["lock"]).status.success(), "lock failed");

    // After locking, `unlocked` should now exit nonzero.
    let u = harness.run(&["unlocked"]);
    assert!(
        !u.status.success(),
        "unlocked returned 0 after lock; stderr={}",
        String::from_utf8_lossy(&u.stderr),
    );

    // Re-unlock and verify the pre-existing entry is readable.
    harness.check(&["unlock"]);
    assert_eq!(
        harness.check(&["get", "before.lock"]).trim_end(),
        "pre-lock-pw"
    );
}
