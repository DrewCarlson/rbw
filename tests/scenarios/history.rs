use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn edit_writes_history_entry() {
    let server = skip_if_no_vaultwarden!();

    let email = "history@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let out = harness.run_with_stdin(&["add", "rotate.me"], b"pw-v1\n\n\n");
    assert!(out.status.success(), "initial add failed");

    let out = harness.run_with_stdin(&["edit", "rotate.me"], b"pw-v2\n\n\n");
    assert!(out.status.success(), "edit failed");

    // history prints `<timestamp>: <previous password>` per entry.
    let hist = harness.check(&["history", "rotate.me"]);
    assert!(
        hist.lines().any(|l| l.trim_end().ends_with(": pw-v1")),
        "expected pw-v1 in history; got:\n{hist}"
    );
    // Current value should not appear in the history output.
    assert!(
        !hist.contains("pw-v2"),
        "current password leaked into history output; got:\n{hist}"
    );
}
