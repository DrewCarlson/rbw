use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn add_list_get() {
    let server = skip_if_no_vaultwarden!();

    let email = "add_list_get@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // `bwx add <name>` reads the new password from stdin when stdin is not a
    // tty. Format matches what `parse_editor` expects: first line password,
    // blank line, notes body.
    let out = harness
        .run_with_stdin(&["add", "example.com"], b"hunter2\n\nnote line 1\n");
    assert!(
        out.status.success(),
        "bwx add failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let listing = harness.check(&["list"]);
    assert!(
        listing.lines().any(|l| l.trim() == "example.com"),
        "expected example.com in listing; got:\n{listing}"
    );

    let got = harness.check(&["get", "example.com"]);
    assert_eq!(
        got.trim_end(),
        "hunter2",
        "expected password 'hunter2', got {got:?}"
    );

    let notes = harness.check(&["get", "--full", "example.com"]);
    assert!(
        notes.contains("note line 1"),
        "expected notes to contain 'note line 1'; got:\n{notes}"
    );
}
