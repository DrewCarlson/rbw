use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn edit_then_remove() {
    let server = skip_if_no_vaultwarden!();

    let email = "edit_remove@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let out = harness
        .run_with_stdin(&["add", "login.example"], b"oldpass\n\nold notes\n");
    assert!(out.status.success(), "bwx add failed");

    assert_eq!(
        harness.check(&["get", "login.example"]).trim_end(),
        "oldpass"
    );

    // Edit rewrites the entry through stdin using the same parse_editor grammar.
    let out = harness.run_with_stdin(
        &["edit", "login.example"],
        b"newpass\n\nnew notes\n",
    );
    assert!(
        out.status.success(),
        "bwx edit failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    assert_eq!(
        harness.check(&["get", "login.example"]).trim_end(),
        "newpass"
    );
    let full = harness.check(&["get", "--full", "login.example"]);
    assert!(
        full.contains("new notes"),
        "expected 'new notes' in full output, got:\n{full}"
    );

    // Remove + confirm it's gone.
    let out = harness.run(&["remove", "login.example"]);
    assert!(
        out.status.success(),
        "bwx remove failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let listing = harness.check(&["list"]);
    assert!(
        !listing.lines().any(|l| l.trim() == "login.example"),
        "entry still present after remove; got:\n{listing}"
    );
}
