use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn get_field_selects_specific_field() {
    let server = skip_if_no_vaultwarden!();

    let email = "field@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Entry with an explicit username so we can fetch `user` via --field.
    let out = harness
        .run_with_stdin(&["add", "field.example", "alice"], b"pw\n\n\n");
    assert!(
        out.status.success(),
        "add failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let got_user = harness
        .check(&["get", "--field", "user", "field.example"])
        .trim_end()
        .to_string();
    assert_eq!(got_user, "alice");

    let got_pw = harness
        .check(&["get", "--field", "password", "field.example"])
        .trim_end()
        .to_string();
    assert_eq!(got_pw, "pw");
}
