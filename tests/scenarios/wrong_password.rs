use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn unlock_with_wrong_password_fails() {
    let server = skip_if_no_vaultwarden!();

    let email = "wrongpw@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    // Construct the harness with a *different* master password than what was
    // registered. bwx should log in (since login uses the real password via
    // pinentry — we pass the wrong one) and unlock should fail.
    let harness = BwxHarness::new(&server, email, "totally wrong password");

    let out = harness.run(&["login"]);
    assert!(
        !out.status.success(),
        "login with wrong password unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_lowercase().contains("incorrect")
            || stderr.to_lowercase().contains("invalid")
            || stderr.contains("400")
            || stderr.contains("401"),
        "expected an auth-failure error message, got:\n{stderr}"
    );
}
