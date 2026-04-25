//! `bwx code` only makes sense on entries that have a TOTP secret. On
//! a plain login entry (no TOTP), it should exit non-zero with a
//! legible error, not panic, return an empty string, or leak anything
//! sensitive to stdout.

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn code_on_login_without_totp_fails_cleanly() {
    let server = skip_if_no_vaultwarden!();
    let email = "no-totp@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    harness.run_with_stdin(&["add", "plain.example"], b"secret-pw\n\n\n");

    let out = harness.run(&["code", "plain.example"]);
    assert!(
        !out.status.success(),
        "bwx code unexpectedly succeeded on a non-TOTP entry: stdout={}",
        String::from_utf8_lossy(&out.stdout),
    );
    assert!(
        out.stdout.is_empty(),
        "bwx code emitted data on the failure path: {:?}",
        String::from_utf8_lossy(&out.stdout),
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("totp") || stderr.contains("code"),
        "expected a TOTP-related error message; got: {stderr}"
    );
    // Belt-and-braces: the master password should never land in
    // stderr/stdout even on error.
    assert!(
        !stderr.contains("secret-pw"),
        "error output leaked the stored password: {stderr}"
    );
}
