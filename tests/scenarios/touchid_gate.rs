//! Exercise the Touch ID gate without actually prompting the user.
//!
//! In debug builds (everything cargo-test produces), `bwx::touchid`
//! honours `BWX_TOUCHID_TEST_BYPASS=allow|deny` and skips the real
//! `LAContext` FFI, treating the env value as a synthetic user
//! response. That lets us lock in the gate semantics in CI without
//! Touch ID hardware.
//!
//! macOS only. On Linux the gate is a compile-time no-op so there's
//! nothing to assert.

#![cfg(target_os = "macos")]

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_off_skips_touchid() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_off@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Add an entry we can `get` later.
    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");

    // touchid_gate is "off" by default. Even with bypass=deny — which
    // would block any consulted prompt — the get must succeed, proving
    // the gate path wasn't consulted at all.
    let out = harness
        .cmd()
        .env("BWX_TOUCHID_TEST_BYPASS", "deny")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "get failed with gate=off: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end(), "pw");
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_all_bypass_allow_succeeds() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_allow@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");

    // Flip gate on. The bypass env has to be set on the *agent*
    // because the gate runs there; easiest way is to stop the agent
    // and let the next CLI invocation — which inherits our env —
    // respawn it.
    harness.check(&["config", "set", "touchid_gate", "all"]);

    let out = harness
        .cmd()
        .env("BWX_TOUCHID_TEST_BYPASS", "allow")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "bypass=allow rejected get: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim_end(), "pw");
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_all_bypass_deny_blocks() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_deny@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");
    harness.check(&["config", "set", "touchid_gate", "all"]);

    let out = harness
        .cmd()
        .env("BWX_TOUCHID_TEST_BYPASS", "deny")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        !out.status.success(),
        "bypass=deny unexpectedly allowed get"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("denied") || stderr.contains("Touch ID"),
        "expected a denial error message, got:\n{stderr}"
    );
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn gate_signing_spares_vault_reads() {
    let server = skip_if_no_vaultwarden!();
    let email = "tid_sign@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness
        .run_with_stdin(&["add", "e1"], b"pw\n\n\n")
        .status
        .success()
        .then_some(())
        .expect("add");
    harness.check(&["config", "set", "touchid_gate", "signing"]);

    // gate=signing means VaultSecret operations bypass the gate entirely.
    // With bypass=deny, get must still succeed (gate not consulted) —
    // proving Gate::Signing excludes VaultSecret.
    let out = harness
        .cmd()
        .env("BWX_TOUCHID_TEST_BYPASS", "deny")
        .args(["get", "e1"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "gate=signing blocked a vault read: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
}
