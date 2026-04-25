//! `bwx config set` must reject values that its key-specific parser
//! can't handle, instead of silently coercing them to a default or a
//! nonsensical state. Covers the two most security-relevant keys:
//! `touchid_gate` (controls whether biometric prompts appear at all)
//! and `ssh_confirm_sign` (controls the SSH-sign confirm dialog).

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn bad_touchid_gate_and_bool_rejected() {
    let server = skip_if_no_vaultwarden!();
    let email = "bad-config@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);

    // --- unknown `touchid_gate` value ---
    let out = harness.run(&["config", "set", "touchid_gate", "maybe"]);
    assert!(
        !out.status.success(),
        "bad touchid_gate accepted; stdout={}",
        String::from_utf8_lossy(&out.stdout),
    );
    // Config value shouldn't have changed.
    let gate_after = harness.check(&["config", "show", "touchid_gate"]);
    assert_eq!(gate_after.trim(), "off");

    // --- non-bool `ssh_confirm_sign` ---
    let out =
        harness.run(&["config", "set", "ssh_confirm_sign", "yes-please"]);
    assert!(
        !out.status.success(),
        "bad ssh_confirm_sign accepted; stdout={}",
        String::from_utf8_lossy(&out.stdout),
    );
    let cfg_show = harness.check(&["config", "show"]);
    assert!(
        !cfg_show.contains("yes-please"),
        "bogus ssh_confirm_sign value leaked into config:\n{cfg_show}"
    );

    // --- unknown key ---
    let out = harness.run(&["config", "set", "no_such_key", "anything"]);
    assert!(
        !out.status.success(),
        "unknown config key accepted; stdout={}",
        String::from_utf8_lossy(&out.stdout),
    );
}
