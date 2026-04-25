use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn config_show_set_unset_roundtrip() {
    let server = skip_if_no_vaultwarden!();

    let email = "config@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);

    // `config show` should surface the email we wrote via the harness.
    let shown = harness.check(&["config", "show"]);
    assert!(
        shown.contains(email),
        "config show missing email; got:\n{shown}"
    );
    assert!(
        shown.contains(&server.base_url),
        "config show missing base_url; got:\n{shown}"
    );

    // Set a new email, confirm, unset it, confirm it disappeared.
    let new_email = "rotated@example.test";
    harness.check(&["config", "set", "email", new_email]);
    let shown = harness.check(&["config", "show"]);
    assert!(
        shown.contains(new_email),
        "set email did not stick; got:\n{shown}"
    );

    harness.check(&["config", "unset", "email"]);
    let shown = harness.check(&["config", "show"]);
    assert!(
        !shown.contains(new_email),
        "unset email still shows; got:\n{shown}"
    );
}
