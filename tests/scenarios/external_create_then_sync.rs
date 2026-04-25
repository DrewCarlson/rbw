use crate::common::{
    authenticate, register_user, upload_login_cipher, BwxHarness,
};
use crate::skip_if_no_vaultwarden;

/// Simulates a second client (e.g. the web vault) creating a cipher while
/// bwx is logged in but unaware. After `bwx sync`, the entry should be
/// visible locally and its decrypted fields should round-trip.
#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn external_cipher_shows_up_after_sync() {
    let server = skip_if_no_vaultwarden!();

    let email = "external@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Initially empty.
    assert!(
        harness.check(&["list"]).trim().is_empty(),
        "expected empty vault on first sync"
    );

    // Drop a cipher on the server via the API as "another client".
    let account =
        authenticate(&server, email, password).expect("authenticate");
    upload_login_cipher(
        &server,
        &account,
        "external.site",
        None,
        Some("alice@external"),
        Some("externalpw"),
    )
    .expect("upload cipher");

    // bwx has not synced yet — listing is still empty.
    assert!(
        !harness
            .check(&["list"])
            .lines()
            .any(|l| l.trim() == "external.site"),
        "bwx saw the entry before sync"
    );

    harness.check(&["sync"]);

    let listing = harness.check(&["list"]);
    assert!(
        listing.lines().any(|l| l.trim() == "external.site"),
        "entry missing after sync:\n{listing}"
    );

    assert_eq!(
        harness.check(&["get", "external.site"]).trim_end(),
        "externalpw"
    );
    assert_eq!(
        harness
            .check(&["get", "--field", "user", "external.site"])
            .trim_end(),
        "alice@external"
    );
}
