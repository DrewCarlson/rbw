use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn generate_stores_entry_and_sync_is_idempotent() {
    let server = skip_if_no_vaultwarden!();

    let email = "generate@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Generate a 24-char password for entry "gen.example"; verify it shows up.
    let gen_out = harness
        .check(&["generate", "24", "gen.example"])
        .trim_end()
        .to_string();
    assert_eq!(
        gen_out.len(),
        24,
        "expected a 24-char generated password, got {gen_out:?}"
    );

    let listing = harness.check(&["list"]);
    assert!(
        listing.lines().any(|l| l.trim() == "gen.example"),
        "expected gen.example in listing:\n{listing}"
    );

    // Round-trip through `get` matches what `generate` printed.
    let fetched = harness
        .check(&["get", "gen.example"])
        .trim_end()
        .to_string();
    assert_eq!(fetched, gen_out, "stored password differs from generated");

    // Sync should be idempotent — running it twice from a clean state yields
    // the same local view.
    let before = harness.check(&["list"]);
    harness.check(&["sync"]);
    let after = harness.check(&["list"]);
    assert_eq!(before, after, "sync mutated the visible listing");
}

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn generate_respects_length_flags() {
    let server = skip_if_no_vaultwarden!();

    let email = "gen_flags@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // `--only-numbers` (no name → don't store, just print)
    let digits = harness.check(&["generate", "--only-numbers", "16"]);
    let digits = digits.trim_end();
    assert_eq!(digits.len(), 16);
    assert!(
        digits.chars().all(|c| c.is_ascii_digit()),
        "--only-numbers returned non-digit chars: {digits:?}"
    );

    // `--no-symbols` (alphanumeric only)
    let alnum = harness.check(&["generate", "--no-symbols", "32"]);
    let alnum = alnum.trim_end();
    assert_eq!(alnum.len(), 32);
    assert!(
        alnum.chars().all(|c| c.is_ascii_alphanumeric()),
        "--no-symbols returned non-alphanumeric chars: {alnum:?}"
    );
}
