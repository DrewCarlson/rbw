use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn get_by_uri_finds_entry() {
    let server = skip_if_no_vaultwarden!();

    let email = "uri@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Add with --uri. bwx persists the URL on the entry's uris array.
    let out = harness.run_with_stdin(
        &["add", "site.example", "--uri", "https://site.example/login"],
        b"sitepw\n\n\n",
    );
    assert!(
        out.status.success(),
        "add --uri failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // `parse_needle` tries URL-parse first; a full URL becomes a Needle::Uri
    // and find_entry searches the uris array.
    let got = harness
        .check(&["get", "https://site.example/login"])
        .trim_end()
        .to_string();
    assert_eq!(got, "sitepw");
}
