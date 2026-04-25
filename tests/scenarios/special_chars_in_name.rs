//! Entry names containing characters that are historically problematic
//! in shell-pipe contexts — forward slash (path-like), vertical bar
//! (cipherstring separator), equals sign (URL-query separator),
//! whitespace, single/double quotes — must round-trip through add /
//! list / get without mangling.

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn shell_metachars_in_name_roundtrip() {
    let server = skip_if_no_vaultwarden!();
    let email = "metachars@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Deliberately pick names that would break a naive cipherstring
    // splitter ('|'), a URL-query parser ('='), a shell-path resolver
    // ('/'), or a format-string argument handler ('{').
    let names = &[
        "svc/github.com",
        "pipe|separator",
        "has=equals",
        "spaces and \"quotes\"",
        "curly{brace}",
        "unicode/café",
    ];

    for (i, name) in names.iter().enumerate() {
        let pw = format!("pw-{i}");
        let stdin = format!("{pw}\n\n\n");
        let out = harness.run_with_stdin(&["add", name], stdin.as_bytes());
        assert!(
            out.status.success(),
            "bwx add failed for {name:?}: stderr={}",
            String::from_utf8_lossy(&out.stderr),
        );
    }

    // Every name should appear verbatim in the listing.
    let listing = harness.check(&["list"]);
    for name in names {
        assert!(
            listing.lines().any(|l| l.trim() == *name),
            "name {name:?} missing from listing:\n{listing}"
        );
    }

    // Each entry's stored password should retrievable by that exact
    // name argument.
    for (i, name) in names.iter().enumerate() {
        let got = harness.check(&["get", name]);
        assert_eq!(
            got.trim_end(),
            format!("pw-{i}"),
            "password mismatch for {name:?}"
        );
    }
}
