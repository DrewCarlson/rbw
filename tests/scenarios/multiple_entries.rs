use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn many_entries_listed_and_fetched() {
    let server = skip_if_no_vaultwarden!();

    let email = "many@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    let names = ["alpha.site", "beta.site", "gamma.site"];
    for (i, name) in names.iter().enumerate() {
        let pw = format!("pw-{i}\n\n");
        let out = harness.run_with_stdin(&["add", name], pw.as_bytes());
        assert!(
            out.status.success(),
            "bwx add {name} failed: stderr={}",
            String::from_utf8_lossy(&out.stderr),
        );
    }

    let listing = harness.check(&["list"]);
    for name in &names {
        assert!(
            listing.lines().any(|l| l.trim() == *name),
            "missing {name} in listing:\n{listing}"
        );
    }

    for (i, name) in names.iter().enumerate() {
        let got = harness.check(&["get", name]).trim_end().to_string();
        assert_eq!(got, format!("pw-{i}"), "wrong password for {name}");
    }

    // `bwx search` should match a substring.
    let search = harness.check(&["search", "beta"]);
    assert!(
        search.lines().any(|l| l.trim() == "beta.site"),
        "search missed beta.site:\n{search}"
    );
}
