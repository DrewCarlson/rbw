//! `bwx --help` and `bwx --version` are the first thing a user runs to
//! sanity-check an install. They must succeed without any config file
//! on disk, without network access, and without spawning an agent —
//! and they must not print any config dir paths that could leak the
//! user's `$HOME` in a bug report.

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn help_and_version_work_without_agent() {
    let server = skip_if_no_vaultwarden!();
    let email = "help@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    // Intentionally skip login/unlock — these subcommands must not
    // depend on the agent.
    let harness = BwxHarness::new(&server, email, password);

    let version = harness.run(&["--version"]);
    assert!(version.status.success(), "bwx --version failed");
    let ver_out = String::from_utf8_lossy(&version.stdout);
    // Expect something of the form "bwx 1.15.0" (semver-ish).
    assert!(
        ver_out.to_lowercase().contains("bwx"),
        "--version output doesn't mention bwx: {ver_out:?}"
    );
    assert!(
        ver_out.chars().any(|c| c.is_ascii_digit()),
        "--version output has no digits: {ver_out:?}"
    );

    let help = harness.run(&["--help"]);
    assert!(help.status.success(), "bwx --help failed");
    let help_out = String::from_utf8_lossy(&help.stdout);
    // Spot-check that a few top-level subcommands are listed.
    for cmd in &["login", "unlock", "get", "add", "list", "sync"] {
        assert!(
            help_out.contains(cmd),
            "--help doesn't list {cmd:?}:\n{help_out}"
        );
    }

    // `bwx help <subcommand>` is equivalent and should also work.
    let get_help = harness.run(&["help", "get"]);
    assert!(get_help.status.success(), "bwx help get failed");
}
