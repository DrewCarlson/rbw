use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn add_into_folder_and_list_shows_it() {
    let server = skip_if_no_vaultwarden!();

    let email = "folders@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Add an entry directly into a new folder. bwx auto-creates the folder
    // server-side on first use.
    let out = harness.run_with_stdin(
        &["add", "work.login", "--folder", "Work"],
        b"workpw\n\n\n",
    );
    assert!(
        out.status.success(),
        "add --folder failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // `list --fields name,folder` groups folder per row.
    let listing = harness.check(&["list", "--fields", "name,folder"]);
    assert!(
        listing
            .lines()
            .any(|l| l.contains("work.login") && l.contains("Work")),
        "expected 'work.login' + 'Work' on same row:\n{listing}"
    );

    // `get --folder Work work.login` narrows find_entry to the folder.
    let got = harness
        .check(&["get", "--folder", "Work", "work.login"])
        .trim_end()
        .to_string();
    assert_eq!(got, "workpw");
}
