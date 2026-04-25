//! Exercise the full encrypt / IPC / decrypt pipeline with non-ASCII
//! content to guard against any byte-boundary / UTF-8 truncation bug
//! in our hand-rolled buffer code (`locked::Vec`, pinentry percent
//! decode, protocol framing, base64 roundtrip, etc.).

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn unicode_name_username_password_notes_survive_roundtrip() {
    let server = skip_if_no_vaultwarden!();
    let email = "unicode@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Mix of emoji (multi-byte), combining diacritics, CJK, RTL, and a
    // few ASCII punctuation chars that bwx's parsers sometimes split
    // on (|, =, \).
    let entry_name = "café 🔐 日本語";
    let username = "üser | root = Adm\\in";
    let password_val = "pässwörd‑123 🚀 الجزائر";
    let notes_body = "line one — naïve ✨\n二行目\nthird";

    // `bwx add <name> [user]` — username is a positional arg. First
    // line of stdin is the password; a blank line separates password
    // from notes body.
    let out = harness.run_with_stdin(
        &["add", entry_name, username],
        format!("{password_val}\n\n{notes_body}\n").as_bytes(),
    );
    assert!(
        out.status.success(),
        "bwx add failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // `list` must show the unicode name byte-for-byte.
    let listing = harness.check(&["list"]);
    assert!(
        listing.lines().any(|l| l.trim() == entry_name),
        "entry name round-trip failed. expected line {entry_name:?}, got:\n{listing}"
    );

    // Password comes back exactly.
    let got_pw = harness.check(&["get", entry_name]);
    assert_eq!(got_pw.trim_end(), password_val);

    // `--full` includes username + notes.
    let full = harness.check(&["get", "--full", entry_name]);
    assert!(
        full.contains(username),
        "username not in --full: expected {username:?}, got:\n{full}"
    );
    assert!(
        full.contains("二行目"),
        "multi-line unicode notes not in --full; got:\n{full}"
    );
}
