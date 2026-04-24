//! Large-payload roundtrip: a notes body that crosses several AES
//! blocks and dwarfs the 4 KiB `locked::FixedVec` password buffer, to
//! make sure nothing along the encrypt → serialize → IPC → deserialize
//! → decrypt path caps or truncates entry bodies (notes flow through
//! `String`, not `locked::Vec`, so this is strictly a sanity check on
//! framing + cipherstring).

use std::fmt::Write as _;

use crate::common::{register_user, RbwHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn large_notes_survive_roundtrip() {
    let server = skip_if_no_vaultwarden!();
    let email = "longnotes@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = RbwHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Vaultwarden caps the cipher `notes` field at 10 000 chars, so we
    // stay just under that while still comfortably exceeding the
    // `locked::FixedVec` 4 KiB password buffer and an AES block. 180
    // numbered lines × ~48 chars ≈ 8.6 KiB — a truncation bug here
    // surfaces as a missing `line 0179:` at the tail.
    let mut notes = String::new();
    for i in 0..180 {
        writeln!(notes, "line {i:04}: abcdefghijklmnopqrstuvwxyz0123456789")
            .unwrap();
    }
    assert!(
        notes.len() > 4 * 1024 && notes.len() < 10_000,
        "test needs >4 KiB and <10 KiB of notes (vaultwarden cap), got {}",
        notes.len()
    );

    let mut stdin = Vec::new();
    stdin.extend_from_slice(b"pw-longnotes\n\n");
    stdin.extend_from_slice(notes.as_bytes());

    let out = harness.run_with_stdin(&["add", "longnotes.example"], &stdin);
    assert!(
        out.status.success(),
        "rbw add failed: stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let full = harness.check(&["get", "--full", "longnotes.example"]);
    // First and last lines must both be present, and the count should
    // match. Scan for "line 0000:" and "line 0255:" as bookends.
    assert!(
        full.contains("line 0000:"),
        "first notes line missing; got {} bytes",
        full.len()
    );
    assert!(
        full.contains("line 0179:"),
        "last notes line missing; got {} bytes (truncation somewhere?)",
        full.len()
    );
}
