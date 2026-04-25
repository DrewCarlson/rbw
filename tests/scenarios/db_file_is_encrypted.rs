//! The on-disk cache (`db_*.json`) must only hold CipherString-wrapped
//! values — never raw plaintext. A subtle serialization bug could
//! cause a decrypted password or note to leak into the cache (and then
//! into any backup system that slurps up the user's data dir). Assert
//! that a password we just stored is *not* greppable in the db file,
//! while the ciphertext envelope markers (`"2.<iv>|<ct>|<mac>"`) are.

use crate::common::{register_user, BwxHarness};
use crate::skip_if_no_vaultwarden;

#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn db_file_contains_ciphertext_not_plaintext() {
    let server = skip_if_no_vaultwarden!();
    let email = "dbcrypt@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();

    // Use a password marker distinctive enough that we can grep for it
    // in the db file without false positives.
    let marker = "Z3ZmUGUhOk9wQG0xMjM0IE1BUktFUg==";
    harness.run_with_stdin(
        &["add", "dbcrypt.target"],
        format!("{marker}\n\n\n").as_bytes(),
    );
    harness.check(&["sync"]);

    // Locate db_*.json under the harness data dir. bwx resolves this
    // dir from `XDG_DATA_HOME` on Linux and `$HOME/Library/…` on
    // macOS; the harness sets both, so we just read whichever applies.
    let env: std::collections::HashMap<_, _> = harness
        .cmd()
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_os_string(), v?.to_os_string())))
        .collect();
    let get = |k: &str| -> std::path::PathBuf {
        std::path::PathBuf::from(
            env.get(std::ffi::OsStr::new(k))
                .unwrap_or_else(|| panic!("{k} not in harness env")),
        )
    };
    // `bwx::dirs::db_file()` resolves under `cache_dir` — `XDG_CACHE_HOME`
    // on Linux, `$HOME/Library/Caches/bwx` on macOS. The filename is
    // `<urlencoded-server>:<email>.json` (no `db_` prefix).
    let cache_dir = if cfg!(target_os = "macos") {
        get("HOME").join("Library/Caches/bwx")
    } else {
        get("XDG_CACHE_HOME").join("bwx")
    };

    let db_path = std::fs::read_dir(&cache_dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", cache_dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("json")
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.contains(':'))
        })
        .unwrap_or_else(|| {
            panic!("no *.json db cache under {}", cache_dir.display())
        });

    let raw = std::fs::read(&db_path).expect("read db");
    let raw_str = String::from_utf8_lossy(&raw);

    assert!(
        !raw_str.contains(marker),
        "db file contains plaintext password marker {marker:?} — cache \
         encryption broken"
    );
    // The Bitwarden AES-CBC-HMAC envelope is serialized as
    // `"2.<iv>|<ct>|<mac>"`. Confirm at least one such value is present
    // so the test fails loudly if the schema flips.
    assert!(
        raw_str.contains("\"2."),
        "db file has no CipherString-looking values; got:\n{}",
        &raw_str[..raw_str.len().min(400)]
    );
}
