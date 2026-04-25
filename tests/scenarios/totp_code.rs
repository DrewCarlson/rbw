use crate::common::{
    authenticate, register_user, upload_login_cipher, BwxHarness,
};
use crate::skip_if_no_vaultwarden;

// RFC 6238 reference secret. Base32 of ASCII "12345678901234567890".
const SECRET_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

/// bwx's `add` CLI can't set the totp field directly. We upload the cipher
/// via the vaultwarden API ourselves (simulating a web-vault client), then
/// sync and ask bwx for a code.
#[test]
#[ignore = "requires vaultwarden binary; run with --ignored"]
fn bwx_code_matches_handrolled_totp() {
    let server = skip_if_no_vaultwarden!();

    let email = "totp@example.test";
    let password = "correct horse battery staple";
    register_user(&server, email, password).expect("register user");

    let account =
        authenticate(&server, email, password).expect("authenticate");

    upload_login_cipher(
        &server,
        &account,
        "totp.site",
        Some(SECRET_B32),
        None,
        None,
    )
    .expect("upload cipher");

    let harness = BwxHarness::new(&server, email, password);
    harness.login_and_unlock();
    harness.check(&["sync"]);

    let out = harness.check(&["code", "totp.site"]);
    let code = out.trim_end().to_string();
    assert_eq!(code.len(), 6, "expected 6-digit TOTP, got {code:?}");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "non-digit in TOTP code: {code:?}"
    );

    // Compute the expected code directly. If bwx happened to run in the
    // previous 30-second window (code is on a step boundary), accept either
    // that window's code or this window's.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let secret = bwx::totp::decode_base32(SECRET_B32).expect("decode b32");
    let here =
        bwx::totp::generate(&secret, now, 30, 6, &bwx::totp::Algorithm::Sha1)
            .expect("generate here");
    let prev = bwx::totp::generate(
        &secret,
        now.saturating_sub(30),
        30,
        6,
        &bwx::totp::Algorithm::Sha1,
    )
    .expect("generate prev");
    assert!(
        code == here || code == prev,
        "bwx code {code:?} matches neither current window ({here:?}) nor \
         previous window ({prev:?})"
    );
}
