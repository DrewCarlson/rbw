//! Shared helpers for the bwx integration tests.

#![allow(dead_code)] // shared helpers; not every scenario uses everything.
#![allow(clippy::items_after_statements)]

/// Start a `VaultwardenServer` or early-return from the calling test function
/// with a helpful message. Must be invoked from within a `#[test] fn` that
/// returns `()`.
#[macro_export]
macro_rules! skip_if_no_vaultwarden {
    () => {
        match $crate::common::VaultwardenServer::start() {
            Some(s) => s,
            None => {
                eprintln!(
                    "skipping: vaultwarden binary not found. \
                     Install with `cargo install --git \
                     https://github.com/dani-garcia/vaultwarden \
                     --features sqlite --locked` or set VAULTWARDEN_BIN."
                );
                return;
            }
        }
    };
}

mod api;
mod harness;
mod server;

pub use api::{
    authenticate, register_user, upload_login_cipher, upload_ssh_cipher,
};
pub use harness::BwxHarness;
pub use server::VaultwardenServer;

#[cfg(test)]
mod unit {
    use super::harness::shell_escape;

    #[test]
    fn escape_preserves_plain() {
        assert_eq!(shell_escape("abc"), "'abc'");
    }

    #[test]
    fn escape_embeds_single_quote() {
        assert_eq!(shell_escape("a'b"), "'a'\\''b'");
    }

    #[allow(dead_code)]
    fn _hush_unused(_: &super::BwxHarness) {}
}
