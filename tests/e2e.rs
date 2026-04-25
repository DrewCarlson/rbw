//! End-to-end integration tests for bwx against a real Vaultwarden server.
//!
//! # Running
//!
//! These tests are marked `#[ignore]` so the default `cargo test` run stays
//! fast. To run them you need a `vaultwarden` binary installed locally:
//!
//! ```sh
//! cargo install --git https://github.com/dani-garcia/vaultwarden \
//!     --features sqlite --locked
//! ```
//!
//! Then run with:
//!
//! ```sh
//! cargo test --test e2e -- --ignored
//! ```
//!
//! Tests are fully parallel-safe: each scenario owns an ephemeral
//! Vaultwarden instance (random port, tempdir data folder) and a dedicated
//! `$XDG_RUNTIME_DIR`/`$XDG_CONFIG_HOME`/`$XDG_CACHE_HOME`/`$XDG_DATA_HOME`/
//! `$HOME` tree so the bwx-agent sockets, config, caches, and logs don't
//! collide.
//!
//! By default the harness looks up `vaultwarden` on `$PATH`. Override with
//! `VAULTWARDEN_BIN=/path/to/vaultwarden` if it lives elsewhere. If the binary
//! cannot be found the scenarios print a helpful message and exit early
//! (tests still report as passing because they are `#[ignore]`-only).
//!
//! Each scenario spins up its own isolated Vaultwarden instance on an
//! ephemeral port and its own tempdir acting as `XDG_*` for bwx, so tests can
//! run in parallel without stomping on each other.

mod common;
mod scenarios;
