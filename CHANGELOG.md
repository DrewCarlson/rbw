# Changelog

## [2.2.2] - Unreleased

* **Faster `--folder` lookup in `bwx add`/`generate`.** When passeing
  `--folder <name>`, the CLI used to decrypt every folder name one
  IPC at a time just to check whether the requested folder already
  existed. Folder lookup now batches into a single `DecryptBatch`,
  one IPC regardless of folder count.
* **Faster `bwx add`/`generate`/`edit`.** New `EncryptBatch` IPC
  (mirrors `DecryptBatch`): the agent encrypts a vector of
  plaintexts in one shot and returns per-item results. `bwx add`
  and `bwx generate` previously fired one IPC each for name,
  username, password, notes, and every URI; `bwx edit` fired one
  per modified field. All three now stage their plaintexts through
  a local `EncryptBatcher` helper and flush a single round trip.
  Minor protocol bump — the new variants are additive, so older
  agents still work for any command that doesn't actually use
  `EncryptBatch`, but `add`/`generate`/`edit` require both binaries
  on this version.
* **Faster full-detail decrypt for `bwx get --full`/`history`/`code`.**
  The full-cipher decrypt path (`decrypt_cipher` /
  `decrypt_cipher_using_search`) previously fired one IPC per
  cipherstring — folder, notes, every history password, both halves
  of every custom field, and every variant-specific field (login
  password/totp/URIs, identity address fields, card numbers, SSH
  key parts). An entry with several history rows and custom fields
  could rack up 20+ synchronous round trips. Both functions now
  stage every field into one `DecryptBatch` via a shared `Batcher`
  helper and assemble results from the response.
* **Faster `bwx get`/`code`/`edit`/`remove`/`history`/`search` on
  large vaults.** `find_entry` and `search` previously made one IPC
  round-trip per cipherstring per entry (name + username + folder +
  notes + every URI + every custom field), which scaled as
  O(entries × fields) and could easily reach hundreds of round-trips
  on a sync. Both now route through a new `decrypt_search_ciphers`
  helper that bundles every field into a single `DecryptBatch` IPC,
  with the agent decrypting them in one shot.
* **Configurable diagnostic logging.** New `logging` config key
  (`bwx config set logging on|off`, default `on`) toggles a single
  bucket of diagnostic output written to stderr — error/warning
  messages plus debug records used to trace internal operations and
  time long-running steps. When `off`, `bwx` and `bwx-agent` emit
  nothing on stderr. Output is restricted to our crates so
  third-party libraries don't leak through; `RUST_LOG`, when set,
  overrides the configured level for ad-hoc debugging. The new
  `bwx::debug_time!` macro is zero-cost when logging is off (no
  `Instant`, no string formatting).
* **macOS-only commands no longer appear in `--help` on other
  platforms.** `bwx touchid {enroll,disable,status}`, `bwx setup-macos`,
  and `bwx teardown-macos` are now `#[cfg(target_os = "macos")]`-gated
  in the clap `Opt` enum, so Linux/BSD builds simply don't list them
  rather than listing them with a stub that errors at runtime. The
  "(macOS only)" suffix has been dropped from the surviving help
  text since it's now redundant.
* **Touch ID wrapper key now lives in the data-protection keychain.**
  All `SecItem*` calls in `src/touchid/keychain.rs` pass
  `kSecUseDataProtectionKeychain = true`. Items are scoped by the
  binary's team-identifier rather than via per-binary login-keychain
  ACLs, so reinstalling or upgrading a Developer-ID-signed bwx no
  longer triggers the "bwx wants to access the keychain" prompt and
  there is no "Always Allow" ACL to manage.

## [2.2.1] - 2026-04-26

* **Same-team peer verification on the agent socket (macOS).** When
  the agent itself is signed with a Team Identifier (Developer ID or
  Apple Development), it now requires connecting clients to be signed
  by the same team via a `SecCodeCheckValidity` requirement string.
  Closes the "another process running as my uid that's signed by some
  other identity". Ad-hoc and unsigned agent builds (local
  `cargo install`, forks without a paid Apple cert) keep the prior
  same-uid-only behavior, so dev workflows aren't disrupted.
* Rejected agent connections now send a `Response::Error` before
  closing instead of dropping silently, so the CLI fails fast with a
  real error message. `bwx stop-agent` (and any other path that ends
  up sending `Quit`) now bounds its `wait_for_exit` poll at 2 seconds
  rather than waiting forever.
* **Fix macOS releases getting killed at exec time.** 2.2.0 binaries
  were signed with a `keychain-access-groups` entitlement that AMFI
  treats as restricted; without a provisioning profile (which a bare
  CLI Mach-O can't carry) the kernel rejects the signature and SIGKILLs
  the process before `main` runs. Drop the entitlement; Touch ID
  enforcement stays put — the agent's presence check still fires
  before the wrapper key is released, the only loss is the
  Keychain-side biometric ACL which was never actually being applied
  on shipped builds anyway.
* `bwx config show/set/unset` now offer the valid configuration keys
  via shell completions and reject unknown keys at the CLI parse step.
  `bwx config unset sync_interval` resets it to the default instead of
  erroring.

## [2.2.0] - 2026-04-26

* Cache `Config::load()` once per `bwx` invocation; trims a few ms of
  redundant disk + JSON parse from every command that touches the
  vault.
* Reuse the search-cipher plaintext when finalising the matched entry
  in `find_entry`, so `get`/`code`/`exec` skip the redundant
  decrypt-via-IPC of name, folder, notes, and login username.
* Skip the second KDF run during `bwx login`. The agent now reuses the
  `Identity` produced while authenticating to unlock the vault,
  shaving 100-500ms off Argon2id-backed accounts on first login.
* Cache the agent protocol-version probe within a single CLI
  invocation, so commands that re-enter `ensure_agent` (e.g.
  `--clipboard`) don't pay for a redundant IPC round-trip.
  `stop_agent()` now invalidates that cache so a later
  `ensure_agent` re-verifies a fresh agent.
* Memoise compiled URI-match regexes during entry lookup. The find
  loop runs the same patterns against every cipher several times per
  search; compiling once per pattern keeps regex-heavy `bwx get`
  callers off the hot path.
* `bwx list` now decrypts the whole vault in a single `DecryptBatch`
  IPC instead of one round-trip per field. Adds `Action::DecryptBatch`
  and `Response::DecryptBatch` to the agent protocol; per-item failures
  are reported back to the caller without aborting the batch.
* Reuse a single `UnixStream` for every IPC inside a `bwx` invocation
  instead of opening a fresh connection per action. Cached socket is
  cleared on send/recv failure (transparent reconnect) and on `Quit`.
* Cap `DecryptBatch` requests at 10,000 items and forward only the
  top-level error context for per-item failures, so the agent doesn't
  echo wrapped error chains over IPC.
* Release workflow attestation step migrated from
  `actions/attest-build-provenance` to `actions/attest@v4.1.0` (the
  upstream-recommended target for new implementations; the old action
  is now just a passthrough wrapper).
* **Wire-format change.** CLI ↔ agent IPC moves from line-delimited
  JSON to length-prefixed MessagePack (`rmp-serde`). 4-byte big-endian
  payload size, 16 MiB cap on both directions, same `Request`/
  `Response` enum shapes. Smaller and faster to encode/decode for
  large payloads (`bwx list`, `DecryptBatch`). **Run `bwx stop-agent`
  after upgrading** so the new CLI doesn't try to talk to a still-
  running pre-2.1.1 agent.
* Agent now caps each request read at 30 seconds and exits the
  connection cleanly on timeout, so a peer that sends a length prefix
  and then stalls can't pin a tokio task forever.

## [2.1.0] - 2026-04-26

## Added

* **`bwx exec --env VAR=ENTRY[#FIELD] -- <cmd>`.** Run a child process
  with vault fields bound to environment variables. Each `--env` flag
  resolves a vault entry (by name, UUID, or URI) and an optional field
  (defaults to `password`); the value is passed via `execve()` only and
  the parent zeroizes its in-process copy as soon as the child has been
  spawned, so secrets never touch disk. The exec'd child's exit code
  (or `128 + signal` on Unix signal termination) is propagated. Drop-in
  replacement for `direnv` + plaintext `.env` files for CLI workflows
  (`bwx exec --env DB_URL=db/prod#uri -- terraform apply`).

## [2.0.2] - 2026-04-25

**Project renamed from `rbw` to `bwx-cli`.** The binaries are now `bwx`
and `bwx-agent`; XDG dirs move from `~/.config/rbw` etc. to
`~/.config/bwx`; the macOS Keychain service is `"bwx"`; LaunchAgent
labels are `drews.website.bwx.*`; env vars use a `BWX_` prefix
(`BWX_PROFILE`, `BWX_TTY`, …). Existing installs need to migrate
config/cache dirs and re-enroll Touch ID.

First-class macOS support, an extensive security hardening pass, and a
substantial dependency-tree reduction. Linux/BSD users get a drop-in
replacement for upstream `rbw` with the same hardening applied.

## Added

* **Touch ID unlock (macOS).** `bwx touchid enroll`/`disable`/`status` wrap
  the vault keys under a Keychain-held wrapper key so biometry can replace
  the master password. Three signing tiers (Developer ID, Apple Development,
  ad-hoc) are detected at runtime and use the strongest available ACL.
* **Per-operation Touch ID gate.** `touchid_gate = off | signing | all`
  optionally requires a biometric prompt before each vault read or SSH
  sign, coalesced to one prompt per `bwx <command>` via a session token.
* **Native macOS dialogs.** Master password, 2FA codes, and SSH-sign
  confirmation render as Aqua dialogs via `osascript` when pinentry isn't
  available; toggled by `macos_unlock_dialog`.
* **`bwx setup-macos` / `bwx teardown-macos`.** Install/remove two
  LaunchAgents — one for `bwx-agent` keepalive, one to publish
  `SSH_AUTH_SOCK` into launchd's environment so GUI apps inherit it.
* **Built-in SSH agent + git commit signing.** Serves SSH keys stored as
  Bitwarden "SSH Key" items. `bwx ssh-public-key`, `bwx ssh-allowed-signers`,
  and `bwx ssh-socket` support `gpg.format = ssh` workflows.
* **`ssh_confirm_sign`.** Optional pinentry CONFIRM dialog before each SSH
  signature, with the requesting program's name + PID surfaced in the
  prompt so the user knows which client is asking.
* **End-to-end test suite.** A vaultwarden-spawning harness with 43
  scenarios, run on Ubuntu and macOS in CI.

## Changed

* Replaced 20+ third-party crates with hand-rolled equivalents where the
  upstream surface was overkill for our use: `axum` → raw tokio HTTP
  parser for the SSO callback, `region` → direct `rustix` mlock/munlock
  (also fixes the musl `munlock` panic on `RLIMIT_MEMLOCK`-constrained
  CI runners), `humantime`, `textwrap`, `terminal_size`, `is-terminal`,
  `percent-encoding`, `uuid`, `directories`, `libc` (direct usage),
  `serde_path_to_error`, `block-padding`, `arrayvec`, `serde_repr`,
  `totp-rs`, `base32`, `anyhow`, `daemonize`, `env_logger`, `hkdf`,
  `clap_complete_nushell`/`clap_complete_fig`, `futures-channel`,
  `futures`. `open` is now gated behind the optional `sso-browser`
  feature.
* Tokio feature set narrowed from `"full"` to the actually-used subset.

## Security

* **All on-disk state forced to 0o600 / 0o700.** `config.json`, `db.json`,
  `touchid.json`, `device_id`, the pidfile, and the agent socket dir are
  re-tightened on every write — explicit `set_permissions` in addition to
  `OpenOptions::mode`, since the latter only applies on file creation.
* **Wrapper seed kept in `locked::Vec` end-to-end.** Touch ID enroll +
  unlock paths never materialize the 64-byte seed in plain heap or on
  the stack; `keychain::load` returns `locked::Vec` directly.
* **Pinentry stdout zeroized.** osascript / Assuan output buffers are
  scrubbed before the parent `Output` drops, so a typed master password
  doesn't linger in the heap.
* **SSH key plaintext minimized.** `ssh-agent` Sign handler decrypts the
  private key only *after* Touch ID + pinentry CONFIRM succeed; cancel
  paths leave no key material in memory.
* **SSO callback hardened.** State-mismatch error no longer embeds the
  64-char OAuth state token. Raw tokio listener replaces axum (smaller
  attack surface, no untrusted body parsing).
* **Agent IPC hardened.** Per-connection `getpeereid` / `SO_PEERCRED`
  check rejects cross-uid clients on shared hosts. Both control and
  ssh-agent sockets bind atomically (tmp + rename) instead of unlink +
  bind. Request and response framing capped at 16 MiB.
* **MAC verify made explicit.** CipherString verification now uses
  `hmac::Mac::verify_slice` (constant-time via `subtle::ConstantTimeEq`)
  with a comment documenting the guarantee.
* **Touch ID session bookkeeping fixed.** Sessions are recorded only
  after a successful unlock, not on bare presence, so a failed unwrap
  doesn't leave a usable auth window for the TTL.
* **SIGTERM/SIGINT zeroize agent state.** In-memory keys are dropped
  through their `mlock`/`zeroize` Drop impls before exit, instead of
  living in kernel buffers until reaping.
* **`pwgen` returns `locked::Password`.** Generated passwords are
  mlocked + zeroized on drop in the immediate caller's scope.

## Install

* macOS: `git clone … && ./scripts/install.sh && bwx setup-macos`. The
  install script auto-picks the strongest signing identity available
  (Developer ID > Apple Development > ad-hoc) and applies the matching
  Keychain ACL strategy.

## [1.15.0] - 2025-12-31

## Added

* Added support for `rbw get --field=private_key` for ssh key entries (#291).
* Added support for `rbw list --field=type` (Antoine Carnec, #283).
* `rbw list --raw` and `rbw search --raw` now also include entry uris (#279).

## Changed

* `rbw search` no longer searches hidden fields (#303).
* `ptrace` and core dumps are now also disabled on macos (Antoine Carnec,
  #300).
* Adjusted metadata to allow installation via `cargo binstall` (GideonBear, #275).
* More accurate shell completion for the `--field` option (Tin Lai, #287).

## Fixed

* `rbw list` and `rbw search` no longer trigger master password reprompt on
  entries with hidden fields (#303).
* `rbw unlocked` now ensures that the agent it is talking to is the correct
  version, even though it doesn't launch a new one (#276).
* A few improvements around pinentry protocol error parsing, to make logs
  more readable.

## [1.14.1] - 2025-09-01

## Added

* Basic shell completion for powershell, elvish, nushell, and fig (#271,
  jasonxue)

## Fixed

* TOTP entries with weak keys are supported again (#272, Maksim Karelov)
* Master password reprompt is no longer triggered for unrelated entries.
  (#268)
* Master password reprompt is always triggered even if no sync has happened.
* `rbw get` with a URL query can now return entries with multiple different
  URLs configured.

## [1.14.0] - 2025-08-24

## Added

* Steam Guard TOTP secrets are now supported. (#250, nikp123)
* SSH Key vault entries are now supported. (#252, Peter Kaplan)
* Master Password Reprompt is now supported.
* `rbw list` and `rbw search` now have a `--raw` option similar to `rbw get`.
* Shell completion now allows autocompleting of entry names, usernames, and
  folders. (#245, Patrick Lenihan)
* Added functionality to allow `rbw` to also act as an SSH agent by setting
  `SSH_AUTH_SOCK` appropriately. (#262, Peter Kaplan)

## Changed

* The `--clipboard` option now has a short alias of `-c`. (#258, Kedap)
* Sped up `rbw list` and `rbw search` by only decrypting fields that will
  actually be displayed.
* `rbw search` now displays results in the same format as `rbw list`, for
  consistency and easier parsing.

## Fixed

* We now automatically remove spaces from TOTP secrets, to handle different
  formatting or copy/pasting issues. (#247, foudil)
* If we create a new directory (for cache, sockets, etc), we now always
  ensure that its permissions are set correctly.
* `git-credential-rbw` now supports git's `credential.useHttpPath`. (#244,
   FoxAmes)
* `identity_url`, `ui_url`, and `notifications_url` are now set properly when
  configuring the `base_url` to be `https://api.bitwarden.eu`.
* `rbw search` now also searches configured URIs in entries.
* All subcommands which select a single entry are now consistent in how they
  allow the entry to be specified.
* Fixed some inconsistencies in how entries are selected when they have the
  same name but some entries have no username specified.
* Always write a pidfile for the agent even if it is not being daemonized, to
  allow running the agent manually during debugging.
* `rbw get` and `rbw search` now correctly return entries whose names are
  UUIDs.
* Email 2FA on the official Bitwarden server should now work again.

## [1.13.2] - 2025-01-06

## Fixed

* Try another clipboard backend to try to fix cross platform issues. (Mag
  Mell, #226)
* `rbw unlocked` no longer starts the agent if it isn't running. (#223)
* The cardholder_name field is now correctly populated for card entries.
  (#204)
* Fix ip address url matching when using the domain match type. (#211)
* Make the behavior of matching urls with no paths when using the exact match
  type more consistent. (#211)

## [1.13.1] - 2024-12-27

### Fixed

* Moved clipboard support to a (default-enabled) feature, since not all
  platforms support it (disabling this feature should allow Android builds to
  work again).

## [1.13.0] - 2024-12-26

### Fixed

* Fix preventing the password type selectors in `rbw generate` from being
  used together. (antecrescent, #198)
* Fix `--clipboard` on Wayland (Maksim Karelov, #192)
* Fix parsing vaults with entries that have non-null field types (Tin Lai, #212)
* Fix lock timeout being reset when checking version (aeber, #216)
* Update API request headers to pass new stricter validation on the official bitwarden.com server (Davide Laezza, #219)
* Make it possible to start the rbw agent process from a graphical session and then access it over SSH (Wim de With, #221)

## [1.12.1] - 2024-07-28

### Fixed

* Fix decrypting folder names of entries with individual item encryption keys.

## [1.12.0] - 2024-07-28

*NOTE: If you were affected by issue #163 (getting messages like `failed to
decrypt encrypted secret: invalid mac` when doing any operations on your
vault), you will need to `rbw sync` after upgrading in order to update your
local vault with the necessary new data.*

### Fixed

* Support decrypting entries encrypted with invididual item encryption keys,
  which are now generated by default from the official Bitwarden clients.
  (#163)
* Correctly handle lowercased and padded base32 TOTP secrets. (owl, #189)
* Make locking agent memory to RAM optional, since it appears to not always
  be available. (#143)

## [1.11.1] - 2024-06-26

### Fixed

* Updated the prelogin API endpoint to use the identity API instead of the
  base API, to correspond with upcoming changes to the official Bitwarden
  server (see https://github.com/bitwarden/server/pull/4206)

## [1.11.0] - 2024-06-20

### Added

* Support SSO login. (dezeroku, #174)
* Added `rbw search`, which finds and displays the name of entries matching a
  given search term.
* Added `--ignorecase` as an option to several subcommands. (Maximilian
  Götsch, #164)
* The JSON output given by `--raw` now also includes the field type.

### Fixed

* Fixed the client id used when logging in, which was causing problems with
  the official Bitwarden server. (Merlin Marek, #186)
* Reworked `rbw-pinentry-keyring` to support passwords with spaces and 2fa
  codes. (Henk van Maanen, #178)
* Try less hard to parse input as a url (so that using `rbw get` on an entry
  name containing a `:` works as expected).

## [1.10.2] - 2024-05-20

### Fixed

* Fix logging into the official Bitwarden server due to changes on their end
  (Gabriel Górski, #175)

## [1.10.1] - 2024-05-08

### Added

* `rbw code` supports TOTP codes which use a SHA256 or SHA512 hash (Jonas, #172)

### Fixed

* Fix `rbw code` searching by UUID (Robert Günzler, #169)

## [1.10.0] - 2024-04-20

### Added

* `rbw get` now supports searching by URL as well (proxict, #132)
* `rbw code` now supports `--clipboard`, and has an alias of `rbw totp` (#127)

### Changed

* Set a user agent for all API calls, not just logging in (#165)

### Fixed

* Also create runtime directories when running with `--no-daemonize` (Wim de With, #155)
* Fix builds on NetBSD (#105)
* Fix logging in when the configured email address differs in case from the email address used when registering (#158)
* Fix editing passwords inadvertently clearing custom field values (#142)

## [1.9.0] - 2024-01-01

### Added

* Secure notes can now be edited (Tin Lai, #137)
* Piping passwords to `rbw edit` is now possible (Tin Lai, #138)

### Fixed

* More consistent behavior from `rbw get --field`, and fix some panics (Jörg Thalheim, #131)
* Fix handling of pinentry EOF (Jörg Thalheim, #140)
* Pass a user agent header to fix logging into the official bitwarden server (Maksim Karelov, #151)
* Support the official bitwarden.eu server (Edvin Åkerfeldt, #152)

## [1.8.3] - 2023-07-20

### Fixed

* Fixed running on linux without an X11 context available. (Benjamin Jacobs,
  #126)

## [1.8.2] - 2023-07-19

### Fixed

* Fixed several issues with notification-based background syncing, it should
  be much more reliable now.

## [1.8.1] - 2023-07-18

### Fixed

* `rbw config set notifications_url` now actually works

## [1.8.0] - 2023-07-18

### Added

* `rbw get --clipboard` to copy the result to the clipboard instead of
  displaying it on stdout. (eatradish, #120)
* Background syncing now additionally happens when the server notifies the
  agent of password updates, instead of needing to wait for the 
  `sync_interval` timer. (Bernd Schoolman, #115)
* New helper script `rbw-pinentry-keyring` which can be used as an alternate
  pinentry program (via `rbw config set pinentry rbw-pinentry-keyring`) to
  automatically read the master password from the system keyring. Currently
  only supports the Gnome keyring via `secret-tool`. (Kai Frische, #122)
* Yubikeys in OTP mode are now supported for logging into a Bitwarden server.
  (troyready, #123)

### Fixed

* Better error reporting when `rbw login` or `rbw register` fail.

## [1.7.1] - 2023-03-27

### Fixed

* argon2 actually works now (#113, Bernd Schoolmann)

## [1.7.0] - 2023-03-25

### Added

* `rbw` now automatically syncs the database from the server at a specified
  interval while it is running. This defaults to once an hour, but is
  configurable via the `sync_interval` option
* Email 2FA is now supported (#111, René 'Necoro' Neumann)
* argon2 KDF is now supported (#109, Bernd Schoolmann)

### Fixed

* `rbw --version` now works again

## [1.6.0] - 2023-03-09

### Added

* `rbw get` now supports a `--raw` option to display the entire contents of
  the entry in JSON format (#97, classabbyamp)

## [1.5.0] - 2023-02-18

### Added

* Support for authenticating to self-hosted Bitwarden servers using client
  certificates (#92, Filipe Pina)
* Support multiple independent profiles via the `BWX_PROFILE` environment
  variable (#93, Skia)
* Add `rbw get --field` (#95, Jericho Keyne)

### Fixed

* Don't panic when not all stdout is read (#82, witcher)
* Fixed duplicated alias names in help output (#46)

## [1.4.3] - 2022-02-10

### Fixed

* Restored packaged scripts to the crate bundle, since they are used by some
  downstream packages (no functional changes) (#81)

## [1.4.2] - 2022-02-10

### Changed

* Device id is now stored in a separate file in the local data directory
  instead of as part of the config (#74)

### Fixed

* Fix api renaming in official bitwarden server (#80)

## [1.4.1] - 2021-10-28

### Added

* `bin/git-credential-rbw` to be used as a
  [git credential helper](https://git-scm.com/docs/gitcredentials#_custom_helpers)
  (#41, xPMo)

### Changed

* Also disable swap and viminfo files when using `EDITOR=nvim` (#70, Dophin2009)

### Fixed

* Properly handle a couple folder name edge cases in `bin/rbw-fzf` (#66,
  mattalexx)
* Support passing command line arguments via `EDITOR`/`VISUAL` (#61, xPMo)

## [1.4.0] - 2021-10-27

### Fixed

* Add `rbw register` to allow `rbw` to work with the official Bitwarden server
  again - see the README for details (#71)

## [1.3.0] - 2021-07-05

### Changed

* Use the system's native TLS certificate store when making HTTP requests.

### Fixed

* Correctly handle TOTP secret strings that copy with spaces (#56, TamasBarta, niki-on-github)

## [1.2.0] - 2021-04-18

### Added

* Shell completion for bash, zsh, and fish (#18)

### Changed

* Prebuilt binaries are now statically linked using musl, to prevent glibc
  version issues once and for all (#47)
* Standardize on RustCrypto in preference to ring or openssl

### Fixed

* `rbw generate` can now choose the same character more than once (#54, rjc)
* Improved handling of password history for entries with no password (#51/#53,
  simias)
* Fix configuring base_url with a trailing slash when using a self-hosted
  version of the official bitwarden server (#49, phylor)

## [1.1.2] - 2021-03-06

### Fixed

* Send warnings about failure to disable PTRACE_ATTACH to the agent logs rather
  than stderr

## [1.1.1] - 2021-03-05

### Fixed

* Fix non-Linux platforms (#44, rjc)

## [1.1.0] - 2021-03-02

### Added

* You can now `rbw config set pinentry pinentry-curses` to change the pinentry
  program used by `rbw` (#39, djmattyg007)

### Changed

* On Linux, the `rbw-agent` process can no longer be attached to by debuggers,
  and no longer produces core dumps (#42, oranenj)
* Suggest rotating the user's encryption key if we see an old cipherstring type
  (#40, rjc)
* Prefer the value of `$VISUAL` when trying to find an editor to run, before
  falling back to `$EDITOR` (#43, rjc)

## [1.0.0] - 2021-02-21

### Added

* Clarified the maintenance policy for this project in the README

### Fixed

* Stop hardcoding /tmp when using the fallback runtime directory (#37, pschmitt)
* Fix `rbw edit` clearing the match detection setting for websites associated
  with the edited password (#34, AdmiralNemo)
  * Note that you will need to `rbw sync` after upgrading and before running
    `rbw edit` in order to correctly update the local database.

## [0.5.2] - 2020-12-02

### Fixed

* `rbw` should once again be usable on systems with glibc-2.28 (such as Debian
  stable).

## [0.5.1] - 2020-12-02

### Fixed

* `rbw code` now always displays the correct number of digits. (#25, Tyilo)
* TOTP secrets can now also be supplied as `otpauth` urls.
* Logging into bitwarden.com with 2fa enabled now works again.

## [0.5.0] - 2020-10-12

### Added

* Add support for cipherstring type 6 (fixes some vaults using an older format
  for organizations data). (Jake Swenson)
* `rbw get --full` now displays URIs, TOTP secrets, and custom fields.
* Add `rbw code` for generating TOTP codes based on secrets stored in
  Bitwarden.
* Add `rbw unlocked` which will exit with success if the agent is unlocked and
  failure if the agent is locked.

### Fixed

* Don't display deleted items (#22, GnunuX)

## [0.4.6] - 2020-07-11

### Fixed

* Login passwords containing a `%` now work properly (albakham).

## [0.4.5] - 2020-07-11

### Fixed

* The pinentry window now no longer times out.

## [0.4.4] - 2020-06-23

### Fixed

* Fix regression in `rbw get` when not specifying a folder.

## [0.4.3] - 2020-06-23

### Added

* `rbw get` now accepts a `--folder` option to pick the folder to search in.

### Changed

* `rbw get --full` now also includes the username. (Jarkko Oranen)

### Fixed

* `rbw` should now be usable on systems with glibc-2.28 (such as Debian
  stable). (incredible-machine)

## [0.4.2] - 2020-05-30

### Fixed

* `rbw` now no longer requires the `XDG_RUNTIME_DIR` environment variable to be
  set.

## [0.4.1] - 2020-05-28

### Fixed

* More improved error messages.

## [0.4.0] - 2020-05-28

### Added

* Authenticator-based two-step login is now supported.

### Fixed

* Correctly handle password retries when entering an invalid password on the
  official Bitwarden server.
* Fix hang when giving an empty string to pinentry.
* The error message from the server is now shown when logging in fails.

## [0.3.5] - 2020-05-25

### Fixed

* Terminal-based pinentry methods should now work correctly (Glandos).
* Further error message improvements.

## [0.3.4] - 2020-05-24

### Fixed

* Handle edge case where a URI entry is set for a cipher but that entry has a
  null URI string (Adrien CLERC).

## [0.3.3] - 2020-05-23

### Fixed

* Set the correct default lock timeout when first creating the config file.
* Add a more useful error when `rbw` is run without being configured first.
* Don't throw an error when attempting to configure the base url before
  configuring the email.
* More improvements to error output.

## [0.3.2] - 2020-05-23

### Fixed

* Improve warning and error output a bit.

## [0.3.1] - 2020-05-23

### Fixed

* Fix option parsing for `rbw list --fields` and `rbw <add|generate> --uri`
  which was inadvertently broken in the previous release.

## [0.3.0] - 2020-05-22

### Fixed

* Better error message if the agent fails to start after daemonizing.
* Always automatically upgrade rbw-agent on new releases.
* Changing configuration now automatically drops in-memory keys (this should
  avoid errors when switching between different servers or accounts).
* Disallow setting `lock_timeout` to `0`, since this will cause the agent to
  immediately drop the decrypted keys before they can be used for decryption,
  even within a single run of the `rbw` client.

## [0.2.2] - 2020-05-17

### Fixed

* Fix syncing from the official Bitwarden server (thanks the_fdw).

### Added

* Added a couple example scripts to the repository for searching using fzf and
  rofi. Contributions and improvements welcome!

## [0.2.1] - 2020-05-03

### Fixed

* Properly maintain folder and URIs when editing an entry.

## [0.2.0] - 2020-05-03

### Added

* Multi-server support - you can now switch between multiple different
  bitwarden servers with `rbw config set base_url` without needing to
  redownload the password database each time.
* `rbw config unset` to reset configuration items back to the default
* `rbw list` and `rbw get` now support card, identity, and secure note entry
  types

### Fixed

* `rbw` is now able to decrypt secrets from organizations you are a member of.
* `rbw stop-agent` now waits for the agent to exit before returning.

### Changed

* Move to the `ring` crate for a bunch of the cryptographic functionality.
* The agent protocol is now versioned, to allow for seamless updates.

## [0.1.1] - 2020-05-01

### Fixed

* Some packaging changes.

## [0.1.0] - 2020-04-20

### Added

* Initial release
