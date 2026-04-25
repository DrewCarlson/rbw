# bwx

Unofficial [Bitwarden](https://bitwarden.com/) CLI with a persistent
background agent — commands don't re-prompt for the master password on
every use, similar to `ssh-agent`.

This fork adds first-class macOS support: Touch ID unlock, native
password dialogs, SSH commit signing, and a one-shot setup command.
On Linux/BSD it's a drop-in replacement for upstream `rbw`.

## Features

- **Persistent agent.** Vault keys live in memory until `lock_timeout`
  of inactivity.
- **Touch ID unlock (macOS).** Enroll once, and biometry replaces the
  master password. The password is only re-entered at enrollment time
  or when biometry is invalidated.
- **Per-operation biometric gate.** Optionally require Touch ID before
  each vault read or SSH sign, with one prompt per `bwx <command>`.
- **Native macOS prompts.** Master password + 2FA code entry render as
  system Aqua dialogs; pinentry isn't required.
- **SSH agent built in.** Serve vault-stored SSH keys, including git
  commit/tag signing via `gpg.format = ssh`.
- **One-shot macOS setup.** `bwx setup-macos` installs the LaunchAgent
  that keeps `bwx-agent` alive and registers the SSH-agent socket so
  terminal sessions (and the GUI apps they launch) can use it via a
  one-line shell-rc export.

## Install

### macOS

```sh
brew install DrewCarlson/tap/bwx-cli
bwx setup-macos               # LaunchAgent that keeps bwx-agent alive
```

The Homebrew install pulls the notarized release tarball, so Touch ID
unlock and the SSH-agent paths just work — no local Rust toolchain or
manual code-signing needed.

### Everywhere else

| Channel                  | Command                                                                            |
|--------------------------|------------------------------------------------------------------------------------|
| crates.io (any platform) | `cargo install --locked bwx-cli` (binaries are `bwx` / `bwx-agent`)                |
| Arch (AUR — release)     | `yay -S bwx-cli` (or any AUR helper)                                               |
| Arch (AUR — git)         | `yay -S bwx-cli-git`                                                               |
| Nix flake                | `nix profile install github:drewcarlson/bwx-cli`                                   |
| Debian / Ubuntu (`.deb`) | download from [GitHub Releases][rel] → `sudo dpkg -i bwx-cli_*_amd64.deb`          |
| Fedora / RHEL (`.rpm`)   | download from [GitHub Releases][rel] → `sudo dnf install ./bwx-cli-*.x86_64.rpm`   |
| Standalone tarball       | download from [GitHub Releases][rel], extract, put `bwx`/`bwx-agent` on PATH       |
| From source (any)        | `git clone … && ./scripts/install.sh` (auto-runs `scripts/sign-macos.sh` on macOS) |

[rel]: https://github.com/drewcarlson/bwx-cli/releases

Each tagged release builds Linux `x86_64` + `aarch64` (glibc and musl)
and macOS `arm64` + `x86_64` artifacts, attached to the GitHub Release.
On Linux you'll also want `pinentry` from your distro so the
master-password prompt has a UI.

### Verifying release artifacts

Every artifact carries a SLSA build-provenance attestation (signed
with the release workflow's GitHub OIDC identity, recorded in the
sigstore rekor transparency log) plus a `.minisig` signature.

```sh
# GitHub-native attestation verify. Confirms the artifact was built
# by the bwx-cli release workflow on a tagged commit; no local key
# to install. Requires the `gh` CLI.
gh attestation verify bwx-cli_2.0.0_amd64.deb \
  --repo drewcarlson/bwx-cli

# Minisign — single shipped pubkey at packaging/minisign.pub.
minisign -V -p packaging/minisign.pub \
  -m bwx-cli_2.0.0_amd64.deb

# `SHA256SUMS` covers every file in the release; verify it once,
# then check artifacts against it.
sha256sum -c SHA256SUMS
```

## Usage

```sh
bwx config set email you@example.com
bwx config set base_url https://vault.example.com   # self-hosted only

bwx register        # only for the official bitwarden.com server
bwx login           # master password + 2FA
bwx sync

bwx add <name>
bwx ls
bwx get <name>      # --full for notes, --field for a specific field,
                    # --raw for JSON
bwx code <name>     # TOTP
bwx edit <name>     # opens $EDITOR
bwx remove <name>
bwx lock            # drop keys from memory

bwx help            # full reference
```

Commands auto-unlock and auto-login as needed. `bwx get` accepts a
name, UUID, or URL.

**Bitwarden.com users:** run `bwx register` once with your
[personal API key](https://bitwarden.com/help/article/personal-api-key/)
before `bwx login`. The official server's bot detection rejects CLI
clients that haven't registered.

## Touch ID unlock (macOS)

Enroll once:

```sh
bwx unlock                  # master password
bwx touchid enroll          # wrap vault keys under a biometric key
bwx touchid status          # confirm
```

After enrollment Touch ID alone unlocks the vault. The master password
is needed again only if you `bwx touchid disable`, change your
enrolled fingerprint set, or re-authenticate with the server.

Optionally prompt Touch ID on each sensitive operation:

```sh
bwx config set touchid_gate all       # every vault read + sign
bwx config set touchid_gate signing   # only SSH signs + TOTP codes
bwx config set touchid_gate off       # default
```

Prompts are coalesced: one `bwx <command>` triggers one Touch ID
dialog regardless of how many internal decrypts it performs.

## SSH agent & git commit signing

bwx-agent exposes an SSH agent that serves SSH keys stored in your
vault. Store an "SSH Key" item, then:

```sh
# Configured automatically by `bwx setup-macos`; explicit equivalent:
export SSH_AUTH_SOCK="$(bwx ssh-socket)"

ssh-add -L                  # list keys
ssh user@host               # authenticate with a vault-stored key
```

Git commit signing via `gpg.format = ssh`:

```sh
git config --global gpg.format ssh
git config --global user.signingkey "$(bwx ssh-public-key <entry>)"
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Optional, for `git log --show-signature`:
bwx ssh-allowed-signers > ~/.config/git/allowed_signers
git config --global gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers
```

Add a confirmation prompt before each signature (defence in depth
against a process silently signing while the agent is unlocked):

```sh
bwx config set ssh_confirm_sign true
```

**Shell + GUI app inheritance.** Modern macOS no longer propagates
`launchctl setenv` into the env of Dock- / Spotlight-launched apps.
Add this line to your shell rc so terminal sessions and the apps
they launch see the bwx ssh-agent:

```sh
export SSH_AUTH_SOCK="$(bwx ssh-socket)"   # ~/.zshrc, ~/.bashrc, …
```

GUI apps that were already open need to be Cmd-Q'd and relaunched
(so their env is re-inherited from the shell) before they pick it up.

**IntelliJ IDEs specifically:** Settings → Version Control → Git →
"Native" (not Built-in). JGit doesn't honor `gpg.format = ssh`.

## Configuration

```sh
bwx config set <key> <value>
bwx config show                  # all keys (JSON)
bwx config show <key>            # single value
bwx config unset <key>
```

| Key | Default | |
|---|---|---|
| `email` | — | Required. |
| `base_url` | `https://api.bitwarden.com` | Self-hosted server URL. |
| `lock_timeout` | `3600` | Seconds idle → re-lock. |
| `sync_interval` | `3600` | Seconds between auto-syncs. `0` disables. |
| `touchid_gate` | `off` | `off` / `signing` / `all`. |
| `macos_unlock_dialog` | `true` (macOS) | Native dialog vs. pinentry. |
| `ssh_confirm_sign` | `false` | Pinentry CONFIRM before each SSH sign. |
| `pinentry` | `pinentry` | Pinentry binary to use. |

### Profiles

Set `BWX_PROFILE=<name>` to keep an independent vault, config, and
agent under that name.

## 2FA

Supported: Email, Authenticator App, Yubico OTP security key.

Not supported: WebAuthn / Passkey, Duo. Add a supported mechanism
alongside them — bwx will use the supported one while your web/mobile
clients keep whichever you prefer.

---

# Appendix: macOS internals

## Code signing

`cargo install` produces unsigned binaries; macOS AMFI kills unsigned
processes that touch the Keychain. `scripts/install.sh` wraps
`cargo install` and runs `scripts/sign-macos.sh`, which auto-picks the
strongest signing identity on your machine:

1. `$IDENTITY` env var (explicit override).
2. Developer ID Application cert (paid Apple Developer program).
3. Apple Development cert (free via Xcode).
4. Ad-hoc.

Keychain security varies by tier:

| Identity                 | Keychain item ACL                                |
|--------------------------|--------------------------------------------------|
| Developer ID Application | OS-enforced biometric ACL — strongest.           |
| Apple Development        | Plain item; Touch ID enforced by bwx-agent only. |
| Ad-hoc                   | Same as Apple Development.                       |

Only Developer ID Application carries `keychain-access-groups` on a
CLI binary; the other tiers would need a provisioning profile, which
bare binaries can't have. The runtime detects which entitlements the
installed binary actually holds and branches automatically — the same
source builds all three tiers. Upgrading tiers later: re-run
`./scripts/install.sh`, then `bwx touchid disable && bwx touchid enroll`
to migrate the Keychain item.

## `bwx setup-macos`

Installs two LaunchAgents under `~/Library/LaunchAgents/`:

- **`drews.website.bwx.ssh-auth-sock`** — runs `~/bin/bwx-set-ssh-sock` at
  login, which calls `launchctl setenv SSH_AUTH_SOCK $(bwx ssh-socket)`.
  Puts the socket into launchd's environment so GUI apps inherit it.
- **`drews.website.bwx.agent`** — runs `bwx-agent --no-daemonize` under
  launchd supervision with `KeepAlive`. Log output lands in
  `~/Library/Application Support/bwx/launchd-agent.{out,err}`.

`bwx teardown-macos` unloads both and removes the files.
