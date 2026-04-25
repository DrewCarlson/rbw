# Release artifact signing & integrity

Each tag triggers a release pipeline that produces signed,
provenance-stamped artifacts. The integrity story has three layers:

| Layer                          | What it gives you                                                                                       | Maintainer setup                                  |
|--------------------------------|---------------------------------------------------------------------------------------------------------|---------------------------------------------------|
| SLSA build provenance          | Cryptographic attestation that the artifact was built by *this* repo's release workflow on a tag       | None — runs automatically via GitHub OIDC         |
| Minisign signature             | Maintainer-owned signature anyone can verify against a single shipped pubkey                            | Two repo secrets + commit `packaging/minisign.pub` |
| Tag protection + Immutable Releases | Once published, the tag and release assets cannot be moved, deleted, or rewritten                  | Two repo settings (manual one-time)               |

Each layer is independent: any one of them is enough to detect an
artifact swap, and verifying all three is cheap.

---

## Layer 1 — SLSA build provenance

Implemented via `actions/attest-build-provenance` in the release
workflow. Every artifact uploaded to a GitHub Release also gets an
in-toto SLSA provenance statement, signed with the workflow's GitHub
OIDC identity (Fulcio short-lived cert) and recorded in the sigstore
rekor transparency log.

Verify as a user:

```sh
gh attestation verify bwx-cli_2.0.0_amd64.deb --repo drewcarlson/bwx-cli
```

`gh` queries the attestation from the rekor log + GitHub, validates
the cert chain back to Fulcio's root, and confirms the signing
identity matches a workflow under `drewcarlson/bwx-cli`. An attacker
publishing a doctored artifact under a different repo can't satisfy
this predicate.

No setup required. Already on.

---

## Layer 2 — Minisign

A traditional offline-signed signature anyone can verify with the
single shipped public key. Friendlier for environments without `gh`
installed.

### One-time minisign setup

1. **Generate a keypair on a trusted machine** (your laptop, not CI).

   ```sh
   minisign -G -p packaging/minisign.pub -s ~/.bwx-minisign.key
   # Choose a strong password; you'll need it as MINISIGN_PASSWORD.
   ```

2. **Add two GitHub repo secrets**
   (Settings → Secrets and variables → Actions → New repository secret):

   - `MINISIGN_PRIVATE_KEY` — the *contents* of `~/.bwx-minisign.key`
     (multi-line, including the `untrusted comment:` header).
   - `MINISIGN_PASSWORD` — the password you chose at generation.

3. **Commit the public key** so users can verify against it:

   ```sh
   git add packaging/minisign.pub
   git commit -m "rotate: bwx-cli minisign pubkey"
   git push
   ```

4. **Back up `~/.bwx-minisign.key`** somewhere offline.

After this, every release adds `<artifact>.minisig` files alongside
the artifacts. Until completed, the minisign step in CI is silently
skipped — the SLSA attestations carry the integrity story alone.

### Verifying as a user

```sh
minisign -V -p packaging/minisign.pub -m bwx-cli_2.0.0_amd64.deb
```

### Rotating a compromised minisign key

1. Generate a fresh keypair (step 1 above).
2. Replace both repo secrets.
3. Commit the new `packaging/minisign.pub`.
4. Cut a new patch release whose changelog notes the rotation and the
   new pubkey fingerprint.
5. Publish a `SECURITY.md` advisory; mark the prior signatures as
   no-longer-trusted.

SLSA attestations don't have this rotation pain — every signature is
already tied to the workflow run's transient identity.

---

## Layer 3a — macOS code-signing + notarization (Developer ID Application)

CI also signs and notarizes the macOS tarballs so users can run
`bwx`/`bwx-agent` straight from a notarized download without
Gatekeeper prompts. Requires a paid Apple Developer account.

This layer is independent of layers 1–2: skip it (don't set the
secrets) and macOS users get an unsigned tarball that they can still
install manually with `xattr -d com.apple.quarantine` after download.

### One-time setup

1. **Export the Developer ID Application certificate from your
   keychain.** Keychain Access → My Certificates → right-click
   "Developer ID Application: Your Name (TEAMID)" → Export → `.p12`.
   Choose a strong passphrase. Save the file somewhere ephemeral.

   ```sh
   # base64 the cert for storing in a GitHub secret
   base64 -i ~/Downloads/bwx-developer-id.p12 | pbcopy
   ```

   Add two repo secrets:
   - `MACOS_DEVELOPER_ID_CERT_P12` — paste from the clipboard above
   - `MACOS_DEVELOPER_ID_CERT_PASSWORD` — the .p12 passphrase

2. **Create an App Store Connect API key for notarization.** Sign in
   at <https://appstoreconnect.apple.com/access/integrations/api>,
   create a key with the **"Developer"** role. Download the `.p8`
   file (one-shot download — back it up offline).

   Add three repo secrets:
   - `MACOS_NOTARIZATION_API_KEY_ID` — the 10-char Key ID shown next
     to the key (e.g. `6F8H9JKLMN`)
   - `MACOS_NOTARIZATION_API_KEY_ISSUER_ID` — the UUID at the top of
     the API Keys page (one per organisation)
   - `MACOS_NOTARIZATION_API_KEY_P8` — base64 of the downloaded `.p8`
     file:
     ```sh
     base64 -i AuthKey_6F8H9JKLMN.p8 | pbcopy
     ```

3. **Verify locally before tagging.** With your Developer ID cert
   already in the login keychain:

   ```sh
   HARDENED_RUNTIME=1 ./scripts/sign-macos.sh ~/.cargo/bin
   codesign -dv --verbose=4 ~/.cargo/bin/bwx
   # → "flags=0x10000(runtime)" confirms hardened runtime is on
   # → "TeamIdentifier=…" + "keychain-access-groups=…" confirms entitlements
   ```

### What CI does on each tagged release

- Imports the .p12 into a per-job temporary keychain (random PW, deleted at job-end).
- Runs `scripts/sign-macos.sh` with `HARDENED_RUNTIME=1` so binaries get the hardened runtime + the `keychain-access-groups` and `allow-unsigned-executable-memory` entitlements.
- Bundles `bwx` + `bwx-agent` + completions + docs into the per-target tarball.
- Submits the tarball to Apple's Notary Service via `notarytool submit --wait`. Bare CLI binaries inside a tarball can't be stapled — the notarization ticket is recorded server-side and Gatekeeper validates online on first run.
- Tears down the keychain even if any prior step failed (`if: always()`).

### What macOS users see

```sh
# Download from GitHub Releases, untar, run.
tar xzf bwx-cli-2.0.0-aarch64-apple-darwin.tar.gz
cd bwx-cli-2.0.0-aarch64-apple-darwin/
./bwx --version
# Gatekeeper checks the notarization ticket once, online, then caches
# the result. No "unidentified developer" prompt.
```

### Rotating the cert

When the .p12 expires (Apple Developer certs are good for ~5 years):
1. Generate / download a new Developer ID Application cert from
   developer.apple.com → Certificates.
2. Re-export to .p12 and update both `MACOS_DEVELOPER_ID_CERT_*`
   secrets.
3. Existing notarized binaries stay valid (Apple's ticket is bound
   to the binary's hash, not the cert's lifetime).

The App Store Connect API key has no expiration but can be revoked
from the same page. If revoked, regenerate and update the three
`MACOS_NOTARIZATION_*` secrets.

---

## Layer 3 — Tag protection + Immutable Releases (one-time repo settings)

Both are GitHub-side toggles that close off the "edit a release after
publish" hole that signing alone can't address.

### A. Enable Immutable Releases (beta)

Settings → Code, planning, and automation → **Releases** →
turn on **"Immutable releases"**.

Once enabled, after a release is published:

- Its assets can't be added, edited, or deleted.
- The backing tag can't be moved or recreated.
- The release notes / metadata are frozen.

This means a leaked admin token can't silently swap a `.deb` after
release.

### B. Add a tag protection ruleset

Settings → Rules → **Rulesets** → New ruleset → Tag.

- **Target**: `refs/tags/v*` (include all version tags).
- **Bypass list**: maintainers only (or empty for max strictness).
- **Rules**:
  - ☑ Restrict creations (only push, not Web UI surprise tag).
  - ☑ Restrict updates (no force-push tags).
  - ☑ Restrict deletions (no `git push --delete`).
  - ☑ Require signed commits (optional but recommended for the tag's
    target commit).

This stops accidental or malicious tag rewrites that would otherwise
produce a "different binary at same tag" attack against pinned
dependencies.

### C. Restrict who can publish releases

Settings → Code, planning, and automation → **Actions** → Workflow
permissions → ensure releases are only created by the workflow
itself, not arbitrary collaborators. Combine with branch protection
on `main` so only reviewed code reaches a release tag.

---

## Auditing past releases

Every release is independently auditable after the fact:

```sh
# All attestations the repo has ever published, newest first.
gh api -X GET '/repos/drewcarlson/bwx-cli/attestations?per_page=20' \
  | jq '.attestations[] | {bundle, subject_digest: .bundle.dsseEnvelope.payload}'

# The transparency log entry behind a specific attestation.
gh attestation verify <file> --repo drewcarlson/bwx-cli --format json \
  | jq '.[].verificationResult.signature.certificate'
```

Sigstore's rekor log is append-only and publicly searchable — the
cryptographic record can't be silently rewritten even by a repo
admin.
