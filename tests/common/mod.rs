//! Shared helpers for the rbw integration tests.
//!
//! This module intentionally lives under `tests/` rather than as a dev-only
//! library crate — it is only ever compiled as part of the `e2e` integration
//! test binary, and is allowed to rely on public APIs of the `rbw` library
//! crate (`src/lib.rs`).

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

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rsa::pkcs8::{EncodePrivateKey as _, EncodePublicKey as _};

// Re-use rbw's own crypto primitives so the registration payload exactly
// matches what the production client would generate/accept.
use rbw::cipherstring::CipherString;
use rbw::identity::Identity;
use rbw::locked;

// ---------------------------------------------------------------------------
// Vaultwarden subprocess
// ---------------------------------------------------------------------------

pub struct VaultwardenServer {
    pub base_url: String,
    pub port: u16,
    child: Child,
    #[allow(dead_code)] // held for RAII cleanup
    data_dir: tempfile::TempDir,
}

impl VaultwardenServer {
    /// Start a fresh vaultwarden instance on an ephemeral port.
    ///
    /// Returns `None` if the `vaultwarden` binary cannot be located, so
    /// callers can gracefully skip the test.
    pub fn start() -> Option<Self> {
        let bin = find_vaultwarden()?;
        let data_dir =
            tempfile::tempdir().expect("create vaultwarden tempdir");
        let port = pick_free_port();
        let base_url = format!("http://127.0.0.1:{port}");

        let mut cmd = Command::new(&bin);
        cmd.env("DATA_FOLDER", data_dir.path())
            .env("ROCKET_PORT", port.to_string())
            .env("ROCKET_ADDRESS", "127.0.0.1")
            .env("DOMAIN", &base_url)
            .env("SIGNUPS_ALLOWED", "true")
            .env("SIGNUPS_VERIFY", "false")
            .env("DISABLE_ICON_DOWNLOAD", "true")
            .env("WEB_VAULT_ENABLED", "false")
            // Keep the log volume down unless the caller opted in.
            .env(
                "ROCKET_LOG_LEVEL",
                std::env::var("VAULTWARDEN_LOG_LEVEL")
                    .unwrap_or_else(|_| "critical".to_string()),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = cmd.spawn().unwrap_or_else(|e| {
            panic!("failed to spawn {}: {e}", bin.display())
        });

        let server = Self {
            base_url,
            port,
            child,
            data_dir,
        };

        if let Err(e) = server.wait_until_ready(Duration::from_secs(10)) {
            // Best-effort: the Drop impl will kill the child.
            panic!("vaultwarden did not become ready: {e}");
        }
        Some(server)
    }

    fn wait_until_ready(&self, timeout: Duration) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(500))
            .build()
            .map_err(|e| format!("build reqwest client: {e}"))?;
        let url = format!("{}/alive", self.base_url);
        let mut last_err = String::from("never attempted");
        while Instant::now() < deadline {
            match client.get(&url).send() {
                Ok(r) if r.status().is_success() => return Ok(()),
                Ok(r) => last_err = format!("HTTP {}", r.status()),
                Err(e) => last_err = e.to_string(),
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        Err(last_err)
    }
}

impl Drop for VaultwardenServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn find_vaultwarden() -> Option<PathBuf> {
    if let Ok(v) = std::env::var("VAULTWARDEN_BIN") {
        if !v.is_empty() {
            let p = PathBuf::from(v);
            if p.exists() {
                return Some(p);
            }
            return None;
        }
    }
    // Search $PATH.
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("vaultwarden");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn pick_free_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = l.local_addr().expect("local_addr").port();
    drop(l);
    port
}

// ---------------------------------------------------------------------------
// rbw harness
// ---------------------------------------------------------------------------

pub struct RbwHarness {
    pub email: String,
    pub password: String,
    pub base_url: String,
    pub tempdir: tempfile::TempDir,
    pub config_home: PathBuf,
    pub cache_home: PathBuf,
    pub data_home: PathBuf,
    pub runtime_dir: PathBuf,
    pub home: PathBuf,
    pub pinentry_path: PathBuf,
}

impl RbwHarness {
    pub fn new(
        server: &VaultwardenServer,
        email: &str,
        password: &str,
    ) -> Self {
        let tempdir = tempfile::tempdir().expect("create rbw tempdir");
        let root = tempdir.path();

        let config_home = root.join("config");
        let cache_home = root.join("cache");
        let data_home = root.join("data");
        let runtime_dir = root.join("run");
        let home = root.join("home");
        for d in [&config_home, &cache_home, &data_home, &runtime_dir, &home]
        {
            std::fs::create_dir_all(d).expect("mkdir tempdir child");
        }

        // `directories::ProjectDirs` honors `XDG_CONFIG_HOME` on Linux but on
        // macOS always resolves to `$HOME/Library/Application Support/rbw`.
        // Compute the right path per platform.
        let rbw_cfg_dir = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/rbw")
        } else {
            config_home.join("rbw")
        };
        std::fs::create_dir_all(&rbw_cfg_dir).expect("mkdir rbw config dir");
        let cfg = serde_json::json!({
            "email": email,
            "base_url": server.base_url,
            "identity_url": format!("{}/identity", server.base_url),
            "lock_timeout": 3600,
            "sync_interval": 3600,
            "pinentry": "pinentry",
            "client_cert_path": null,
            "device_id": null,
            "sso_id": null,
            "ui_url": null,
            "notifications_url": null,
        });
        std::fs::write(
            rbw_cfg_dir.join("config.json"),
            serde_json::to_string_pretty(&cfg).unwrap(),
        )
        .expect("write config.json");

        // Write a fake pinentry that speaks just enough of the Assuan
        // protocol to satisfy src/pinentry.rs.
        let pinentry_path = root.join("fake-pinentry.sh");
        let script = format!(
            "#!/bin/sh\n\
             # Minimal Assuan-protocol pinentry that always answers with the\n\
             # test master password. Reads client commands on stdin and replies\n\
             # on stdout.\n\
             printf 'OK Pleased to meet you\\n'\n\
             while IFS= read -r line; do\n\
                 case \"$line\" in\n\
                     GETPIN*)\n\
                         printf 'D %s\\n' {pw}\n\
                         printf 'OK\\n'\n\
                         ;;\n\
                     BYE*)\n\
                         printf 'OK closing connection\\n'\n\
                         exit 0\n\
                         ;;\n\
                     *)\n\
                         printf 'OK\\n'\n\
                         ;;\n\
                 esac\n\
             done\n",
            pw = shell_escape(password),
        );
        std::fs::write(&pinentry_path, script).expect("write pinentry");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut perms = std::fs::metadata(&pinentry_path)
                .expect("stat pinentry")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&pinentry_path, perms)
                .expect("chmod pinentry");
        }

        // Re-write config.json with the real pinentry path now that we know
        // it.
        let cfg = serde_json::json!({
            "email": email,
            "base_url": server.base_url,
            "identity_url": format!("{}/identity", server.base_url),
            "lock_timeout": 3600,
            "sync_interval": 3600,
            "pinentry": pinentry_path.to_string_lossy(),
            "client_cert_path": null,
            "device_id": null,
            "sso_id": null,
            "ui_url": null,
            "notifications_url": null,
        });
        std::fs::write(
            rbw_cfg_dir.join("config.json"),
            serde_json::to_string_pretty(&cfg).unwrap(),
        )
        .expect("rewrite config.json");

        Self {
            email: email.to_string(),
            password: password.to_string(),
            base_url: server.base_url.clone(),
            tempdir,
            config_home,
            cache_home,
            data_home,
            runtime_dir,
            home,
            pinentry_path,
        }
    }

    /// Build a `Command` for the rbw binary under test, with all XDG env
    /// variables pointed at this harness's tempdir.
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rbw"));
        self.apply_env(&mut cmd);
        cmd
    }

    /// Run `rbw <args...>` and return the captured output. Panics on spawn
    /// failure but always returns `Output` — the caller decides how to handle
    /// non-zero exit.
    pub fn run(&self, args: &[&str]) -> std::process::Output {
        self.cmd()
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("spawn rbw {args:?}: {e}"))
    }

    /// Same as `run` but asserts the command exited 0 and returns stdout as
    /// `String`. Dumps both streams plus agent logs into the panic message on
    /// failure.
    pub fn check(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "rbw {args:?} failed: status={:?}\nstdout={}\nstderr={}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            self.agent_logs(),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Snapshot of whatever rbw-agent has written to its redirected stdout/
    /// stderr files. Useful for diagnosing failures since the daemonized
    /// agent detaches from the test harness's stream capture.
    pub fn agent_logs(&self) -> String {
        let data_dir = if cfg!(target_os = "macos") {
            self.home.join("Library/Application Support/rbw")
        } else {
            self.data_home.join("rbw")
        };
        let mut out = String::new();
        for (name, rel) in
            [("agent.err", "agent.err"), ("agent.out", "agent.out")]
        {
            let path = data_dir.join(rel);
            match std::fs::read_to_string(&path) {
                Ok(s) if !s.is_empty() => {
                    use std::fmt::Write as _;
                    let _ =
                        writeln!(out, "--- {name} ({}) ---", path.display());
                    out.push_str(&s);
                    if !s.ends_with('\n') {
                        out.push('\n');
                    }
                }
                _ => {}
            }
        }
        if out.is_empty() {
            out.push_str("(agent logs empty or missing)\n");
        }
        out
    }

    /// Run `rbw <args...>` feeding `stdin_data` on standard input.
    pub fn run_with_stdin(
        &self,
        args: &[&str],
        stdin_data: &[u8],
    ) -> std::process::Output {
        use std::io::Write as _;

        let mut child = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn rbw {args:?}: {e}"));
        {
            let mut stdin = child.stdin.take().expect("stdin piped");
            stdin.write_all(stdin_data).expect("write to rbw stdin");
        }
        child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("wait rbw {args:?}: {e}"))
    }

    /// Log into the server + unlock the vault. Used as the first step of
    /// almost every scenario.
    pub fn login_and_unlock(&self) {
        self.check(&["login"]);
        self.check(&["unlock"]);
    }

    /// Convenience: install an `$EDITOR` that rewrites the supplied tempfile
    /// with `new_contents` exactly, so `rbw edit` / `rbw add` become
    /// deterministic. The script is written under the harness tempdir and its
    /// path is returned — callers set it on `cmd()` via `.env("EDITOR", ...)`.
    pub fn fake_editor(&self, new_contents: &str) -> PathBuf {
        let path = self.tempdir.path().join("fake-editor.sh");
        let body = format!(
            "#!/bin/sh\n\
             # Overwrite the file rbw passed us with a fixed payload.\n\
             cat <<'__RBW_E2E_EOF__' > \"$1\"\n{new_contents}\n__RBW_E2E_EOF__\n",
        );
        std::fs::write(&path, body).expect("write fake editor");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mut p =
                std::fs::metadata(&path).expect("stat editor").permissions();
            p.set_mode(0o755);
            std::fs::set_permissions(&path, p).expect("chmod editor");
        }
        path
    }

    fn apply_env(&self, cmd: &mut Command) {
        cmd.env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_CACHE_HOME", &self.cache_home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("HOME", &self.home)
            .env("RBW_AGENT", env!("CARGO_BIN_EXE_rbw-agent"))
            // Keep tests non-interactive and deterministic.
            .env_remove("RBW_PROFILE")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("SSH_AUTH_SOCK");
    }
}

impl Drop for RbwHarness {
    fn drop(&mut self) {
        // Best-effort: stop any agent this harness may have spawned so it
        // releases the socket before the tempdir is unlinked.
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rbw"));
        self.apply_env(&mut cmd);
        let _ = cmd
            .arg("stop-agent")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

fn shell_escape(s: &str) -> String {
    // Single-quote wrap, escaping embedded single quotes.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

// ---------------------------------------------------------------------------
// User registration against vaultwarden
// ---------------------------------------------------------------------------

const KDF_ITERATIONS: u32 = 600_000;
const KDF_TYPE_PBKDF2: u8 = 0;

/// Register a new account on the given vaultwarden server using the
/// Bitwarden `/identity/accounts/register` endpoint. Mirrors the bitwarden
/// web vault's registration payload: derives a master key via PBKDF2, wraps a
/// random 64-byte vault key with it, and attaches a freshly-generated RSA
/// keypair.
pub fn register_user(
    server: &VaultwardenServer,
    email: &str,
    password: &str,
) -> Result<(), String> {
    // 1. Derive master key + master-password hash via rbw's Identity type.
    let mut pw_vec = locked::Vec::new();
    pw_vec.extend(password.as_bytes().iter().copied());
    let locked_pw = locked::Password::new(pw_vec);

    let identity = Identity::new(
        email,
        &locked_pw,
        // KdfType::Pbkdf2 is #[repr] but the enum isn't public as u8; pass
        // via the public type.
        rbw::api::KdfType::Pbkdf2,
        KDF_ITERATIONS,
        None,
        None,
    )
    .map_err(|e| format!("derive identity: {e}"))?;

    // 2. Generate a random 64-byte vault key (enc_key||mac_key) and wrap it
    //    with the stretched master key.
    use rand_8::RngCore as _;
    let mut vault_bytes = [0u8; 64];
    rand_8::rngs::OsRng.fill_bytes(&mut vault_bytes);

    let protected_symmetric_key =
        CipherString::encrypt_symmetric(&identity.keys, &vault_bytes)
            .map_err(|e| format!("encrypt vault key: {e}"))?
            .to_string();

    // 3. Build a locked::Keys around the vault key for wrapping the private
    //    key below.
    let mut vault_keys_buf = locked::Vec::new();
    vault_keys_buf.extend(vault_bytes.iter().copied());
    let vault_keys = locked::Keys::new(vault_keys_buf);

    // 4. Generate an RSA-2048 keypair. Public key is sent as raw SPKI DER
    //    (base64), private key is wrapped PKCS#8 DER with the vault key.
    let mut rng = rand_8::rngs::OsRng;
    let rsa_priv = rsa::RsaPrivateKey::new(&mut rng, 2048)
        .map_err(|e| format!("generate rsa: {e}"))?;
    let rsa_pub = rsa::RsaPublicKey::from(&rsa_priv);

    let pub_spki_der = rsa_pub
        .to_public_key_der()
        .map_err(|e| format!("encode rsa pub: {e}"))?;
    let pub_b64 = base64_encode(pub_spki_der.as_bytes());

    let priv_pkcs8 = rsa_priv
        .to_pkcs8_der()
        .map_err(|e| format!("encode rsa priv: {e}"))?;
    let wrapped_priv =
        CipherString::encrypt_symmetric(&vault_keys, priv_pkcs8.as_bytes())
            .map_err(|e| format!("wrap rsa priv: {e}"))?
            .to_string();

    // 5. Base64-encode the master-password hash.
    let mph_b64 = base64_encode(identity.master_password_hash.hash());

    // 6. POST the registration.
    let body = serde_json::json!({
        "email": email,
        "name": email,
        "masterPasswordHash": mph_b64,
        "masterPasswordHint": null,
        "key": protected_symmetric_key,
        "keys": {
            "publicKey": pub_b64,
            "encryptedPrivateKey": wrapped_priv,
        },
        "kdf": KDF_TYPE_PBKDF2,
        "kdfIterations": KDF_ITERATIONS,
        "referenceData": null,
    });

    let url = format!("{}/identity/accounts/register", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .map_err(|e| format!("POST register: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!("register failed: {status} body={text}"));
    }
    Ok(())
}

fn base64_encode(b: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.encode(b)
}

fn base64_encode_url_safe_no_pad(b: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(b)
}

// ---------------------------------------------------------------------------
// Authenticated API helper — for tests that need to create entries the way
// "another client" would (outside of the rbw binary under test), most
// commonly to populate a field like `totp` that rbw's CLI can't set.
// ---------------------------------------------------------------------------

pub struct Account {
    pub access_token: String,
    pub vault_keys: locked::Keys,
}

/// Authenticate against vaultwarden's /identity/connect/token password flow.
/// Mirrors what rbw's own login does, but runs in-process so tests can POST
/// ciphers directly to the server.
pub fn authenticate(
    server: &VaultwardenServer,
    email: &str,
    password: &str,
) -> Result<Account, String> {
    let mut pw_vec = locked::Vec::new();
    pw_vec.extend(password.as_bytes().iter().copied());
    let locked_pw = locked::Password::new(pw_vec);

    let identity = Identity::new(
        email,
        &locked_pw,
        rbw::api::KdfType::Pbkdf2,
        KDF_ITERATIONS,
        None,
        None,
    )
    .map_err(|e| format!("derive identity: {e}"))?;

    let form = [
        ("grant_type", "password"),
        ("scope", "api offline_access"),
        ("client_id", "cli"),
        ("deviceType", "8"),
        ("deviceIdentifier", "00000000-0000-0000-0000-000000000001"),
        ("deviceName", "rbw-e2e"),
        ("devicePushToken", ""),
        ("username", email),
        (
            "password",
            &base64_encode(identity.master_password_hash.hash()),
        ),
    ];

    let url = format!("{}/identity/connect/token", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .header(
            "auth-email",
            base64_encode_url_safe_no_pad(email.as_bytes()),
        )
        .form(&form)
        .send()
        .map_err(|e| format!("POST token: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!("token failed: {status} body={text}"));
    }
    let body: serde_json::Value =
        resp.json().map_err(|e| format!("token json: {e}"))?;
    let access_token = body
        .get("access_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no access_token in response: {body}"))?
        .to_string();
    let protected_key = body
        .get("Key")
        .or_else(|| body.get("key"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("no key in response: {body}"))?;

    let wrapped = CipherString::new(protected_key)
        .map_err(|e| format!("parse key: {e}"))?;
    let vault_vec = wrapped
        .decrypt_locked_symmetric(&identity.keys)
        .map_err(|e| format!("unwrap vault key: {e}"))?;
    let vault_keys = locked::Keys::new(vault_vec);

    Ok(Account {
        access_token,
        vault_keys,
    })
}

/// Upload an `SshKey` cipher (Bitwarden type 5). `private_key_openssh` is
/// the full PEM-wrapped OpenSSH private key; `public_key_openssh` is the
/// single line `ssh-ed25519 AAAA... [comment]` form; `fingerprint` is
/// typically `SHA256:…`. All three are encrypted client-side.
pub fn upload_ssh_cipher(
    server: &VaultwardenServer,
    account: &Account,
    name: &str,
    private_key_openssh: &str,
    public_key_openssh: &str,
    fingerprint: &str,
) -> Result<(), String> {
    let encrypt = |s: &str| -> Result<String, String> {
        CipherString::encrypt_symmetric(&account.vault_keys, s.as_bytes())
            .map(|c| c.to_string())
            .map_err(|e| format!("encrypt field: {e}"))
    };

    let body = serde_json::json!({
        "type": 5,
        "name": encrypt(name)?,
        "notes": null,
        "favorite": false,
        "folderId": null,
        "organizationId": null,
        "sshKey": {
            "privateKey": encrypt(private_key_openssh)?,
            "publicKey": encrypt(public_key_openssh)?,
            "keyFingerprint": encrypt(fingerprint)?,
        },
    });

    let url = format!("{}/api/ciphers", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&account.access_token)
        .json(&body)
        .send()
        .map_err(|e| format!("POST ssh cipher: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!(
            "ssh cipher upload failed: {status} body={text}"
        ));
    }
    Ok(())
}

/// Upload a Login cipher with the supplied plaintext fields. Everything
/// listed on the cipher is encrypted client-side with the account's vault
/// key first; vaultwarden never sees plaintext.
pub fn upload_login_cipher(
    server: &VaultwardenServer,
    account: &Account,
    name: &str,
    totp: Option<&str>,
    username: Option<&str>,
    password_value: Option<&str>,
) -> Result<(), String> {
    let encrypt = |s: &str| -> Result<String, String> {
        CipherString::encrypt_symmetric(&account.vault_keys, s.as_bytes())
            .map(|c| c.to_string())
            .map_err(|e| format!("encrypt field: {e}"))
    };

    let enc_name = encrypt(name)?;
    let enc_totp = totp.map(encrypt).transpose()?;
    let enc_user = username.map(encrypt).transpose()?;
    let enc_password = password_value.map(encrypt).transpose()?;

    let body = serde_json::json!({
        "type": 1,
        "name": enc_name,
        "notes": null,
        "favorite": false,
        "folderId": null,
        "organizationId": null,
        "login": {
            "username": enc_user,
            "password": enc_password,
            "totp": enc_totp,
            "uris": null,
        },
    });

    let url = format!("{}/api/ciphers", server.base_url);
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&url)
        .bearer_auth(&account.access_token)
        .json(&body)
        .send()
        .map_err(|e| format!("POST cipher: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(format!("cipher upload failed: {status} body={text}"));
    }
    Ok(())
}

// Make sure shell_escape doesn't bit-rot if the harness ever stops using it.
#[cfg(test)]
mod unit {
    use super::shell_escape;

    #[test]
    fn escape_preserves_plain() {
        assert_eq!(shell_escape("abc"), "'abc'");
    }

    #[test]
    fn escape_embeds_single_quote() {
        assert_eq!(shell_escape("a'b"), "'a'\\''b'");
    }

    #[allow(dead_code)]
    fn _hush_unused(_: &super::RbwHarness) {}
}
