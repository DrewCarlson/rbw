//! Shared helpers for the rbw integration tests.
//!
//! This module intentionally lives under `tests/` rather than as a dev-only
//! library crate — it is only ever compiled as part of the `e2e` integration
//! test binary, and is allowed to rely on public APIs of the `rbw` library
//! crate (`src/lib.rs`).

#![allow(dead_code)] // shared helpers; not every scenario uses everything.

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
        let data_dir = tempfile::tempdir().expect("create vaultwarden tempdir");
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
            // Keep the log volume down unless the caller opted in.
            .env(
                "ROCKET_LOG_LEVEL",
                std::env::var("VAULTWARDEN_LOG_LEVEL")
                    .unwrap_or_else(|_| "critical".to_string()),
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = cmd
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {bin:?}: {e}"));

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
    pub fn new(server: &VaultwardenServer, email: &str, password: &str) -> Self {
        let tempdir = tempfile::tempdir().expect("create rbw tempdir");
        let root = tempdir.path();

        let config_home = root.join("config");
        let cache_home = root.join("cache");
        let data_home = root.join("data");
        let runtime_dir = root.join("run");
        let home = root.join("home");
        for d in [
            &config_home,
            &cache_home,
            &data_home,
            &runtime_dir,
            &home,
        ] {
            std::fs::create_dir_all(d).expect("mkdir tempdir child");
        }

        // Write config.json pointing at the ephemeral vaultwarden instance.
        // rbw's `dirs::profile()` returns "rbw" when `RBW_PROFILE` is unset,
        // so the config path is `<config_home>/rbw/config.json`.
        let rbw_cfg_dir = config_home.join("rbw");
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

    fn apply_env(&self, cmd: &mut Command) {
        cmd.env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_CACHE_HOME", &self.cache_home)
            .env("XDG_DATA_HOME", &self.data_home)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("HOME", &self.home)
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
