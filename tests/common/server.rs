use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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
