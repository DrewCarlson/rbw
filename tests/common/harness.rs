use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::server::VaultwardenServer;

pub struct BwxHarness {
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

impl BwxHarness {
    pub fn new(
        server: &VaultwardenServer,
        email: &str,
        password: &str,
    ) -> Self {
        let tempdir = tempfile::tempdir().expect("create bwx tempdir");
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
        // macOS always resolves to `$HOME/Library/Application Support/bwx`.
        let bwx_cfg_dir = if cfg!(target_os = "macos") {
            home.join("Library/Application Support/bwx")
        } else {
            config_home.join("bwx")
        };
        std::fs::create_dir_all(&bwx_cfg_dir).expect("mkdir bwx config dir");
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
            "macos_unlock_dialog": false,
        });
        std::fs::write(
            bwx_cfg_dir.join("config.json"),
            serde_json::to_string_pretty(&cfg).unwrap(),
        )
        .expect("write config.json");

        // Fake pinentry that speaks just enough of the Assuan protocol to
        // satisfy src/pinentry.rs.
        let pinentry_path = root.join("fake-pinentry.sh");
        let script = format!(
            "#!/bin/sh\n\
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

        // Rewrite config.json with the real pinentry path.
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
            "macos_unlock_dialog": false,
        });
        std::fs::write(
            bwx_cfg_dir.join("config.json"),
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

    /// Build a `Command` for the bwx binary under test, with all XDG env
    /// variables pointed at this harness's tempdir.
    pub fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bwx"));
        self.apply_env(&mut cmd);
        cmd
    }

    /// Run `bwx <args...>` and return the captured output. Panics on spawn
    /// failure but always returns `Output` — the caller decides how to handle
    /// non-zero exit.
    pub fn run(&self, args: &[&str]) -> std::process::Output {
        self.cmd()
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("spawn bwx {args:?}: {e}"))
    }

    /// Replace the fake pinentry script so CONFIRM dialogs reply with an
    /// Assuan error (user cancelled). GETPIN still returns the master
    /// password so unlock flows keep working.
    pub fn reject_confirm_prompts(&self) {
        let script = format!(
            "#!/bin/sh\n\
             printf 'OK Pleased to meet you\\n'\n\
             while IFS= read -r line; do\n\
                 case \"$line\" in\n\
                     GETPIN*)\n\
                         printf 'D %s\\n' {pw}\n\
                         printf 'OK\\n'\n\
                         ;;\n\
                     CONFIRM*)\n\
                         printf 'ERR 83886179 canceled\\n'\n\
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
            pw = shell_escape(&self.password),
        );
        std::fs::write(&self.pinentry_path, script)
            .expect("rewrite pinentry");
    }

    /// Same as `run` but asserts the command exited 0 and returns stdout as
    /// `String`. Dumps both streams plus agent logs into the panic message on
    /// failure.
    pub fn check(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "bwx {args:?} failed: status={:?}\nstdout={}\nstderr={}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
            self.agent_logs(),
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    /// Snapshot of whatever bwx-agent has written to its redirected stdout/
    /// stderr files. Useful for diagnosing failures since the daemonized
    /// agent detaches from the test harness's stream capture.
    pub fn agent_logs(&self) -> String {
        let data_dir = if cfg!(target_os = "macos") {
            self.home.join("Library/Application Support/bwx")
        } else {
            self.data_home.join("bwx")
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

    /// Run `bwx <args...>` feeding `stdin_data` on standard input.
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
            .unwrap_or_else(|e| panic!("spawn bwx {args:?}: {e}"));
        {
            let mut stdin = child.stdin.take().expect("stdin piped");
            stdin.write_all(stdin_data).expect("write to bwx stdin");
        }
        child
            .wait_with_output()
            .unwrap_or_else(|e| panic!("wait bwx {args:?}: {e}"))
    }

    /// Log into the server and unlock the vault.
    pub fn login_and_unlock(&self) {
        self.check(&["login"]);
        self.check(&["unlock"]);
    }

    /// Install an `$EDITOR` that rewrites the supplied tempfile with
    /// `new_contents` exactly, so `bwx edit` / `bwx add` become deterministic.
    pub fn fake_editor(&self, new_contents: &str) -> PathBuf {
        let path = self.tempdir.path().join("fake-editor.sh");
        let body = format!(
            "#!/bin/sh\n\
             cat <<'__BWX_E2E_EOF__' > \"$1\"\n{new_contents}\n__BWX_E2E_EOF__\n",
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
            .env("BWX_AGENT", env!("CARGO_BIN_EXE_bwx-agent"))
            .env_remove("BWX_PROFILE")
            .env_remove("DISPLAY")
            .env_remove("WAYLAND_DISPLAY")
            .env_remove("SSH_AUTH_SOCK");
    }
}

impl Drop for BwxHarness {
    fn drop(&mut self) {
        // Stop any agent this harness spawned so it releases the socket
        // before the tempdir is unlinked.
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bwx"));
        self.apply_env(&mut cmd);
        let _ = cmd
            .arg("stop-agent")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

pub(super) fn shell_escape(s: &str) -> String {
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
