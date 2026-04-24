use crate::prelude::*;

use std::io::{Read as _, Write as _};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Config {
    pub email: Option<String>,
    pub sso_id: Option<String>,
    pub base_url: Option<String>,
    pub identity_url: Option<String>,
    pub ui_url: Option<String>,
    pub notifications_url: Option<String>,
    #[serde(default = "default_lock_timeout")]
    pub lock_timeout: u64,
    #[serde(default = "default_sync_interval")]
    pub sync_interval: u64,
    #[serde(default = "default_pinentry")]
    pub pinentry: String,
    pub client_cert_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub ssh_confirm_sign: bool,
    /// On macOS, controls how the master-password prompt is shown at
    /// unlock time. Default `true` renders a native `CFUserNotification`
    /// modal (works from daemonized contexts — ssh-sign, Finder-
    /// launched GUI git, etc.). Set `false` to fall back to pinentry
    /// if you prefer the terminal experience. No effect on other
    /// platforms.
    #[serde(default = "default_macos_unlock_dialog")]
    pub macos_unlock_dialog: bool,
    #[serde(
        default,
        with = "touchid_gate_serde",
        skip_serializing_if = "is_touchid_gate_off"
    )]
    pub touchid_gate: crate::touchid::Gate,
    // backcompat, no longer generated in new configs
    #[serde(skip_serializing)]
    pub device_id: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            email: None,
            sso_id: None,
            base_url: None,
            identity_url: None,
            ui_url: None,
            notifications_url: None,
            lock_timeout: default_lock_timeout(),
            sync_interval: default_sync_interval(),
            pinentry: default_pinentry(),
            client_cert_path: None,
            ssh_confirm_sign: false,
            macos_unlock_dialog: default_macos_unlock_dialog(),
            touchid_gate: crate::touchid::Gate::Off,
            device_id: None,
        }
    }
}

pub fn default_lock_timeout() -> u64 {
    3600
}

pub fn default_sync_interval() -> u64 {
    3600
}

pub fn default_pinentry() -> String {
    "pinentry".to_string()
}

pub const fn default_macos_unlock_dialog() -> bool {
    cfg!(target_os = "macos")
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_touchid_gate_off(g: &crate::touchid::Gate) -> bool {
    matches!(g, crate::touchid::Gate::Off)
}

mod touchid_gate_serde {
    use std::str::FromStr as _;

    use serde::{Deserialize as _, Deserializer, Serializer};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S: Serializer>(
        g: &crate::touchid::Gate,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(&g.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<crate::touchid::Gate, D::Error> {
        let s = String::deserialize(d)?;
        crate::touchid::Gate::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh = std::fs::File::open(&file).map_err(|source| {
            Error::LoadConfig {
                source,
                file: file.clone(),
            }
        })?;
        let mut json = String::new();
        fh.read_to_string(&mut json)
            .map_err(|source| Error::LoadConfig {
                source,
                file: file.clone(),
            })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub async fn load_async() -> Result<Self> {
        let file = crate::dirs::config_file();
        let mut fh =
            tokio::fs::File::open(&file).await.map_err(|source| {
                Error::LoadConfigAsync {
                    source,
                    file: file.clone(),
                }
            })?;
        let mut json = String::new();
        fh.read_to_string(&mut json).await.map_err(|source| {
            Error::LoadConfigAsync {
                source,
                file: file.clone(),
            }
        })?;
        let mut slf: Self = serde_json::from_str(&json)
            .map_err(|source| Error::LoadConfigJson { source, file })?;
        if slf.lock_timeout == 0 {
            log::warn!("lock_timeout must be greater than 0");
            slf.lock_timeout = default_lock_timeout();
        }
        Ok(slf)
    }

    pub fn save(&self) -> Result<()> {
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let file = crate::dirs::config_file();
        // unwrap is safe here because Self::filename is explicitly
        // constructed as a filename in a directory
        std::fs::create_dir_all(file.parent().unwrap()).map_err(
            |source| Error::SaveConfig {
                source,
                file: file.clone(),
            },
        )?;
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file)
            .map_err(|source| Error::SaveConfig {
                source,
                file: file.clone(),
            })?;
        // `OpenOptions::mode` only applies on file creation; if the
        // file already exists (e.g. a user created it with a looser
        // mode) we still want to tighten it every time rbw writes.
        fh.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| Error::SaveConfig {
                source,
                file: file.clone(),
            })?;
        fh.write_all(
            serde_json::to_string(self)
                .map_err(|source| Error::SaveConfigJson {
                    source,
                    file: file.clone(),
                })?
                .as_bytes(),
        )
        .map_err(|source| Error::SaveConfig { source, file })?;
        Ok(())
    }

    pub fn validate() -> Result<()> {
        let config = Self::load()?;
        if config.email.is_none() {
            return Err(Error::ConfigMissingEmail);
        }
        Ok(())
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone().map_or_else(
            || "https://api.bitwarden.com".to_string(),
            |url| {
                let clean_url = url.trim_end_matches('/');
                if clean_url == "https://api.bitwarden.eu" {
                    "https://api.bitwarden.eu".to_string()
                } else {
                    format!("{clean_url}/api")
                }
            },
        )
    }

    pub fn identity_url(&self) -> String {
        self.identity_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://identity.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://identity.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/identity")
                    }
                },
            )
        })
    }

    pub fn ui_url(&self) -> String {
        self.ui_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://vault.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://vault.bitwarden.eu".to_string()
                    } else {
                        clean_url.to_string()
                    }
                },
            )
        })
    }

    pub fn notifications_url(&self) -> String {
        self.notifications_url.clone().unwrap_or_else(|| {
            self.base_url.clone().map_or_else(
                || "https://notifications.bitwarden.com".to_string(),
                |url| {
                    let clean_url = url.trim_end_matches('/');
                    if clean_url == "https://api.bitwarden.eu" {
                        "https://notifications.bitwarden.eu".to_string()
                    } else {
                        format!("{clean_url}/notifications")
                    }
                },
            )
        })
    }

    pub fn client_cert_path(&self) -> Option<&std::path::Path> {
        self.client_cert_path.as_deref()
    }

    pub fn server_name(&self) -> String {
        self.base_url
            .clone()
            .unwrap_or_else(|| "default".to_string())
    }
}

pub async fn device_id(config: &Config) -> Result<String> {
    let file = crate::dirs::device_id_file();
    if let Ok(mut fh) = tokio::fs::File::open(&file).await {
        let mut s = String::new();
        fh.read_to_string(&mut s)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        Ok(s.trim().to_string())
    } else {
        use std::os::unix::fs::PermissionsExt as _;
        let id = config.device_id.as_ref().map_or_else(
            || crate::uuid::new_v4().to_string(),
            String::to_string,
        );
        let mut fh = tokio::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&file)
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        // `OpenOptions::mode` only applies on create; tighten
        // unconditionally so a pre-existing loose-mode file gets
        // corrected on the next write.
        fh.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(|e| Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            })?;
        fh.write_all(id.as_bytes()).await.map_err(|e| {
            Error::LoadDeviceId {
                source: e,
                file: file.clone(),
            }
        })?;
        Ok(id)
    }
}
