//! On-disk wrapper blob for Touch ID-enrolled vault keys.
//!
//! Written by `bwx touchid enroll`, read by the agent on unlock. Holds
//! `CipherString`-wrapped vault keys + the Keychain label whose item
//! holds the wrapping key. The wrapping key itself never touches
//! disk; only the encrypted blob does.
#![allow(clippy::doc_markdown)]

use crate::locked;
use crate::prelude::Error as BwxError;

const FILENAME: &str = "touchid.json";

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Blob {
    /// Keychain `kSecAttrAccount` value pointing at the wrapper key.
    pub keychain_label: String,
    /// Main vault key (64 bytes = 32 enc + 32 mac), wrapped with the
    /// Keychain-held wrapper key.
    pub wrapped_priv_key: String,
    /// Per-organization 64-byte symmetric keys, each wrapped the same
    /// way.
    pub wrapped_org_keys: std::collections::BTreeMap<String, String>,
}

impl Blob {
    pub fn path() -> std::path::PathBuf {
        crate::dirs::make_all().ok();
        // Stash under the data dir — same place agent.err etc. live.
        data_dir_for_blob().join(FILENAME)
    }

    pub fn exists() -> bool {
        Self::path().exists()
    }

    pub fn load() -> Result<Self, BwxError> {
        let path = Self::path();
        let json = std::fs::read_to_string(&path).map_err(|source| {
            BwxError::LoadConfig {
                source,
                file: path.clone(),
            }
        })?;
        serde_json::from_str(&json)
            .map_err(|source| BwxError::Json { source })
    }

    pub fn save(&self) -> Result<(), BwxError> {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
        let path = Self::path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| {
                BwxError::SaveConfig {
                    source,
                    file: path.clone(),
                }
            })?;
        }
        let json = serde_json::to_string(self)
            .map_err(|source| BwxError::Json { source })?;
        let mut fh = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .map_err(|source| BwxError::SaveConfig {
                source,
                file: path.clone(),
            })?;
        fh.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|source| BwxError::SaveConfig {
                source,
                file: path.clone(),
            })?;
        fh.write_all(json.as_bytes())
            .map_err(|source| BwxError::SaveConfig { source, file: path })?;
        Ok(())
    }

    pub fn remove() -> Result<(), BwxError> {
        let path = Self::path();
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(BwxError::SaveConfig { source, file: path }),
        }
    }
}

fn data_dir_for_blob() -> std::path::PathBuf {
    // Re-use the XDG data dir that already holds agent.err, agent.out,
    // device_id, etc.
    let p = crate::dirs::agent_stdout_file();
    p.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    )
}

/// Derive a 64-byte wrapping `Keys` from a random 64-byte seed. The
/// Keychain stores this seed; at use time we wrap it in a `locked::Keys`
/// for the existing `CipherString` APIs.
pub fn keys_from_wrapper_seed(seed: &[u8]) -> locked::Keys {
    assert_eq!(seed.len(), 64, "wrapper seed must be 64 bytes");
    let mut buf = locked::Vec::new();
    buf.extend(seed.iter().copied());
    locked::Keys::new(buf)
}
