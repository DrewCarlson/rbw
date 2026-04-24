use crate::prelude::*;

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};

pub fn make_all() -> Result<()> {
    create_dir_all_with_permissions(&cache_dir(), 0o700)?;
    create_dir_all_with_permissions(&runtime_dir(), 0o700)?;
    create_dir_all_with_permissions(&data_dir(), 0o700)?;

    Ok(())
}

fn create_dir_all_with_permissions(
    path: &std::path::Path,
    mode: u32,
) -> Result<()> {
    // ensure the initial directory creation happens with the correct mode,
    // to avoid race conditions
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    // but also make sure to forcibly set the mode, in case the directory
    // already existed
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|source| Error::CreateDirectory {
            source,
            file: path.to_path_buf(),
        })?;
    Ok(())
}

pub fn config_file() -> std::path::PathBuf {
    config_dir().join("config.json")
}

pub fn db_file(server: &str, email: &str) -> std::path::PathBuf {
    let server = urlencoding::encode(server).into_owned();
    cache_dir().join(format!("{server}:{email}.json"))
}

pub fn pid_file() -> std::path::PathBuf {
    runtime_dir().join("pidfile")
}

pub fn agent_stdout_file() -> std::path::PathBuf {
    data_dir().join("agent.out")
}

pub fn agent_stderr_file() -> std::path::PathBuf {
    data_dir().join("agent.err")
}

pub fn device_id_file() -> std::path::PathBuf {
    data_dir().join("device_id")
}

pub fn socket_file() -> std::path::PathBuf {
    runtime_dir().join("socket")
}

pub fn ssh_agent_socket_file() -> std::path::PathBuf {
    runtime_dir().join("ssh-agent-socket")
}

fn home_dir() -> std::path::PathBuf {
    std::env::var_os("HOME").map_or_else(
        || std::path::PathBuf::from("/"),
        std::path::PathBuf::from,
    )
}

#[cfg(target_os = "macos")]
fn config_dir() -> std::path::PathBuf {
    home_dir()
        .join("Library/Application Support")
        .join(profile())
}

#[cfg(target_os = "macos")]
fn cache_dir() -> std::path::PathBuf {
    home_dir().join("Library/Caches").join(profile())
}

#[cfg(target_os = "macos")]
fn data_dir() -> std::path::PathBuf {
    config_dir()
}

#[cfg(not(target_os = "macos"))]
fn xdg_or(env: &str, fallback_rel: &str) -> std::path::PathBuf {
    std::env::var_os(env)
        .filter(|v| std::path::Path::new(v).is_absolute())
        .map_or_else(|| home_dir().join(fallback_rel), std::path::PathBuf::from)
}

#[cfg(not(target_os = "macos"))]
fn config_dir() -> std::path::PathBuf {
    xdg_or("XDG_CONFIG_HOME", ".config").join(profile())
}

#[cfg(not(target_os = "macos"))]
fn cache_dir() -> std::path::PathBuf {
    xdg_or("XDG_CACHE_HOME", ".cache").join(profile())
}

#[cfg(not(target_os = "macos"))]
fn data_dir() -> std::path::PathBuf {
    xdg_or("XDG_DATA_HOME", ".local/share").join(profile())
}

fn runtime_dir() -> std::path::PathBuf {
    #[cfg(not(target_os = "macos"))]
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR") {
        if std::path::Path::new(&d).is_absolute() {
            return std::path::PathBuf::from(d).join(profile());
        }
    }
    format!(
        "{}/{}-{}",
        std::env::temp_dir().to_string_lossy(),
        profile(),
        rustix::process::getuid().as_raw()
    )
    .into()
}

pub fn profile() -> String {
    match std::env::var("RBW_PROFILE") {
        Ok(profile) if !profile.is_empty() => format!("rbw-{profile}"),
        _ => "rbw".to_string(),
    }
}
