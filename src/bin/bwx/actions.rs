use std::{io::Read as _, os::unix::ffi::OsStringExt as _};

use crate::bin_error;

/// Per-CLI-process session identifier. Attached to every outbound
/// request so the agent can collapse a single `bwx <command>` invocation
/// into one Touch ID prompt even when it fires many `Decrypt`/`Encrypt`
/// IPCs.
fn session_id() -> String {
    static ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ID.get_or_init(|| bwx::uuid::new_v4().to_string()).clone()
}

/// Human-readable command description surfaced in biometric and pinentry
/// prompts on the agent side. Set once at startup from `main.rs`.
static PURPOSE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn set_purpose(s: String) {
    let _ = PURPOSE.set(s);
}

fn build_request(action: bwx::protocol::Action) -> bwx::protocol::Request {
    bwx::protocol::Request::new_with_session(
        get_environment(),
        action,
        session_id(),
        PURPOSE.get().cloned(),
    )
}

pub fn register() -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::Register)
}

pub fn login() -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::Login)
}

pub fn unlock() -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::Unlock)
}

pub fn unlocked() -> bin_error::Result<()> {
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            sock.send(&build_request(bwx::protocol::Action::CheckLock))?;

            let res = sock.recv()?;
            match res {
                bwx::protocol::Response::Ack => Ok(()),
                bwx::protocol::Response::Error { error } => {
                    Err(bin_error::Error::msg(error))
                }
                _ => Err(bin_error::Error::msg(format!(
                    "unexpected message: {res:?}"
                ))),
            }
        }
        Err(e) => {
            if matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
            ) {
                return Err(bin_error::Error::msg("agent not running"));
            }
            Err(e.into())
        }
    }
}

pub fn sync() -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::Sync)
}

pub fn lock() -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::Lock)
}

pub fn quit() -> bin_error::Result<()> {
    // Drop any cached connection up-front: the agent we're about to ask
    // to exit is the one any cached socket points at, and we don't want
    // a later request() to chase a dead fd.
    crate::sock::Sock::invalidate_cached();
    match crate::sock::Sock::connect() {
        Ok(mut sock) => {
            let pidfile = bwx::dirs::pid_file();
            let mut pid = String::new();
            std::fs::File::open(pidfile)?.read_to_string(&mut pid)?;
            let Some(pid) =
                rustix::process::Pid::from_raw(pid.trim_end().parse()?)
            else {
                return Err(bin_error::Error::msg(
                    "failed to read pid from pidfile",
                ));
            };
            sock.send(&build_request(bwx::protocol::Action::Quit))?;
            wait_for_exit(pid);
            Ok(())
        }
        Err(e) => match e.kind() {
            // if the socket doesn't exist, or the socket exists but nothing
            // is listening on it, the agent must already be not running
            std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::NotFound => Ok(()),
            _ => Err(e.into()),
        },
    }
}

pub fn decrypt(
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> bin_error::Result<String> {
    let res = crate::sock::request(&build_request(
        bwx::protocol::Action::Decrypt {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;
    match res {
        bwx::protocol::Response::Decrypt { plaintext } => Ok(plaintext),
        bwx::protocol::Response::Error { error } => {
            Err(bin_error::Error::msg(format!("failed to decrypt: {error}")))
        }
        _ => Err(bin_error::Error::msg(format!(
            "unexpected message: {res:?}"
        ))),
    }
}

pub fn decrypt_batch(
    items: Vec<bwx::protocol::DecryptItem>,
) -> bin_error::Result<Vec<bin_error::Result<String>>> {
    let res = crate::sock::request(&build_request(
        bwx::protocol::Action::DecryptBatch { items },
    ))?;
    match res {
        bwx::protocol::Response::DecryptBatch { results } => Ok(results
            .into_iter()
            .map(|r| match r {
                bwx::protocol::DecryptItemResult::Ok { plaintext } => {
                    Ok(plaintext)
                }
                bwx::protocol::DecryptItemResult::Err { error } => {
                    Err(bin_error::Error::msg(format!(
                        "failed to decrypt: {error}"
                    )))
                }
            })
            .collect()),
        bwx::protocol::Response::Error { error } => {
            Err(bin_error::Error::msg(format!("failed to decrypt: {error}")))
        }
        _ => Err(bin_error::Error::msg(format!(
            "unexpected message: {res:?}"
        ))),
    }
}

pub fn encrypt(
    plaintext: &str,
    org_id: Option<&str>,
) -> bin_error::Result<String> {
    let res = crate::sock::request(&build_request(
        bwx::protocol::Action::Encrypt {
            plaintext: plaintext.to_string(),
            org_id: org_id.map(std::string::ToString::to_string),
        },
    ))?;
    match res {
        bwx::protocol::Response::Encrypt { cipherstring } => Ok(cipherstring),
        bwx::protocol::Response::Error { error } => {
            Err(bin_error::Error::msg(format!("failed to encrypt: {error}")))
        }
        _ => Err(bin_error::Error::msg(format!(
            "unexpected message: {res:?}"
        ))),
    }
}

pub fn clipboard_store(text: &str) -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::ClipboardStore {
        text: text.to_string(),
    })
}

#[cfg(target_os = "macos")]
pub fn touchid_enroll() -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::TouchIdEnroll)
}

pub fn touchid_disable() -> bin_error::Result<()> {
    simple_action(bwx::protocol::Action::TouchIdDisable)
}

pub fn touchid_status() -> bin_error::Result<(bool, String, Option<String>)> {
    let res = crate::sock::request(&build_request(
        bwx::protocol::Action::TouchIdStatus,
    ))?;
    match res {
        bwx::protocol::Response::TouchIdStatus {
            enrolled,
            gate,
            keychain_label,
        } => Ok((enrolled, gate, keychain_label)),
        bwx::protocol::Response::Error { error } => {
            Err(bin_error::Error::msg(error))
        }
        _ => Err(bin_error::Error::msg(format!(
            "unexpected message: {res:?}"
        ))),
    }
}

pub fn version() -> bin_error::Result<u32> {
    let res =
        crate::sock::request(&build_request(bwx::protocol::Action::Version))?;
    match res {
        bwx::protocol::Response::Version { version } => Ok(version),
        bwx::protocol::Response::Error { error } => Err(
            bin_error::Error::msg(format!("failed to get version: {error}")),
        ),
        _ => Err(bin_error::Error::msg(format!(
            "unexpected message: {res:?}"
        ))),
    }
}

fn simple_action(action: bwx::protocol::Action) -> bin_error::Result<()> {
    let res = crate::sock::request(&build_request(action))?;
    match res {
        bwx::protocol::Response::Ack => Ok(()),
        bwx::protocol::Response::Error { error } => {
            Err(bin_error::Error::msg(error))
        }
        _ => Err(bin_error::Error::msg(format!(
            "unexpected message: {res:?}"
        ))),
    }
}

fn wait_for_exit(pid: rustix::process::Pid) {
    // Bounded so an agent that ignores Quit (e.g. because it rejected
    // the connection on a code-requirement check) doesn't pin us
    // indefinitely. The CLI caller already has the error from the
    // rejected probe; we just want to give a cooperating agent enough
    // time to actually shut down before returning.
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if rustix::process::test_kill_process(pid).is_err() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn get_environment() -> bwx::protocol::Environment {
    let tty = std::env::var_os("BWX_TTY").or_else(|| {
        rustix::termios::ttyname(std::io::stdin(), vec![])
            .ok()
            .map(|p| std::ffi::OsString::from_vec(p.as_bytes().to_vec()))
    });

    let env_vars = std::env::vars_os()
        .filter(|(var_name, _)| {
            (*bwx::protocol::ENVIRONMENT_VARIABLES_OS).contains(var_name)
        })
        .collect();
    bwx::protocol::Environment::new(tty, env_vars)
}
