use std::os::unix::ffi::OsStrExt as _;

use crate::bin_error::{self, ContextExt as _};

pub(super) const MISSING_CONFIG_HELP: &str =
    "Before using bwx, you must configure the email address you would like to \
    use to log in to the server by running:\n\n    \
        bwx config set email <email>\n\n\
    Additionally, if you are using a self-hosted installation, you should \
    run:\n\n    \
        bwx config set base_url <url>\n\n\
    and, if your server has a non-default identity url:\n\n    \
        bwx config set identity_url <url>\n";

pub(super) const HELP_PW: &str = r"
# The first line of this file will be the password, and the remainder of the
# file (after any blank lines after the password) will be stored as a note.
# Lines with leading # will be ignored.
";

pub(super) const HELP_NOTES: &str = r"
# The content of this file will be stored as a note.
# Lines with leading # will be ignored.
";

#[allow(clippy::many_single_char_names)]
pub(super) fn format_rfc3339(t: std::time::SystemTime) -> String {
    // Hinnant civil_from_days, restricted to post-1970 (days >= 0) so all
    // arithmetic stays in u64 and avoids signed/unsigned casts.
    let dur = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let nanos = dur.subsec_nanos();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (hour, r) = (rem / 3600, rem % 3600);
    let (minute, second) = (r / 60, r % 60);
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y0 = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y0 + 1 } else { y0 };
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{nanos:09}Z"
    )
}

pub(super) fn val_display_or_store(clipboard: bool, password: &str) -> bool {
    if clipboard {
        match clipboard_store(password) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("{e}");
                false
            }
        }
    } else {
        println!("{password}");
        true
    }
}

pub(super) fn display_field(
    name: &str,
    field: Option<&str>,
    clipboard: bool,
) -> bool {
    field.map_or_else(
        || false,
        |field| val_display_or_store(clipboard, &format!("{name}: {field}")),
    )
}

pub(super) fn print_opt(v: Option<&str>) {
    if let Some(s) = v {
        println!("{s}");
    }
}

pub(super) fn parse_editor(
    contents: &str,
) -> (Option<String>, Option<String>) {
    let mut lines = contents.lines();

    let password = lines.next().map(std::string::ToString::to_string);

    let mut notes: String = lines
        .skip_while(|line| line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .fold(String::new(), |mut notes, line| {
            notes.push_str(line);
            notes.push('\n');
            notes
        });
    while notes.ends_with('\n') {
        notes.pop();
    }
    let notes = if notes.is_empty() { None } else { Some(notes) };

    (password, notes)
}

pub(super) fn load_db() -> bin_error::Result<bwx::db::Db> {
    let config = bwx::config::Config::load_cached()?;
    config.email.as_ref().map_or_else(
        || {
            Err(crate::bin_error::err!(
                "failed to find email address in config"
            ))
        },
        |email| {
            bwx::db::Db::load(&config.server_name(), email)
                .map_err(crate::bin_error::Error::new)
        },
    )
}

pub(super) fn save_db(db: &bwx::db::Db) -> bin_error::Result<()> {
    let config = bwx::config::Config::load_cached()?;
    config.email.as_ref().map_or_else(
        || {
            Err(crate::bin_error::err!(
                "failed to find email address in config"
            ))
        },
        |email| {
            db.save(&config.server_name(), email)
                .map_err(crate::bin_error::Error::new)
        },
    )
}

pub(super) fn remove_db() -> bin_error::Result<()> {
    let config = bwx::config::Config::load_cached()?;
    config.email.as_ref().map_or_else(
        || {
            Err(crate::bin_error::err!(
                "failed to find email address in config"
            ))
        },
        |email| {
            bwx::db::Db::remove(&config.server_name(), email)
                .map_err(crate::bin_error::Error::new)
        },
    )
}

pub(super) fn clipboard_store(val: &str) -> bin_error::Result<()> {
    ensure_agent()?;
    crate::actions::clipboard_store(val)?;

    Ok(())
}

pub(super) fn ensure_agent() -> bin_error::Result<()> {
    check_config()?;
    if matches!(check_agent_version(), Ok(())) {
        return Ok(());
    }
    run_agent()?;
    check_agent_version()?;
    Ok(())
}

fn run_agent() -> bin_error::Result<()> {
    let agent_path = std::env::var_os("BWX_AGENT");
    let agent_path = agent_path
        .as_deref()
        .unwrap_or_else(|| std::ffi::OsStr::from_bytes(b"bwx-agent"));
    let status = std::process::Command::new(agent_path)
        .status()
        .context("failed to run bwx-agent")?;
    if !status.success() {
        if let Some(code) = status.code() {
            if code != 23 {
                return Err(crate::bin_error::err!(
                    "failed to run bwx-agent: {status}"
                ));
            }
        }
    }

    Ok(())
}

fn check_config() -> bin_error::Result<()> {
    bwx::config::Config::validate().map_err(|e| {
        log::error!("{MISSING_CONFIG_HELP}");
        crate::bin_error::Error::new(e)
    })
}

// Cache for the per-invocation result of `check_agent_version`. Reset by
// `invalidate_agent_version_cache()` whenever we deliberately stop the
// agent so a later `ensure_agent` in the same process re-verifies a
// fresh agent rather than trusting the prior probe.
static AGENT_VERSION_VERIFIED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub(super) fn check_agent_version() -> bin_error::Result<()> {
    use std::sync::atomic::Ordering;
    if AGENT_VERSION_VERIFIED.load(Ordering::Acquire) {
        return Ok(());
    }

    let client_version = bwx::protocol::VERSION;
    let agent_version = version_or_quit()?;
    if agent_version != client_version {
        crate::actions::quit()?;
        return Err(crate::bin_error::err!(
            "client protocol version is {client_version} but agent protocol version is {agent_version}"
        ));
    }
    AGENT_VERSION_VERIFIED.store(true, Ordering::Release);
    Ok(())
}

pub(super) fn invalidate_agent_version_cache() {
    AGENT_VERSION_VERIFIED.store(false, std::sync::atomic::Ordering::Release);
}

fn version_or_quit() -> bin_error::Result<u32> {
    crate::actions::version().inspect_err(|_| {
        let _ = crate::actions::quit();
    })
}
