use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::os::unix::io::{AsFd as _, OwnedFd};

use crate::bin_error::{self, ContextExt as _};

pub struct StartupAck {
    writer: OwnedFd,
}

impl StartupAck {
    pub fn ack(self) -> bin_error::Result<()> {
        rustix::io::write(&self.writer, &[0])?;
        Ok(())
    }
}

/// Open + flock the pidfile. If another agent already holds the lock,
/// exit with code 23 instead of bubbling an error. This is the same
/// "already running" signal the daemonized parent uses, but applied
/// uniformly so that the `--no-daemonize` path (used by the launchd
/// keepalive plist) doesn't spam its log with "failed to lock pid file"
/// every time launchd respawns into a still-occupied slot.
fn lock_pidfile_or_exit_if_running() -> bin_error::Result<std::fs::File> {
    match open_and_lock_pidfile() {
        Ok(f) => Ok(f),
        Err(e) => {
            let mut cur: Option<&(dyn std::error::Error + 'static)> =
                std::error::Error::source(&e);
            while let Some(c) = cur {
                if let Some(errno) = c.downcast_ref::<rustix::io::Errno>() {
                    if *errno == rustix::io::Errno::WOULDBLOCK
                        || *errno == rustix::io::Errno::AGAIN
                    {
                        std::process::exit(23);
                    }
                    break;
                }
                cur = c.source();
            }
            Err(e)
        }
    }
}

fn open_and_lock_pidfile() -> bin_error::Result<std::fs::File> {
    let pidfile = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(bwx::dirs::pid_file())
        .context("failed to open pid file")?;
    rustix::fs::flock(
        &pidfile,
        rustix::fs::FlockOperation::NonBlockingLockExclusive,
    )
    .context("failed to lock pid file")?;
    Ok(pidfile)
}

fn redirect_fd_to<Fd: std::os::unix::io::AsFd>(
    src: Fd,
    target_raw: std::os::unix::io::RawFd,
) -> bin_error::Result<()> {
    // SAFETY: we are reconstructing an OwnedFd from a well-known standard fd
    // (0/1/2) purely so that `dup2` can overwrite it; we then forget it to
    // avoid closing the fd we just installed.
    let mut target = unsafe {
        <OwnedFd as std::os::unix::io::FromRawFd>::from_raw_fd(target_raw)
    };
    let res = rustix::io::dup2(src, &mut target);
    std::mem::forget(target);
    res.context("failed to dup2")?;
    Ok(())
}

pub fn daemonize(
    no_daemonize: bool,
) -> bin_error::Result<Option<StartupAck>> {
    if no_daemonize {
        let pidfile = lock_pidfile_or_exit_if_running()?;
        writeln!(&pidfile, "{}", std::process::id())
            .context("failed to write pid file")?;
        // don't close the pidfile until the process exits, to ensure it
        // stays locked
        std::mem::forget(pidfile);

        return Ok(None);
    }

    // Lock the pidfile in the original (pre-fork) process so that the
    // "already running" condition is visible to the user-facing parent via
    // its exit code, instead of only being observable in the detached
    // grandchild.
    let pidfile = lock_pidfile_or_exit_if_running()?;

    let stdout = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(bwx::dirs::agent_stdout_file())?;
    let stderr = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(bwx::dirs::agent_stderr_file())?;
    let devnull_in = rustix::fs::open(
        "/dev/null",
        rustix::fs::OFlags::RDONLY,
        rustix::fs::Mode::empty(),
    )
    .context("failed to open /dev/null")?;

    let (r, w) = rustix::pipe::pipe()?;

    // SAFETY: fork is called before any tokio runtime or other threads are
    // started (see real_main in main.rs). The parent returns without
    // touching global state beyond reading the pipe and exiting; the
    // children only call async-signal-safe rustix/libc wrappers plus
    // std::fs open/write before the final return into tokio.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error())
            .context("first fork failed");
    }
    if pid > 0 {
        // original parent: wait for ack from grandchild, then exit
        drop(w);
        let mut buf = [0u8; 1];
        match rustix::io::read(&r, &mut buf) {
            Ok(1) => std::process::exit(0),
            // EOF before ack means the daemon child died without signaling
            // success; propagate a generic failure exit code.
            _ => std::process::exit(1),
        }
    }

    // first child (session leader candidate)
    drop(r);
    rustix::process::setsid().context("setsid failed")?;

    // SAFETY: same invariants as the first fork; no runtime has been
    // started in this process.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error())
            .context("second fork failed");
    }
    if pid > 0 {
        // intermediate exits immediately so the grandchild is reparented
        // to init and cannot reacquire a controlling terminal.
        // SAFETY: _exit is async-signal-safe and avoids running atexit
        // handlers inherited from the parent.
        unsafe { libc::_exit(0) };
    }

    // grandchild: finalize daemon state
    rustix::process::chdir("/").context("chdir / failed")?;

    redirect_fd_to(devnull_in.as_fd(), libc::STDIN_FILENO)?;
    redirect_fd_to(stdout.as_fd(), libc::STDOUT_FILENO)?;
    redirect_fd_to(stderr.as_fd(), libc::STDERR_FILENO)?;
    drop(devnull_in);
    drop(stdout);
    drop(stderr);

    writeln!(&pidfile, "{}", std::process::id())
        .context("failed to write pid file")?;
    // keep the pidfile fd open for the life of the process so the advisory
    // lock is held until exit
    std::mem::forget(pidfile);

    Ok(Some(StartupAck { writer: w }))
}
