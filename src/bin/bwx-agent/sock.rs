use crate::bin_error::{self, ContextExt as _};
use tokio::io::{
    AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _,
};

/// Cap on the size of a single JSON-line request from the CLI. The real
/// protocol messages are small (a few KB at most), so 16 MiB is an
/// extravagantly generous ceiling that still blocks a misbehaving (or
/// malicious, if the 0o700-dir assumption is ever violated) client from
/// pushing the agent into unbounded heap growth with a newline-free
/// stream.
const MAX_MESSAGE: u64 = 16 * 1024 * 1024;

pub struct Sock(tokio::net::UnixStream);

impl Sock {
    pub fn new(s: tokio::net::UnixStream) -> Self {
        Self(s)
    }

    pub async fn send(
        &mut self,
        res: &bwx::protocol::Response,
    ) -> bin_error::Result<()> {
        if let bwx::protocol::Response::Error { error } = res {
            log::warn!("{error}");
        }

        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(res)
                .context("failed to serialize message")?
                .as_bytes(),
        )
        .await
        .context("failed to write message to socket")?;
        sock.write_all(b"\n")
            .await
            .context("failed to write message to socket")?;
        Ok(())
    }

    pub async fn recv(
        &mut self,
    ) -> bin_error::Result<std::result::Result<bwx::protocol::Request, String>>
    {
        let Self(sock) = self;
        let limited = (&mut *sock).take(MAX_MESSAGE);
        let mut buf = tokio::io::BufReader::new(limited);
        let mut line = String::new();
        buf.read_line(&mut line)
            .await
            .context("failed to read message from socket")?;
        if line.is_empty() {
            return Ok(Err("connection closed".to_string()));
        }
        if !line.ends_with('\n') {
            return Ok(Err(format!(
                "message exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        Ok(serde_json::from_str(&line)
            .map_err(|e| format!("failed to parse message '{line}': {e}")))
    }
}

/// Verify that the peer connected to `stream` is running as the same
/// uid as this process. Unix sockets in a 0o700 runtime dir already
/// block cross-user access at the filesystem layer; this is
/// belt-and-braces for the case where someone loosens those dir
/// permissions, mounts the path into a sandbox, or passes the
/// connected fd across a privilege boundary. Rejects gracefully (error
/// return, no panic) so the accept loop stays up.
pub fn check_peer_uid(
    stream: &tokio::net::UnixStream,
) -> bin_error::Result<()> {
    use std::os::unix::io::AsRawFd as _;
    let fd = stream.as_raw_fd();
    let peer_uid = peer_uid(fd).context("failed to read peer uid")?;
    // SAFETY: getuid is infallible.
    let self_uid = unsafe { libc::getuid() };
    if peer_uid != self_uid {
        return Err(bin_error::Error::msg(format!(
            "peer uid {peer_uid} does not match agent uid {self_uid}; \
             refusing connection"
        )));
    }
    Ok(())
}

/// Read the uid of the process connected on the other end of a Unix
/// socket fd. `SO_PEERCRED` is the Linux idiom (glibc's `getpeereid`
/// wraps it, but musl omits the wrapper and the libc crate follows
/// suit, so we call it directly). `getpeereid` is the BSD / macOS
/// idiom.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_ucred(fd: std::os::unix::io::RawFd) -> std::io::Result<libc::ucred> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = u32::try_from(std::mem::size_of::<libc::ucred>())
        .expect("ucred size fits in socklen_t");
    // SAFETY: `fd` is a valid Unix-socket fd owned by the caller;
    // `cred` and `len` are stack-local outs of the correct types.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::from_mut::<libc::ucred>(&mut cred).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cred)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> std::io::Result<u32> {
    peer_ucred(fd).map(|c| c.uid)
}

/// Peer PID of a Unix-socket fd. Best effort — returns `None` if the
/// platform doesn't expose it (or if the syscall fails). Used only for
/// building a human-readable description of which client is making a
/// request; never for authorization.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_pid(fd: std::os::unix::io::RawFd) -> Option<i32> {
    peer_ucred(fd).ok().map(|c| c.pid)
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn peer_uid(fd: std::os::unix::io::RawFd) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: `fd` is a valid Unix-socket fd owned by the caller;
    // getpeereid writes only to the two u32 out-params.
    let rc = unsafe { libc::getpeereid(fd, &raw mut uid, &raw mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid)
}

/// macOS exposes the peer pid via `LOCAL_PEERPID` (level `SOL_LOCAL`,
/// which is `0` for `AF_UNIX`). Both constants are stable in Darwin's
/// `sys/un.h`. Best effort — returns `None` on error, since this is
/// only used for the human-readable prompt description.
#[cfg(target_os = "macos")]
pub fn peer_pid(fd: std::os::unix::io::RawFd) -> Option<i32> {
    // From <sys/un.h>: #define LOCAL_PEERPID 2, SOL_LOCAL = 0.
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERPID: libc::c_int = 2;
    let mut pid: libc::pid_t = 0;
    let mut len = u32::try_from(std::mem::size_of::<libc::pid_t>())
        .expect("pid_t fits in socklen_t");
    // SAFETY: `fd` is a valid Unix-socket fd; pid/len are stack-local.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            SOL_LOCAL,
            LOCAL_PEERPID,
            std::ptr::from_mut::<libc::pid_t>(&mut pid).cast(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(pid)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
)))]
pub fn peer_pid(_fd: std::os::unix::io::RawFd) -> Option<i32> {
    None
}

pub fn listen() -> bin_error::Result<tokio::net::UnixListener> {
    let path = bwx::dirs::socket_file();
    let sock = bind_atomic(&path).context("failed to listen on socket")?;
    log::debug!("listening on socket {}", path.to_string_lossy());
    Ok(sock)
}

/// Bind a `UnixListener` at `path` without a remove-then-bind TOCTOU
/// window. We bind to a unique sibling path (`<name>.<pid>.<rand>.tmp`)
/// in the same directory and then `rename(2)` it onto `path`. `rename`
/// is atomic within a filesystem and clobbers any existing file at the
/// destination, so a racing same-user process can't slip a symlink or
/// regular file under us between the unlink and the bind (the old
/// pattern).
pub fn bind_atomic(
    path: &std::path::Path,
) -> std::io::Result<tokio::net::UnixListener> {
    // Try the atomic path. If it fails for *any* reason — including
    // Darwin's ~104-byte `sockaddr_un.sun_path` limit once the tmp
    // suffix is appended — fall back to the legacy unlink-then-bind
    // approach so the agent still starts. The fallback has a tiny
    // same-user TOCTOU window, which is blocked in practice by our
    // 0o700 runtime dir, but we log it so it's observable.
    match bind_atomic_inner(path) {
        Ok(l) => Ok(l),
        Err(e) => {
            log::warn!(
                "bind_atomic failed ({e}); falling back to unlink-then-bind \
                 on {}. TOCTOU mitigation partially degraded; socket is \
                 still protected by its 0o700 parent dir.",
                path.display()
            );
            let _ = std::fs::remove_file(path);
            tokio::net::UnixListener::bind(path)
        }
    }
}

fn bind_atomic_inner(
    path: &std::path::Path,
) -> std::io::Result<tokio::net::UnixListener> {
    use rand::RngCore as _;
    use std::fmt::Write as _;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path has no parent directory",
        )
    })?;
    // Minimal tmp name: 4 random bytes of hex with a tiny prefix. Keeps
    // the total tmp path length under Darwin's 104-byte `sun_path`
    // limit in almost all layouts. The filename itself doesn't need to
    // resemble the target — we rename(2) over the target below.
    let mut nonce = [0u8; 4];
    rand::rng().fill_bytes(&mut nonce);
    let mut nonce_hex = String::with_capacity(nonce.len() * 2 + 2);
    nonce_hex.push_str(".t");
    for b in &nonce {
        write!(&mut nonce_hex, "{b:02x}").unwrap();
    }
    let tmp = parent.join(nonce_hex);

    // Best-effort cleanup of our own tmp name in case a prior crashed
    // agent left one behind. The nonce makes a collision vanishingly
    // unlikely, but harmless to clean anyway.
    let _ = std::fs::remove_file(&tmp);

    let listener = tokio::net::UnixListener::bind(&tmp)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        // Don't leak the tmp socket if rename somehow fails.
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(listener)
}
