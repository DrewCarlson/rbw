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
        res: &rbw::protocol::Response,
    ) -> bin_error::Result<()> {
        if let rbw::protocol::Response::Error { error } = res {
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
    ) -> bin_error::Result<std::result::Result<rbw::protocol::Request, String>>
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
    let mut peer_uid: libc::uid_t = u32::MAX;
    let mut peer_gid: libc::gid_t = u32::MAX;
    // SAFETY: we own a valid UnixStream fd for the duration of this
    // call; getpeereid writes only to the two out-params we just
    // stack-allocated.
    let rc =
        unsafe { libc::getpeereid(fd, &raw mut peer_uid, &raw mut peer_gid) };
    if rc != 0 {
        return Err(bin_error::Error::from(std::io::Error::last_os_error()))
            .context("failed to read peer uid");
    }
    // SAFETY: getuid can't fail.
    let self_uid = unsafe { libc::getuid() };
    if peer_uid != self_uid {
        return Err(bin_error::Error::msg(format!(
            "peer uid {peer_uid} does not match agent uid {self_uid}; \
             refusing connection"
        )));
    }
    Ok(())
}

pub fn listen() -> bin_error::Result<tokio::net::UnixListener> {
    let path = rbw::dirs::socket_file();
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
    use rand::RngCore as _;
    use std::fmt::Write as _;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path has no parent directory",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "socket path has no file name",
        )
    })?;
    let mut nonce = [0u8; 8];
    rand::rng().fill_bytes(&mut nonce);
    let mut nonce_hex = String::with_capacity(nonce.len() * 2);
    for b in &nonce {
        write!(&mut nonce_hex, "{b:02x}").unwrap();
    }
    let tmp_name = format!(
        "{}.{}.{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        nonce_hex,
    );
    let tmp = parent.join(tmp_name);

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
