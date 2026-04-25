use std::io::{BufRead as _, Write as _};

use crate::bin_error::{self, ContextExt as _};

/// Cap on the size of a single JSON-line response from the agent. 16 MiB
/// is far beyond any real vault-entry payload; this just blocks a
/// runaway or malicious agent from pushing the CLI into unbounded
/// heap growth.
const MAX_MESSAGE: u64 = 16 * 1024 * 1024;

pub struct Sock(std::os::unix::net::UnixStream);

impl Sock {
    // not returning bin_error::Result here because we want to be able to handle
    // specific kinds of std::io::Results differently
    pub fn connect() -> std::io::Result<Self> {
        Ok(Self(std::os::unix::net::UnixStream::connect(
            bwx::dirs::socket_file(),
        )?))
    }

    pub fn send(
        &mut self,
        msg: &bwx::protocol::Request,
    ) -> bin_error::Result<()> {
        let Self(sock) = self;
        sock.write_all(
            serde_json::to_string(msg)
                .context("failed to serialize message to agent")?
                .as_bytes(),
        )
        .context("failed to send message to agent")?;
        sock.write_all(b"\n")
            .context("failed to send message to agent")?;
        Ok(())
    }

    pub fn recv(&mut self) -> bin_error::Result<bwx::protocol::Response> {
        let Self(sock) = self;
        let limited = std::io::Read::take(&mut *sock, MAX_MESSAGE);
        let mut buf = std::io::BufReader::new(limited);
        let mut line = String::new();
        buf.read_line(&mut line)
            .context("failed to read message from agent")?;
        if !line.ends_with('\n') {
            return Err(bin_error::Error::msg(format!(
                "agent response exceeds {MAX_MESSAGE}-byte cap"
            )));
        }
        serde_json::from_str(&line)
            .context("failed to parse message from agent")
    }
}
