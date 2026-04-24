use signature::{RandomizedSigner as _, SignatureEncoding as _, Signer as _};

const SSH_AGENT_RSA_SHA2_256: u32 = 2;
const SSH_AGENT_RSA_SHA2_512: u32 = 4;

#[derive(Clone)]
pub struct SshAgent {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl SshAgent {
    pub fn new(
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self { state }
    }

    pub async fn run(self) -> crate::bin_error::Result<()> {
        let socket = rbw::dirs::ssh_agent_socket_file();
        let listener = crate::sock::bind_atomic(&socket)?;
        ssh_agent_lib::agent::listen(UidFilteredUnixListener(listener), self)
            .await
            .map_err(|e| crate::bin_error::Error::Boxed(Box::new(e)))?;

        Ok(())
    }
}

/// Per-connection ssh-agent session. Carries a human-readable `peer`
/// description (program name + pid) so the Touch ID / pinentry prompts
/// tell the user *which* local client is requesting the signature,
/// instead of the generic "rbw-agent wants to sign with …". The peer
/// string is never used for authorization — it's diagnostic/UX only.
#[derive(Clone)]
pub struct SshSession {
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    peer: String,
}

// The blanket `Agent<UnixListener> for T: Session + Clone` shipped by
// ssh-agent-lib only covers the concrete `UnixListener` type, so we
// have to restate it for our filtered wrapper — otherwise `listen`
// can't resolve a session factory.
impl ssh_agent_lib::agent::Agent<UidFilteredUnixListener> for SshAgent {
    fn new_session(
        &mut self,
        socket: &tokio::net::UnixStream,
    ) -> impl ssh_agent_lib::agent::Session {
        use std::os::unix::io::AsRawFd as _;
        let peer = describe_peer(socket.as_raw_fd());
        log::debug!("ssh-agent: accepted connection from {peer}");
        SshSession {
            state: self.state.clone(),
            peer,
        }
    }
}

/// Build a "`<program>` (pid `<pid>`)" description of the peer on a
/// connected Unix-socket fd. Entirely best-effort: if any lookup fails
/// we substitute an "unknown" placeholder.
fn describe_peer(fd: std::os::unix::io::RawFd) -> String {
    let Some(pid) = crate::sock::peer_pid(fd) else {
        return "unknown client".to_string();
    };
    let name = peer_program_name(pid).unwrap_or_else(|| "<unknown>".into());
    format!("{name} (pid {pid})")
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_program_name(pid: i32) -> Option<String> {
    // /proc/<pid>/comm holds the `TASK_COMM_LEN`-truncated program
    // name (no path). Good enough for a prompt.
    let raw = std::fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "macos")]
fn peer_program_name(pid: i32) -> Option<String> {
    // libc::proc_pidpath fills a caller-provided buffer with the
    // executable's full path. Returns the number of bytes written, or
    // a negative value on error.
    // `PROC_PIDPATHINFO_MAXSIZE` is Darwin-defined as 4 * `MAXPATHLEN`
    // (= 4096); it fits in a `usize` but is typed `c_int`, so the
    // widening needs an explicit allow for the `as_conversions` lint.
    #[allow(clippy::as_conversions)]
    const BUF_LEN: usize = libc::PROC_PIDPATHINFO_MAXSIZE as usize;
    let mut buf = [0u8; BUF_LEN];
    // SAFETY: buf is stack-allocated of the documented size;
    // proc_pidpath writes at most `buf.len()` bytes.
    let written = unsafe {
        libc::proc_pidpath(
            pid,
            buf.as_mut_ptr().cast(),
            u32::try_from(buf.len()).ok()?,
        )
    };
    if written <= 0 {
        return None;
    }
    let n = usize::try_from(written).ok()?;
    let path = std::str::from_utf8(&buf[..n]).ok()?;
    // Collapse to the basename for the prompt; the full path is
    // noise most of the time.
    Some(
        std::path::Path::new(path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(path)
            .to_string(),
    )
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos"
)))]
fn peer_program_name(_pid: i32) -> Option<String> {
    None
}

#[derive(Debug)]
struct UidFilteredUnixListener(tokio::net::UnixListener);

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::ListeningSocket for UidFilteredUnixListener {
    type Stream = tokio::net::UnixStream;
    async fn accept(&mut self) -> std::io::Result<Self::Stream> {
        loop {
            let (stream, _addr) = self.0.accept().await?;
            match crate::sock::check_peer_uid(&stream) {
                Ok(()) => return Ok(stream),
                Err(e) => {
                    log::warn!("ssh-agent: rejecting connection: {e:#}");
                }
            }
        }
    }
}

#[ssh_agent_lib::async_trait]
impl ssh_agent_lib::agent::Session for SshSession {
    async fn request_identities(
        &mut self,
    ) -> Result<
        Vec<ssh_agent_lib::proto::Identity>,
        ssh_agent_lib::error::AgentError,
    > {
        crate::actions::get_ssh_public_keys(self.state.clone())
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?
            .into_iter()
            .map(|p| {
                p.parse::<ssh_agent_lib::ssh_key::PublicKey>()
                    .map(|pk| ssh_agent_lib::proto::Identity {
                        pubkey: pk.key_data().clone(),
                        comment: String::new(),
                    })
                    .map_err(ssh_agent_lib::error::AgentError::other)
            })
            .collect()
    }

    async fn sign(
        &mut self,
        request: ssh_agent_lib::proto::SignRequest,
    ) -> Result<
        ssh_agent_lib::ssh_key::Signature,
        ssh_agent_lib::error::AgentError,
    > {
        let pubkey =
            ssh_agent_lib::ssh_key::PublicKey::new(request.pubkey, "");

        // Phase 1: locate the matching entry and decrypt just the public
        // key + entry name — enough to show the user a named prompt —
        // while leaving the *private* key cipherstring encrypted. This
        // way, if the user cancels Touch ID or pinentry CONFIRM below,
        // no plaintext RSA / Ed25519 key material ever sits on the heap.
        let located = crate::actions::locate_ssh_private_key(
            self.state.clone(),
            pubkey,
        )
        .await
        .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;

        let gate = rbw::config::Config::load()
            .map_or(rbw::touchid::Gate::Off, |c| c.touchid_gate);
        if rbw::touchid::gate_applies(gate, rbw::touchid::Kind::SshSign) {
            let ok = rbw::touchid::require_presence(&format!(
                "{peer} wants to sign with SSH key {name:?}",
                peer = self.peer,
                name = located.name,
            ))
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;
            if !ok {
                return Err(ssh_agent_lib::error::AgentError::Other(
                    "signature declined by Touch ID".into(),
                ));
            }
        }

        // Optional confirm-on-sign. Reads both the config flag and the
        // last-known pinentry environment from the shared state.
        let (confirm_required, pinentry, environment) = {
            let state = self.state.lock().await;
            let config = rbw::config::Config::load().map_err(|e| {
                ssh_agent_lib::error::AgentError::Other(e.into())
            })?;
            (
                config.ssh_confirm_sign,
                config.pinentry,
                state.last_environment().clone(),
            )
        };
        if confirm_required {
            let ok = rbw::pinentry::confirm(
                &pinentry,
                "Sign",
                &format!(
                    "{peer} wants to sign with key {name:?}",
                    peer = self.peer,
                    name = located.name,
                ),
                &environment,
            )
            .await
            .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;
            if !ok {
                return Err(ssh_agent_lib::error::AgentError::Other(
                    "signature declined by user".into(),
                ));
            }
        }

        // User has confirmed. Decrypt the private key *now*, sign with
        // it, and drop it at end-of-scope — plaintext key material is
        // alive only for the narrow window of the signing operation.
        let private_key = crate::actions::decrypt_located_ssh_private_key(
            self.state.clone(),
            &located,
        )
        .await
        .map_err(|e| ssh_agent_lib::error::AgentError::Other(e.into()))?;

        match private_key.key_data() {
            ssh_agent_lib::ssh_key::private::KeypairData::Ed25519(key) => key
                .try_sign(&request.data)
                .map_err(ssh_agent_lib::error::AgentError::other),

            ssh_agent_lib::ssh_key::private::KeypairData::Rsa(key) => {
                let p = rsa::BigUint::from_bytes_be(key.private.p.as_bytes());
                let q = rsa::BigUint::from_bytes_be(key.private.q.as_bytes());
                let e = rsa::BigUint::from_bytes_be(key.public.e.as_bytes());
                let rsa_key = rsa::RsaPrivateKey::from_p_q(p, q, e)
                    .map_err(ssh_agent_lib::error::AgentError::other)?;

                let mut rng = rand_8::rngs::OsRng;

                let (algorithm, sig_bytes) = if request.flags
                    & SSH_AGENT_RSA_SHA2_512
                    != 0
                {
                    let signing_key =
                        rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(
                            rsa_key,
                        );
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("rsa-sha2-512", signature.to_bytes())
                } else if request.flags & SSH_AGENT_RSA_SHA2_256 != 0 {
                    let signing_key =
                        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(
                            rsa_key,
                        );
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("rsa-sha2-256", signature.to_bytes())
                } else {
                    let signing_key = rsa::pkcs1v15::SigningKey::<sha1::Sha1>::new_unprefixed(rsa_key);
                    let signature = signing_key
                        .try_sign_with_rng(&mut rng, &request.data)
                        .map_err(ssh_agent_lib::error::AgentError::other)?;

                    ("ssh-rsa", signature.to_bytes())
                };

                Ok(ssh_agent_lib::ssh_key::Signature::new(
                    ssh_agent_lib::ssh_key::Algorithm::new(algorithm)
                        .map_err(ssh_agent_lib::error::AgentError::other)?,
                    sig_bytes,
                )
                .map_err(ssh_agent_lib::error::AgentError::other)?)
            }

            // TODO: Check which other key types are supported by bitwarden
            other => Err(ssh_agent_lib::error::AgentError::Other(
                format!("Unsupported key type: {other:?}").into(),
            )),
        }
    }
}
