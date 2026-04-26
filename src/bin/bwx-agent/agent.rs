use crate::bin_error::{self, ContextExt as _};
use futures_util::StreamExt as _;

pub struct Agent {
    timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
}

impl Agent {
    pub fn new(
        timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        sync_timer_r: tokio::sync::mpsc::UnboundedReceiver<()>,
        state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    ) -> Self {
        Self {
            timer_r,
            sync_timer_r,
            state,
        }
    }

    pub async fn run(
        self,
        listener: tokio::net::UnixListener,
    ) -> bin_error::Result<()> {
        pub enum Event {
            Request(std::io::Result<tokio::net::UnixStream>),
            Timeout(()),
            Sync(()),
        }

        let notifications = self
            .state
            .lock()
            .await
            .notifications_handler
            .get_channel()
            .await;
        let notifications =
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                notifications,
            )
            .map(|message| match message {
                crate::notifications::Message::Logout => Event::Timeout(()),
                crate::notifications::Message::Sync => Event::Sync(()),
            })
            .boxed();

        let mut stream = futures_util::stream::select_all([
            tokio_stream::wrappers::UnixListenerStream::new(listener)
                .map(Event::Request)
                .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.timer_r,
            )
            .map(Event::Timeout)
            .boxed(),
            tokio_stream::wrappers::UnboundedReceiverStream::new(
                self.sync_timer_r,
            )
            .map(Event::Sync)
            .boxed(),
            notifications,
        ]);
        while let Some(event) = stream.next().await {
            match event {
                Event::Request(res) => {
                    let stream =
                        res.context("failed to accept incoming connection")?;
                    if let Err(e) = crate::sock::check_peer_uid(&stream) {
                        log::warn!("rejecting connection: {e:#}");
                        spawn_reject(stream, format!("{e:#}"));
                        continue;
                    }
                    if let Err(e) = crate::peer_check::check_peer_team(
                        crate::sock::peer_pid_of(&stream),
                    ) {
                        log::warn!("rejecting connection: {e:#}");
                        spawn_reject(stream, format!("{e:#}"));
                        continue;
                    }
                    let mut sock = crate::sock::Sock::new(stream);
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        let res =
                            handle_request(&mut sock, state.clone()).await;
                        if let Err(e) = res {
                            // unwrap is the only option here
                            sock.send(&bwx::protocol::Response::Error {
                                error: format!("{e:#}"),
                            })
                            .await
                            .unwrap();
                        }
                    });
                }
                Event::Timeout(()) => {
                    self.state.lock().await.clear();
                }
                Event::Sync(()) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        // this could fail if we aren't logged in, but we
                        // don't care about that
                        if let Err(e) =
                            crate::actions::sync(None, state.clone()).await
                        {
                            eprintln!("failed to sync: {e:#}");
                        }
                    });
                    self.state.lock().await.set_sync_timeout();
                }
            }
        }
        Ok(())
    }
}

/// Upper bound on how long the agent waits for a peer to finish
/// sending a single request. A peer that sends a length prefix and
/// then stalls otherwise pins this tokio task indefinitely.
const RECV_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Send a single `Response::Error` over a connection we're refusing,
/// then close it. Lets the peer fail fast with a real error string
/// instead of blocking on an EOF detection on the recv side.
fn spawn_reject(stream: tokio::net::UnixStream, error: String) {
    tokio::spawn(async move {
        let mut sock = crate::sock::Sock::new(stream);
        let _ = sock.send(&bwx::protocol::Response::Error { error }).await;
    });
}

async fn handle_request(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    let req = if let Ok(r) =
        tokio::time::timeout(RECV_TIMEOUT, sock.recv()).await
    {
        r?
    } else {
        let _ = sock
            .send(&bwx::protocol::Response::Error {
                error: "request read timed out".to_string(),
            })
            .await;
        return Ok(());
    };
    let req = match req {
        Ok(msg) => msg,
        Err(error) => {
            sock.send(&bwx::protocol::Response::Error { error }).await?;
            return Ok(());
        }
    };
    let (action, environment, session_id, purpose) = req.into_parts();
    let set_timeout = match &action {
        bwx::protocol::Action::Register => {
            crate::actions::register(sock, &environment).await?;
            true
        }
        bwx::protocol::Action::Login => {
            crate::actions::login(sock, state.clone(), &environment).await?;
            true
        }
        bwx::protocol::Action::Unlock => {
            crate::actions::unlock(sock, state.clone(), &environment).await?;
            true
        }
        bwx::protocol::Action::CheckLock => {
            crate::actions::check_lock(sock, state.clone()).await?;
            false
        }
        bwx::protocol::Action::Lock => {
            crate::actions::lock(sock, state.clone()).await?;
            // Revoke Touch ID authorizations so the next unlock prompts.
            state.lock().await.clear_touchid_sessions();
            false
        }
        bwx::protocol::Action::Sync => {
            crate::actions::sync(Some(sock), state.clone()).await?;
            false
        }
        bwx::protocol::Action::Decrypt {
            cipherstring,
            entry_key,
            org_id,
        } => {
            let cipherstring = cipherstring.clone();
            let entry_key = entry_key.clone();
            let org_id = org_id.clone();
            crate::actions::decrypt(
                sock,
                state.clone(),
                &environment,
                &cipherstring,
                entry_key.as_deref(),
                org_id.as_deref(),
                session_id.as_deref(),
                purpose.as_deref(),
            )
            .await?;
            true
        }
        bwx::protocol::Action::DecryptBatch { items } => {
            let items = items.clone();
            crate::actions::decrypt_batch(
                sock,
                state.clone(),
                &environment,
                items,
                session_id.as_deref(),
                purpose.as_deref(),
            )
            .await?;
            true
        }
        bwx::protocol::Action::Encrypt { plaintext, org_id } => {
            crate::actions::encrypt(
                sock,
                state.clone(),
                plaintext,
                org_id.as_deref(),
                session_id.as_deref(),
                purpose.as_deref(),
            )
            .await?;
            true
        }
        bwx::protocol::Action::ClipboardStore { text } => {
            crate::actions::clipboard_store(
                sock,
                state.clone(),
                text,
                session_id.as_deref(),
                purpose.as_deref(),
            )
            .await?;
            true
        }
        bwx::protocol::Action::Quit => std::process::exit(0),
        bwx::protocol::Action::Version => {
            crate::actions::version(sock).await?;
            false
        }
        bwx::protocol::Action::TouchIdEnroll => {
            crate::actions::touchid_enroll(sock, state.clone()).await?;
            true
        }
        bwx::protocol::Action::TouchIdDisable => {
            crate::actions::touchid_disable(sock).await?;
            false
        }
        bwx::protocol::Action::TouchIdStatus => {
            crate::actions::touchid_status(sock).await?;
            false
        }
    };

    let mut state = state.lock().await;
    state.set_last_environment(environment);
    if set_timeout {
        state.set_timeout();
    }

    Ok(())
}
