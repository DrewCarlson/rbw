use crate::bin_error::ContextExt as _;

mod actions;
mod agent;
mod bin_error;
mod daemon;
mod debugger;
mod notifications;
mod sock;
mod ssh_agent;
mod state;
mod timeout;

async fn tokio_main(
    startup_ack: Option<crate::daemon::StartupAck>,
) -> bin_error::Result<()> {
    let listener = crate::sock::listen()?;

    if let Some(startup_ack) = startup_ack {
        startup_ack.ack()?;
    }

    let config = bwx::config::Config::load()?;
    let timeout_duration =
        std::time::Duration::from_secs(config.lock_timeout);
    let sync_timeout_duration =
        std::time::Duration::from_secs(config.sync_interval);
    let (timeout, timer_r) = crate::timeout::Timeout::new();
    let (sync_timeout, sync_timer_r) = crate::timeout::Timeout::new();
    if sync_timeout_duration > std::time::Duration::ZERO {
        sync_timeout.set(sync_timeout_duration);
    }
    let notifications_handler = crate::notifications::Handler::new();
    let state =
        std::sync::Arc::new(tokio::sync::Mutex::new(crate::state::State {
            priv_key: None,
            org_keys: None,
            timeout,
            timeout_duration,
            sync_timeout,
            sync_timeout_duration,
            notifications_handler,
            master_password_reprompt: std::collections::HashSet::new(),
            master_password_reprompt_initialized: false,
            touchid_sessions: std::collections::HashMap::new(),
            last_environment: bwx::protocol::Environment::default(),
            #[cfg(feature = "clipboard")]
            clipboard: arboard::Clipboard::new()
                .inspect_err(|e| {
                    log::warn!("couldn't create clipboard context: {e}");
                })
                .ok(),
        }));

    let agent =
        crate::agent::Agent::new(timer_r, sync_timer_r, state.clone());

    let ssh_agent = crate::ssh_agent::SshAgent::new(state.clone());

    // Install a best-effort SIGTERM/SIGINT handler so keys in
    // `State` are zeroized (via `Drop` on `locked::Vec`) before the
    // process exits, rather than living in kernel buffers until the
    // reaper gets around to reclaiming pages.
    let shutdown_state = state.clone();
    tokio::select! {
        res = async { tokio::try_join!(agent.run(listener), ssh_agent.run()) } => {
            res?;
        }
        () = shutdown_signal() => {
            log::info!("bwx-agent: shutdown signal received; clearing state");
            shutdown_state.lock().await.clear();
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                log::warn!("could not install SIGTERM handler: {e}");
                // Fall back to only SIGINT.
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = term.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn real_main() -> bin_error::Result<()> {
    bwx::logger::init("info");

    let no_daemonize = std::env::args()
        .nth(1)
        .is_some_and(|arg| arg == "--no-daemonize");

    bwx::dirs::make_all()?;

    let startup_ack =
        daemon::daemonize(no_daemonize).context("failed to daemonize")?;

    if let Err(e) = debugger::disable_tracing() {
        log::warn!("{e}");
    }

    let (w, r) = std::sync::mpsc::channel();
    // can't use tokio::main because we need to daemonize before starting the
    // tokio runloop, or else things break
    // unwrap is fine here because there's no good reason that this should
    // ever fail
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        if let Err(e) = tokio_main(startup_ack).await {
            // this unwrap is fine because it's the only real option here
            w.send(e).unwrap();
        }
    });

    if let Ok(e) = r.recv() {
        return Err(e);
    }

    Ok(())
}

fn main() {
    let res = real_main();

    if let Err(e) = res {
        // XXX log file?
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}
