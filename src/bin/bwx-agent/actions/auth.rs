use super::sync::sync;
use super::util::{
    config_base_url, config_email, config_pinentry, load_db, respond_ack,
    save_db,
};
use crate::bin_error::{self, ContextExt as _};

/// Gate a pending sensitive response on a Touch ID prompt if the user
/// has opted in. The CLI-assigned `session_id` coalesces the many
/// `Decrypt`/`Encrypt` IPCs of one `bwx <command>` into one prompt.
/// Sessions expire after `TOUCHID_SESSION_TTL` of inactivity and are
/// flushed on lock. No-op on non-macOS.
pub(super) async fn enforce_touchid_gate(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    kind: bwx::touchid::Kind,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    let gate = bwx::config::Config::load()
        .map_or(bwx::touchid::Gate::Off, |c| c.touchid_gate);
    if !bwx::touchid::gate_applies(gate, kind) {
        return Ok(());
    }
    if let Some(id) = session_id {
        let mut s = state.lock().await;
        if s.touchid_session_is_fresh(id) {
            // Bump the idle timer so long commands don't expire mid-run.
            s.record_touchid_session(id);
            return Ok(());
        }
        // Session not fresh. If enrolled, evict in-memory keys so the
        // "vault stays locked at rest" invariant holds — the Touch ID
        // prompt below will re-load them from Keychain.
        #[cfg(target_os = "macos")]
        if bwx::touchid::blob::Blob::exists() {
            s.priv_key = None;
            s.org_keys = None;
        }
        drop(s);
    }
    let reason = purpose.map_or_else(
        || format!("bwx: authorize {kind:?} access"),
        |p| format!("bwx: authorize {p}"),
    );
    let ok = bwx::touchid::require_presence(&reason)
        .await
        .map_err(|e| bin_error::Error::msg(e.to_string()))?;
    if !ok {
        return Err(bin_error::Error::msg(
            "request denied: Touch ID not confirmed",
        ));
    }
    // If keys were evicted on session expiry above, reload them from
    // the Touch ID blob. The prompt just confirmed also authorizes the
    // Keychain retrieval (same biometric session), so no double-prompt.
    //
    // Record the session only after a successful unlock — a failed
    // unlock means the biometric confirm didn't produce usable keys,
    // and the next request should re-prompt rather than reuse this
    // auth window.
    if state.lock().await.needs_unlock()
        && !try_unlock_via_touchid(state.clone()).await.is_unlocked()
    {
        return Err(bin_error::Error::msg(
            "Touch ID unlock failed after gate confirmation",
        ));
    }
    if let Some(id) = session_id {
        state.lock().await.record_touchid_session(id);
    }
    Ok(())
}

pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &bwx::protocol::Environment,
) -> bin_error::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| bwx::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(bin_error::Error::msg(format!(
                "couldn't find host in bwx base url {url_str}"
            )));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let client_id = bwx::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = bwx::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = bwx::locked::ApiKey::new(client_id, client_secret);
            match bwx::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(bwx::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(bwx::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

pub async fn login(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &bwx::protocol::Environment,
) -> bin_error::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| bwx::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(bin_error::Error::msg(format!(
                "couldn't find host in bwx base url {url_str}"
            )));
        };

        let email = config_email().await?;

        let mut err_msg = None;
        'attempts: for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = prompt_master_password(
                "Log in to bwx",
                &format!("Enter your Bitwarden master password for {host}"),
                environment,
                err.as_deref(),
            )
            .await
            .context("failed to read master password")?;
            match bwx::actions::login(&email, password.clone(), None, None)
                .await
            {
                Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                    identity,
                )) => {
                    login_success(
                        state.clone(),
                        access_token,
                        refresh_token,
                        kdf,
                        iterations,
                        memory,
                        parallelism,
                        protected_key,
                        identity,
                        db,
                    )
                    .await?;
                    break 'attempts;
                }
                Err(bwx::error::Error::TwoFactorRequired {
                    providers,
                    sso_email_2fa_session_token,
                }) => {
                    let supported_types = vec![
                        bwx::api::TwoFactorProviderType::Authenticator,
                        bwx::api::TwoFactorProviderType::Yubikey,
                        bwx::api::TwoFactorProviderType::Email,
                    ];

                    for provider in supported_types {
                        if providers.contains(&provider) {
                            if provider
                                == bwx::api::TwoFactorProviderType::Email
                            {
                                if let Some(sso_email_2fa_session_token) =
                                    sso_email_2fa_session_token
                                {
                                    bwx::actions::send_two_factor_email(
                                        &email,
                                        &sso_email_2fa_session_token,
                                    )
                                    .await?;
                                }
                            }
                            let (
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                                identity,
                            ) = two_factor(
                                environment,
                                &email,
                                password.clone(),
                                provider,
                            )
                            .await?;
                            login_success(
                                state.clone(),
                                access_token,
                                refresh_token,
                                kdf,
                                iterations,
                                memory,
                                parallelism,
                                protected_key,
                                identity,
                                db,
                            )
                            .await?;
                            break 'attempts;
                        }
                    }
                    return Err(bin_error::Error::msg(format!(
                        "unsupported two factor methods: {providers:?}"
                    )));
                }
                Err(bwx::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(bwx::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to log in to bitwarden instance");
                    }
                    err_msg = Some(message);
                }
                Err(e) => {
                    return Err(e)
                        .context("failed to log in to bitwarden instance")
                }
            }
        }
    }

    respond_ack(sock).await?;

    Ok(())
}

async fn two_factor(
    environment: &bwx::protocol::Environment,
    email: &str,
    password: bwx::locked::Password,
    provider: bwx::api::TwoFactorProviderType,
) -> bin_error::Result<(
    String,
    String,
    bwx::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
    bwx::identity::Identity,
)> {
    let mut err_msg = None;
    for i in 1_u8..=3 {
        let err = if i > 1 {
            // this unwrap is safe because we only ever continue the loop if
            // we have set err_msg
            Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
        } else {
            None
        };
        let code = prompt_two_factor_code(
            provider.header(),
            provider.message(),
            provider.grab(),
            environment,
            err.as_deref(),
        )
        .await
        .context("failed to read 2FA code")?;
        let code = std::str::from_utf8(code.password())
            .context("code was not valid utf8")?;
        match bwx::actions::login(
            email,
            password.clone(),
            Some(code),
            Some(provider),
        )
        .await
        {
            Ok((
                access_token,
                refresh_token,
                kdf,
                iterations,
                memory,
                parallelism,
                protected_key,
                identity,
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                    identity,
                ))
            }
            Err(bwx::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(bwx::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(bwx::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(bwx::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            Err(e) => {
                return Err(e)
                    .context("failed to log in to bitwarden instance")
            }
        }
    }

    unreachable!()
}

#[allow(clippy::too_many_arguments)]
async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: bwx::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    identity: bwx::identity::Identity,
    mut db: bwx::db::Db,
) -> bin_error::Result<()> {
    db.access_token = Some(access_token.clone());
    db.refresh_token = Some(refresh_token.clone());
    db.kdf = Some(kdf);
    db.iterations = Some(iterations);
    db.memory = memory;
    db.parallelism = parallelism;
    db.protected_key = Some(protected_key.clone());
    save_db(&db).await?;

    sync(None, state.clone()).await?;
    let db = load_db().await?;

    let Some(protected_private_key) = db.protected_private_key else {
        return Err(bin_error::Error::msg(
            "failed to find protected private key in db",
        ));
    };

    let res = bwx::actions::unlock_with_identity(
        &identity,
        &protected_key,
        &protected_private_key,
        &db.protected_org_keys,
    );

    match res {
        Ok((keys, org_keys)) => {
            let mut state = state.lock().await;
            state.priv_key = Some(keys);
            state.org_keys = Some(org_keys);
        }
        Err(e) => return Err(e).context("failed to unlock database"),
    }

    Ok(())
}

/// Prompt the user for the master password. On macOS defaults to a
/// native secure dialog (works without a terminal — needed for ssh-sign
/// and GUI-triggered unlocks); set `macos_unlock_dialog = false` to
/// force pinentry. Other platforms always use pinentry.
pub(super) async fn prompt_master_password(
    title: &str,
    pinentry_desc: &str,
    environment: &bwx::protocol::Environment,
    err: Option<&str>,
) -> bin_error::Result<bwx::locked::Password> {
    let use_native = cfg!(target_os = "macos")
        && bwx::config::Config::load_async()
            .await
            .map_or(cfg!(target_os = "macos"), |c| c.macos_unlock_dialog);

    let message = err.map_or_else(
        || pinentry_desc.to_string(),
        |e| format!("{e} — {pinentry_desc}"),
    );

    if use_native {
        let title = title.to_string();
        // osascript display dialog is synchronous; run on a blocking
        // thread so it doesn't stall the tokio runtime.
        match tokio::task::spawn_blocking(move || {
            bwx::pinentry_native::prompt_master_password(&title, &message)
        })
        .await
        .map_err(|e| bin_error::Error::msg(format!("join: {e}")))?
        {
            Ok(pw) => return Ok(pw),
            Err(bwx::error::Error::NativePromptUnsupported) => {
                // Shouldn't happen on macOS; fall through to pinentry.
            }
            Err(e) => return Err(e.into()),
        }
    }

    let pinentry = config_pinentry().await?;
    bwx::pinentry::getpin(
        &pinentry,
        title,
        pinentry_desc,
        err,
        environment,
        true,
    )
    .await
    .context("failed to read password from pinentry")
}

/// Prompt for a 2FA code. Uses the native macOS dialog when available;
/// falls back to pinentry on non-macOS or when `macos_unlock_dialog` is
/// off.
async fn prompt_two_factor_code(
    title: &str,
    message: &str,
    grab: bool,
    environment: &bwx::protocol::Environment,
    err: Option<&str>,
) -> bin_error::Result<bwx::locked::Password> {
    let use_native = cfg!(target_os = "macos")
        && bwx::config::Config::load_async()
            .await
            .map_or(cfg!(target_os = "macos"), |c| c.macos_unlock_dialog);

    if use_native {
        let body = err.map_or_else(
            || message.to_string(),
            |e| format!("{e} — {message}"),
        );
        let title = title.to_string();
        match tokio::task::spawn_blocking(move || {
            bwx::pinentry_native::prompt(
                &title,
                &body,
                "Submit",
                bwx::pinentry_native::InputKind::Secret,
            )
        })
        .await
        .map_err(|e| bin_error::Error::msg(format!("join: {e}")))?
        {
            Ok(code) => return Ok(code),
            Err(bwx::error::Error::NativePromptUnsupported) => {}
            Err(e) => return Err(e.into()),
        }
    }

    let pinentry = config_pinentry().await?;
    bwx::pinentry::getpin(&pinentry, title, message, err, environment, grab)
        .await
        .context("failed to read code from pinentry")
}

async fn prompt_unlock_password(
    environment: &bwx::protocol::Environment,
    err: Option<&str>,
) -> bin_error::Result<bwx::locked::Password> {
    let profile = bwx::dirs::profile();
    prompt_master_password(
        "Unlock bwx vault",
        &format!("Unlock the local database for '{profile}'"),
        environment,
        err,
    )
    .await
}

pub(super) async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &bwx::protocol::Environment,
) -> bin_error::Result<()> {
    if state.lock().await.needs_unlock() {
        // Prefer Touch ID-based unlock if enrolled and the gate is
        // active. Falls through to pinentry on cancel or error,
        // surfacing the reason in the first prompt so the user knows
        // why the master password is being asked for.
        let touchid_hint = match try_unlock_via_touchid(state.clone()).await {
            TouchIdUnlockOutcome::Unlocked => return Ok(()),
            TouchIdUnlockOutcome::Fallback(reason) => Some(reason),
        };

        let db = load_db().await?;

        let Some(kdf) = db.kdf else {
            return Err(bin_error::Error::msg(
                "failed to find kdf type in db",
            ));
        };

        let Some(iterations) = db.iterations else {
            return Err(bin_error::Error::msg(
                "failed to find number of iterations in db",
            ));
        };

        let memory = db.memory;
        let parallelism = db.parallelism;

        let Some(protected_key) = db.protected_key else {
            return Err(bin_error::Error::msg(
                "failed to find protected key in db",
            ));
        };
        let Some(protected_private_key) = db.protected_private_key else {
            return Err(bin_error::Error::msg(
                "failed to find protected private key in db",
            ));
        };

        let email = config_email().await?;

        // Seed the retry loop with the Touch ID fallback reason so the
        // first prompt explains why the user is seeing it.
        let mut err_msg = touchid_hint.map(str::to_string);
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                err_msg.clone()
            };
            let password =
                prompt_unlock_password(environment, err.as_deref())
                    .await
                    .context("failed to read master password")?;
            match bwx::actions::unlock(
                &email,
                &password,
                kdf,
                iterations,
                memory,
                parallelism,
                &protected_key,
                &protected_private_key,
                &db.protected_org_keys,
            ) {
                Ok((keys, org_keys)) => {
                    unlock_success(state, keys, org_keys).await?;
                    break;
                }
                Err(bwx::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(bwx::error::Error::IncorrectPassword {
                            message,
                        })
                        .context("failed to unlock database");
                    }
                    err_msg = Some(message);
                }
                Err(e) => return Err(e).context("failed to unlock database"),
            }
        }
    }

    Ok(())
}

pub async fn unlock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &bwx::protocol::Environment,
) -> bin_error::Result<()> {
    unlock_state(state, environment).await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: bwx::locked::Keys,
    org_keys: std::collections::HashMap<String, bwx::locked::Keys>,
) -> bin_error::Result<()> {
    let mut state = state.lock().await;
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
    Ok(())
}

/// Outcome of an attempted Touch ID-backed unlock. `Fallback` carries a
/// human-readable hint for the caller's next prompt so the user knows
/// why they're being asked for the master password instead of seeing a
/// Touch ID dialog.
#[derive(Debug)]
enum TouchIdUnlockOutcome {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    Unlocked,
    Fallback(&'static str),
}

impl TouchIdUnlockOutcome {
    fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked)
    }
}

/// Attempt to unlock the vault using the Touch ID-enrolled wrapper key.
/// Returns `Fallback(reason)` when enrollment is absent, the gate is
/// off, or the user cancelled / biometry was invalidated — caller falls
/// through to pinentry, optionally surfacing `reason` in the prompt.
#[cfg(target_os = "macos")]
async fn try_unlock_via_touchid(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> TouchIdUnlockOutcome {
    let gate = bwx::config::Config::load()
        .map_or(bwx::touchid::Gate::Off, |c| c.touchid_gate);
    if matches!(gate, bwx::touchid::Gate::Off) {
        log::debug!("touchid: gate is off; skipping Keychain unlock");
        return TouchIdUnlockOutcome::Fallback(
            "Touch ID gate disabled (touchid_gate=off)",
        );
    }
    let Ok(blob) = bwx::touchid::blob::Blob::load() else {
        log::debug!("touchid: no enrollment blob on disk");
        return TouchIdUnlockOutcome::Fallback(
            "no Touch ID enrollment (run `bwx touchid enroll`)",
        );
    };
    log::debug!(
        "touchid: attempting Keychain load for label {label}",
        label = blob.keychain_label
    );
    let prompt = format!("Unlock the {} vault", bwx::dirs::profile());
    let seed =
        match bwx::touchid::keychain::load(&blob.keychain_label, &prompt) {
            Ok(bytes) if bytes.data().len() == 64 => bytes,
            Ok(other) => {
                log::warn!(
                    "touchid: wrapper key has unexpected length: {}",
                    other.data().len()
                );
                return TouchIdUnlockOutcome::Fallback(
                    "Touch ID wrapper key corrupted; re-enroll",
                );
            }
            Err(bwx::touchid::keychain::Error::UserCancelled) => {
                log::debug!("touchid: user cancelled Keychain prompt");
                return TouchIdUnlockOutcome::Fallback("Touch ID cancelled");
            }
            Err(bwx::touchid::keychain::Error::Invalidated) => {
                log::warn!(
                    "touchid: biometric set changed; master password \
                 required to re-enroll"
                );
                return TouchIdUnlockOutcome::Fallback(
                    "biometric set changed — run `bwx touchid enroll` \
                 after unlocking to re-bind",
                );
            }
            Err(bwx::touchid::keychain::Error::NotFound) => {
                log::warn!(
                    "touchid: enrollment blob present but Keychain item \
                 missing; likely deleted outside bwx"
                );
                return TouchIdUnlockOutcome::Fallback(
                    "Touch ID Keychain item missing; re-enroll",
                );
            }
            Err(e) => {
                log::warn!("touchid: Keychain load failed: {e}");
                return TouchIdUnlockOutcome::Fallback(
                    "Touch ID unlock failed (see agent log)",
                );
            }
        };
    let wrapper_keys =
        bwx::touchid::blob::keys_from_wrapper_seed(seed.data());

    let Ok(cs) = bwx::cipherstring::CipherString::new(&blob.wrapped_priv_key)
    else {
        log::warn!("touchid: wrapped priv_key cipherstring malformed");
        return TouchIdUnlockOutcome::Fallback(
            "Touch ID blob corrupted; re-enroll",
        );
    };
    let Ok(priv_bytes) = cs.decrypt_locked_symmetric(&wrapper_keys) else {
        log::warn!("touchid: priv_key unwrap failed");
        return TouchIdUnlockOutcome::Fallback(
            "Touch ID blob decrypt failed; re-enroll",
        );
    };
    let priv_key = bwx::locked::Keys::new(priv_bytes);

    let mut org_keys = std::collections::HashMap::new();
    for (oid, wrapped) in &blob.wrapped_org_keys {
        let Ok(cs) = bwx::cipherstring::CipherString::new(wrapped) else {
            log::warn!("touchid: wrapped org_key for {oid} malformed");
            return TouchIdUnlockOutcome::Fallback(
                "Touch ID blob corrupted; re-enroll",
            );
        };
        let Ok(bytes) = cs.decrypt_locked_symmetric(&wrapper_keys) else {
            log::warn!("touchid: org_key for {oid} unwrap failed");
            return TouchIdUnlockOutcome::Fallback(
                "Touch ID blob decrypt failed; re-enroll",
            );
        };
        org_keys.insert(oid.clone(), bwx::locked::Keys::new(bytes));
    }

    let mut s = state.lock().await;
    s.priv_key = Some(priv_key);
    s.org_keys = Some(org_keys);
    log::debug!(
        "touchid: vault unlocked via Keychain ({} org key(s))",
        blob.wrapped_org_keys.len()
    );
    TouchIdUnlockOutcome::Unlocked
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unused_async)]
async fn try_unlock_via_touchid(
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> TouchIdUnlockOutcome {
    TouchIdUnlockOutcome::Fallback("Touch ID not supported on this platform")
}

pub async fn lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    state.lock().await.clear();

    respond_ack(sock).await?;

    Ok(())
}

pub async fn check_lock(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    if state.lock().await.needs_unlock() {
        return Err(bin_error::Error::msg("agent is locked"));
    }

    respond_ack(sock).await?;

    Ok(())
}
