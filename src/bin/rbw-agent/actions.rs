use crate::bin_error::{self, ContextExt as _};
use sha2::Digest as _;

/// Gate a pending sensitive response on a Touch ID prompt if the user has
/// opted in. A `session_id` (assigned by the rbw CLI once per invocation)
/// lets us coalesce the many `Decrypt`/`Encrypt` IPCs fired by a single
/// `rbw <command>` into one prompt. Sessions expire after
/// `TOUCHID_SESSION_TTL` of inactivity, and are flushed whenever the
/// vault is locked. Cancelling the prompt returns a clean error. No
/// behavior on non-macOS builds.
async fn enforce_touchid_gate(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    kind: rbw::touchid::Kind,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    let gate = rbw::config::Config::load()
        .map_or(rbw::touchid::Gate::Off, |c| c.touchid_gate);
    if !rbw::touchid::gate_applies(gate, kind) {
        return Ok(());
    }
    if let Some(id) = session_id {
        let mut s = state.lock().await;
        if s.touchid_session_is_fresh(id) {
            // Bump the idle timer so long commands don't expire mid-run.
            s.record_touchid_session(id);
            return Ok(());
        }
        // Session not fresh. If we're enrolled, evict the in-memory keys
        // so the "vault stays locked at rest" invariant holds — a new
        // Touch ID prompt below will re-load them from Keychain.
        #[cfg(target_os = "macos")]
        if rbw::touchid::blob::Blob::exists() {
            s.priv_key = None;
            s.org_keys = None;
        }
        drop(s);
    }
    let reason = purpose.map_or_else(
        || format!("rbw: authorize {kind:?} access"),
        |p| format!("rbw: authorize {p}"),
    );
    let ok = rbw::touchid::require_presence(&reason)
        .await
        .map_err(|e| bin_error::Error::msg(e.to_string()))?;
    if !ok {
        return Err(bin_error::Error::msg(
            "request denied: Touch ID not confirmed",
        ));
    }
    if let Some(id) = session_id {
        state.lock().await.record_touchid_session(id);
    }
    // If keys were evicted on session expiry above, transparently
    // reload them from the Touch ID blob. The prompt the user just
    // confirmed also authorizes this Keychain retrieval (same
    // biometric session), so no double-prompt in practice.
    if state.lock().await.needs_unlock()
        && !try_unlock_via_touchid(state.clone()).await.is_unlocked()
    {
        return Err(bin_error::Error::msg(
            "Touch ID unlock failed after gate confirmation",
        ));
    }
    Ok(())
}

pub async fn register(
    sock: &mut crate::sock::Sock,
    environment: &rbw::protocol::Environment,
) -> bin_error::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(bin_error::Error::msg(format!(
                "couldn't find host in rbw base url {url_str}"
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
            let client_id = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__id",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_id from pinentry")?;
            let client_secret = rbw::pinentry::getpin(
                &config_pinentry().await?,
                "API key client__secret",
                &format!("Log in to {host}"),
                err.as_deref(),
                environment,
                false,
            )
            .await
            .context("failed to read client_secret from pinentry")?;
            let apikey = rbw::locked::ApiKey::new(client_id, client_secret);
            match rbw::actions::register(&email, apikey.clone()).await {
                Ok(()) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
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
    environment: &rbw::protocol::Environment,
) -> bin_error::Result<()> {
    let db = load_db().await.unwrap_or_else(|_| rbw::db::Db::new());

    if db.needs_login() {
        let url_str = config_base_url().await?;
        let url = reqwest::Url::parse(&url_str)
            .context("failed to parse base url")?;
        let Some(host) = url.host_str() else {
            return Err(bin_error::Error::msg(format!(
                "couldn't find host in rbw base url {url_str}"
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
                "Log in to rbw",
                &format!("Enter your Bitwarden master password for {host}"),
                environment,
                err.as_deref(),
            )
            .await
            .context("failed to read master password")?;
            match rbw::actions::login(&email, password.clone(), None, None)
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
                        password,
                        db,
                        email,
                    )
                    .await?;
                    break 'attempts;
                }
                Err(rbw::error::Error::TwoFactorRequired {
                    providers,
                    sso_email_2fa_session_token,
                }) => {
                    let supported_types = vec![
                        rbw::api::TwoFactorProviderType::Authenticator,
                        rbw::api::TwoFactorProviderType::Yubikey,
                        rbw::api::TwoFactorProviderType::Email,
                    ];

                    for provider in supported_types {
                        if providers.contains(&provider) {
                            if provider
                                == rbw::api::TwoFactorProviderType::Email
                            {
                                if let Some(sso_email_2fa_session_token) =
                                    sso_email_2fa_session_token
                                {
                                    rbw::actions::send_two_factor_email(
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
                                password,
                                db,
                                email,
                            )
                            .await?;
                            break 'attempts;
                        }
                    }
                    return Err(bin_error::Error::msg(format!(
                        "unsupported two factor methods: {providers:?}"
                    )));
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
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
    environment: &rbw::protocol::Environment,
    email: &str,
    password: rbw::locked::Password,
    provider: rbw::api::TwoFactorProviderType,
) -> bin_error::Result<(
    String,
    String,
    rbw::api::KdfType,
    u32,
    Option<u32>,
    Option<u32>,
    String,
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
        match rbw::actions::login(
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
            )) => {
                return Ok((
                    access_token,
                    refresh_token,
                    kdf,
                    iterations,
                    memory,
                    parallelism,
                    protected_key,
                ))
            }
            Err(rbw::error::Error::IncorrectPassword { message }) => {
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
                        message,
                    })
                    .context("failed to log in to bitwarden instance");
                }
                err_msg = Some(message);
            }
            // can get this if the user passes an empty string
            Err(rbw::error::Error::TwoFactorRequired { .. }) => {
                let message = "TOTP code is not a number".to_string();
                if i == 3 {
                    return Err(rbw::error::Error::IncorrectPassword {
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

async fn login_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    access_token: String,
    refresh_token: String,
    kdf: rbw::api::KdfType,
    iterations: u32,
    memory: Option<u32>,
    parallelism: Option<u32>,
    protected_key: String,
    password: rbw::locked::Password,
    mut db: rbw::db::Db,
    email: String,
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

    let res = rbw::actions::unlock(
        &email,
        &password,
        kdf,
        iterations,
        memory,
        parallelism,
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

/// Prompt the user for the master password. On macOS this defaults to
/// a native secure dialog (works without a terminal — ideal for
/// ssh-sign / GUI-triggered unlocks, and the only option when pinentry
/// isn't installed); user can set `macos_unlock_dialog = false` to
/// force pinentry. On other platforms this always goes through
/// pinentry.
///
/// `title` is the dialog/pinentry header. `pinentry_desc` is what
/// pinentry shows beneath it; the native dialog uses a longer auto-
/// generated body that embeds the error context for retries.
async fn prompt_master_password(
    title: &str,
    pinentry_desc: &str,
    environment: &rbw::protocol::Environment,
    err: Option<&str>,
) -> bin_error::Result<rbw::locked::Password> {
    let use_native = cfg!(target_os = "macos")
        && rbw::config::Config::load_async()
            .await
            .map_or(cfg!(target_os = "macos"), |c| c.macos_unlock_dialog);

    let message = err.map_or_else(
        || pinentry_desc.to_string(),
        |e| format!("{e} — {pinentry_desc}"),
    );

    if use_native {
        let title = title.to_string();
        // osascript display dialog is synchronous / blocking; run on a
        // blocking thread so we don't stall the tokio runtime.
        match tokio::task::spawn_blocking(move || {
            rbw::pinentry_native::prompt_master_password(&title, &message)
        })
        .await
        .map_err(|e| bin_error::Error::msg(format!("join: {e}")))?
        {
            Ok(pw) => return Ok(pw),
            Err(rbw::error::Error::NativePromptUnsupported) => {
                // Shouldn't happen on macOS; fall through to pinentry.
            }
            Err(e) => return Err(e.into()),
        }
    }

    let pinentry = config_pinentry().await?;
    rbw::pinentry::getpin(
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

/// Prompt for a 2FA code. Goes through the native macOS dialog in
/// visible-text mode (codes aren't secrets worth masking and the
/// Yubikey/TOTP codes are short enough that users want to see them).
/// Falls back to pinentry on non-macOS or when `macos_unlock_dialog`
/// is off.
async fn prompt_two_factor_code(
    title: &str,
    message: &str,
    grab: bool,
    environment: &rbw::protocol::Environment,
    err: Option<&str>,
) -> bin_error::Result<rbw::locked::Password> {
    let use_native = cfg!(target_os = "macos")
        && rbw::config::Config::load_async()
            .await
            .map_or(cfg!(target_os = "macos"), |c| c.macos_unlock_dialog);

    if use_native {
        let body = err.map_or_else(
            || message.to_string(),
            |e| format!("{e} — {message}"),
        );
        let title = title.to_string();
        match tokio::task::spawn_blocking(move || {
            rbw::pinentry_native::prompt(
                &title,
                &body,
                "Submit",
                rbw::pinentry_native::InputKind::Secret,
            )
        })
        .await
        .map_err(|e| bin_error::Error::msg(format!("join: {e}")))?
        {
            Ok(code) => return Ok(code),
            Err(rbw::error::Error::NativePromptUnsupported) => {}
            Err(e) => return Err(e.into()),
        }
    }

    let pinentry = config_pinentry().await?;
    rbw::pinentry::getpin(&pinentry, title, message, err, environment, grab)
        .await
        .context("failed to read code from pinentry")
}

/// Convenience wrapper for the unlock path.
async fn prompt_unlock_password(
    environment: &rbw::protocol::Environment,
    err: Option<&str>,
) -> bin_error::Result<rbw::locked::Password> {
    let profile = rbw::dirs::profile();
    prompt_master_password(
        "Unlock rbw vault",
        &format!("Unlock the local database for '{profile}'"),
        environment,
        err,
    )
    .await
}

async fn unlock_state(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
) -> bin_error::Result<()> {
    if state.lock().await.needs_unlock() {
        // Prefer Touch ID-based unlock if the user has enrolled and the
        // gate is active. Falls through to pinentry on cancel or error,
        // surfacing the reason in the first prompt so the user knows
        // why the master password is suddenly being asked for.
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

        // Seed the retry loop with the Touch ID fallback reason (if any)
        // so the first prompt explains why the user is seeing it.
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
            match rbw::actions::unlock(
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
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
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
    environment: &rbw::protocol::Environment,
) -> bin_error::Result<()> {
    unlock_state(state, environment).await?;

    respond_ack(sock).await?;

    Ok(())
}

async fn unlock_success(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    keys: rbw::locked::Keys,
    org_keys: std::collections::HashMap<String, rbw::locked::Keys>,
) -> bin_error::Result<()> {
    let mut state = state.lock().await;
    state.priv_key = Some(keys);
    state.org_keys = Some(org_keys);
    Ok(())
}

/// Attempt to unlock the vault using the Touch ID-enrolled wrapper key.
/// Outcome of an attempted Touch ID-backed unlock. The `Fallback`
/// variants feed a human-readable hint into the caller's next prompt
/// so the user knows why they're suddenly being asked for the master
/// password instead of just seeing a Touch ID dialog.
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

/// Attempt to unlock the vault using the Touch ID-enrolled wrapper
/// key. Returns `Unlocked` on success. Returns `Fallback(reason)` when
/// enrollment is absent, the gate is off, or the user cancelled /
/// biometry was invalidated — the caller should then fall through to
/// the pinentry path, optionally surfacing `reason` in the prompt.
#[cfg(target_os = "macos")]
async fn try_unlock_via_touchid(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> TouchIdUnlockOutcome {
    let gate = rbw::config::Config::load()
        .map_or(rbw::touchid::Gate::Off, |c| c.touchid_gate);
    if matches!(gate, rbw::touchid::Gate::Off) {
        log::debug!("touchid: gate is off; skipping Keychain unlock");
        return TouchIdUnlockOutcome::Fallback(
            "Touch ID gate disabled (touchid_gate=off)",
        );
    }
    let Ok(blob) = rbw::touchid::blob::Blob::load() else {
        log::debug!("touchid: no enrollment blob on disk");
        return TouchIdUnlockOutcome::Fallback(
            "no Touch ID enrollment (run `rbw touchid enroll`)",
        );
    };
    log::debug!(
        "touchid: attempting Keychain load for label {label}",
        label = blob.keychain_label
    );
    let prompt = format!("Unlock the {} vault", rbw::dirs::profile());
    let seed =
        match rbw::touchid::keychain::load(&blob.keychain_label, &prompt) {
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
            Err(rbw::touchid::keychain::Error::UserCancelled) => {
                log::debug!("touchid: user cancelled Keychain prompt");
                return TouchIdUnlockOutcome::Fallback("Touch ID cancelled");
            }
            Err(rbw::touchid::keychain::Error::Invalidated) => {
                log::warn!(
                    "touchid: biometric set changed; master password \
                 required to re-enroll"
                );
                return TouchIdUnlockOutcome::Fallback(
                    "biometric set changed — run `rbw touchid enroll` \
                 after unlocking to re-bind",
                );
            }
            Err(rbw::touchid::keychain::Error::NotFound) => {
                log::warn!(
                    "touchid: enrollment blob present but Keychain item \
                 missing; likely deleted outside rbw"
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
        rbw::touchid::blob::keys_from_wrapper_seed(seed.data());

    let Ok(cs) = rbw::cipherstring::CipherString::new(&blob.wrapped_priv_key)
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
    let priv_key = rbw::locked::Keys::new(priv_bytes);

    let mut org_keys = std::collections::HashMap::new();
    for (oid, wrapped) in &blob.wrapped_org_keys {
        let Ok(cs) = rbw::cipherstring::CipherString::new(wrapped) else {
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
        org_keys.insert(oid.clone(), rbw::locked::Keys::new(bytes));
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

pub async fn sync(
    sock: Option<&mut crate::sock::Sock>,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    let mut db = load_db().await?;

    let access_token = if let Some(access_token) = &db.access_token {
        access_token.clone()
    } else {
        return Err(bin_error::Error::msg(
            "failed to find access token in db",
        ));
    };
    let refresh_token = if let Some(refresh_token) = &db.refresh_token {
        refresh_token.clone()
    } else {
        return Err(bin_error::Error::msg(
            "failed to find refresh token in db",
        ));
    };
    let (
        access_token,
        (protected_key, protected_private_key, protected_org_keys, entries),
    ) = rbw::actions::sync(&access_token, &refresh_token)
        .await
        .context("failed to sync database from server")?;
    state.lock().await.set_master_password_reprompt(&entries);
    if let Some(access_token) = access_token {
        db.access_token = Some(access_token);
    }
    db.protected_key = Some(protected_key);
    db.protected_private_key = Some(protected_private_key);
    db.protected_org_keys = protected_org_keys;
    db.entries = entries;
    save_db(&db).await?;

    if let Err(e) = subscribe_to_notifications(state.clone()).await {
        eprintln!("failed to subscribe to notifications: {e}");
    }

    if let Some(sock) = sock {
        respond_ack(sock).await?;
    }

    Ok(())
}

async fn decrypt_cipher(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> bin_error::Result<String> {
    let mut state = state.lock().await;
    if !state.master_password_reprompt_initialized() {
        let db = load_db().await?;
        state.set_master_password_reprompt(&db.entries);
    }
    let Some(keys) = state.key(org_id) else {
        return Err(bin_error::Error::msg(
            "failed to find decryption keys in in-memory state",
        ));
    };
    let entry_key = if let Some(entry_key) = entry_key {
        let key_cipherstring =
            rbw::cipherstring::CipherString::new(entry_key)
                .context("failed to parse individual item encryption key")?;
        Some(rbw::locked::Keys::new(
            key_cipherstring.decrypt_locked_symmetric(keys).context(
                "failed to decrypt individual item encryption key",
            )?,
        ))
    } else {
        None
    };

    let mut sha256 = sha2::Sha256::new();
    sha256.update(cipherstring);
    let master_password_reprompt: [u8; 32] = sha256.finalize().into();
    if state
        .master_password_reprompt
        .contains(&master_password_reprompt)
    {
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

        let mut err_msg = None;
        for i in 1_u8..=3 {
            let err = if i > 1 {
                // this unwrap is safe because we only ever continue the loop
                // if we have set err_msg
                Some(format!("{} (attempt {}/3)", err_msg.unwrap(), i))
            } else {
                None
            };
            let password = prompt_master_password(
                "Master Password",
                "Accessing this entry requires the master password",
                environment,
                err.as_deref(),
            )
            .await
            .context("failed to read master password")?;
            match rbw::actions::unlock(
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
                Ok(_) => {
                    break;
                }
                Err(rbw::error::Error::IncorrectPassword { message }) => {
                    if i == 3 {
                        return Err(rbw::error::Error::IncorrectPassword {
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

    let cipherstring = rbw::cipherstring::CipherString::new(cipherstring)
        .context("failed to parse encrypted secret")?;
    let plaintext = String::from_utf8(
        cipherstring
            .decrypt_symmetric(keys, entry_key.as_ref())
            .context("failed to decrypt encrypted secret")?,
    )
    .context("failed to parse decrypted secret")?;

    Ok(plaintext)
}

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &rbw::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    enforce_touchid_gate(
        state.clone(),
        rbw::touchid::Kind::VaultSecret,
        session_id,
        purpose,
    )
    .await?;
    let plaintext =
        decrypt_cipher(state, environment, cipherstring, entry_key, org_id)
            .await?;
    respond_decrypt(sock, plaintext).await?;

    Ok(())
}

pub async fn encrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    plaintext: &str,
    org_id: Option<&str>,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    enforce_touchid_gate(
        state.clone(),
        rbw::touchid::Kind::VaultSecret,
        session_id,
        purpose,
    )
    .await?;
    let state = state.lock().await;
    let Some(keys) = state.key(org_id) else {
        return Err(bin_error::Error::msg(
            "failed to find encryption keys in in-memory state",
        ));
    };
    let cipherstring = rbw::cipherstring::CipherString::encrypt_symmetric(
        keys,
        plaintext.as_bytes(),
    )
    .context("failed to encrypt plaintext secret")?;

    respond_encrypt(sock, cipherstring.to_string()).await?;

    Ok(())
}

#[cfg(feature = "clipboard")]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    text: &str,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    enforce_touchid_gate(
        state.clone(),
        rbw::touchid::Kind::VaultSecret,
        session_id,
        purpose,
    )
    .await?;
    let mut state = state.lock().await;
    if let Some(clipboard) = &mut state.clipboard {
        clipboard.set_text(text).map_err(|e| {
            bin_error::Error::msg(format!(
                "couldn't store value to clipboard: {e}"
            ))
        })?;
    }

    respond_ack(sock).await?;

    Ok(())
}

#[cfg(not(feature = "clipboard"))]
pub async fn clipboard_store(
    sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    _text: &str,
    _session_id: Option<&str>,
    _purpose: Option<&str>,
) -> bin_error::Result<()> {
    sock.send(&rbw::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> bin_error::Result<()> {
    sock.send(&rbw::protocol::Response::Version {
        version: rbw::protocol::VERSION,
    })
    .await?;

    Ok(())
}

async fn respond_ack(sock: &mut crate::sock::Sock) -> bin_error::Result<()> {
    sock.send(&rbw::protocol::Response::Ack).await?;

    Ok(())
}

#[cfg(target_os = "macos")]
pub async fn touchid_enroll(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    use rand::RngCore as _;

    // Require an unlocked vault so we have keys to wrap.
    {
        let s = state.lock().await;
        if s.needs_unlock() {
            return Err(bin_error::Error::msg(
                "cannot enroll Touch ID while vault is locked; \
                 run `rbw unlock` first",
            ));
        }
    }

    // Generate a random 64-byte wrapper seed. The buffer lives in a
    // `locked::Vec` (mlocked + zeroized on drop) so the seed never sits
    // in ordinary heap / stack memory that could be recovered from a
    // core dump or swap.
    let mut seed = rbw::locked::Vec::new();
    seed.extend(std::iter::repeat_n(0u8, 64));
    rand::rng().fill_bytes(seed.data_mut());
    let wrapper_keys =
        rbw::touchid::blob::keys_from_wrapper_seed(seed.data());

    let label = format!("rbw-touchid-{}", rbw::uuid::new_v4());

    let (wrapped_priv_key, wrapped_org_keys) = {
        let s = state.lock().await;
        let priv_key = s.priv_key.as_ref().ok_or_else(|| {
            bin_error::Error::msg("priv_key missing post-unlock")
        })?;
        let org_keys = s.org_keys.as_ref().ok_or_else(|| {
            bin_error::Error::msg("org_keys missing post-unlock")
        })?;
        let wrapped_priv =
            rbw::cipherstring::CipherString::encrypt_symmetric(
                &wrapper_keys,
                priv_key.as_bytes(),
            )
            .context("wrap priv_key")?
            .to_string();
        let mut wrapped_org = std::collections::BTreeMap::new();
        for (oid, k) in org_keys {
            wrapped_org.insert(
                oid.clone(),
                rbw::cipherstring::CipherString::encrypt_symmetric(
                    &wrapper_keys,
                    k.as_bytes(),
                )
                .with_context(|| format!("wrap org key {oid}"))?
                .to_string(),
            );
        }
        (wrapped_priv, wrapped_org)
    };

    // If a prior enrollment exists, remove it first — we're rotating.
    if let Ok(existing) = rbw::touchid::blob::Blob::load() {
        let _ = rbw::touchid::keychain::delete(&existing.keychain_label);
    }
    rbw::touchid::keychain::store(&label, seed.data())
        .map_err(|e| bin_error::Error::msg(e.to_string()))?;

    let blob = rbw::touchid::blob::Blob {
        keychain_label: label,
        wrapped_priv_key,
        wrapped_org_keys,
    };
    blob.save().context("write touchid blob")?;

    respond_ack(sock).await?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unused_async)]
pub async fn touchid_enroll(
    _sock: &mut crate::sock::Sock,
    _state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    Err(bin_error::Error::msg(
        "touchid enroll is only supported on macOS",
    ))
}

pub async fn touchid_disable(
    sock: &mut crate::sock::Sock,
) -> bin_error::Result<()> {
    #[cfg(target_os = "macos")]
    if let Ok(blob) = rbw::touchid::blob::Blob::load() {
        let _ = rbw::touchid::keychain::delete(&blob.keychain_label);
    }
    rbw::touchid::blob::Blob::remove().context("remove touchid blob")?;
    respond_ack(sock).await?;
    Ok(())
}

pub async fn touchid_status(
    sock: &mut crate::sock::Sock,
) -> bin_error::Result<()> {
    let config = rbw::config::Config::load()
        .unwrap_or_else(|_| rbw::config::Config::new());
    let (enrolled, label) = match rbw::touchid::blob::Blob::load() {
        Ok(blob) => (true, Some(blob.keychain_label)),
        Err(_) => (false, None),
    };
    sock.send(&rbw::protocol::Response::TouchIdStatus {
        enrolled,
        gate: config.touchid_gate.to_string(),
        keychain_label: label,
    })
    .await?;
    Ok(())
}

async fn respond_decrypt(
    sock: &mut crate::sock::Sock,
    plaintext: String,
) -> bin_error::Result<()> {
    sock.send(&rbw::protocol::Response::Decrypt { plaintext })
        .await?;

    Ok(())
}

async fn respond_encrypt(
    sock: &mut crate::sock::Sock,
    cipherstring: String,
) -> bin_error::Result<()> {
    sock.send(&rbw::protocol::Response::Encrypt { cipherstring })
        .await?;

    Ok(())
}

async fn config_email() -> bin_error::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    config.email.map_or_else(
        || {
            Err(bin_error::Error::msg(
                "failed to find email address in config",
            ))
        },
        Ok,
    )
}

async fn load_db() -> bin_error::Result<rbw::db::Db> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        Ok(rbw::db::Db::load_async(&config.server_name(), email).await?)
    } else {
        Err(bin_error::Error::msg(
            "failed to find email address in config",
        ))
    }
}

async fn save_db(db: &rbw::db::Db) -> bin_error::Result<()> {
    let config = rbw::config::Config::load_async().await?;
    if let Some(email) = &config.email {
        db.save_async(&config.server_name(), email).await?;
        Ok(())
    } else {
        Err(bin_error::Error::msg(
            "failed to find email address in config",
        ))
    }
}

async fn config_base_url() -> bin_error::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.base_url())
}

async fn config_pinentry() -> bin_error::Result<String> {
    let config = rbw::config::Config::load_async().await?;
    Ok(config.pinentry)
}

pub async fn subscribe_to_notifications(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<()> {
    if state.lock().await.notifications_handler.is_connected() {
        return Ok(());
    }

    let config = rbw::config::Config::load_async()
        .await
        .context("Config is missing")?;
    let email = config.email.clone().context("Config is missing email")?;
    let db = rbw::db::Db::load_async(config.server_name().as_str(), &email)
        .await?;
    let access_token =
        db.access_token.context("Error getting access token")?;

    let websocket_url = format!(
        "{}/hub?access_token={}",
        config.notifications_url(),
        access_token
    )
    .replace("https://", "wss://");

    let mut state = state.lock().await;
    state
        .notifications_handler
        .connect(websocket_url)
        .await
        .err()
        .map_or_else(
            || Ok(()),
            |err| Err(bin_error::Error::msg(err.to_string())),
        )
}

pub async fn get_ssh_public_keys(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
) -> bin_error::Result<Vec<String>> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let db = load_db().await?;
    let mut pubkeys = Vec::new();

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            public_key: Some(encrypted),
            ..
        } = &entry.data
        {
            let plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                encrypted,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;

            pubkeys.push(plaintext);
        }
    }

    Ok(pubkeys)
}

/// Encrypted handle to an SSH entry that matched the requested pubkey.
/// Holds the still-encrypted `private_key` cipherstring plus whatever
/// envelope metadata we need to decrypt it later, after user
/// confirmation. The plaintext private key is intentionally **not**
/// pulled into memory here so a cancelled confirm leaves no key
/// material on the heap.
pub struct LocatedSshEntry {
    pub private_key_enc: String,
    pub entry_key: Option<String>,
    pub org_id: Option<String>,
    pub name: String,
}

pub async fn locate_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    request_public_key: ssh_agent_lib::ssh_key::PublicKey,
) -> bin_error::Result<LocatedSshEntry> {
    let environment = {
        let state = state.lock().await;
        state.set_timeout();
        state.last_environment().clone()
    };
    unlock_state(state.clone(), &environment).await?;

    let request_bytes = request_public_key.to_bytes();

    let db = load_db().await?;

    for entry in db.entries {
        if let rbw::db::EntryData::SshKey {
            private_key,
            public_key,
            ..
        } = &entry.data
        {
            let Some(public_key_enc) = public_key else {
                continue;
            };
            let public_key_plaintext = decrypt_cipher(
                state.clone(),
                &environment,
                public_key_enc,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
            .await?;
            let public_key_bytes =
                ssh_agent_lib::ssh_key::PublicKey::from_openssh(
                    &public_key_plaintext,
                )
                .map_err(|e| bin_error::Error::Boxed(Box::new(e)))?
                .to_bytes();

            if public_key_bytes == request_bytes {
                let private_key_enc =
                    private_key.as_ref().ok_or_else(|| {
                        bin_error::Error::msg(
                            "Matching entry has no private key",
                        )
                    })?;

                let name_plaintext = decrypt_cipher(
                    state.clone(),
                    &environment,
                    &entry.name,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .await
                .unwrap_or_else(|_| "<unknown>".to_string());

                return Ok(LocatedSshEntry {
                    private_key_enc: private_key_enc.clone(),
                    entry_key: entry.key.clone(),
                    org_id: entry.org_id.clone(),
                    name: name_plaintext,
                });
            }
        }
    }

    Err(bin_error::Error::msg("No matching private key found"))
}

/// Second phase of the split SSH-sign flow: decrypt the private key
/// cipherstring located by `locate_ssh_private_key`, only after the
/// user has already confirmed Touch ID / pinentry CONFIRM. Callers
/// must drop the returned `PrivateKey` as soon as the sign operation
/// completes.
pub async fn decrypt_located_ssh_private_key(
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    located: &LocatedSshEntry,
) -> bin_error::Result<ssh_agent_lib::ssh_key::PrivateKey> {
    let environment = {
        let state = state.lock().await;
        state.last_environment().clone()
    };
    let plaintext = decrypt_cipher(
        state,
        &environment,
        &located.private_key_enc,
        located.entry_key.as_deref(),
        located.org_id.as_deref(),
    )
    .await?;
    ssh_agent_lib::ssh_key::PrivateKey::from_openssh(plaintext)
        .map_err(|e| bin_error::Error::Boxed(Box::new(e)))
}
