use super::auth::enforce_touchid_gate;
use super::sync::decrypt_cipher;
use super::util::{respond_ack, respond_decrypt, respond_encrypt};
use crate::bin_error::{self, ContextExt as _};

pub async fn decrypt(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &bwx::protocol::Environment,
    cipherstring: &str,
    entry_key: Option<&str>,
    org_id: Option<&str>,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    enforce_touchid_gate(
        state.clone(),
        bwx::touchid::Kind::VaultSecret,
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

pub async fn decrypt_batch(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &bwx::protocol::Environment,
    items: Vec<bwx::protocol::DecryptItem>,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    enforce_touchid_gate(
        state.clone(),
        bwx::touchid::Kind::VaultSecret,
        session_id,
        purpose,
    )
    .await?;

    let mut results = Vec::with_capacity(items.len());
    for item in items {
        match decrypt_cipher(
            state.clone(),
            environment,
            &item.cipherstring,
            item.entry_key.as_deref(),
            item.org_id.as_deref(),
        )
        .await
        {
            Ok(plaintext) => {
                results.push(bwx::protocol::DecryptItemResult::Ok {
                    plaintext,
                });
            }
            Err(e) => {
                results.push(bwx::protocol::DecryptItemResult::Err {
                    error: format!("{e:#}"),
                });
            }
        }
    }

    sock.send(&bwx::protocol::Response::DecryptBatch { results })
        .await?;

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
        bwx::touchid::Kind::VaultSecret,
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
    let cipherstring = bwx::cipherstring::CipherString::encrypt_symmetric(
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
        bwx::touchid::Kind::VaultSecret,
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
    sock.send(&bwx::protocol::Response::Error {
        error: "clipboard not supported".to_string(),
    })
    .await?;

    Ok(())
}

pub async fn version(sock: &mut crate::sock::Sock) -> bin_error::Result<()> {
    sock.send(&bwx::protocol::Response::Version {
        version: bwx::protocol::VERSION,
    })
    .await?;

    Ok(())
}
