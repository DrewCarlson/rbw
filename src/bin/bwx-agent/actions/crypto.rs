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

/// Hard ceiling on items in a single `DecryptBatch`. Comfortably above
/// any realistic vault size (~thousands of entries × a handful of
/// fields) and well under what a 16 MiB request frame could pack.
const BATCH_MAX_ITEMS: usize = 10_000;

pub async fn decrypt_batch(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    environment: &bwx::protocol::Environment,
    items: Vec<bwx::protocol::DecryptItem>,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    if items.len() > BATCH_MAX_ITEMS {
        sock.send(&bwx::protocol::Response::Error {
            error: format!(
                "decrypt batch too large ({} items, max {BATCH_MAX_ITEMS})",
                items.len()
            ),
        })
        .await?;
        return Ok(());
    }

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
                results
                    .push(bwx::protocol::DecryptItemResult::Ok { plaintext });
            }
            Err(e) => {
                results.push(bwx::protocol::DecryptItemResult::Err {
                    error: sanitize_batch_item_error(&e),
                });
            }
        }
    }

    sock.send(&bwx::protocol::Response::DecryptBatch { results })
        .await?;

    Ok(())
}

/// Forward only the top-level context for a per-item batch failure.
/// We intentionally drop the source chain so a future error wrapping
/// (path, token, ciphertext bytes) can't ride out over IPC; the
/// categorical message is enough to tell `bwx list` why a row was
/// dropped.
fn sanitize_batch_item_error(e: &bin_error::Error) -> String {
    match e {
        bin_error::Error::Msg(s) => s.clone(),
        bin_error::Error::WithContext { context, .. } => context.clone(),
        bin_error::Error::Boxed(_) => "decrypt failed".to_string(),
    }
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

pub async fn encrypt_batch(
    sock: &mut crate::sock::Sock,
    state: std::sync::Arc<tokio::sync::Mutex<crate::state::State>>,
    items: Vec<bwx::protocol::EncryptItem>,
    session_id: Option<&str>,
    purpose: Option<&str>,
) -> bin_error::Result<()> {
    if items.len() > BATCH_MAX_ITEMS {
        sock.send(&bwx::protocol::Response::Error {
            error: format!(
                "encrypt batch too large ({} items, max {BATCH_MAX_ITEMS})",
                items.len()
            ),
        })
        .await?;
        return Ok(());
    }

    enforce_touchid_gate(
        state.clone(),
        bwx::touchid::Kind::VaultSecret,
        session_id,
        purpose,
    )
    .await?;

    let state = state.lock().await;
    let mut results = Vec::with_capacity(items.len());
    for item in items {
        let Some(keys) = state.key(item.org_id.as_deref()) else {
            results.push(bwx::protocol::EncryptItemResult::Err {
                error: "failed to find encryption keys in in-memory state"
                    .to_string(),
            });
            continue;
        };
        match bwx::cipherstring::CipherString::encrypt_symmetric(
            keys,
            item.plaintext.as_bytes(),
        ) {
            Ok(cs) => {
                results.push(bwx::protocol::EncryptItemResult::Ok {
                    cipherstring: cs.to_string(),
                });
            }
            Err(e) => {
                let wrapped = bin_error::Error::with_context(
                    e,
                    "failed to encrypt plaintext secret",
                );
                results.push(bwx::protocol::EncryptItemResult::Err {
                    error: sanitize_batch_item_error(&wrapped),
                });
            }
        }
    }

    sock.send(&bwx::protocol::Response::EncryptBatch { results })
        .await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_drops_source_chain_for_with_context() {
        let inner =
            std::io::Error::other("<sensitive: mac mismatch on 0xabcdef...>");
        let wrapped =
            bin_error::Error::with_context(inner, "failed to decrypt entry");
        let out = sanitize_batch_item_error(&wrapped);
        assert_eq!(out, "failed to decrypt entry");
        assert!(!out.contains("0xabcdef"));
    }

    #[test]
    fn sanitize_passes_through_msg_variant() {
        let e = bin_error::Error::Msg("agent locked".into());
        assert_eq!(sanitize_batch_item_error(&e), "agent locked");
    }

    #[test]
    fn sanitize_boxed_returns_generic() {
        let io_err =
            std::io::Error::other("/tmp/secret-token-AKIAIOSFODNN7EXAMPLE");
        let boxed = bin_error::Error::Boxed(Box::new(io_err));
        let out = sanitize_batch_item_error(&boxed);
        assert_eq!(out, "decrypt failed");
        assert!(!out.contains("AKIA"));
    }
}
