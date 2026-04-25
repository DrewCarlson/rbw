//! Touch ID / biometric authorization gate.
//!
//! macOS-only feature; see `SPIKE_TOUCHID.md` for the architecture
//! discussion. On macOS the gate calls `LAContext::evaluate_policy` via
//! `objc2-local-authentication`. On other platforms `require_presence`
//! is a stub that always returns `Ok(true)`, so callers can use the
//! same API everywhere without cfg gating at every site.

pub mod blob;
#[cfg(target_os = "macos")]
pub mod keychain;

use std::fmt;
use std::str::FromStr;

/// Which categories of operation should require biometric confirmation.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum Gate {
    /// No biometric prompt. Always the value on non-macOS builds.
    #[default]
    Off,
    /// Only ssh-agent sign requests and `bwx code` TOTP generation.
    Signing,
    /// Every response that carries plaintext secret material.
    All,
}

impl FromStr for Gate {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "off" | "false" => Ok(Self::Off),
            "signing" => Ok(Self::Signing),
            "all" | "true" => Ok(Self::All),
            other => Err(format!(
                "invalid touchid_gate value {other:?} (expected \
                 off/signing/all)"
            )),
        }
    }
}

impl fmt::Display for Gate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Off => "off",
            Self::Signing => "signing",
            Self::All => "all",
        })
    }
}

/// Category of operation a call site represents. Used with a `Gate` to
/// decide whether a biometric prompt is required.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// SSH-agent sign request.
    SshSign,
    /// `bwx code` TOTP generation.
    TotpCode,
    /// Agent `Decrypt` / `Encrypt` / clipboard response carrying vault
    /// secret material.
    VaultSecret,
}

#[must_use]
pub fn gate_applies(gate: Gate, kind: Kind) -> bool {
    match gate {
        Gate::Off => false,
        Gate::Signing => matches!(kind, Kind::SshSign | Kind::TotpCode),
        Gate::All => true,
    }
}

/// Await a biometric confirmation from the user.
///
/// Returns `Ok(true)` if the user authenticated, `Ok(false)` if they
/// cancelled, `Err(..)` only for unexpected failures (hardware missing,
/// permissions, etc.). On non-macOS builds this always returns `Ok(true)`.
#[cfg(target_os = "macos")]
pub async fn require_presence(reason: &str) -> Result<bool, Error> {
    macos::require_presence(reason).await
}

#[cfg(not(target_os = "macos"))]
#[allow(clippy::unused_async)]
pub async fn require_presence(_reason: &str) -> Result<bool, Error> {
    Ok(true)
}

#[derive(Debug)]
pub enum Error {
    /// Biometry is not available on this machine (no hardware, lid
    /// closed, or the user has disabled Touch ID for this app).
    Unavailable(String),
    /// Something else went wrong talking to the OS.
    Os(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(s) => {
                write!(f, "biometry unavailable: {s}")
            }
            Self::Os(s) => write!(f, "LocalAuthentication error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

#[cfg(target_os = "macos")]
mod macos {
    use block2::RcBlock;
    use objc2::rc::Retained;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};

    use super::Error;

    /// Test bypass for e2e scenarios: if set to "allow"/"deny" AND the
    /// binary was built with debug assertions, the FFI call is skipped and
    /// the bypass value is used. Ignored in release builds.
    fn debug_bypass() -> Option<bool> {
        if !cfg!(debug_assertions) {
            return None;
        }
        match std::env::var("BWX_TOUCHID_TEST_BYPASS").ok().as_deref() {
            Some("allow") => Some(true),
            Some("deny") => Some(false),
            _ => None,
        }
    }

    /// Synchronous setup: create the `LAContext`, install the completion
    /// handler, kick off `evaluatePolicy`. Returns a `Receiver` that will
    /// be signalled when the OS callback fires. All objc types are
    /// confined to this function so they never cross an `.await`, keeping
    /// the outer async future `Send`.
    fn begin_presence_check(
        reason: &str,
    ) -> Result<tokio::sync::oneshot::Receiver<Result<bool, Error>>, Error>
    {
        // SAFETY: LAContext::new is a +1-retain convenience constructor.
        let ctx: Retained<LAContext> = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

        if let Err(err) = unsafe { ctx.canEvaluatePolicy_error(policy) } {
            return Err(Error::Unavailable(
                err.localizedDescription().to_string(),
            ));
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<Result<bool, Error>>();
        let tx = std::sync::Mutex::new(Some(tx));
        let block = RcBlock::new(move |success: Bool, err: *mut NSError| {
            let claimed = tx.lock().unwrap().take();
            if let Some(tx) = claimed {
                let res = if success.as_bool() {
                    Ok(true)
                } else if err.is_null() {
                    Ok(false)
                } else {
                    // SAFETY: the framework hands us a retained NSError
                    // that's live for the duration of the callback.
                    let desc =
                        unsafe { (*err).localizedDescription().to_string() };
                    let code = unsafe { (*err).code() };
                    if code == -2 || code == -4 {
                        // LAError.userCancel = -2; LAError.systemCancel = -4
                        Ok(false)
                    } else {
                        Err(Error::Os(format!("code={code}: {desc}")))
                    }
                };
                let _ = tx.send(res);
            }
        });

        let reason_ns = NSString::from_str(reason);
        unsafe {
            ctx.evaluatePolicy_localizedReason_reply(
                policy, &reason_ns, &block,
            );
        }
        Ok(rx)
    }

    pub async fn require_presence(reason: &str) -> Result<bool, Error> {
        if let Some(v) = debug_bypass() {
            return Ok(v);
        }
        let rx = begin_presence_check(reason)?;
        rx.await.map_err(|_| Error::Os("reply dropped".into()))?
    }
}

#[cfg(test)]
mod tests {
    use super::{gate_applies, Gate, Kind};

    #[test]
    fn gate_off_never_applies() {
        for k in [Kind::SshSign, Kind::TotpCode, Kind::VaultSecret] {
            assert!(!gate_applies(Gate::Off, k));
        }
    }

    #[test]
    fn gate_signing_matches_only_signing_kinds() {
        assert!(gate_applies(Gate::Signing, Kind::SshSign));
        assert!(gate_applies(Gate::Signing, Kind::TotpCode));
        assert!(!gate_applies(Gate::Signing, Kind::VaultSecret));
    }

    #[test]
    fn gate_all_applies_everywhere() {
        for k in [Kind::SshSign, Kind::TotpCode, Kind::VaultSecret] {
            assert!(gate_applies(Gate::All, k));
        }
    }

    #[test]
    fn gate_parse_roundtrip() {
        for g in [Gate::Off, Gate::Signing, Gate::All] {
            let s = g.to_string();
            let parsed: Gate = s.parse().expect("parse");
            assert_eq!(g, parsed);
        }
    }

    #[test]
    fn gate_parse_rejects_garbage() {
        assert!("maybe".parse::<Gate>().is_err());
    }
}
