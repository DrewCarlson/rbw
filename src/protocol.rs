use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};

pub const VERSION: u32 = {
    const fn unwrap(res: &Result<u32, std::num::ParseIntError>) -> u32 {
        match res {
            Ok(t) => *t,
            Err(_) => panic!("failed to parse cargo version"),
        }
    }

    let major = env!("CARGO_PKG_VERSION_MAJOR");
    let minor = env!("CARGO_PKG_VERSION_MINOR");
    let patch = env!("CARGO_PKG_VERSION_PATCH");

    unwrap(&u32::from_str_radix(major, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(minor, 10)) * 1_000_000
        + unwrap(&u32::from_str_radix(patch, 10)) * 1_000_000
};

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Request {
    tty: Option<String>,
    environment: Option<Environment>,
    action: Action,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    /// Human-readable description of what the user ran (e.g. `get
    /// google.com`). Used only to enrich agent-side UI prompts (Touch ID
    /// dialog, pinentry CONFIRM); not authentication-relevant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    purpose: Option<String>,
}

impl Request {
    pub fn new(environment: Environment, action: Action) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            action,
            session_id: None,
            purpose: None,
        }
    }

    /// Like `new`, but tags the request with a per-CLI-process session
    /// token and a human-readable purpose string. The agent coalesces
    /// Touch ID prompts by session so a single `bwx <command>` invocation
    /// only pops one biometric dialog regardless of how many
    /// `Decrypt`/`Encrypt` IPCs it fires; the purpose is shown on the
    /// prompt itself.
    pub fn new_with_session(
        environment: Environment,
        action: Action,
        session_id: String,
        purpose: Option<String>,
    ) -> Self {
        Self {
            tty: None,
            environment: Some(environment),
            action,
            session_id: Some(session_id),
            purpose,
        }
    }

    pub fn into_parts(
        self,
    ) -> (Action, Environment, Option<String>, Option<String>) {
        (
            self.action,
            self.environment.unwrap_or_else(|| Environment {
                tty: self.tty.map(|tty| SerializableOsString(tty.into())),
                env_vars: vec![],
            }),
            self.session_id,
            self.purpose,
        )
    }
}

// Taken from https://github.com/gpg/gnupg/blob/36dbca3e6944d13e75e96eace634e58a7d7e201d/common/session-env.c#L62-L91
pub const ENVIRONMENT_VARIABLES: &[&str] = &[
    // Used to set ttytype
    "TERM",
    // The X display
    "DISPLAY",
    // Xlib Authentication
    "XAUTHORITY",
    // Used by Xlib to select X input modules (e.g. "@im=SCIM")
    "XMODIFIERS",
    // For the Wayland display engine.
    "WAYLAND_DISPLAY",
    // Used by Qt and other non-GTK toolkits to check for X11 or Wayland
    "XDG_SESSION_TYPE",
    // Used by Qt to explicitly request X11 or Wayland; in particular, needed to
    // make Qt use Wayland on GNOME
    "QT_QPA_PLATFORM",
    // Used by GTK to select GTK input modules (e.g. "scim-bridge")
    "GTK_IM_MODULE",
    // Used by GNOME 3 to talk to gcr over dbus
    "DBUS_SESSION_BUS_ADDRESS",
    // Used by Qt to select Qt input modules (e.g. "xim")
    "QT_IM_MODULE",
    // Used for communication with non-standard Pinentries
    "PINENTRY_USER_DATA",
    // Used to pass window information
    "PINENTRY_GEOM_HINT",
];

pub static ENVIRONMENT_VARIABLES_OS: std::sync::LazyLock<
    Vec<std::ffi::OsString>,
> = std::sync::LazyLock::new(|| {
    ENVIRONMENT_VARIABLES
        .iter()
        .map(std::ffi::OsString::from)
        .collect()
});

#[derive(Hash, PartialEq, Eq, Debug, Clone)]
struct SerializableOsString(std::ffi::OsString);

impl serde::Serialize for SerializableOsString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&crate::base64::encode(self.0.as_bytes()))
    }
}

impl<'de> serde::Deserialize<'de> for SerializableOsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = SerializableOsString;

            fn expecting(
                &self,
                formatter: &mut std::fmt::Formatter,
            ) -> std::fmt::Result {
                formatter.write_str("base64 encoded os string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SerializableOsString(std::ffi::OsString::from_vec(
                    crate::base64::decode(s).map_err(|_| {
                        E::invalid_value(serde::de::Unexpected::Str(s), &self)
                    })?,
                )))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Default, Clone)]
pub struct Environment {
    tty: Option<SerializableOsString>,
    env_vars: Vec<(SerializableOsString, SerializableOsString)>,
}

impl Environment {
    pub fn new(
        tty: Option<std::ffi::OsString>,
        env_vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    ) -> Self {
        Self {
            tty: tty.map(SerializableOsString),
            env_vars: env_vars
                .into_iter()
                .map(|(k, v)| {
                    (SerializableOsString(k), SerializableOsString(v))
                })
                .collect(),
        }
    }

    pub fn tty(&self) -> Option<&std::ffi::OsStr> {
        self.tty.as_ref().map(|tty| tty.0.as_os_str())
    }

    pub fn env_vars(
        &self,
    ) -> std::collections::HashMap<std::ffi::OsString, std::ffi::OsString>
    {
        self.env_vars
            .iter()
            .map(|(var, val)| (var.0.clone(), val.0.clone()))
            .filter(|(var, _)| (*ENVIRONMENT_VARIABLES_OS).contains(var))
            .collect()
    }
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct DecryptItem {
    pub cipherstring: String,
    pub entry_key: Option<String>,
    pub org_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "outcome")]
pub enum DecryptItemResult {
    Ok { plaintext: String },
    Err { error: String },
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct EncryptItem {
    pub plaintext: String,
    pub org_id: Option<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "outcome")]
pub enum EncryptItemResult {
    Ok { cipherstring: String },
    Err { error: String },
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Action {
    Login,
    Register,
    Unlock,
    CheckLock,
    Lock,
    Sync,
    Decrypt {
        cipherstring: String,
        entry_key: Option<String>,
        org_id: Option<String>,
    },
    /// Decrypt many cipherstrings in one IPC. Touch ID is gated once for
    /// the whole batch; per-item failures are surfaced in `results` so
    /// the caller can decide whether to fail loud or skip the bad entry.
    DecryptBatch {
        items: Vec<DecryptItem>,
    },
    Encrypt {
        plaintext: String,
        org_id: Option<String>,
    },
    /// Encrypt many plaintexts in one IPC. Touch ID is gated once for the
    /// whole batch; per-item failures are surfaced in `results` so the
    /// caller can decide whether to fail loud or skip the bad item.
    EncryptBatch {
        items: Vec<EncryptItem>,
    },
    ClipboardStore {
        text: String,
    },
    Quit,
    Version,
    /// Enroll the currently-unlocked vault keys under a Touch ID-gated
    /// Keychain wrapper key. Requires the agent to already be unlocked.
    TouchIdEnroll,
    /// Remove the Keychain wrapper key and the on-disk enrollment blob.
    TouchIdDisable,
    /// Report whether Touch ID enrollment is active and summarise the
    /// current `touchid_gate` setting.
    TouchIdStatus,
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[serde(tag = "type")]
pub enum Response {
    Ack,
    Error {
        error: String,
    },
    Decrypt {
        plaintext: String,
    },
    DecryptBatch {
        results: Vec<DecryptItemResult>,
    },
    Encrypt {
        cipherstring: String,
    },
    EncryptBatch {
        results: Vec<EncryptItemResult>,
    },
    Version {
        version: u32,
    },
    TouchIdStatus {
        enrolled: bool,
        gate: String,
        keychain_label: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rmp_roundtrip<T>(value: &T) -> T
    where
        T: serde::Serialize + serde::de::DeserializeOwned,
    {
        let bytes = rmp_serde::to_vec(value).unwrap();
        rmp_serde::from_slice(&bytes).unwrap()
    }

    #[test]
    fn action_decrypt_msgpack_roundtrip() {
        let a = Action::Decrypt {
            cipherstring: "2.aaa|bbb|ccc".to_string(),
            entry_key: Some("ek".to_string()),
            org_id: None,
        };
        let bytes = rmp_serde::to_vec(&a).unwrap();
        // Sanity-check: msgpack should be tighter than JSON for this
        // payload. JSON of the same struct is ~95 bytes.
        assert!(bytes.len() < 90, "msgpack payload {} bytes", bytes.len());
        match rmp_roundtrip(&a) {
            Action::Decrypt {
                cipherstring,
                entry_key,
                org_id,
            } => {
                assert_eq!(cipherstring, "2.aaa|bbb|ccc");
                assert_eq!(entry_key.as_deref(), Some("ek"));
                assert_eq!(org_id, None);
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    #[test]
    fn decrypt_batch_roundtrip_preserves_order_and_results() {
        let req = Action::DecryptBatch {
            items: vec![
                DecryptItem {
                    cipherstring: "a".into(),
                    entry_key: None,
                    org_id: None,
                },
                DecryptItem {
                    cipherstring: "b".into(),
                    entry_key: Some("k".into()),
                    org_id: Some("org".into()),
                },
            ],
        };
        match rmp_roundtrip(&req) {
            Action::DecryptBatch { items } => {
                assert_eq!(items.len(), 2);
                assert_eq!(items[0].cipherstring, "a");
                assert_eq!(items[1].entry_key.as_deref(), Some("k"));
            }
            other => panic!("unexpected variant: {other:?}"),
        }

        let resp = Response::DecryptBatch {
            results: vec![
                DecryptItemResult::Ok {
                    plaintext: "hello".into(),
                },
                DecryptItemResult::Err {
                    error: "decrypt failed".into(),
                },
            ],
        };
        match rmp_roundtrip(&resp) {
            Response::DecryptBatch { results } => {
                assert_eq!(results.len(), 2);
                assert!(matches!(
                    results[0],
                    DecryptItemResult::Ok { ref plaintext } if plaintext == "hello"
                ));
                assert!(matches!(
                    results[1],
                    DecryptItemResult::Err { ref error } if error == "decrypt failed"
                ));
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
