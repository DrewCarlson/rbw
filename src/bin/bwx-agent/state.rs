use sha2::Digest as _;

/// How long a Touch ID authorization remains valid for a given session
/// before the agent will prompt again. Bumped on every access, so the
/// window is "idle time," not a hard upper bound on the total command
/// duration. 60 s is long enough for slow interactive commands and short
/// enough that a backgrounded stale session can't be reused tomorrow.
const TOUCHID_SESSION_TTL: std::time::Duration =
    std::time::Duration::from_secs(60);

pub struct State {
    pub priv_key: Option<bwx::locked::Keys>,
    pub org_keys:
        Option<std::collections::HashMap<String, bwx::locked::Keys>>,
    pub timeout: crate::timeout::Timeout,
    pub timeout_duration: std::time::Duration,
    pub sync_timeout: crate::timeout::Timeout,
    pub sync_timeout_duration: std::time::Duration,
    pub notifications_handler: crate::notifications::Handler,
    pub master_password_reprompt: std::collections::HashSet<[u8; 32]>,
    pub master_password_reprompt_initialized: bool,

    /// Session tokens that have already cleared a Touch ID prompt, each
    /// mapped to the last time we saw activity from that session. Bumped
    /// on every authorized access so a long-running command doesn't time
    /// out mid-execution. Cleared on `Lock`.
    pub touchid_sessions:
        std::collections::HashMap<String, std::time::Instant>,

    // this is stored here specifically for the use of the ssh agent, because
    // requests made to the ssh agent don't include an environment, and so we
    // can't properly initialize the pinentry process. we work around this by
    // just reusing the last environment we saw being sent to the main agent
    // (there should be at least one in most cases because you need to start
    // the bwx agent in order to make it start serving on the ssh agent
    // socket, and that initial request should come with an environment).
    //
    // we should not use this for any requests on the main agent, those
    // should all send their own environment over.
    pub last_environment: bwx::protocol::Environment,

    #[cfg(feature = "clipboard")]
    pub clipboard: Option<arboard::Clipboard>,
}

impl State {
    pub fn key(&self, org_id: Option<&str>) -> Option<&bwx::locked::Keys> {
        org_id.map_or(self.priv_key.as_ref(), |id| {
            self.org_keys.as_ref().and_then(|h| h.get(id))
        })
    }

    pub fn needs_unlock(&self) -> bool {
        self.priv_key.is_none() || self.org_keys.is_none()
    }

    pub fn set_timeout(&self) {
        self.timeout.set(self.timeout_duration);
    }

    pub fn clear(&mut self) {
        self.priv_key = None;
        self.org_keys = None;
        self.timeout.clear();
        self.clear_touchid_sessions();
    }

    /// Touch ID session cache helpers. A session with a still-fresh
    /// timestamp (within `TOUCHID_SESSION_TTL`) may skip the biometric
    /// prompt on subsequent requests within the same `bwx <command>`
    /// invocation.
    pub fn touchid_session_is_fresh(&self, session_id: &str) -> bool {
        self.touchid_sessions
            .get(session_id)
            .is_some_and(|ts| ts.elapsed() < TOUCHID_SESSION_TTL)
    }

    pub fn record_touchid_session(&mut self, session_id: &str) {
        self.touchid_sessions
            .insert(session_id.to_string(), std::time::Instant::now());
        self.prune_touchid_sessions();
    }

    pub fn clear_touchid_sessions(&mut self) {
        self.touchid_sessions.clear();
    }

    fn prune_touchid_sessions(&mut self) {
        self.touchid_sessions
            .retain(|_, ts| ts.elapsed() < TOUCHID_SESSION_TTL);
    }

    pub fn set_sync_timeout(&self) {
        self.sync_timeout.set(self.sync_timeout_duration);
    }

    // the way we structure the client/agent split in bwx makes the master
    // password reprompt feature a bit complicated to implement - it would be
    // a lot easier to just have the client do the prompting, but that would
    // leave it open to someone reading the cipherstring from the local
    // database and passing it to the agent directly, bypassing the client.
    // the agent is the thing that holds the unlocked secrets, so it also
    // needs to be the thing guarding access to master password reprompt
    // entries. we only pass individual cipherstrings to the agent though, so
    // the agent needs to be able to recognize the cipherstrings that need
    // reprompting, without the additional context of the entry they came
    // from. in addition, because the reprompt state is stored in the sync db
    // in plaintext, we can't just read it from the db directly, because
    // someone could just edit the file on disk before making the request.
    //
    // therefore, the solution we choose here is to keep an in-memory set of
    // cipherstrings that we know correspond to entries with master password
    // reprompt enabled. this set is only updated when the agent itself does
    // a sync, so it can't be bypassed by editing the on-disk file directly.
    // if the agent gets a request for any of those cipherstrings that it saw
    // marked as master password reprompt during the most recent sync, it
    // forces a reprompt.
    pub fn set_master_password_reprompt(
        &mut self,
        entries: &[bwx::db::Entry],
    ) {
        self.master_password_reprompt.clear();

        let mut hasher = sha2::Sha256::new();
        let mut insert = |s: Option<&str>| {
            if let Some(s) = s {
                if !s.is_empty() {
                    hasher.update(s);
                    self.master_password_reprompt
                        .insert(hasher.finalize_reset().into());
                }
            }
        };

        for entry in entries {
            if !entry.master_password_reprompt() {
                continue;
            }

            match &entry.data {
                bwx::db::EntryData::Login { password, totp, .. } => {
                    insert(password.as_deref());
                    insert(totp.as_deref());
                }
                bwx::db::EntryData::Card { number, code, .. } => {
                    insert(number.as_deref());
                    insert(code.as_deref());
                }
                bwx::db::EntryData::Identity {
                    ssn,
                    passport_number,
                    ..
                } => {
                    insert(ssn.as_deref());
                    insert(passport_number.as_deref());
                }
                bwx::db::EntryData::SecureNote => {}
                bwx::db::EntryData::SshKey { private_key, .. } => {
                    insert(private_key.as_deref());
                }
            }

            for field in &entry.fields {
                if field.ty == Some(bwx::api::FieldType::Hidden) {
                    insert(field.value.as_deref());
                }
            }
        }

        self.master_password_reprompt_initialized = true;
    }

    pub fn master_password_reprompt_initialized(&self) -> bool {
        self.master_password_reprompt_initialized
    }

    pub fn last_environment(&self) -> &bwx::protocol::Environment {
        &self.last_environment
    }

    pub fn set_last_environment(
        &mut self,
        environment: bwx::protocol::Environment,
    ) {
        self.last_environment = environment;
    }
}
