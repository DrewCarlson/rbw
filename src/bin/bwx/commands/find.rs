use super::cipher::{DecryptedCipher, DecryptedSearchCipher};
use super::decrypt::{
    decrypt_cipher, decrypt_cipher_using_search, decrypt_search_cipher,
};
use crate::bin_error;

#[derive(Debug, Clone)]
pub enum Needle {
    Name(String),
    Uri(url::Url),
    Uuid(bwx::uuid::Uuid, String),
}

impl std::fmt::Display for Needle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match &self {
            Self::Name(name) => name.clone(),
            Self::Uri(uri) => uri.to_string(),
            Self::Uuid(_, s) => s.clone(),
        };
        write!(f, "{value}")
    }
}

#[allow(clippy::unnecessary_wraps)]
pub fn parse_needle(arg: &str) -> Result<Needle, std::convert::Infallible> {
    if let Ok(uuid) = arg.parse::<bwx::uuid::Uuid>() {
        return Ok(Needle::Uuid(uuid, arg.to_string()));
    }
    if let Ok(url) = url::Url::parse(arg) {
        if url.is_special() {
            return Ok(Needle::Uri(url));
        }
    }

    Ok(Needle::Name(arg.to_string()))
}

pub(super) fn matches_url(
    url: &str,
    match_type: Option<bwx::api::UriMatchType>,
    given_url: &url::Url,
) -> bool {
    match match_type.unwrap_or(bwx::api::UriMatchType::Domain) {
        bwx::api::UriMatchType::Domain => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && (self_host_port == given_host_port
                            || given_host_port
                                .ends_with(&format!(".{self_host_port}")))
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
                || given_host_port.ends_with(&format!(".{url}"))
        }
        bwx::api::UriMatchType::Host => {
            let Some(given_host_port) = host_port(given_url) else {
                return false;
            };
            if let Ok(self_url) = url::Url::parse(url) {
                if let Some(self_host_port) = host_port(&self_url) {
                    if self_url.scheme() == given_url.scheme()
                        && self_host_port == given_host_port
                    {
                        return true;
                    }
                }
            }
            url == given_host_port
        }
        bwx::api::UriMatchType::StartsWith => {
            given_url.to_string().starts_with(url)
        }
        bwx::api::UriMatchType::Exact => {
            if given_url.path() == "/" {
                given_url.to_string().trim_end_matches('/')
                    == url.trim_end_matches('/')
            } else {
                given_url.to_string() == url
            }
        }
        bwx::api::UriMatchType::RegularExpression => {
            let Some(rx) = compile_regex_cached(url) else {
                return false;
            };
            rx.is_match(given_url.as_ref())
        }
        bwx::api::UriMatchType::Never => false,
    }
}

/// Compile a URI-match regex once per CLI invocation. `find_entry_raw`
/// re-runs its match loop several times with different strict flags, so
/// the same `url` strings get compared against many ciphers many times
/// per `bwx get`.
fn compile_regex_cached(url: &str) -> Option<std::sync::Arc<regex::Regex>> {
    use std::sync::{Arc, Mutex, OnceLock};
    static CACHE: OnceLock<
        Mutex<std::collections::HashMap<String, Option<Arc<regex::Regex>>>>,
    > = OnceLock::new();
    let cache =
        CACHE.get_or_init(|| Mutex::new(std::collections::HashMap::new()));
    let mut guard = cache.lock().ok()?;
    if let Some(entry) = guard.get(url) {
        return entry.clone();
    }
    let compiled = regex::Regex::new(url).ok().map(Arc::new);
    guard.insert(url.to_string(), compiled.clone());
    compiled
}

fn host_port(url: &url::Url) -> Option<String> {
    let host = url.host_str()?;
    Some(
        url.port().map_or_else(
            || host.to_string(),
            |port| format!("{host}:{port}"),
        ),
    )
}

pub(super) fn find_entry(
    db: &bwx::db::Db,
    mut needle: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bin_error::Result<(bwx::db::Entry, DecryptedCipher)> {
    if let Needle::Uuid(uuid, s) = needle {
        for cipher in &db.entries {
            if cipher.id.parse::<bwx::uuid::Uuid>() == Ok(uuid) {
                return Ok((cipher.clone(), decrypt_cipher(cipher)?));
            }
        }
        needle = Needle::Name(s);
    }

    let ciphers: Vec<(bwx::db::Entry, DecryptedSearchCipher)> = db
        .entries
        .iter()
        .map(|entry| {
            decrypt_search_cipher(entry)
                .map(|decrypted| (entry.clone(), decrypted))
        })
        .collect::<bin_error::Result<_>>()?;
    let (entry, search) =
        find_entry_raw(&ciphers, &needle, username, folder, ignore_case)?;
    let decrypted_entry = decrypt_cipher_using_search(&entry, &search)?;
    Ok((entry, decrypted_entry))
}

pub(super) fn find_entry_raw(
    entries: &[(bwx::db::Entry, DecryptedSearchCipher)],
    needle: &Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bin_error::Result<(bwx::db::Entry, DecryptedSearchCipher)> {
    let mut matches: Vec<(bwx::db::Entry, DecryptedSearchCipher)> = vec![];

    let find_matches = |strict_username, strict_folder, exact| {
        entries
            .iter()
            .filter(|&(_, decrypted_cipher)| {
                decrypted_cipher.matches(
                    needle,
                    username,
                    folder,
                    ignore_case,
                    strict_username,
                    strict_folder,
                    exact,
                )
            })
            .cloned()
            .collect()
    };

    for exact in [true, false] {
        matches = find_matches(true, true, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }

        let strict_folder_matches = find_matches(false, true, exact);
        let strict_username_matches = find_matches(true, false, exact);
        if strict_folder_matches.len() == 1
            && strict_username_matches.len() != 1
        {
            return Ok(strict_folder_matches[0].clone());
        } else if strict_folder_matches.len() != 1
            && strict_username_matches.len() == 1
        {
            return Ok(strict_username_matches[0].clone());
        }

        matches = find_matches(false, false, exact);
        if matches.len() == 1 {
            return Ok(matches[0].clone());
        }
    }

    if matches.is_empty() {
        Err(crate::bin_error::err!("no entry found"))
    } else {
        let entries: Vec<String> = matches
            .iter()
            .map(|(_, decrypted)| decrypted.display_name())
            .collect();
        let entries = entries.join(", ");
        Err(crate::bin_error::err!("multiple entries found: {entries}"))
    }
}
