use std::io::Write as _;

use super::auth::unlock;
use super::cipher::{DecryptedData, DecryptedListCipher};
use super::decrypt::{decrypt_list_ciphers, decrypt_search_cipher};
use super::field::ListField;
use super::find::{find_entry, Needle};
use super::totp::generate_totp;
use super::util::{load_db, val_display_or_store};
use crate::bin_error::{self, ContextExt as _};

pub fn list(fields: &[String], raw: bool) -> bin_error::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<bin_error::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;
    let mut entries = decrypt_list_ciphers(&db.entries, &fields)?;
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

#[allow(clippy::fn_params_excessive_bools)]
pub fn get(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    field: Option<&str>,
    full: bool,
    raw: bool,
    clipboard: bool,
    ignore_case: bool,
    list_fields: bool,
) -> bin_error::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    if list_fields {
        decrypted.display_fields_list();
    } else if raw {
        decrypted.display_json(&desc)?;
    } else if full {
        decrypted.display_long(&desc, clipboard);
    } else if let Some(field) = field {
        decrypted.display_field(&desc, field, clipboard);
    } else {
        decrypted.display_short(&desc, clipboard);
    }

    Ok(())
}

fn print_entry_list(
    entries: &[DecryptedListCipher],
    fields: &[ListField],
    raw: bool,
) -> bin_error::Result<()> {
    if raw {
        serde_json::to_writer_pretty(std::io::stdout(), &entries)
            .context("failed to write entries to stdout".to_string())?;
        println!();
    } else {
        for entry in entries {
            let values: Vec<String> = fields
                .iter()
                .map(|field| match field {
                    ListField::Id => entry.id.clone(),
                    ListField::Name => entry.name.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::User => entry.user.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Folder => entry.folder.as_ref().map_or_else(
                        String::new,
                        std::string::ToString::to_string,
                    ),
                    ListField::Uri => {
                        // "uri" is not listed in the TryFrom
                        // implementation, so there's no way to try to
                        // print it (and it's not clear what that would
                        // look like, since it's a list and not a single
                        // string)
                        unreachable!()
                    }
                    ListField::EntryType => {
                        entry.entry_type.as_ref().map_or_else(
                            String::new,
                            std::string::ToString::to_string,
                        )
                    }
                })
                .collect();

            // write to stdout but don't panic when pipe get's closed
            // this happens when piping stdout in a shell
            match writeln!(&mut std::io::stdout(), "{}", values.join("\t")) {
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    Ok(())
                }
                res => res,
            }?;
        }
    }

    Ok(())
}

pub fn search(
    term: &str,
    fields: &[String],
    folder: Option<&str>,
    raw: bool,
) -> bin_error::Result<()> {
    let fields: Vec<ListField> = if raw {
        ListField::all()
    } else {
        fields
            .iter()
            .map(std::convert::TryFrom::try_from)
            .collect::<bin_error::Result<_>>()?
    };

    unlock()?;

    let db = load_db()?;

    let mut entries: Vec<DecryptedListCipher> = db
        .entries
        .iter()
        .map(decrypt_search_cipher)
        .filter(|entry| {
            entry
                .as_ref()
                .map_or(true, |entry| entry.search_match(term, folder))
        })
        .map(|entry| entry.map(std::convert::Into::into))
        .collect::<Result<_, crate::bin_error::Error>>()?;
    entries.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    print_entry_list(&entries, &fields, raw)?;

    Ok(())
}

pub fn code(
    needle: Needle,
    user: Option<&str>,
    folder: Option<&str>,
    clipboard: bool,
    ignore_case: bool,
) -> bin_error::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        user.map_or_else(String::new, |s| format!("{s}@")),
        needle
    );

    let (_, decrypted) =
        find_entry(&db, needle, user, folder, ignore_case)
            .with_context(|| format!("couldn't find entry for '{desc}'"))?;

    if let DecryptedData::Login { totp, .. } = decrypted.data {
        if let Some(totp) = totp {
            val_display_or_store(clipboard, &generate_totp(&totp)?);
        } else {
            return Err(crate::bin_error::err!(
                "entry does not contain a totp secret"
            ));
        }
    } else {
        return Err(crate::bin_error::err!("not a login entry"));
    }

    Ok(())
}

pub fn history(
    name: Needle,
    username: Option<&str>,
    folder: Option<&str>,
    ignore_case: bool,
) -> bin_error::Result<()> {
    unlock()?;

    let db = load_db()?;

    let desc = format!(
        "{}{}",
        username.map_or_else(String::new, |s| format!("{s}@")),
        name
    );

    let (_, decrypted) = find_entry(&db, name, username, folder, ignore_case)
        .with_context(|| format!("couldn't find entry for '{desc}'"))?;
    for history in decrypted.history {
        println!("{}: {}", history.last_used_date, history.password);
    }

    Ok(())
}
