use super::cipher::{
    DecryptedCipher, DecryptedData, DecryptedField, DecryptedHistoryEntry,
    DecryptedListCipher, DecryptedSearchCipher, DecryptedUri,
};
use super::field::{Field, ListField};
use crate::bin_error;

pub(super) fn decrypt_field(
    name: Field,
    field: Option<&str>,
    entry_key: Option<&str>,
    org_id: Option<&str>,
) -> Option<String> {
    let field = field
        .as_ref()
        .map(|field| crate::actions::decrypt(field, entry_key, org_id))
        .transpose();
    match field {
        Ok(field) => field,
        Err(e) => {
            log::warn!("failed to decrypt {name}: {e}");
            None
        }
    }
}

/// Batched form of `decrypt_list_cipher`: stages every per-field
/// decrypt for the whole entry slice into a single `DecryptBatch` IPC,
/// then assembles the results back into per-entry list ciphers. Avoids
/// the N-IPC-per-entry blowup on `bwx list` for large vaults.
pub(super) fn decrypt_list_ciphers(
    entries: &[bwx::db::Entry],
    fields: &[ListField],
) -> bin_error::Result<Vec<DecryptedListCipher>> {
    struct Slots {
        id: String,
        entry_type: Option<String>,
        name_idx: Option<usize>,
        user_idx: Option<usize>,
        folder_idx: Option<usize>,
        // None means "list field not requested or not a Login"; an empty
        // Vec means "Login with no URIs".
        uri_indices: Option<Vec<usize>>,
    }

    let want_name = fields.contains(&ListField::Name);
    let want_user = fields.contains(&ListField::User);
    let want_folder = fields.contains(&ListField::Folder);
    let want_uris = fields.contains(&ListField::Uri);
    let want_type = fields.contains(&ListField::EntryType);

    let mut items: Vec<bwx::protocol::DecryptItem> = Vec::new();
    let mut slots: Vec<Slots> = Vec::with_capacity(entries.len());

    let push = |items: &mut Vec<bwx::protocol::DecryptItem>,
                cipherstring: &str,
                entry_key: Option<&str>,
                org_id: Option<&str>|
     -> usize {
        items.push(bwx::protocol::DecryptItem {
            cipherstring: cipherstring.to_string(),
            entry_key: entry_key.map(std::string::ToString::to_string),
            org_id: org_id.map(std::string::ToString::to_string),
        });
        items.len() - 1
    };

    for entry in entries {
        let entry_type = if want_type {
            Some(
                match &entry.data {
                    bwx::db::EntryData::Login { .. } => "Login",
                    bwx::db::EntryData::Identity { .. } => "Identity",
                    bwx::db::EntryData::SshKey { .. } => "SSH Key",
                    bwx::db::EntryData::SecureNote => "Note",
                    bwx::db::EntryData::Card { .. } => "Card",
                }
                .to_string(),
            )
        } else {
            None
        };

        let name_idx = want_name.then(|| {
            push(
                &mut items,
                &entry.name,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        });

        let user_idx = if want_user {
            match &entry.data {
                bwx::db::EntryData::Login {
                    username: Some(u), ..
                } => Some(push(
                    &mut items,
                    u,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )),
                _ => None,
            }
        } else {
            None
        };

        // Folder names always use the local key (folders are scoped to
        // the user's own vault, not the organisation).
        let folder_idx = if want_folder {
            entry
                .folder
                .as_ref()
                .map(|f| push(&mut items, f, None, None))
        } else {
            None
        };

        let uri_indices = if want_uris {
            match &entry.data {
                bwx::db::EntryData::Login { uris, .. } => Some(
                    uris.iter()
                        .map(|s| {
                            push(
                                &mut items,
                                &s.uri,
                                entry.key.as_deref(),
                                entry.org_id.as_deref(),
                            )
                        })
                        .collect(),
                ),
                _ => None,
            }
        } else {
            None
        };

        slots.push(Slots {
            id: entry.id.clone(),
            entry_type,
            name_idx,
            user_idx,
            folder_idx,
            uri_indices,
        });
    }

    let results = if items.is_empty() {
        Vec::new()
    } else {
        crate::actions::decrypt_batch(items)?
    };

    let take = |idx: Option<usize>, label: &str| -> Option<String> {
        idx.and_then(|i| match &results[i] {
            Ok(s) => Some(s.clone()),
            Err(e) => {
                log::warn!("failed to decrypt {label}: {e}");
                None
            }
        })
    };

    let mut out = Vec::with_capacity(slots.len());
    for s in slots {
        let name = if want_name {
            // Per-entry name decrypt failure is fatal, matching the
            // existing single-entry path (`decrypt_list_cipher`).
            match s.name_idx {
                Some(i) => match &results[i] {
                    Ok(s) => Some(s.clone()),
                    Err(e) => {
                        return Err(crate::bin_error::err!(
                            "failed to decrypt entry name: {e}"
                        ));
                    }
                },
                None => None,
            }
        } else {
            None
        };
        let user = take(s.user_idx, "username");
        let folder = if want_folder {
            match s.folder_idx {
                Some(i) => match &results[i] {
                    Ok(p) => Some(p.clone()),
                    Err(e) => {
                        return Err(crate::bin_error::err!(
                            "failed to decrypt folder name: {e}"
                        ));
                    }
                },
                None => None,
            }
        } else {
            None
        };
        let uris = s.uri_indices.map(|idxs| {
            idxs.into_iter()
                .filter_map(|i| match &results[i] {
                    Ok(p) => Some(p.clone()),
                    Err(e) => {
                        log::warn!("failed to decrypt uri: {e}");
                        None
                    }
                })
                .collect()
        });

        out.push(DecryptedListCipher {
            id: s.id,
            name,
            user,
            folder,
            uris,
            entry_type: s.entry_type,
        });
    }

    Ok(out)
}

pub(super) fn decrypt_search_cipher(
    entry: &bwx::db::Entry,
) -> bin_error::Result<DecryptedSearchCipher> {
    let id = entry.id.clone();
    let name = crate::actions::decrypt(
        &entry.name,
        entry.key.as_deref(),
        entry.org_id.as_deref(),
    )?;
    let user = match &entry.data {
        bwx::db::EntryData::Login { username, .. } => decrypt_field(
            Field::Username,
            username.as_deref(),
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        ),
        _ => None,
    };
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let uris = if let bwx::db::EntryData::Login { uris, .. } = &entry.data {
        uris.iter()
            .filter_map(|s| {
                decrypt_field(
                    Field::Uris,
                    Some(&s.uri),
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )
                .map(|uri| (uri, s.match_type))
            })
            .collect()
    } else {
        vec![]
    };
    let fields = entry
        .fields
        .iter()
        .filter_map(|field| {
            if field.ty == Some(bwx::api::FieldType::Hidden) {
                None
            } else {
                field.value.as_ref()
            }
        })
        .map(|value| {
            crate::actions::decrypt(
                value,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .collect::<bin_error::Result<_>>()?;
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let entry_type = (match &entry.data {
        bwx::db::EntryData::Login { .. } => "Login",
        bwx::db::EntryData::Identity { .. } => "Identity",
        bwx::db::EntryData::SshKey { .. } => "SSH Key",
        bwx::db::EntryData::SecureNote => "Note",
        bwx::db::EntryData::Card { .. } => "Card",
    })
    .to_string();

    Ok(DecryptedSearchCipher {
        id,
        entry_type,
        folder,
        name,
        user,
        uris,
        fields,
        notes,
    })
}

/// Build a `DecryptedCipher` for an entry that we already searched, reusing
/// the plaintext fields that `decrypt_search_cipher` already produced
/// (name, folder, notes, login username/URIs). Saves the redundant IPC
/// round-trips for those fields on every `bwx get`/`code`/etc. lookup.
pub(super) fn decrypt_cipher_using_search(
    entry: &bwx::db::Entry,
    search: &DecryptedSearchCipher,
) -> bin_error::Result<DecryptedCipher> {
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        crate::actions::decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        crate::actions::decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
            })
        })
        .collect::<bin_error::Result<_>>()?;
    let history = entry
        .history
        .iter()
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: crate::actions::decrypt(
                    &history_entry.password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<bin_error::Result<_>>()?;

    let data = match &entry.data {
        bwx::db::EntryData::Login {
            password,
            totp,
            uris,
            ..
        } => DecryptedData::Login {
            username: search.user.clone(),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            // URIs aren't reused from the search cipher: the search path
            // drops decrypt failures, but the full cipher signals failure
            // by returning `None` for the whole list. Decrypt fresh to
            // preserve that distinction.
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
                })
                .collect(),
        },
        // Other entry types don't expose enough overlap with the search
        // cipher to skip work; fall through to the standard path.
        _ => return decrypt_cipher(entry),
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder: search.folder.clone(),
        name: search.name.clone(),
        data,
        fields,
        notes: search.notes.clone(),
        history,
    })
}

pub(super) fn decrypt_cipher(
    entry: &bwx::db::Entry,
) -> bin_error::Result<DecryptedCipher> {
    // folder name should always be decrypted with the local key because
    // folders are local to a specific user's vault, not the organization
    let folder = entry
        .folder
        .as_ref()
        .map(|folder| crate::actions::decrypt(folder, None, None))
        .transpose();
    let folder = match folder {
        Ok(folder) => folder,
        Err(e) => {
            log::warn!("failed to decrypt folder name: {e}");
            None
        }
    };
    let fields = entry
        .fields
        .iter()
        .map(|field| {
            Ok(DecryptedField {
                name: field
                    .name
                    .as_ref()
                    .map(|name| {
                        crate::actions::decrypt(
                            name,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                value: field
                    .value
                    .as_ref()
                    .map(|value| {
                        crate::actions::decrypt(
                            value,
                            entry.key.as_deref(),
                            entry.org_id.as_deref(),
                        )
                    })
                    .transpose()?,
                ty: field.ty,
            })
        })
        .collect::<bin_error::Result<_>>()?;
    let notes = entry
        .notes
        .as_ref()
        .map(|notes| {
            crate::actions::decrypt(
                notes,
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            )
        })
        .transpose();
    let notes = match notes {
        Ok(notes) => notes,
        Err(e) => {
            log::warn!("failed to decrypt notes: {e}");
            None
        }
    };
    let history = entry
        .history
        .iter()
        .map(|history_entry| {
            Ok(DecryptedHistoryEntry {
                last_used_date: history_entry.last_used_date.clone(),
                password: crate::actions::decrypt(
                    &history_entry.password,
                    entry.key.as_deref(),
                    entry.org_id.as_deref(),
                )?,
            })
        })
        .collect::<bin_error::Result<_>>()?;

    let data = match &entry.data {
        bwx::db::EntryData::Login {
            username,
            password,
            totp,
            uris,
        } => DecryptedData::Login {
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            password: decrypt_field(
                Field::Password,
                password.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            totp: decrypt_field(
                Field::Totp,
                totp.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            uris: uris
                .iter()
                .map(|s| {
                    decrypt_field(
                        Field::Uris,
                        Some(&s.uri),
                        entry.key.as_deref(),
                        entry.org_id.as_deref(),
                    )
                    .map(|uri| DecryptedUri {
                        uri,
                        match_type: s.match_type,
                    })
                })
                .collect(),
        },
        bwx::db::EntryData::Card {
            cardholder_name,
            number,
            brand,
            exp_month,
            exp_year,
            code,
        } => DecryptedData::Card {
            cardholder_name: decrypt_field(
                Field::Cardholder,
                cardholder_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            number: decrypt_field(
                Field::CardNumber,
                number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            brand: decrypt_field(
                Field::Brand,
                brand.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_month: decrypt_field(
                Field::ExpMonth,
                exp_month.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            exp_year: decrypt_field(
                Field::ExpYear,
                exp_year.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            code: decrypt_field(
                Field::Cvv,
                code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        bwx::db::EntryData::Identity {
            title,
            first_name,
            middle_name,
            last_name,
            address1,
            address2,
            address3,
            city,
            state,
            postal_code,
            country,
            phone,
            email,
            ssn,
            license_number,
            passport_number,
            username,
        } => DecryptedData::Identity {
            title: decrypt_field(
                Field::Title,
                title.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            first_name: decrypt_field(
                Field::FirstName,
                first_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            middle_name: decrypt_field(
                Field::MiddleName,
                middle_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            last_name: decrypt_field(
                Field::LastName,
                last_name.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address1: decrypt_field(
                Field::Address1,
                address1.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address2: decrypt_field(
                Field::Address2,
                address2.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            address3: decrypt_field(
                Field::Address3,
                address3.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            city: decrypt_field(
                Field::City,
                city.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            state: decrypt_field(
                Field::State,
                state.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            postal_code: decrypt_field(
                Field::PostalCode,
                postal_code.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            country: decrypt_field(
                Field::Country,
                country.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            phone: decrypt_field(
                Field::Phone,
                phone.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            email: decrypt_field(
                Field::Email,
                email.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            ssn: decrypt_field(
                Field::Ssn,
                ssn.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            license_number: decrypt_field(
                Field::License,
                license_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            passport_number: decrypt_field(
                Field::Passport,
                passport_number.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            username: decrypt_field(
                Field::Username,
                username.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
        bwx::db::EntryData::SecureNote => DecryptedData::SecureNote {},
        bwx::db::EntryData::SshKey {
            public_key,
            fingerprint,
            private_key,
        } => DecryptedData::SshKey {
            public_key: decrypt_field(
                Field::PublicKey,
                public_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            fingerprint: decrypt_field(
                Field::Fingerprint,
                fingerprint.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
            private_key: decrypt_field(
                Field::PrivateKey,
                private_key.as_deref(),
                entry.key.as_deref(),
                entry.org_id.as_deref(),
            ),
        },
    };

    Ok(DecryptedCipher {
        id: entry.id.clone(),
        folder,
        name: crate::actions::decrypt(
            &entry.name,
            entry.key.as_deref(),
            entry.org_id.as_deref(),
        )?,
        data,
        fields,
        notes,
        history,
    })
}
