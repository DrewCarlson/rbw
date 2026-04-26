//! Keychain storage for bwx's Touch ID wrapper key.
//!
//! All `SecItem*` calls pass `kSecUseDataProtectionKeychain = true`,
//! so items live in the modern data-protection keychain rather than
//! the legacy file-based login keychain. Scoping is by the binary's
//! team-identifier (or per-binary identifier when ad-hoc signed); no
//! per-item ACL prompts. `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
//! keeps the bytes off iCloud Keychain and bound to this device.
//! Touch ID enforcement happens in the agent via `require_presence`
//! before this module is asked to load the bytes.
#![allow(
    clippy::borrow_as_ptr,
    clippy::as_conversions,
    clippy::too_long_first_doc_paragraph
)]

use core_foundation::base::TCFType as _;
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef, OSStatus};
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecMatchLimit, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete,
};

// `kSecUseOperationPrompt`, `kSecAttrAccessible` (the dictionary KEY;
// distinct from the `kSecAttrAccessible*` VALUE constants that are
// exported), and `kSecUseDataProtectionKeychain` aren't re-exported by
// security-framework-sys. They're singleton CFStringRefs from
// Security.framework resolved by the system linker.
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecUseOperationPrompt: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecUseDataProtectionKeychain: CFStringRef;
}

/// Keychain generic-password `service` value shared by all bwx Touch ID
/// items; per-enrollment labels distinguish them.
const SERVICE: &str = "bwx";

#[derive(Debug)]
pub enum Error {
    /// The biometric user cancelled the prompt or authentication failed.
    UserCancelled,
    /// `SecItem*` returned an auth-failed status. With the current
    /// presence-only model this generally means the user denied the
    /// prompt; callers handle it the same as `UserCancelled` but the
    /// distinct variant lets logs say which the OS reported.
    Invalidated,
    /// The Keychain entry doesn't exist.
    NotFound,
    /// Any other error surfaced by `SecItem*`.
    Os(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserCancelled => f.write_str("keychain: cancelled"),
            Self::Invalidated => f.write_str("keychain: auth failed"),
            Self::NotFound => f.write_str("keychain: item not found"),
            Self::Os(s) => write!(f, "keychain: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Store `secret` under the given label.
pub fn store(label: &str, secret: &[u8]) -> Result<(), Error> {
    unsafe {
        let service = CFString::new(SERVICE);
        let account = CFString::new(label);
        let data = CFData::from_buffer(secret);
        let class = CFString::wrap_under_get_rule(kSecClassGenericPassword);
        let accessible_v = CFString::wrap_under_get_rule(
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        );
        let attr_accessible =
            CFString::wrap_under_get_rule(kSecAttrAccessible);
        let attr_service = CFString::wrap_under_get_rule(kSecAttrService);
        let attr_account = CFString::wrap_under_get_rule(kSecAttrAccount);
        let value_data = CFString::wrap_under_get_rule(kSecValueData);
        let class_key = CFString::wrap_under_get_rule(kSecClass);
        let use_dp =
            CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain);

        let dict = CFDictionary::from_CFType_pairs(&[
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
            (value_data.as_CFType(), data.as_CFType()),
            (attr_accessible.as_CFType(), accessible_v.as_CFType()),
            (use_dp.as_CFType(), CFBoolean::true_value().as_CFType()),
        ]);

        let status =
            SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut());
        map_status(status, "SecItemAdd")
    }
}

/// Load the bytes stored under `label`.
///
/// `prompt` is forwarded as `kSecUseOperationPrompt`; the agent's
/// `require_presence` call has already gated the read by the time we
/// land here, so the system UI normally stays out of the way.
pub fn load(label: &str, prompt: &str) -> Result<crate::locked::Vec, Error> {
    unsafe {
        let service = CFString::new(SERVICE);
        let account = CFString::new(label);
        let prompt_cf = CFString::new(prompt);
        let class = CFString::wrap_under_get_rule(kSecClassGenericPassword);
        let class_key = CFString::wrap_under_get_rule(kSecClass);
        let attr_service = CFString::wrap_under_get_rule(kSecAttrService);
        let attr_account = CFString::wrap_under_get_rule(kSecAttrAccount);
        let return_data = CFString::wrap_under_get_rule(kSecReturnData);
        let match_limit = CFString::wrap_under_get_rule(kSecMatchLimit);
        let match_limit_one = CFNumber::from(1i64);
        let use_operation_prompt =
            CFString::wrap_under_get_rule(kSecUseOperationPrompt);
        let use_dp =
            CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain);

        let dict = CFDictionary::from_CFType_pairs(&[
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
            (return_data.as_CFType(), CFBoolean::true_value().as_CFType()),
            (match_limit.as_CFType(), match_limit_one.as_CFType()),
            (use_operation_prompt.as_CFType(), prompt_cf.as_CFType()),
            (use_dp.as_CFType(), CFBoolean::true_value().as_CFType()),
        ]);

        let mut result: CFTypeRef = std::ptr::null();
        let status =
            SecItemCopyMatching(dict.as_concrete_TypeRef(), &raw mut result);
        match status {
            s if s == errSecSuccess && !result.is_null() => {
                let data = CFData::wrap_under_create_rule(result as *mut _);
                // Copy CFData bytes directly into a locked (mlocked +
                // zeroized-on-drop) buffer; avoid a plain `Vec<u8>` that
                // would linger on the heap after this function returns.
                let mut buf = crate::locked::Vec::new();
                buf.extend(data.bytes().iter().copied());
                Ok(buf)
            }
            s if s == errSecItemNotFound => Err(Error::NotFound),
            // errSecUserCanceled = -128, errSecAuthFailed = -25293
            -128 => Err(Error::UserCancelled),
            -25293 => Err(Error::Invalidated),
            other => {
                Err(Error::Os(format!("SecItemCopyMatching: status {other}")))
            }
        }
    }
}

/// Delete the item under `label`. Returns `Ok(())` whether or not the
/// item existed — disable should be idempotent.
pub fn delete(label: &str) -> Result<(), Error> {
    unsafe {
        let service = CFString::new(SERVICE);
        let account = CFString::new(label);
        let class = CFString::wrap_under_get_rule(kSecClassGenericPassword);
        let class_key = CFString::wrap_under_get_rule(kSecClass);
        let attr_service = CFString::wrap_under_get_rule(kSecAttrService);
        let attr_account = CFString::wrap_under_get_rule(kSecAttrAccount);
        let use_dp =
            CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain);

        let dict = CFDictionary::from_CFType_pairs(&[
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
            (use_dp.as_CFType(), CFBoolean::true_value().as_CFType()),
        ]);

        let status = SecItemDelete(dict.as_concrete_TypeRef());
        match status {
            s if s == errSecSuccess || s == errSecItemNotFound => Ok(()),
            other => Err(Error::Os(format!("SecItemDelete: status {other}"))),
        }
    }
}

/// Check whether an item exists under `label` without triggering any
/// biometric prompt. Used by `bwx touchid status`.
pub fn exists(label: &str) -> Result<bool, Error> {
    unsafe {
        let service = CFString::new(SERVICE);
        let account = CFString::new(label);
        let class = CFString::wrap_under_get_rule(kSecClassGenericPassword);
        let class_key = CFString::wrap_under_get_rule(kSecClass);
        let attr_service = CFString::wrap_under_get_rule(kSecAttrService);
        let attr_account = CFString::wrap_under_get_rule(kSecAttrAccount);
        let match_limit = CFString::wrap_under_get_rule(kSecMatchLimit);
        let match_limit_one = CFNumber::from(1i64);
        let use_dp =
            CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain);

        // Don't request return_data — that would force a biometric
        // prompt. Just ask whether the record exists by matching on
        // service+account.
        let dict = CFDictionary::from_CFType_pairs(&[
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
            (match_limit.as_CFType(), match_limit_one.as_CFType()),
            (use_dp.as_CFType(), CFBoolean::true_value().as_CFType()),
        ]);

        let mut result: CFTypeRef = std::ptr::null();
        let status =
            SecItemCopyMatching(dict.as_concrete_TypeRef(), &raw mut result);
        if !result.is_null() {
            CFRelease(result);
        }
        match status {
            s if s == errSecSuccess => Ok(true),
            s if s == errSecItemNotFound => Ok(false),
            other => Err(Error::Os(format!(
                "SecItemCopyMatching (exists): status {other}"
            ))),
        }
    }
}

fn map_status(status: OSStatus, api: &str) -> Result<(), Error> {
    match status {
        s if s == errSecSuccess => Ok(()),
        -128 => Err(Error::UserCancelled),
        -25293 => Err(Error::Invalidated),
        other => Err(Error::Os(format!("{api}: status {other}"))),
    }
}
