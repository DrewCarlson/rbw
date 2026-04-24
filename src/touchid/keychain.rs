//! Biometric-gated Keychain storage for rbw's Touch ID wrapper key.
//!
//! The high-level `security-framework` crate doesn't expose
//! `SecAccessControl`, so we drop down to `core-foundation` +
//! `security-framework-sys` and build the query dictionaries
//! directly. That's the only way to attach a
//! `kSecAccessControlBiometryCurrentSet` ACL.
#![allow(
    clippy::borrow_as_ptr,
    clippy::as_conversions,
    clippy::too_long_first_doc_paragraph
)]

use core_foundation::base::{CFType, TCFType as _};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::error::{CFError, CFErrorRef};
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{
    kCFAllocatorDefault, CFRelease, CFTypeRef, OSStatus,
};
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
use security_framework_sys::access_control::{
    kSecAccessControlBiometryCurrentSet, SecAccessControlCreateWithFlags,
};
use security_framework_sys::base::{errSecItemNotFound, errSecSuccess};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecMatchLimit, kSecReturnData, kSecValueData,
};
use security_framework_sys::keychain_item::{
    SecItemAdd, SecItemCopyMatching, SecItemDelete,
};

// `kSecUseOperationPrompt` and `kSecAttrAccessible` (the dictionary KEY;
// distinct from the `kSecAttrAccessible*` VALUE constants that are
// exported) aren't re-exported by security-framework-sys. They're
// singleton CFStringRefs from Security.framework resolved by the system
// linker.
//
// `SecTaskCreateFromSelf` + `SecTaskCopyValueForEntitlement` let us
// read our own code-signing entitlements at runtime so we can branch
// on whether the binary was signed with a `keychain-access-groups`
// entitlement (see `access_group_from_entitlement`).
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecUseOperationPrompt: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessGroup: CFStringRef;
    static kSecAttrAccessControl: CFStringRef;

    fn SecTaskCreateFromSelf(
        allocator: *const std::ffi::c_void,
    ) -> *mut std::ffi::c_void;
    fn SecTaskCopyValueForEntitlement(
        task: *mut std::ffi::c_void,
        entitlement: CFStringRef,
        error: *mut core_foundation_sys::error::CFErrorRef,
    ) -> core_foundation_sys::base::CFTypeRef;
}

/// Returns `Some("<team>.rbw")` if this binary is code-signed with a
/// `keychain-access-groups` entitlement (Apple Development or Developer
/// ID tier). Returns `None` for ad-hoc / unsigned binaries; those use
/// the plain Keychain path (no ACL, no access group).
fn access_group_from_entitlement() -> Option<String> {
    use core_foundation::array::CFArray;
    use core_foundation::base::TCFType as _;

    unsafe {
        let task = SecTaskCreateFromSelf(std::ptr::null());
        if task.is_null() {
            return None;
        }
        let key = CFString::new("keychain-access-groups");
        let mut err = std::ptr::null_mut();
        let value = SecTaskCopyValueForEntitlement(
            task,
            key.as_concrete_TypeRef(),
            &raw mut err,
        );
        CFRelease(task.cast());
        if value.is_null() {
            return None;
        }
        // Entitlement value is a CFArray<CFString>. Take the first entry.
        let array: CFArray<CFString> =
            CFArray::wrap_under_create_rule(value.cast());
        array.get(0).map(|s| s.to_string())
    }
}

/// True iff we're running with a `keychain-access-groups` entitlement,
/// in which case we upgrade to biometric ACL + access group.
pub fn have_biometric_entitlement() -> bool {
    access_group_from_entitlement().is_some()
}

/// Keychain generic-password `service` value. All rbw Touch ID items
/// share this, with per-enrollment labels distinguishing them.
const SERVICE: &str = "rbw";

#[derive(Debug)]
pub enum Error {
    /// The biometric user cancelled the prompt or authentication failed.
    UserCancelled,
    /// The stored item was invalidated because the biometric set changed
    /// (`BiometryCurrentSet` auto-invalidates on fingerprint changes).
    /// Callers should prompt the user to re-enroll.
    Invalidated,
    /// The Keychain entry doesn't exist.
    NotFound,
    /// Any other error surfaced by `SecItem*` / `SecAccessControl*`.
    Os(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserCancelled => f.write_str("keychain: cancelled"),
            Self::Invalidated => {
                f.write_str("keychain: biometric set invalidated")
            }
            Self::NotFound => f.write_str("keychain: item not found"),
            Self::Os(s) => write!(f, "keychain: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Store `secret` under the given label. On signed builds (Apple
/// Development or Developer ID) we attach a
/// `kSecAccessControlBiometryCurrentSet` ACL + team-scoped access group
/// so the Keychain itself enforces biometry on retrieval. On ad-hoc /
/// unsigned builds the Keychain item is plain (only protected by
/// `WhenUnlockedThisDeviceOnly`) and our `require_presence` call is
/// what forces the Touch ID prompt.
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

        let mut pairs: Vec<(CFType, CFType)> = vec![
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
            (value_data.as_CFType(), data.as_CFType()),
            (attr_accessible.as_CFType(), accessible_v.as_CFType()),
        ];
        let access_group_cf;
        let attr_access_group_cf;
        let access_control_cf;
        let attr_access_control_cf;
        if let Some(group) = access_group_from_entitlement() {
            access_group_cf = CFString::new(&group);
            attr_access_group_cf =
                CFString::wrap_under_get_rule(kSecAttrAccessGroup);
            pairs.push((
                attr_access_group_cf.as_CFType(),
                access_group_cf.as_CFType(),
            ));

            access_control_cf = create_biometric_access_control()?;
            attr_access_control_cf =
                CFString::wrap_under_get_rule(kSecAttrAccessControl);
            pairs.push((
                attr_access_control_cf.as_CFType(),
                CFType::wrap_under_create_rule(access_control_cf.cast()),
            ));
        }
        let dict = CFDictionary::from_CFType_pairs(&pairs);

        let status =
            SecItemAdd(dict.as_concrete_TypeRef(), std::ptr::null_mut());
        map_status(status, "SecItemAdd")
    }
}

/// Load the bytes stored under `label`.
///
/// Blocks until the user approves Touch ID; cancelling returns
/// `Error::UserCancelled`. If the biometric enrollment has changed since
/// this item was written, macOS returns an "authentication failed"
/// error which we map to `Error::Invalidated`.
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

        let mut pairs: Vec<(CFType, CFType)> = vec![
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
            (return_data.as_CFType(), CFBoolean::true_value().as_CFType()),
            (match_limit.as_CFType(), match_limit_one.as_CFType()),
            (use_operation_prompt.as_CFType(), prompt_cf.as_CFType()),
        ];
        let access_group_cf;
        let attr_access_group_cf;
        if let Some(group) = access_group_from_entitlement() {
            access_group_cf = CFString::new(&group);
            attr_access_group_cf =
                CFString::wrap_under_get_rule(kSecAttrAccessGroup);
            pairs.push((
                attr_access_group_cf.as_CFType(),
                access_group_cf.as_CFType(),
            ));
        }
        let dict = CFDictionary::from_CFType_pairs(&pairs);

        let mut result: CFTypeRef = std::ptr::null();
        let status =
            SecItemCopyMatching(dict.as_concrete_TypeRef(), &raw mut result);
        match status {
            s if s == errSecSuccess && !result.is_null() => {
                let data = CFData::wrap_under_create_rule(result as *mut _);
                // Copy the CFData bytes directly into a locked (mlocked +
                // zeroized-on-drop) buffer. Never materialize a plain
                // `Vec<u8>` that would linger on the heap after this
                // function returns.
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

        let mut pairs: Vec<(CFType, CFType)> = vec![
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
        ];
        let access_group_cf;
        let attr_access_group_cf;
        if let Some(group) = access_group_from_entitlement() {
            access_group_cf = CFString::new(&group);
            attr_access_group_cf =
                CFString::wrap_under_get_rule(kSecAttrAccessGroup);
            pairs.push((
                attr_access_group_cf.as_CFType(),
                access_group_cf.as_CFType(),
            ));
        }
        let dict = CFDictionary::from_CFType_pairs(&pairs);

        let status = SecItemDelete(dict.as_concrete_TypeRef());
        match status {
            s if s == errSecSuccess || s == errSecItemNotFound => Ok(()),
            other => Err(Error::Os(format!("SecItemDelete: status {other}"))),
        }
    }
}

/// Check whether an item exists under `label` without triggering any
/// biometric prompt. Used by `rbw touchid status`.
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

        // Don't request return_data — that would force a biometric
        // prompt. Just ask whether the record exists by matching on
        // service+account.
        let dict = CFDictionary::from_CFType_pairs(&[
            (class_key.as_CFType(), class.as_CFType()),
            (attr_service.as_CFType(), service.as_CFType()),
            (attr_account.as_CFType(), account.as_CFType()),
            (match_limit.as_CFType(), match_limit_one.as_CFType()),
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

/// Build a `SecAccessControlRef` with biometry-current-set + unlocked-
/// this-device-only. Only used on the signed-with-entitlement path.
unsafe fn create_biometric_access_control(
) -> Result<*mut std::ffi::c_void, Error> {
    let mut err: CFErrorRef = std::ptr::null_mut();
    let access_control = unsafe {
        SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            kSecAccessControlBiometryCurrentSet,
            &raw mut err,
        )
    };
    if access_control.is_null() {
        let msg = if err.is_null() {
            "SecAccessControlCreateWithFlags returned null".to_string()
        } else {
            let cferr = unsafe { CFError::wrap_under_create_rule(err) };
            cferr.description().to_string()
        };
        return Err(Error::Os(msg));
    }
    Ok(access_control.cast())
}

fn map_status(status: OSStatus, api: &str) -> Result<(), Error> {
    match status {
        s if s == errSecSuccess => Ok(()),
        -128 => Err(Error::UserCancelled),
        -25293 => Err(Error::Invalidated),
        other => Err(Error::Os(format!("{api}: status {other}"))),
    }
}
