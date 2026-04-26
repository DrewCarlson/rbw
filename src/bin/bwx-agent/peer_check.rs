//! Same-team code-requirement check for IPC peers (macOS).
//!
//! `check_peer_uid` already blocks cross-user clients. On macOS, when
//! the agent itself is signed with a Team Identifier (Developer ID or
//! Apple Development), this module additionally requires the peer to
//! be signed by the same team — closing the "another process running
//! as my uid that's signed by some other identity" gap.
//!
//! Ad-hoc and unsigned agent builds (local dev, forks without a paid
//! Apple cert) have no team id, so the check is a no-op and the agent
//! continues to accept any same-uid peer. That keeps `cargo install`,
//! `cargo run`, and fork builds working without ceremony.

use crate::bin_error;

#[cfg(target_os = "macos")]
mod imp {
    use core_foundation::base::TCFType as _;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::CFString;
    use core_foundation_sys::base::{CFRelease, OSStatus};
    use core_foundation_sys::dictionary::{
        CFDictionaryGetValue, CFDictionaryRef,
    };
    use core_foundation_sys::string::CFStringRef;
    use security_framework_sys::code_signing::{
        kSecGuestAttributePid, SecCSFlags, SecCodeCheckValidity,
        SecCodeCopyGuestWithAttributes, SecCodeCopySelf, SecCodeRef,
        SecRequirementCreateWithString, SecRequirementRef,
    };
    use std::sync::OnceLock;

    use crate::bin_error;

    const K_SEC_CS_DEFAULT_FLAGS: SecCSFlags = 0;
    /// `kSecCSSigningInformation` from `<Security/SecCode.h>`. Tells
    /// `SecCodeCopySigningInformation` to populate signing-identity
    /// fields (`TeamIdentifier`, signing certs) in the returned dict.
    const K_SEC_CS_SIGNING_INFORMATION: SecCSFlags = 1 << 1;

    // security-framework-sys doesn't export these; declare them
    // manually. Both are stable Security.framework exports.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        fn SecCodeCopySigningInformation(
            code: SecCodeRef,
            flags: SecCSFlags,
            information: *mut CFDictionaryRef,
        ) -> OSStatus;
        static kSecCodeInfoTeamIdentifier: CFStringRef;
    }

    /// Team Identifier of this agent process, captured once at first
    /// call. `None` when the agent is ad-hoc/unsigned (typical for
    /// local dev and forks without a Developer ID).
    pub fn agent_team_id() -> Option<&'static str> {
        static ID: OnceLock<Option<String>> = OnceLock::new();
        ID.get_or_init(detect_self_team_id).as_deref()
    }

    fn detect_self_team_id() -> Option<String> {
        unsafe {
            let mut self_code: SecCodeRef = std::ptr::null_mut();
            if SecCodeCopySelf(K_SEC_CS_DEFAULT_FLAGS, &raw mut self_code)
                != 0
                || self_code.is_null()
            {
                return None;
            }
            let mut info: CFDictionaryRef = std::ptr::null();
            let s = SecCodeCopySigningInformation(
                self_code,
                K_SEC_CS_SIGNING_INFORMATION,
                &raw mut info,
            );
            CFRelease(self_code.cast());
            if s != 0 || info.is_null() {
                return None;
            }
            let team = team_id_from_info(info);
            CFRelease(info.cast());
            team
        }
    }

    unsafe fn team_id_from_info(info: CFDictionaryRef) -> Option<String> {
        let key = unsafe { kSecCodeInfoTeamIdentifier };
        let value = unsafe { CFDictionaryGetValue(info, key.cast()) };
        if value.is_null() {
            return None;
        }
        // Value is a +0 (get-rule) CFString owned by `info`; retain
        // through wrap_under_get_rule before stringifying.
        let cfstr = unsafe { CFString::wrap_under_get_rule(value.cast()) };
        let s = cfstr.to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    /// Verify that the process at `peer_pid` is signed under `expected`
    /// team identifier. Used only when the agent itself has a team id
    /// to compare against.
    pub fn verify_peer_team(
        peer_pid: i32,
        expected: &str,
    ) -> bin_error::Result<()> {
        unsafe {
            let pid_key =
                CFString::wrap_under_get_rule(kSecGuestAttributePid);
            let pid_num = CFNumber::from(i64::from(peer_pid));
            let attrs = CFDictionary::from_CFType_pairs(&[(
                pid_key.as_CFType(),
                pid_num.as_CFType(),
            )]);

            let mut peer_code: SecCodeRef = std::ptr::null_mut();
            let s = SecCodeCopyGuestWithAttributes(
                std::ptr::null_mut(),
                attrs.as_concrete_TypeRef(),
                K_SEC_CS_DEFAULT_FLAGS,
                &raw mut peer_code,
            );
            if s != 0 || peer_code.is_null() {
                return Err(bin_error::Error::msg(format!(
                    "SecCodeCopyGuestWithAttributes(pid={peer_pid}) \
                     status {s}"
                )));
            }

            // Apple Developer ID / Apple Development certs both put the
            // team id in the leaf certificate's OU, anchored at Apple.
            let req_text = CFString::new(&format!(
                r#"anchor apple generic and certificate leaf[subject.OU] = "{expected}""#
            ));
            let mut req: SecRequirementRef = std::ptr::null_mut();
            let s = SecRequirementCreateWithString(
                req_text.as_concrete_TypeRef(),
                K_SEC_CS_DEFAULT_FLAGS,
                &raw mut req,
            );
            if s != 0 || req.is_null() {
                CFRelease(peer_code.cast());
                return Err(bin_error::Error::msg(format!(
                    "SecRequirementCreateWithString status {s}"
                )));
            }

            let s =
                SecCodeCheckValidity(peer_code, K_SEC_CS_DEFAULT_FLAGS, req);
            CFRelease(peer_code.cast());
            CFRelease(req.cast());
            if s == 0 {
                Ok(())
            } else {
                Err(bin_error::Error::msg(format!(
                    "peer pid {peer_pid} does not satisfy team \"{expected}\" \
                     code requirement (status {s})"
                )))
            }
        }
    }
}

/// Run the same-team code-requirement check on a peer. No-op when the
/// agent itself has no team identifier to compare against (ad-hoc /
/// unsigned / non-macOS) so dev and fork builds keep working.
#[cfg(target_os = "macos")]
pub fn check_peer_team(peer_pid: Option<i32>) -> bin_error::Result<()> {
    let Some(team) = imp::agent_team_id() else {
        return Ok(());
    };
    let Some(pid) = peer_pid else {
        return Err(bin_error::Error::msg(
            "agent is signed but peer pid is unavailable; \
             refusing connection",
        ));
    };
    imp::verify_peer_team(pid, team)
}

// Result return kept for cross-platform signature parity with the
// macOS implementation.
#[cfg(not(target_os = "macos"))]
#[allow(clippy::unnecessary_wraps)]
pub fn check_peer_team(_peer_pid: Option<i32>) -> bin_error::Result<()> {
    Ok(())
}
