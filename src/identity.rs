use crate::prelude::*;

use hmac::Mac as _;
use sha1::Digest as _;

fn hkdf_expand_sha256(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
    const HASH_LEN: usize = 32;
    if out.len() > 255 * HASH_LEN {
        return Err(Error::HkdfExpand);
    }
    let mut prev: [u8; HASH_LEN] = [0; HASH_LEN];
    let mut prev_len = 0;
    let mut counter: u8 = 1;
    let mut offset = 0;
    while offset < out.len() {
        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(prk)
            .map_err(|_| Error::HkdfExpand)?;
        mac.update(&prev[..prev_len]);
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes();
        let take = (out.len() - offset).min(HASH_LEN);
        out[offset..offset + take].copy_from_slice(&block[..take]);
        prev.copy_from_slice(&block);
        prev_len = HASH_LEN;
        offset += take;
        counter = counter.wrapping_add(1);
    }
    Ok(())
}

pub struct Identity {
    pub email: String,
    pub keys: crate::locked::Keys,
    pub master_password_hash: crate::locked::PasswordHash,
}

impl Identity {
    pub fn new(
        email: &str,
        password: &crate::locked::Password,
        kdf: crate::api::KdfType,
        iterations: u32,
        memory: Option<u32>,
        parallelism: Option<u32>,
    ) -> Result<Self> {
        let email = email.trim().to_lowercase();

        let iterations = std::num::NonZeroU32::new(iterations)
            .ok_or(Error::Pbkdf2ZeroIterations)?;

        let mut keys = crate::locked::Vec::new();
        keys.extend(std::iter::repeat_n(0, 64));

        let enc_key = &mut keys.data_mut()[0..32];

        match kdf {
            crate::api::KdfType::Pbkdf2 => {
                pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
                    password.password(),
                    email.as_bytes(),
                    iterations.get(),
                    enc_key,
                )
                .map_err(|_| Error::Pbkdf2)?;
            }

            crate::api::KdfType::Argon2id => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(email.as_bytes());
                let salt = hasher.finalize();

                let argon2_config = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    argon2::Params::new(
                        memory.unwrap() * 1024,
                        iterations.get(),
                        parallelism.unwrap(),
                        Some(32),
                    )
                    .unwrap(),
                );
                argon2::Argon2::hash_password_into(
                    &argon2_config,
                    password.password(),
                    &salt,
                    enc_key,
                )
                .map_err(|_| Error::Argon2)?;
            }
        }

        let mut hash = crate::locked::Vec::new();
        hash.extend(std::iter::repeat_n(0, 32));
        pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
            enc_key,
            password.password(),
            1,
            hash.data_mut(),
        )
        .map_err(|_| Error::Pbkdf2)?;

        let mut prk: [u8; 32] = [0; 32];
        prk.copy_from_slice(enc_key);
        hkdf_expand_sha256(&prk, b"enc", enc_key)?;
        let mac_key = &mut keys.data_mut()[32..64];
        hkdf_expand_sha256(&prk, b"mac", mac_key)?;

        let keys = crate::locked::Keys::new(keys);
        let master_password_hash = crate::locked::PasswordHash::new(hash);

        Ok(Self {
            email: email.clone(),
            keys,
            master_password_hash,
        })
    }
}

#[test]
fn test_hkdf_expand_sha256_rfc5869_a1() {
    // RFC 5869 Appendix A.1
    let prk: [u8; 32] = [
        0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f,
        0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f,
        0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
    ];
    let info: [u8; 10] =
        [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let expected: [u8; 42] = [
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f,
        0x64, 0xd0, 0x36, 0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a,
        0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf, 0x34,
        0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
    ];
    let mut out = [0_u8; 42];
    hkdf_expand_sha256(&prk, &info, &mut out).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn test_hkdf_expand_sha256_rfc5869_a2() {
    // RFC 5869 Appendix A.2 — longer inputs, 82-byte output to exercise
    // the multi-block counter path (T(1)..T(6)).
    let prk: [u8; 32] = [
        0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c,
        0x9c, 0xeb, 0x35, 0xb4, 0x5c, 0xef, 0x76, 0x00, 0x14, 0x90, 0x46,
        0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f, 0xc2, 0x44,
    ];
    let info: [u8; 80] = [
        0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
        0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5,
        0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb,
        0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6,
        0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
        0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
        0xfd, 0xfe, 0xff,
    ];
    let expected: [u8; 82] = [
        0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7,
        0x8c, 0x59, 0x6a, 0x49, 0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e,
        0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c, 0x59,
        0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6,
        0x5e, 0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09,
        0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30,
        0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1,
        0xf3, 0x43, 0x4f, 0x1d, 0x87,
    ];
    let mut out = [0_u8; 82];
    hkdf_expand_sha256(&prk, &info, &mut out).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn test_hkdf_expand_sha256_rfc5869_a3() {
    // RFC 5869 Appendix A.3 — empty info (salt was empty upstream too;
    // we only exercise the Expand step here).
    let prk: [u8; 32] = [
        0x19, 0xef, 0x24, 0xa3, 0x2c, 0x71, 0x7b, 0x16, 0x7f, 0x33, 0xa9,
        0x1d, 0x6f, 0x64, 0x8b, 0xdf, 0x96, 0x59, 0x67, 0x76, 0xaf, 0xdb,
        0x63, 0x77, 0xac, 0x43, 0x4c, 0x1c, 0x29, 0x3c, 0xcb, 0x04,
    ];
    let expected: [u8; 42] = [
        0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f, 0x71, 0x5f, 0x80,
        0x2a, 0x06, 0x3c, 0x5a, 0x31, 0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1,
        0x87, 0x9e, 0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d, 0x9d,
        0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a, 0x96, 0xc8,
    ];
    let mut out = [0_u8; 42];
    hkdf_expand_sha256(&prk, &[], &mut out).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn test_hkdf_expand_sha256_rejects_oversize_output() {
    // HKDF caps L at 255*HashLen = 8160 bytes for SHA-256.
    let prk = [0u8; 32];
    let mut out = vec![0_u8; 8161];
    assert!(hkdf_expand_sha256(&prk, &[], &mut out).is_err());
}
