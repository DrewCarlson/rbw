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
    let info: [u8; 10] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
    ];
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
