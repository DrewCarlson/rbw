use hmac::{Hmac, Mac};

pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
    Steam,
}

const STEAM_CHARS: &[u8] = b"23456789BCDFGHJKMNPQRTVWXY";

pub fn decode_base32(input: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = input
        .trim()
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let trimmed: &[u8] = {
        let mut end = cleaned.len();
        while end > 0 && cleaned[end - 1] == b'=' {
            end -= 1;
        }
        &cleaned[..end]
    };
    let mut out = Vec::with_capacity(trimmed.len() * 5 / 8);
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;
    for &b in trimmed {
        let v: u16 = match b {
            b'A'..=b'Z' => u16::from(b - b'A'),
            b'a'..=b'z' => u16::from(b - b'a'),
            b'2'..=b'7' => u16::from(b - b'2') + 26,
            _ => return None,
        };
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = u8::try_from((buffer >> bits) & 0xff).ok()?;
            out.push(byte);
            buffer &= (1_u16 << bits).wrapping_sub(1);
        }
    }
    Some(out)
}

pub fn generate(
    secret: &[u8],
    unix_secs: u64,
    step: u64,
    digits: u32,
    algorithm: &Algorithm,
) -> crate::error::Result<String> {
    let totp_err = |msg: &str| crate::error::Error::Totp {
        msg: msg.to_string(),
    };
    let counter = (unix_secs / step).to_be_bytes();
    let mac: Vec<u8> = match algorithm {
        Algorithm::Sha1 | Algorithm::Steam => {
            let mut m = Hmac::<sha1::Sha1>::new_from_slice(secret).map_err(
                |e| crate::error::Error::Totp {
                    msg: format!("invalid hmac key: {e}"),
                },
            )?;
            m.update(&counter);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha256 => {
            let mut m = Hmac::<sha2::Sha256>::new_from_slice(secret).map_err(
                |e| crate::error::Error::Totp {
                    msg: format!("invalid hmac key: {e}"),
                },
            )?;
            m.update(&counter);
            m.finalize().into_bytes().to_vec()
        }
        Algorithm::Sha512 => {
            let mut m = Hmac::<sha2::Sha512>::new_from_slice(secret).map_err(
                |e| crate::error::Error::Totp {
                    msg: format!("invalid hmac key: {e}"),
                },
            )?;
            m.update(&counter);
            m.finalize().into_bytes().to_vec()
        }
    };

    let offset = usize::from(
        *mac.last().ok_or_else(|| totp_err("empty hmac output"))? & 0x0f,
    );
    let mut truncated = u32::from_be_bytes(
        mac[offset..offset + 4]
            .try_into()
            .map_err(|_| totp_err("totp truncation failed"))?,
    ) & 0x7fff_ffff;

    let digits_usize = usize::try_from(digits)
        .map_err(|_| totp_err("digits out of range"))?;

    match algorithm {
        Algorithm::Sha1 | Algorithm::Sha256 | Algorithm::Sha512 => {
            let modulus = 10_u32
                .checked_pow(digits)
                .ok_or_else(|| totp_err("digits too large"))?;
            Ok(format!(
                "{:0width$}",
                truncated % modulus,
                width = digits_usize
            ))
        }
        Algorithm::Steam => {
            let len = u32::try_from(STEAM_CHARS.len())
                .map_err(|_| totp_err("steam alphabet too large"))?;
            let mut s = String::with_capacity(digits_usize);
            for _ in 0..digits {
                let idx = usize::try_from(truncated % len)
                    .map_err(|_| totp_err("steam index error"))?;
                s.push(char::from(STEAM_CHARS[idx]));
                truncated /= len;
            }
            Ok(s)
        }
    }
}

#[cfg(test)]
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
mod test {
    use super::{decode_base32, generate, Algorithm, STEAM_CHARS};

    #[test]
    fn test_decode_base32_basic() {
        assert_eq!(decode_base32("MZXW6===").unwrap(), b"foo");
        assert_eq!(decode_base32("MZXW6").unwrap(), b"foo");
        assert_eq!(decode_base32("mzxw6").unwrap(), b"foo");
        assert_eq!(decode_base32("MZ XW 6").unwrap(), b"foo");
        assert_eq!(decode_base32("MZXW6YQ=").unwrap(), b"foob");
        assert_eq!(decode_base32("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(decode_base32("MZXW6YTBOI======").unwrap(), b"foobar");
        assert!(decode_base32("!!!").is_none());
    }

    #[test]
    fn test_rfc6238_sha1() {
        let secret = b"12345678901234567890";
        let cases = [
            (59_u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ];
        for (t, expected) in cases {
            let code = generate(secret, t, 30, 8, &Algorithm::Sha1).unwrap();
            assert_eq!(code, expected, "time={t}");
        }
    }

    #[test]
    fn test_rfc6238_sha256() {
        let secret = b"12345678901234567890123456789012";
        let code = generate(secret, 59, 30, 8, &Algorithm::Sha256).unwrap();
        assert_eq!(code, "46119246");
    }

    #[test]
    fn test_rfc6238_sha512() {
        let secret =
            b"1234567890123456789012345678901234567890123456789012345678901234";
        let code = generate(secret, 59, 30, 8, &Algorithm::Sha512).unwrap();
        assert_eq!(code, "90693936");
    }

    #[test]
    fn test_digits_six() {
        let secret = b"12345678901234567890";
        let code = generate(secret, 59, 30, 6, &Algorithm::Sha1).unwrap();
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_steam() {
        let secret = decode_base32("STEAMKEY234567").unwrap();
        let code =
            generate(&secret, 1_000_000_000, 30, 5, &Algorithm::Steam).unwrap();
        assert_eq!(code.len(), 5);
        for c in code.chars() {
            assert!(STEAM_CHARS.contains(&(c as u8)));
        }
        let pinned =
            generate(b"12345678901234567890", 59, 30, 5, &Algorithm::Steam)
                .unwrap();
        assert_eq!(pinned, "PV9M4");
    }
}
