use rand::RngCore as _;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Uuid([u8; 16]);

#[derive(Debug, PartialEq, Eq)]
pub struct ParseUuidError;

impl std::fmt::Display for ParseUuidError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid uuid")
    }
}

impl std::error::Error for ParseUuidError {}

pub fn new_v4() -> Uuid {
    let mut bytes = [0_u8; 16];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut bytes);
    // RFC 4122 version 4 and variant bits
    bytes[6] = 0x40 | (bytes[6] & 0x0F);
    bytes[8] = 0x80 | (bytes[8] & 0x3F);
    Uuid(bytes)
}

impl Uuid {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3],
            b[4], b[5],
            b[6], b[7],
            b[8], b[9],
            b[10], b[11], b[12], b[13], b[14], b[15],
        )
    }
}

impl std::str::FromStr for Uuid {
    type Err = ParseUuidError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 36 {
            return Err(ParseUuidError);
        }
        // hyphen positions per RFC 4122 canonical form
        if bytes[8] != b'-'
            || bytes[13] != b'-'
            || bytes[18] != b'-'
            || bytes[23] != b'-'
        {
            return Err(ParseUuidError);
        }
        let hex_positions = [
            0, 2, 4, 6, 9, 11, 14, 16, 19, 21, 24, 26, 28, 30, 32, 34,
        ];
        let mut out = [0_u8; 16];
        for (i, &pos) in hex_positions.iter().enumerate() {
            let hi = from_hex(bytes[pos])?;
            let lo = from_hex(bytes[pos + 1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(Self(out))
    }
}

fn from_hex(b: u8) -> Result<u8, ParseUuidError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ParseUuidError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr as _;

    #[test]
    fn version_and_variant_bits() {
        for _ in 0..64 {
            let u = new_v4();
            let b = u.as_bytes();
            assert_eq!(b[6] & 0xF0, 0x40, "version nibble must be 4");
            assert_eq!(b[8] & 0xC0, 0x80, "variant must be RFC 4122");
        }
    }

    #[test]
    fn round_trip() {
        let u = new_v4();
        let s = u.to_string();
        let parsed = Uuid::from_str(&s).unwrap();
        assert_eq!(u, parsed);
        assert_eq!(s.len(), 36);
    }

    #[test]
    fn pinned_format() {
        let bytes = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0x4c, 0xde, 0x8f, 0x01,
            0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        ];
        let u = Uuid(bytes);
        assert_eq!(
            u.to_string(),
            "01234567-89ab-4cde-8f01-23456789abcd"
        );
        let parsed =
            Uuid::from_str("01234567-89ab-4cde-8f01-23456789abcd").unwrap();
        assert_eq!(parsed, u);
    }

    #[test]
    fn rejects_malformed() {
        assert!(Uuid::from_str("").is_err());
        assert!(Uuid::from_str("not-a-uuid").is_err());
        assert!(
            Uuid::from_str("01234567-89ab-4cde-8f01-23456789abcdx").is_err()
        );
        assert!(
            Uuid::from_str("01234567x89ab-4cde-8f01-23456789abcd").is_err()
        );
        assert!(
            Uuid::from_str("0123456g-89ab-4cde-8f01-23456789abcd").is_err()
        );
    }

    #[test]
    fn accepts_uppercase_outputs_lowercase() {
        let u =
            Uuid::from_str("01234567-89AB-4CDE-8F01-23456789ABCD").unwrap();
        assert_eq!(u.to_string(), "01234567-89ab-4cde-8f01-23456789abcd");
    }
}
