//! WireGuard key types.
//!
//! Secrecy is enforced at the type level: [`SecretKey`] has no `Display` and a
//! redacting `Debug`, so a private or preshared key cannot reach a log line,
//! an error message or an IPC frame by accident. [`PublicKey`] prints freely.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Length of every WireGuard Curve25519 key.
pub const KEY_LEN: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyError {
    #[error("not valid base64")]
    NotBase64,
    #[error("expected {KEY_LEN} bytes, got {0}")]
    WrongLength(usize),
}

fn decode(s: &str) -> Result<[u8; KEY_LEN], KeyError> {
    let raw = B64.decode(s.trim()).map_err(|_| KeyError::NotBase64)?;
    raw.try_into()
        .map_err(|v: Vec<u8>| KeyError::WrongLength(v.len()))
}

/// A WireGuard public key. Safe to print.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_base64(s: &str) -> Result<Self, KeyError> {
        decode(s).map(Self)
    }

    pub fn to_base64(&self) -> String {
        B64.encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_base64())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_base64())
    }
}

impl std::str::FromStr for PublicKey {
    type Err = KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_base64(s)
    }
}

impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

// SecretKey intentionally implements neither Serialize nor Deserialize: key
// material is loaded from a 0600 file by path, never from config or IPC.

/// A WireGuard private or preshared key.
///
/// Deliberately implements neither `Display` nor `Serialize`; reaching the
/// bytes requires the explicit [`SecretKey::expose`].
#[derive(Clone, PartialEq, Eq)]
pub struct SecretKey([u8; KEY_LEN]);

impl SecretKey {
    pub fn from_base64(s: &str) -> Result<Self, KeyError> {
        decode(s).map(Self)
    }

    /// Yield the raw key. Every call site is a place a secret could leak.
    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Base64 form, for handing to a tunnel backend. Never log the result.
    pub fn expose_base64(&self) -> String {
        B64.encode(self.0)
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk=";

    #[test]
    fn round_trips_base64() {
        let k = PublicKey::from_base64(VALID).unwrap();
        assert_eq!(k.to_base64(), VALID);
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        assert!(PublicKey::from_base64(&format!("  {VALID}\n")).is_ok());
    }

    #[test]
    fn rejects_non_base64() {
        assert_eq!(
            PublicKey::from_base64("not a key!").unwrap_err(),
            KeyError::NotBase64
        );
    }

    #[test]
    fn rejects_a_key_of_the_wrong_length() {
        // 16 bytes, validly encoded.
        assert_eq!(
            PublicKey::from_base64("AAAAAAAAAAAAAAAAAAAAAA==").unwrap_err(),
            KeyError::WrongLength(16)
        );
    }

    #[test]
    fn secret_keys_are_redacted_in_debug_output() {
        let secret = SecretKey::from_base64(VALID).unwrap();
        let rendered = format!("{secret:?}");
        assert_eq!(rendered, "SecretKey(<redacted>)");
        // The point of the type: the material must not appear anywhere.
        assert!(!rendered.contains("PyLC"));
    }

    #[test]
    fn public_keys_are_visible_in_debug_output() {
        let public = PublicKey::from_base64(VALID).unwrap();
        assert!(format!("{public:?}").contains(VALID));
    }
}
