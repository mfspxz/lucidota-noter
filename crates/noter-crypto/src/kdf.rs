//! Passphrase KDF (Argon2id) and subkey derivation (BLAKE3 keyed).
//!
//! - [`derive_master_key`]: Argon2id(passphrase, salt) -> 32-byte master key.
//!   Parameters: m=64MiB, t=3, p=4 (OWASP-recommended interactive baseline).
//! - [`derive_subkey`]: domain-separated subkey via BLAKE3 keyed hash
//!   (context string hashed into the key). Not a custom construction: it is
//!   exactly BLAKE3 in keyed mode with the context folded in.
//! - [`fingerprint`]: public, non-secret 16-byte identifier for a key.

use crate::{CryptoError, SecretBytes};
use argon2::{Argon2, Params};

/// 16-byte random salt for Argon2id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Salt([u8; 16]);

impl Salt {
    pub fn generate() -> Self {
        Self(rand::random())
    }
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Parse a 32-char hex salt (as stored by the UI).
    pub fn from_hex(hex: &str) -> Result<Self, crate::CryptoError> {
        if hex.len() != 32 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(crate::CryptoError::Malformed("salt must be 32 hex chars"));
        }
        let mut out = [0u8; 16];
        for i in 0..16 {
            out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16)
                .map_err(|_| crate::CryptoError::Malformed("salt must be 32 hex chars"))?;
        }
        Ok(Self(out))
    }

    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

/// Derive the 32-byte master key from a passphrase and salt (Argon2id).
pub fn derive_master_key(passphrase: &str, salt: &Salt) -> Result<SecretBytes, CryptoError> {
    // m = 64 MiB, t = 3, p = 4.
    let params = Params::new(64 * 1024, 3, 4, Some(32)).map_err(|_| CryptoError::KdfFailed)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt.as_bytes(), &mut out)
        .map_err(|_| CryptoError::KdfFailed)?;
    Ok(SecretBytes::new(out))
}

/// Derive a domain-separated subkey from the master key.
///
/// `context` names the purpose, e.g. b"noter/store/v1", b"noter/sync/v1".
/// Different contexts yield unrelated keys.
pub fn derive_subkey(master: &SecretBytes, context: &[u8]) -> SecretBytes {
    // BLAKE3 keyed mode, with the context folded into the key material.
    // Key = BLAKE3(master || len(context) || context) would be a custom
    // construction; instead we hash the context with the master key as the
    // BLAKE3 key directly and prepend context bytes to the input.
    let keyed = blake3::Hasher::new_keyed(master.as_bytes());
    let mut h = keyed;
    h.update(&(context.len() as u64).to_le_bytes());
    h.update(context);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    SecretBytes::new(out)
}

/// Public 16-byte fingerprint of a key (for display / key confirmation).
pub fn fingerprint(key: &SecretBytes) -> [u8; 16] {
    let h = blake3::hash(key.as_bytes());
    let mut fp = [0u8; 16];
    fp.copy_from_slice(&h.as_bytes()[..16]);
    fp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_deterministic() {
        let salt = Salt([7u8; 16]);
        let k1 = derive_master_key("correct horse battery staple", &salt).unwrap();
        let k2 = derive_master_key("correct horse battery staple", &salt).unwrap();
        assert_eq!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn kdf_salt_matters() {
        let k1 = derive_master_key("pw", &Salt([1u8; 16])).unwrap();
        let k2 = derive_master_key("pw", &Salt([2u8; 16])).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn kdf_passphrase_matters() {
        let salt = Salt([1u8; 16]);
        let k1 = derive_master_key("pw1", &salt).unwrap();
        let k2 = derive_master_key("pw2", &salt).unwrap();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn subkeys_domain_separated() {
        let master = SecretBytes::generate();
        let a = derive_subkey(&master, b"noter/store/v1");
        let b = derive_subkey(&master, b"noter/sync/v1");
        let c = derive_subkey(&master, b"noter/store/v1");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes(), c.as_bytes());
    }

    #[test]
    fn salt_hex_roundtrip() {
        let s = Salt::generate();
        let h = s.to_hex();
        assert_eq!(h.len(), 32);
        assert_eq!(Salt::from_hex(&h).unwrap(), s);
        assert!(Salt::from_hex("xyz").is_err());
        assert!(Salt::from_hex(&"zz".repeat(16)).is_err());
    }

    #[test]
    fn fingerprint_stable_and_short() {
        let k = SecretBytes::generate();
        assert_eq!(fingerprint(&k), fingerprint(&k));
        assert_eq!(fingerprint(&k).len(), 16);
    }
}
