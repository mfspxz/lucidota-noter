//! AEAD envelope: XChaCha20-Poly1305 with a random 24-byte nonce per message.
//!
//! Wire format: `nonce(24) || ciphertext+tag`.
//! Random nonces mean the same plaintext never produces the same ciphertext.

use crate::{CryptoError, SecretBytes};
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    XChaCha20Poly1305, XNonce,
};

pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// Encrypt `plaintext` under `key`. Returns `nonce || ciphertext || tag`.
pub fn encrypt(key: &SecretBytes, plaintext: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(
        &cipher
            .encrypt(&nonce, plaintext)
            .expect("encryption cannot fail with a valid key"),
    );
    out
}

/// Decrypt a blob produced by [`encrypt`].
pub fn decrypt(key: &SecretBytes, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(CryptoError::Malformed("aead blob shorter than nonce+tag"));
    }
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let nonce = XNonce::from_slice(&blob[..NONCE_LEN]);
    cipher
        .decrypt(nonce, &blob[NONCE_LEN..])
        .map_err(|_| CryptoError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = SecretBytes::generate();
        let pt = b"the quick brown fox";
        let ct = encrypt(&key, pt);
        assert_eq!(decrypt(&key, &ct).unwrap(), pt);
    }

    #[test]
    fn random_nonce_means_no_deterministic_ciphertext() {
        let key = SecretBytes::generate();
        let c1 = encrypt(&key, b"same");
        let c2 = encrypt(&key, b"same");
        assert_ne!(c1, c2);
    }

    #[test]
    fn tamper_detected() {
        let key = SecretBytes::generate();
        let mut ct = encrypt(&key, b"secret");
        ct[NONCE_LEN] ^= 0xFF;
        assert_eq!(
            decrypt(&key, &ct).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn wrong_key_fails() {
        let k1 = SecretBytes::generate();
        let k2 = SecretBytes::generate();
        let ct = encrypt(&k1, b"secret");
        assert_eq!(
            decrypt(&k2, &ct).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn truncated_blob_rejected() {
        let key = SecretBytes::generate();
        assert!(decrypt(&key, &[0u8; 10]).is_err());
        assert!(decrypt(&key, &[]).is_err());
    }

    #[test]
    fn empty_plaintext_ok() {
        let key = SecretBytes::generate();
        let ct = encrypt(&key, b"");
        assert_eq!(decrypt(&key, &ct).unwrap(), b"");
    }

    #[test]
    fn large_plaintext_roundtrip() {
        let key = SecretBytes::generate();
        let pt: Vec<u8> = (0..1_000_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(decrypt(&key, &encrypt(&key, &pt)).unwrap(), pt);
    }
}
