use thiserror::Error;

/// All errors surfaced by noter-crypto.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    /// AEAD authentication tag verification failed (tamper / wrong key).
    #[error("decryption failed: authentication tag invalid")]
    AuthenticationFailed,
    /// Signature did not verify.
    #[error("signature verification failed")]
    BadSignature,
    /// Malformed key / nonce / ciphertext encoding.
    #[error("malformed input: {0}")]
    Malformed(&'static str),
    /// KDF parameters rejected.
    #[error("key derivation failed")]
    KdfFailed,
}
