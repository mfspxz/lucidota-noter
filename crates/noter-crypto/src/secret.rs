use zeroize::{Zeroize, ZeroizeOnDrop};

/// 32 bytes of secret material that zeroizes on drop.
///
/// All keys in noter-crypto are carried in this type so a stray
/// `Drop` cannot leave key material in freed memory.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes([u8; 32]);

impl SecretBytes {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Generate fresh random key material from the OS RNG.
    pub fn generate() -> Self {
        Self(rand::random())
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretBytes([redacted])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_key() {
        let s = SecretBytes::new([0xABu8; 32]);
        assert!(!format!("{:?}", s).contains("ab"));
        assert_eq!(format!("{:?}", s), "SecretBytes([redacted])");
    }

    #[test]
    fn generate_is_random() {
        let a = SecretBytes::generate();
        let b = SecretBytes::generate();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
