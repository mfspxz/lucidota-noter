//! ECIES-style public-key encryption (noter-010 sharing primitive).
//!
//! `seal_for(recipient, plaintext)`: generate an ephemeral X25519 keypair,
//! agree a shared secret with the recipient's public key, derive a pairwise
//! AEAD key, encrypt. Wire format:
//! `ephemeral_pubkey(32) || nonce(24) || ciphertext+tag`.
//!
//! Only the holder of the recipient's X25519 static secret can open it.

use crate::{agree, decrypt, encrypt, pairwise_key, CryptoError, PublicIdentity};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

pub const EPHEMERAL_LEN: usize = 32;

/// Encrypt `plaintext` so only `recipient` can read it.
pub fn seal_for(recipient: &PublicIdentity, plaintext: &[u8]) -> Vec<u8> {
    let ephemeral = StaticSecret::random_from_rng(OsRng);
    let eph_pub = XPublic::from(&ephemeral);
    let shared = agree(&ephemeral, &recipient.x25519_public());
    let key = pairwise_key(&shared);
    let ct = encrypt(&key, plaintext);
    let mut out = Vec::with_capacity(EPHEMERAL_LEN + ct.len());
    out.extend_from_slice(eph_pub.as_bytes());
    out.extend_from_slice(&ct);
    out
}

/// Decrypt a box made by [`seal_for`] for us.
pub fn open_from(our_secret: &StaticSecret, sealed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if sealed.len() < EPHEMERAL_LEN {
        return Err(CryptoError::Malformed("sealed box too short"));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&sealed[..EPHEMERAL_LEN]);
    let shared = agree(our_secret, &XPublic::from(eph));
    let key = pairwise_key(&shared);
    decrypt(&key, &sealed[EPHEMERAL_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceIdentity;

    #[test]
    fn seal_open_roundtrip() {
        let bob = DeviceIdentity::generate();
        let sealed = seal_for(&bob.public(), b"for bob only");
        assert_eq!(
            open_from(bob.x25519_secret(), &sealed).unwrap(),
            b"for bob only"
        );
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let bob = DeviceIdentity::generate();
        let mallory = DeviceIdentity::generate();
        let sealed = seal_for(&bob.public(), b"for bob only");
        assert_eq!(
            open_from(mallory.x25519_secret(), &sealed).unwrap_err(),
            CryptoError::AuthenticationFailed
        );
    }

    #[test]
    fn sealed_is_randomized() {
        let bob = DeviceIdentity::generate();
        let s1 = seal_for(&bob.public(), b"x");
        let s2 = seal_for(&bob.public(), b"x");
        assert_ne!(s1, s2);
    }

    #[test]
    fn tampered_box_rejected() {
        let bob = DeviceIdentity::generate();
        let mut sealed = seal_for(&bob.public(), b"x");
        sealed[40] ^= 1;
        assert!(open_from(bob.x25519_secret(), &sealed).is_err());
    }

    #[test]
    fn empty_plaintext_box() {
        let bob = DeviceIdentity::generate();
        let sealed = seal_for(&bob.public(), b"");
        assert_eq!(open_from(bob.x25519_secret(), &sealed).unwrap(), b"");
    }
}
