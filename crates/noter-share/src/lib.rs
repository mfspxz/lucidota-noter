//! NOTER E2EE sharing (noter-010).
//!
//! Share a note with **another user** (different master key, different
//! devices) without trusting any server or relay:
//!
//! 1. Fresh random 32-byte share key K.
//! 2. Note JSON + attachment bytes sealed with K (XChaCha20-Poly1305).
//! 3. K wrapped with ECIES for the recipient (`seal_for` — ephemeral X25519
//!    + AEAD). Only the recipient's X25519 static secret opens it.
//! 4. Whole package signed with the sender's Ed25519 identity.
//!
//! The recipient verifies the sender's signature against the sender's
//! public identity (exchanged out-of-band), unwraps K, decrypts.
//! A relay/storage server sees only opaque blobs.

use noter_crypto::{
    decrypt, encrypt, open_from, seal_for, CryptoError, DeviceIdentity, PublicIdentity, SecretBytes,
};
use noter_model::Note;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShareError {
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("sender identity does not match package")]
    SenderMismatch,
}

/// One shared attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedAttachment {
    pub name: String,
    pub mime: String,
    pub bytes: Vec<u8>,
}

/// Inner plaintext of a share package (sealed with the share key).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShareInner {
    note: Note,
    attachments: Vec<SharedAttachment>,
}

/// A share package, safe to send over any untrusted channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharePackage {
    pub v: u8,
    pub sender: PublicIdentity,
    /// ECIES box holding the share key, for the recipient.
    pub key_box: Vec<u8>,
    /// XChaCha20-Poly1305-sealed ShareInner under the share key.
    pub payload_sealed: Vec<u8>,
    /// Ed25519 signature over sign_bytes().
    pub sig: Vec<u8>,
}

impl SharePackage {
    fn sign_bytes(&self) -> Vec<u8> {
        let mut b = serde_json::to_vec(&self.sender).expect("serializes");
        b.extend_from_slice(&self.key_box);
        b.extend_from_slice(b"\x00");
        b.extend_from_slice(&self.payload_sealed);
        b
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serializes")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, ShareError> {
        Ok(serde_json::from_slice(b)?)
    }
}

/// Share `note` (+ attachments) with the holder of `recipient`.
pub fn share_note(
    note: &Note,
    attachments: &[SharedAttachment],
    sender: &DeviceIdentity,
    recipient: &PublicIdentity,
) -> SharePackage {
    let share_key = SecretBytes::generate();
    let inner = ShareInner {
        note: note.clone(),
        attachments: attachments.to_vec(),
    };
    let inner_json = serde_json::to_vec(&inner).expect("serializes");
    let payload_sealed = encrypt(&share_key, &inner_json);
    let key_box = seal_for(recipient, share_key.as_bytes());
    let mut pkg = SharePackage {
        v: 1,
        sender: sender.public(),
        key_box,
        payload_sealed,
        sig: Vec::new(),
    };
    pkg.sig = sender.sign(&pkg.sign_bytes()).to_vec();
    pkg
}

/// Receive a share package. `expected_sender` must be the sender's public
/// identity (out-of-band); mismatch or bad signature fails closed.
pub fn receive_package(
    pkg: &SharePackage,
    recipient: &DeviceIdentity,
    expected_sender: &PublicIdentity,
) -> Result<(Note, Vec<SharedAttachment>), ShareError> {
    if pkg.v != 1 {
        return Err(ShareError::SenderMismatch);
    }
    if &pkg.sender != expected_sender {
        return Err(ShareError::SenderMismatch);
    }
    let sig: [u8; 64] = pkg
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::Malformed("sig length"))?;
    pkg.sender
        .verify(&pkg.sign_bytes(), &sig)
        .map_err(ShareError::Crypto)?;
    let key_bytes = open_from(recipient.x25519_secret(), &pkg.key_box)?;
    let share_key = SecretBytes::new(
        key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("share key length"))?,
    );
    let inner_json = decrypt(&share_key, &pkg.payload_sealed)?;
    let inner: ShareInner = serde_json::from_slice(&inner_json)?;
    Ok((inner.note, inner.attachments))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn users() -> (DeviceIdentity, DeviceIdentity) {
        (DeviceIdentity::generate(), DeviceIdentity::generate())
    }

    fn sample_note() -> Note {
        let mut n = Note::new("Shared", "hello **shared** world [[x]]");
        n.tags = vec!["shared".into()];
        n
    }

    #[test]
    fn share_receive_roundtrip() {
        let (alice, bob) = users();
        let note = sample_note();
        let atts = vec![SharedAttachment {
            name: "a.bin".into(),
            mime: "application/octet-stream".into(),
            bytes: b"0123456789".to_vec(),
        }];
        let pkg = share_note(&note, &atts, &alice, &bob.public());
        let (got_note, got_atts) = receive_package(&pkg, &bob, &alice.public()).unwrap();
        assert_eq!(got_note, note);
        assert_eq!(got_atts, atts);
    }

    #[test]
    fn package_serializes_for_transport() {
        let (alice, bob) = users();
        let pkg = share_note(&sample_note(), &[], &alice, &bob.public());
        let bytes = pkg.to_bytes();
        let pkg2 = SharePackage::from_bytes(&bytes).unwrap();
        let (note, _) = receive_package(&pkg2, &bob, &alice.public()).unwrap();
        assert_eq!(note.title, "Shared");
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let (alice, bob) = users();
        let mallory = DeviceIdentity::generate();
        let pkg = share_note(&sample_note(), &[], &alice, &bob.public());
        assert!(receive_package(&pkg, &mallory, &alice.public()).is_err());
        let _ = bob;
    }

    #[test]
    fn tampered_payload_fails() {
        let (alice, bob) = users();
        let mut pkg = share_note(&sample_note(), &[], &alice, &bob.public());
        pkg.payload_sealed[30] ^= 1;
        assert!(receive_package(&pkg, &bob, &alice.public()).is_err());
    }

    #[test]
    fn sender_spoof_fails() {
        let (alice, bob) = users();
        let mallory = DeviceIdentity::generate();
        let pkg = share_note(&sample_note(), &[], &alice, &bob.public());
        // Attacker claims to be mallory: identity mismatch fails closed.
        assert!(receive_package(&pkg, &bob, &mallory.public()).is_err());
        // Attacker rewrites sender field but can't forge alice's signature.
        let mut pkg2 = pkg.clone();
        pkg2.sender = mallory.public();
        assert!(receive_package(&pkg2, &bob, &mallory.public()).is_err());
    }

    #[test]
    fn share_key_is_fresh_per_package() {
        let (alice, bob) = users();
        let p1 = share_note(&sample_note(), &[], &alice, &bob.public());
        let p2 = share_note(&sample_note(), &[], &alice, &bob.public());
        assert_ne!(p1.key_box, p2.key_box);
        assert_ne!(p1.payload_sealed, p2.payload_sealed);
    }

    #[test]
    fn empty_attachments_ok() {
        let (alice, bob) = users();
        let pkg = share_note(&sample_note(), &[], &alice, &bob.public());
        let (note, atts) = receive_package(&pkg, &bob, &alice.public()).unwrap();
        assert!(atts.is_empty());
        assert_eq!(note.body_md, "hello **shared** world [[x]]");
    }
}
