//! Device identity: Ed25519 signing keys + X25519 encryption keys.
//!
//! Every NOTER device holds one [`DeviceIdentity`]. The Ed25519 public key is
//! the device's long-term identity (used to sign sync envelopes); the X25519
//! keypair (derived from the same secret seed via the standard
//! ed25519->x25519 conversion... we instead generate an independent X25519
//! keypair from the OS RNG to avoid any non-standard conversion) is used for
//! key agreement.

use crate::{CryptoError, SecretBytes};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

/// A device's long-term identity: Ed25519 signing + X25519 encryption keypairs.
pub struct DeviceIdentity {
    signing: SigningKey,
    x_secret: StaticSecret,
}

impl DeviceIdentity {
    /// Generate a fresh identity from the OS RNG.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing = SigningKey::generate(&mut csprng);
        let x_secret = StaticSecret::random_from_rng(&mut csprng);
        Self { signing, x_secret }
    }

    /// The public half, safe to share.
    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            ed25519: self.signing.verifying_key().to_bytes(),
            x25519: XPublic::from(&self.x_secret).to_bytes(),
        }
    }

    /// Sign bytes with the Ed25519 identity key.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// The X25519 static secret (for key agreement). Keep private.
    pub fn x25519_secret(&self) -> &StaticSecret {
        &self.x_secret
    }

    /// Export the secret seed (32B Ed25519 seed || 32B X25519 secret) for backup.
    /// Caller is responsible for encrypting this at rest.
    pub fn export_seed(&self) -> SecretSeed {
        let mut seed = [0u8; 64];
        seed[..32].copy_from_slice(&self.signing.to_bytes());
        seed[32..].copy_from_slice(self.x_secret.as_bytes());
        SecretSeed(seed)
    }

    /// Build an identity directly from 64 seed bytes
    /// (32B Ed25519 seed || 32B X25519 secret).
    pub fn from_seed_bytes(seed: &[u8; 64]) -> Result<Self, CryptoError> {
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&seed[..32]);
        let signing = SigningKey::from_bytes(&ed);
        let x_secret = StaticSecret::from({
            let mut b = [0u8; 32];
            b.copy_from_slice(&seed[32..]);
            b
        });
        Ok(Self { signing, x_secret })
    }

    /// Restore from an exported seed.
    pub fn import_seed(seed: &SecretSeed) -> Result<Self, CryptoError> {
        let mut ed = [0u8; 32];
        ed.copy_from_slice(&seed.0[..32]);
        let signing = SigningKey::from_bytes(&ed);
        let x_secret = StaticSecret::from({
            let mut b = [0u8; 32];
            b.copy_from_slice(&seed.0[32..]);
            b
        });
        Ok(Self { signing, x_secret })
    }
}

/// Exported identity seed (encrypt before storing).
#[derive(Clone)]
pub struct SecretSeed([u8; 64]);

impl SecretSeed {
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Drop for SecretSeed {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Public device identity: 32B Ed25519 verify key + 32B X25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub ed25519: [u8; 32],
    pub x25519: [u8; 32],
}

impl PublicIdentity {
    /// Verify an Ed25519 signature from this device.
    pub fn verify(&self, msg: &[u8], sig: &[u8; 64]) -> Result<(), CryptoError> {
        let vk = VerifyingKey::from_bytes(&self.ed25519)
            .map_err(|_| CryptoError::Malformed("bad ed25519 public key"))?;
        vk.verify(msg, &Signature::from_bytes(sig))
            .map_err(|_| CryptoError::BadSignature)
    }

    /// This device's X25519 public key for key agreement.
    pub fn x25519_public(&self) -> XPublic {
        XPublic::from(self.x25519)
    }

    /// Short human-readable fingerprint (hex of BLAKE3(pubkeys)[..8]).
    pub fn fingerprint(&self) -> String {
        let mut h = blake3::Hasher::new();
        h.update(&self.ed25519);
        h.update(&self.x25519);
        hex_of(&h.finalize().as_bytes()[..8])
    }
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Perform X25519 key agreement: our static secret x their public key.
pub fn agree(ours: &StaticSecret, theirs: &XPublic) -> SecretBytes {
    SecretBytes::new(ours.diffie_hellman(theirs).to_bytes())
}

/// AEAD key for a pairwise channel: BLAKE3(shared_secret, b"noter/pairwise/v1").
pub fn pairwise_key(shared: &SecretBytes) -> SecretBytes {
    let mut h = blake3::Hasher::new_keyed(shared.as_bytes());
    h.update(b"noter/pairwise/v1");
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    SecretBytes::new(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let id = DeviceIdentity::generate();
        let msg = b"hello noter";
        let sig = id.sign(msg);
        id.public().verify(msg, &sig).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let id = DeviceIdentity::generate();
        let sig = id.sign(b"real");
        assert_eq!(
            id.public().verify(b"fake", &sig).unwrap_err(),
            CryptoError::BadSignature
        );
    }

    #[test]
    fn verify_rejects_wrong_device() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        let sig = a.sign(b"msg");
        assert_eq!(
            b.public().verify(b"msg", &sig).unwrap_err(),
            CryptoError::BadSignature
        );
    }

    #[test]
    fn x25519_agreement_matches_both_sides() {
        let a = DeviceIdentity::generate();
        let b = DeviceIdentity::generate();
        let s1 = agree(a.x25519_secret(), &b.public().x25519_public());
        let s2 = agree(b.x25519_secret(), &a.public().x25519_public());
        assert_eq!(s1.as_bytes(), s2.as_bytes());
    }

    #[test]
    fn seed_export_import_preserves_identity() {
        let id = DeviceIdentity::generate();
        let seed = id.export_seed();
        let id2 = DeviceIdentity::import_seed(&seed).unwrap();
        assert_eq!(id.public(), id2.public());
        // Signatures from the restored identity verify under the same pubkey.
        let sig = id2.sign(b"x");
        id.public().verify(b"x", &sig).unwrap();
    }

    #[test]
    fn fingerprint_is_stable_hex16() {
        let id = DeviceIdentity::generate();
        let fp = id.public().fingerprint();
        assert_eq!(fp.len(), 16);
        assert_eq!(fp, id.public().fingerprint());
    }
}
