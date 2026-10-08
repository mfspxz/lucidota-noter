use crate::VersionVector;
use noter_crypto::{decrypt, derive_subkey, encrypt, CryptoError, DeviceIdentity, PublicIdentity, SecretBytes};
use serde::{Deserialize, Serialize};

pub const SYNC_CTX: &[u8] = b"noter/sync/v1";

/// Signed header of a sync envelope. The signature covers the canonical
/// JSON of the header plus the sealed payload bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub note_id: String,
    pub writer_id: String,
    pub vv: VersionVector,
    pub updated_ms: i64,
    pub deleted: bool,
    pub writer_pub: PublicIdentity,
}

/// A sealed, signed note state for transport between devices.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub header: EnvelopeHeader,
    /// XChaCha20-Poly1305-sealed serialized note (sync subkey).
    pub payload_sealed: Vec<u8>,
    /// Ed25519 signature over sign_bytes().
    pub sig: Vec<u8>,
}

impl Envelope {
    /// Create an envelope: seal the note payload, sign header+sealed payload.
    pub fn seal(
        identity: &DeviceIdentity,
        device_id: &str,
        master: &SecretBytes,
        note_id: &str,
        note_json: &[u8],
        vv: VersionVector,
        updated_ms: i64,
        deleted: bool,
    ) -> Self {
        let sync_key = derive_subkey(master, SYNC_CTX);
        let payload_sealed = encrypt(&sync_key, note_json);
        let header = EnvelopeHeader {
            note_id: note_id.to_string(),
            writer_id: device_id.to_string(),
            vv,
            updated_ms,
            deleted,
            writer_pub: identity.public(),
        };
        let sig = identity.sign(&Self::sign_bytes_static(&header, &payload_sealed)).to_vec();
        Self {
            header,
            payload_sealed,
            sig,
        }
    }

    fn sign_bytes_static(header: &EnvelopeHeader, sealed: &[u8]) -> Vec<u8> {
        let mut h = serde_json::to_vec(header).expect("header serializes");
        h.extend_from_slice(b"\x00");
        h.extend_from_slice(sealed);
        h
    }

    fn sign_bytes(&self) -> Vec<u8> {
        Self::sign_bytes_static(&self.header, &self.payload_sealed)
    }

    /// Verify the writer's signature. Fails closed on unknown/tampered data.
    pub fn verify(&self) -> Result<(), CryptoError> {
        let sig: [u8; 64] = self
            .sig
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Malformed("signature must be 64 bytes"))?;
        self.header.writer_pub.verify(&self.sign_bytes(), &sig)
    }

    /// Decrypt the payload (caller must hold the master key).
    pub fn open(&self, master: &SecretBytes) -> Result<Vec<u8>, CryptoError> {
        let sync_key = derive_subkey(master, SYNC_CTX);
        decrypt(&sync_key, &self.payload_sealed)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("envelope serializes")
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_pair() -> (DeviceIdentity, SecretBytes) {
        (DeviceIdentity::generate(), SecretBytes::generate())
    }

    #[test]
    fn seal_verify_open_roundtrip() {
        let (id, master) = env_pair();
        let mut vv = VersionVector::new();
        vv.bump("d1");
        let e = Envelope::seal(&id, "d1", &master, "n1", b"{\"t\":1}", vv, 123, false);
        e.verify().unwrap();
        assert_eq!(e.open(&master).unwrap(), b"{\"t\":1}");
    }

    #[test]
    fn tampered_payload_fails_verify() {
        let (id, master) = env_pair();
        let mut e = Envelope::seal(&id, "d1", &master, "n1", b"x", VersionVector::new(), 1, false);
        e.payload_sealed[10] ^= 1;
        assert!(e.verify().is_err());
    }

    #[test]
    fn tampered_header_fails_verify() {
        let (id, master) = env_pair();
        let mut e = Envelope::seal(&id, "d1", &master, "n1", b"x", VersionVector::new(), 1, false);
        e.header.updated_ms = 999;
        assert!(e.verify().is_err());
    }

    #[test]
    fn wrong_master_cannot_open() {
        let (id, master) = env_pair();
        let e = Envelope::seal(&id, "d1", &master, "n1", b"x", VersionVector::new(), 1, false);
        e.verify().unwrap(); // signature still fine
        assert!(e.open(&SecretBytes::generate()).is_err());
    }

    #[test]
    fn bytes_roundtrip() {
        let (id, master) = env_pair();
        let e = Envelope::seal(&id, "d1", &master, "n1", b"x", VersionVector::new(), 1, false);
        let e2 = Envelope::from_bytes(&e.to_bytes()).unwrap();
        e2.verify().unwrap();
    }
}
