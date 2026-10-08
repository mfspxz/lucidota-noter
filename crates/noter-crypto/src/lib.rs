//! NOTER crypto core (noter-001).
//!
//! Audited primitives only. There is NO custom crypto in this crate.
//!
//! | Primitive           | Crate              | Role                                        |
//! |---------------------|--------------------|---------------------------------------------|
//! | XChaCha20-Poly1305  | chacha20poly1305   | AEAD for all payload encryption             |
//! | X25519              | x25519-dalek       | Key agreement (ECIES boxes, sync handshake) |
//! | Ed25519             | ed25519-dalek      | Device identity signatures                  |
//! | Argon2id            | argon2             | Passphrase -> master key KDF                |
//! | BLAKE3 (keyed)      | blake3             | Subkey derivation / fingerprints            |
//!
//! Secret material is held in [`SecretBytes`] which zeroizes on drop.

pub mod aead;
pub mod boxcrypt;
pub mod error;
pub mod identity;
pub mod kdf;
pub mod secret;

pub use aead::{decrypt, encrypt};
pub use boxcrypt::{open_from, seal_for};
pub use error::CryptoError;
pub use identity::{agree, pairwise_key, DeviceIdentity, PublicIdentity};
pub use kdf::{derive_master_key, derive_subkey, fingerprint, Salt};
pub use secret::SecretBytes;
