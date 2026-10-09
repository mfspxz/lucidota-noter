//! NOTER mesh transport (noter-005).
//!
//! Local peer-to-peer sync with **no central server**:
//!
//! - [`MeshNode`]: binds a TCP port, answers discovery beacons, accepts
//!   encrypted sessions.
//! - [`Session`]: an authenticated-encrypted channel to one peer.
//!   Handshake: ephemeral X25519 exchange (both sides), session key =
//!   BLAKE3(DH(eph_i, eph_r), b"noter/mesh/v1" || eph_i || eph_r).
//!   Then each side sends its [`PublicIdentity`] plus an Ed25519 signature
//!   over the handshake transcript, binding its static identity to this
//!   session. Frames are length-prefixed XChaCha20-Poly1305 blobs.
//! - Discovery: UDP broadcast beacons (`NOTER1` magic) on the LAN;
//!   [`MeshNode::discover`] collects responders for a bounded window.
//!
//! Trust model (honest): the mesh gives confidentiality + session binding.
//! End-to-end authenticity of *notes* comes from the sync layer's envelope
//! signatures + peer registry — a mesh MITM at handshake time learns
//! nothing (envelopes are sealed with the sync subkey) and cannot forge
//! note writes.

mod discovery;
mod error;
mod session;

pub use discovery::{beacon, discover, Beacon};
pub use error::MeshError;
pub use session::{MeshNode, Session};

pub use noter_crypto::PublicIdentity;
