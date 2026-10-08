//! NOTER sync protocol (noter-004).
//!
//! Devices of one user share the master key (passphrase-derived). Sync moves
//! **signed envelopes** between devices over any transport (mesh, airgap,
//! relay — the relay learns nothing: payloads are sealed with a sync subkey).
//!
//! - [`VersionVector`]: per-note `device_id -> counter`, element-wise merge.
//! - [`Envelope`]: signed, sealed note state. Signature covers the header +
//!   sealed payload, so tampering is detected before decryption.
//! - Merge rule (conflict-free, deterministic):
//!   1. If incoming VV dominates local, apply incoming.
//!   2. If local dominates, keep local.
//!   3. If concurrent: deterministic winner by
//!      `(total_version desc, updated_ms desc, writer_id asc)`; the loser is
//!      preserved as a conflict copy (`<id>/conflict/<writer>/<version>`).
//!      No data is ever silently dropped.

mod engine;
mod envelope;
mod vector;

pub use engine::{MergeOutcome, SyncEngine, SyncError};
pub use envelope::{Envelope, EnvelopeHeader};
pub use vector::{VersionVector, VectorCmp};
