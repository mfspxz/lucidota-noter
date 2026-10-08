//! NOTER encrypted local store (noter-002).
//!
//! Two layers, both with audited primitives:
//! 1. **Whole-file encryption**: SQLCipher (AES-256-CBC + HMAC) via
//!    `PRAGMA key`. Key = BLAKE3-subkey(master, b"noter/sqlcipher/v1").
//! 2. **Payload sealing**: every note/attachment payload is additionally
//!    XChaCha20-Poly1305-sealed with a separate subkey
//!    (b"noter/payload/v1") before it touches SQLite. Defense in depth:
//!    the file key alone does not decrypt payloads.
//!
//! Schema:
//! - `notes(note_id TEXT PK, updated_ms INTEGER, deleted INTEGER,
//!   vv BLOB, payload BLOB)` — `vv` = serialized version vector (sync),
//!   `payload` = sealed serialized note.
//! - `attachments(att_id TEXT PK, note_id TEXT, name TEXT, mime TEXT,
//!   size INTEGER, payload BLOB)` — payload = sealed bytes.

mod error;
mod store;

pub use error::StoreError;
pub use store::{AttachmentMeta, NoteRecord, Store};

/// Current wall-clock time in milliseconds (for updated_ms).
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
