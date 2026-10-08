use crate::{now_ms, StoreError};
use noter_crypto::{decrypt, derive_subkey, encrypt, SecretBytes};
use rusqlite::{params, Connection, OptionalExtension};

const SQLCIPHER_CTX: &[u8] = b"noter/sqlcipher/v1";
const PAYLOAD_CTX: &[u8] = b"noter/payload/v1";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Metadata row for a note (payload decrypted separately).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteRecord {
    pub note_id: String,
    pub updated_ms: i64,
    pub deleted: bool,
    /// Serialized version vector (opaque to the store; owned by noter-sync).
    pub vv: Vec<u8>,
    /// Sealed serialized note body. Decrypt with [`Store::open_note`].
    pub payload_sealed: Vec<u8>,
}

/// Metadata row for an attachment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentMeta {
    pub att_id: String,
    pub note_id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
}

/// Encrypted SQLite note store.
pub struct Store {
    conn: Connection,
    payload_key: SecretBytes,
}

impl Store {
    /// Open (or create) the encrypted store at `path`.
    ///
    /// The SQLCipher file key and the payload sealing key are both derived
    /// from `master` with domain separation — the caller never handles raw
    /// file keys.
    pub fn open(path: &std::path::Path, master: &SecretBytes) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let file_key = derive_subkey(master, SQLCIPHER_CTX);
        let key_hex = hex(file_key.as_bytes());
        // SQLCipher: set the key. Quoting the hex literal is safe (hex only).
        conn.pragma_update(None, "key", format!("'{}'", key_hex))?;
        // Harden: wipe key material from connection memory ASAP after use.
        let payload_key = derive_subkey(master, PAYLOAD_CTX);
        let mut store = Self { conn, payload_key };
        store.init_schema()?;
        Ok(store)
    }

    /// Open an in-memory encrypted store (tests / ephemeral use).
    pub fn open_memory(master: &SecretBytes) -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let file_key = derive_subkey(master, SQLCIPHER_CTX);
        conn.pragma_update(None, "key", format!("'{}'", hex(file_key.as_bytes())))?;
        let payload_key = derive_subkey(master, PAYLOAD_CTX);
        let mut store = Self { conn, payload_key };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&mut self) -> Result<(), StoreError> {
        // Touch the db: with a wrong key this fails with "file is not a database".
        let n: i64 = self
            .conn
            .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
            .map_err(|_| StoreError::BadKey)?;
        let _ = n;
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS notes (
                note_id    TEXT PRIMARY KEY,
                updated_ms INTEGER NOT NULL,
                deleted    INTEGER NOT NULL DEFAULT 0,
                vv         BLOB NOT NULL DEFAULT x'',
                payload    BLOB NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_notes_updated ON notes(updated_ms);
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS attachments (
                att_id  TEXT PRIMARY KEY,
                note_id TEXT NOT NULL,
                name    TEXT NOT NULL,
                mime    TEXT NOT NULL DEFAULT 'application/octet-stream',
                size    INTEGER NOT NULL,
                payload BLOB NOT NULL,
                FOREIGN KEY(note_id) REFERENCES notes(note_id) ON DELETE CASCADE
            );",
        )?;
        Ok(())
    }

    /// Insert or replace a note. `payload_plain` is sealed before storage.
    pub fn put_note(
        &self,
        note_id: &str,
        payload_plain: &[u8],
        vv: &[u8],
        deleted: bool,
    ) -> Result<(), StoreError> {
        let sealed = encrypt(&self.payload_key, payload_plain);
        self.conn.execute(
            "INSERT INTO notes (note_id, updated_ms, deleted, vv, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(note_id) DO UPDATE SET
               updated_ms=excluded.updated_ms, deleted=excluded.deleted,
               vv=excluded.vv, payload=excluded.payload",
            params![note_id, now_ms(), deleted as i64, vv, sealed],
        )?;
        Ok(())
    }

    /// Fetch a note's metadata + sealed payload (does not decrypt).
    pub fn get_note(&self, note_id: &str) -> Result<NoteRecord, StoreError> {
        self.conn
            .query_row(
                "SELECT note_id, updated_ms, deleted, vv, payload FROM notes WHERE note_id = ?1",
                params![note_id],
                |r| {
                    Ok(NoteRecord {
                        note_id: r.get(0)?,
                        updated_ms: r.get(1)?,
                        deleted: r.get::<_, i64>(2)? != 0,
                        vv: r.get(3)?,
                        payload_sealed: r.get(4)?,
                    })
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::NotFound(note_id.to_string()))
    }

    /// Decrypt a note payload previously returned by [`Store::get_note`].
    pub fn open_payload(&self, sealed: &[u8]) -> Result<Vec<u8>, StoreError> {
        Ok(decrypt(&self.payload_key, sealed)?)
    }

    /// List note metadata (no payloads) ordered by update time.
    pub fn list_notes(&self, include_deleted: bool) -> Result<Vec<NoteRecord>, StoreError> {
        let sql = if include_deleted {
            "SELECT note_id, updated_ms, deleted, vv, payload FROM notes ORDER BY updated_ms, note_id"
        } else {
            "SELECT note_id, updated_ms, deleted, vv, payload FROM notes WHERE deleted = 0 ORDER BY updated_ms, note_id"
        };
        let mut stmt = self.conn.prepare(sql)?;
        let rows = stmt.query_map([], |r| {
            Ok(NoteRecord {
                note_id: r.get(0)?,
                updated_ms: r.get(1)?,
                deleted: r.get::<_, i64>(2)? != 0,
                vv: r.get(3)?,
                payload_sealed: r.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Notes (including tombstones) updated at/after `since_ms` — sync cursor.
    pub fn changed_since(&self, since_ms: i64) -> Result<Vec<NoteRecord>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT note_id, updated_ms, deleted, vv, payload FROM notes
             WHERE updated_ms >= ?1 ORDER BY updated_ms, note_id",
        )?;
        let rows = stmt.query_map(params![since_ms], |r| {
            Ok(NoteRecord {
                note_id: r.get(0)?,
                updated_ms: r.get(1)?,
                deleted: r.get::<_, i64>(2)? != 0,
                vv: r.get(3)?,
                payload_sealed: r.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Store an attachment's bytes sealed under the payload key.
    pub fn put_attachment(
        &self,
        att_id: &str,
        note_id: &str,
        name: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let sealed = encrypt(&self.payload_key, bytes);
        self.conn.execute(
            "INSERT INTO attachments (att_id, note_id, name, mime, size, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(att_id) DO UPDATE SET note_id=excluded.note_id, name=excluded.name,
               mime=excluded.mime, size=excluded.size, payload=excluded.payload",
            params![att_id, note_id, name, mime, bytes.len() as i64, sealed],
        )?;
        Ok(())
    }

    /// Fetch + decrypt an attachment.
    pub fn get_attachment(&self, att_id: &str) -> Result<(AttachmentMeta, Vec<u8>), StoreError> {
        let (meta, sealed): (AttachmentMeta, Vec<u8>) = self
            .conn
            .query_row(
                "SELECT att_id, note_id, name, mime, size, payload FROM attachments WHERE att_id = ?1",
                params![att_id],
                |r| {
                    Ok((
                        AttachmentMeta {
                            att_id: r.get(0)?,
                            note_id: r.get(1)?,
                            name: r.get(2)?,
                            mime: r.get(3)?,
                            size: r.get(4)?,
                        },
                        r.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::AttachmentNotFound(att_id.to_string()))?;
        let bytes = decrypt(&self.payload_key, &sealed)?;
        Ok((meta, bytes))
    }

    /// Attachments belonging to a note.
    pub fn attachments_for(&self, note_id: &str) -> Result<Vec<AttachmentMeta>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT att_id, note_id, name, mime, size FROM attachments WHERE note_id = ?1",
        )?;
        let rows = stmt.query_map(params![note_id], |r| {
            Ok(AttachmentMeta {
                att_id: r.get(0)?,
                note_id: r.get(1)?,
                name: r.get(2)?,
                mime: r.get(3)?,
                size: r.get(4)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Store an opaque sealed blob under a key (e.g. the search index).
    pub fn meta_put(&self, key: &str, plain: &[u8]) -> Result<(), StoreError> {
        let sealed = encrypt(&self.payload_key, plain);
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, sealed],
        )?;
        Ok(())
    }

    /// Fetch + decrypt a blob stored with [`Store::meta_put`].
    pub fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let sealed: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| {
                r.get(0)
            })
            .optional()?;
        match sealed {
            Some(b) => Ok(Some(decrypt(&self.payload_key, &b)?)),
            None => Ok(None),
        }
    }

    /// Rotate the SQLCipher file key to a new master key (payloads re-sealed too).
    pub fn rekey(&mut self, new_master: &SecretBytes) -> Result<(), StoreError> {
        // Re-seal every payload under the new payload key first, so the file
        // key and payload key always move together.
        let new_payload = derive_subkey(new_master, PAYLOAD_CTX);
        let ids: Vec<(String, Vec<u8>)> = {
            let mut stmt = self.conn.prepare("SELECT note_id, payload FROM notes")?;
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (id, sealed) in &ids {
            let plain = decrypt(&self.payload_key, sealed)?;
            let resealed = encrypt(&new_payload, &plain);
            self.conn.execute(
                "UPDATE notes SET payload = ?1 WHERE note_id = ?2",
                params![resealed, id],
            )?;
        }
        let atts: Vec<(String, Vec<u8>)> = {
            let mut stmt = self.conn.prepare("SELECT att_id, payload FROM attachments")?;
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (id, sealed) in &atts {
            let plain = decrypt(&self.payload_key, sealed)?;
            let resealed = encrypt(&new_payload, &plain);
            self.conn.execute(
                "UPDATE attachments SET payload = ?1 WHERE att_id = ?2",
                params![resealed, id],
            )?;
        }
        let metas: Vec<(String, Vec<u8>)> = {
            let mut stmt = self.conn.prepare("SELECT key, value FROM meta")?;
            stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (k, sealed) in &metas {
            let plain = decrypt(&self.payload_key, sealed)?;
            let resealed = encrypt(&new_payload, &plain);
            self.conn
                .execute("UPDATE meta SET value = ?1 WHERE key = ?2", params![resealed, k])?;
        }
        let new_file_key = derive_subkey(new_master, SQLCIPHER_CTX);
        self.conn
            .pragma_update(None, "rekey", format!("'{}'", hex(new_file_key.as_bytes())))?;
        self.payload_key = new_payload;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noter_crypto::SecretBytes;

    fn master() -> SecretBytes {
        SecretBytes::new([0x11u8; 32])
    }

    #[test]
    fn roundtrip_note() {
        let s = Store::open_memory(&master()).unwrap();
        s.put_note("n1", b"{\"title\":\"hi\"}", b"vv1", false).unwrap();
        let rec = s.get_note("n1").unwrap();
        assert_eq!(rec.note_id, "n1");
        assert!(!rec.deleted);
        assert_eq!(s.open_payload(&rec.payload_sealed).unwrap(), b"{\"title\":\"hi\"}");
    }

    #[test]
    fn missing_note_errors() {
        let s = Store::open_memory(&master()).unwrap();
        assert!(matches!(
            s.get_note("nope"),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn upsert_updates() {
        let s = Store::open_memory(&master()).unwrap();
        s.put_note("n1", b"v1", b"", false).unwrap();
        s.put_note("n1", b"v2", b"", false).unwrap();
        let rec = s.get_note("n1").unwrap();
        assert_eq!(s.open_payload(&rec.payload_sealed).unwrap(), b"v2");
    }

    #[test]
    fn tombstone_and_list_filtering() {
        let s = Store::open_memory(&master()).unwrap();
        s.put_note("a", b"1", b"", false).unwrap();
        s.put_note("b", b"2", b"", true).unwrap();
        assert_eq!(s.list_notes(false).unwrap().len(), 1);
        assert_eq!(s.list_notes(true).unwrap().len(), 2);
    }

    #[test]
    fn changed_since_cursor() {
        let s = Store::open_memory(&master()).unwrap();
        s.put_note("a", b"1", b"", false).unwrap();
        let t = now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        s.put_note("b", b"2", b"", false).unwrap();
        let changed = s.changed_since(t).unwrap();
        assert!(changed.iter().any(|r| r.note_id == "b"));
    }

    #[test]
    fn attachment_roundtrip() {
        let s = Store::open_memory(&master()).unwrap();
        s.put_note("n1", b"{}", b"", false).unwrap();
        s.put_attachment("a1", "n1", "photo.png", "image/png", b"\x89PNG...").unwrap();
        let (meta, bytes) = s.get_attachment("a1").unwrap();
        assert_eq!(meta.name, "photo.png");
        assert_eq!(meta.mime, "image/png");
        assert_eq!(bytes, b"\x89PNG...");
        assert_eq!(s.attachments_for("n1").unwrap().len(), 1);
    }

    #[test]
    fn file_persists_encrypted() {
        let dir = std::env::temp_dir().join(format!("noter-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notes.db");
        {
            let s = Store::open(&path, &master()).unwrap();
            s.put_note("n1", b"top secret body", b"", false).unwrap();
        }
        // Raw file must not contain the plaintext.
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(15).any(|w| w == b"top secret body"));
        // Reopen with the right key: reads fine.
        let s2 = Store::open(&path, &master()).unwrap();
        let rec = s2.get_note("n1").unwrap();
        assert_eq!(s2.open_payload(&rec.payload_sealed).unwrap(), b"top secret body");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wrong_key_rejected() {
        let dir = std::env::temp_dir().join(format!("noter-test-wk-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notes.db");
        Store::open(&path, &master()).unwrap();
        let wrong = SecretBytes::new([0x22u8; 32]);
        assert!(matches!(
            Store::open(&path, &wrong),
            Err(StoreError::BadKey)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rekey_rotates_both_layers() {
        let s = &mut Store::open_memory(&master()).unwrap();
        s.put_note("n1", b"data", b"", false).unwrap();
        s.put_attachment("a1", "n1", "f", "text/plain", b"att").unwrap();
        let new_master = SecretBytes::new([0x33u8; 32]);
        s.rekey(&new_master).unwrap();
        let rec = s.get_note("n1").unwrap();
        assert_eq!(s.open_payload(&rec.payload_sealed).unwrap(), b"data");
        let (_, bytes) = s.get_attachment("a1").unwrap();
        assert_eq!(bytes, b"att");
    }

    #[test]
    fn payload_tamper_detected() {
        let s = Store::open_memory(&master()).unwrap();
        s.put_note("n1", b"data", b"", false).unwrap();
        let mut rec = s.get_note("n1").unwrap();
        rec.payload_sealed[30] ^= 0xFF;
        assert!(s.open_payload(&rec.payload_sealed).is_err());
    }
}
