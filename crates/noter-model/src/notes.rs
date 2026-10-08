use crate::{now_ms, AttachmentRef, Note};
use noter_store::{Store, StoreError};
use std::collections::{HashMap, HashSet};

/// High-level note operations over an encrypted [`Store`].
pub struct Notes<'a> {
    store: &'a Store,
}

impl<'a> Notes<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    fn serialize(note: &Note) -> Result<Vec<u8>, StoreError> {
        Ok(serde_json::to_vec(note)?)
    }

    fn deserialize(bytes: &[u8]) -> Result<Note, StoreError> {
        Ok(serde_json::from_slice(bytes)?)
    }

    /// Create a note and persist it.
    pub fn create(&self, mut note: Note) -> Result<Note, StoreError> {
        note.updated_ms = now_ms();
        let vv = version_vector(&note);
        self.store
            .put_note(&note.id, &Self::serialize(&note)?, &vv, false)?;
        Ok(note)
    }

    /// Load a note by id (decrypted).
    pub fn get(&self, id: &str) -> Result<Note, StoreError> {
        let rec = self.store.get_note(id)?;
        if rec.deleted {
            return Err(StoreError::NotFound(id.to_string()));
        }
        Self::deserialize(&self.store.open_payload(&rec.payload_sealed)?)
    }

    /// Replace a note's content; bumps version + timestamp.
    pub fn update(&self, mut note: Note) -> Result<Note, StoreError> {
        note.version += 1;
        note.updated_ms = now_ms();
        let vv = version_vector(&note);
        self.store
            .put_note(&note.id, &Self::serialize(&note)?, &vv, false)?;
        Ok(note)
    }

    /// Soft-delete (tombstone) a note.
    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        let mut note = self.get(id)?;
        note.version += 1;
        note.updated_ms = now_ms();
        let vv = version_vector(&note);
        self.store
            .put_note(id, &Self::serialize(&note)?, &vv, true)?;
        Ok(())
    }

    /// All live notes (decrypted).
    pub fn list(&self) -> Result<Vec<Note>, StoreError> {
        self.store
            .list_notes(false)?
            .iter()
            .map(|r| Self::deserialize(&self.store.open_payload(&r.payload_sealed)?))
            .collect()
    }

    /// Attach bytes to a note; returns the attachment descriptor.
    pub fn attach(
        &self,
        note_id: &str,
        name: &str,
        mime: &str,
        bytes: &[u8],
    ) -> Result<AttachmentRef, StoreError> {
        let mut note = self.get(note_id)?;
        let att_id = uuid::Uuid::new_v4().simple().to_string();
        self.store
            .put_attachment(&att_id, note_id, name, mime, bytes)?;
        let aref = AttachmentRef {
            att_id,
            name: name.to_string(),
            mime: mime.to_string(),
            size: bytes.len() as i64,
        };
        note.attachments.push(aref.clone());
        self.update(note)?;
        Ok(aref)
    }

    /// Read an attachment's bytes.
    pub fn read_attachment(&self, att_id: &str) -> Result<Vec<u8>, StoreError> {
        Ok(self.store.get_attachment(att_id)?.1)
    }

    /// Build the link graph over all live notes.
    pub fn graph(&self) -> Result<Graph, StoreError> {
        let notes = self.list()?;
        let mut edges: HashMap<String, Vec<String>> = HashMap::new();
        let live: HashSet<String> = notes.iter().map(|n| n.id.clone()).collect();
        for n in &notes {
            edges.insert(n.id.clone(), n.links());
        }
        // Backlinks: for each target, which live notes link to it.
        let mut backlinks: HashMap<String, Vec<String>> = HashMap::new();
        for n in &notes {
            for t in n.links() {
                backlinks.entry(t).or_default().push(n.id.clone());
            }
        }
        Ok(Graph {
            edges,
            backlinks,
            live,
        })
    }
}

/// Minimal version-vector encoding for the sync layer: `v<version>` for now.
/// (Full multi-device vectors live in noter-sync; the store carries them opaquely.)
fn version_vector(note: &Note) -> Vec<u8> {
    format!("v{}", note.version).into_bytes()
}

/// Directed graph of note links.
#[derive(Debug, Default)]
pub struct Graph {
    /// note_id -> outgoing wikilink targets (may include dangling targets).
    pub edges: HashMap<String, Vec<String>>,
    /// target_id -> live note ids linking to it.
    pub backlinks: HashMap<String, Vec<String>>,
    /// ids of live (non-deleted) notes.
    pub live: HashSet<String>,
}

impl Graph {
    /// Notes linking to `id` (dangling-target queries return empty).
    pub fn backlinks(&self, id: &str) -> &[String] {
        self.backlinks.get(id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Outgoing links of `id` restricted to live targets.
    pub fn live_links(&self, id: &str) -> Vec<&String> {
        self.edges
            .get(id)
            .map(|ts| ts.iter().filter(|t| self.live.contains(*t)).collect())
            .unwrap_or_default()
    }

    /// Dangling targets: linked but no live note with that id.
    pub fn dangling(&self) -> Vec<&String> {
        let mut out: Vec<&String> = self
            .backlinks
            .keys()
            .filter(|t| !self.live.contains(*t))
            .collect();
        out.sort();
        out.dedup();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noter_crypto::SecretBytes;
    use noter_store::Store;

    fn setup() -> (Store, ()) {
        (Store::open_memory(&SecretBytes::new([9u8; 32])).unwrap(), ())
    }

    #[test]
    fn create_get_roundtrip() {
        let (store, _) = setup();
        let notes = Notes::new(&store);
        let n = notes.create(Note::new("T", "hello **md**")).unwrap();
        let got = notes.get(&n.id).unwrap();
        assert_eq!(got.title, "T");
        assert_eq!(got.body_md, "hello **md**");
        assert_eq!(got.version, 1);
    }

    #[test]
    fn update_bumps_version() {
        let (store, _) = setup();
        let notes = Notes::new(&store);
        let n = notes.create(Note::new("T", "a")).unwrap();
        let mut n2 = n.clone();
        n2.body_md = "b".into();
        let n2 = notes.update(n2).unwrap();
        assert_eq!(n2.version, 2);
        assert_eq!(notes.get(&n.id).unwrap().body_md, "b");
    }

    #[test]
    fn delete_tombstones() {
        let (store, _) = setup();
        let notes = Notes::new(&store);
        let n = notes.create(Note::new("T", "a")).unwrap();
        notes.delete(&n.id).unwrap();
        assert!(notes.get(&n.id).is_err());
        assert!(notes.list().unwrap().is_empty());
    }

    #[test]
    fn attach_and_read() {
        let (store, _) = setup();
        let notes = Notes::new(&store);
        let n = notes.create(Note::new("T", "a")).unwrap();
        let aref = notes
            .attach(&n.id, "f.bin", "application/octet-stream", b"0123456789")
            .unwrap();
        assert_eq!(aref.size, 10);
        assert_eq!(notes.read_attachment(&aref.att_id).unwrap(), b"0123456789");
        let got = notes.get(&n.id).unwrap();
        assert_eq!(got.attachments.len(), 1);
    }

    #[test]
    fn wikilink_extraction() {
        assert_eq!(
            crate::extract_links("see [[abc]] and [[def|Label]] done"),
            vec!["abc".to_string(), "def".to_string()]
        );
        assert_eq!(crate::extract_links("no links here"), Vec::<String>::new());
        assert_eq!(crate::extract_links("empty [[]] skip"), Vec::<String>::new());
        assert_eq!(
            crate::extract_links("escaped \\[[abc]] skip"),
            Vec::<String>::new()
        );
        // Unterminated: ignored.
        assert_eq!(crate::extract_links("bad [[abc"), Vec::<String>::new());
    }

    #[test]
    fn graph_backlinks_and_dangling() {
        let (store, _) = setup();
        let notes = Notes::new(&store);
        let mut a = Note::new("A", "links [[B]] and [[ghost]]");
        a.id = "A".into();
        let mut b = Note::new("B", "links [[A]]");
        b.id = "B".into();
        notes.create(a).unwrap();
        notes.create(b).unwrap();
        let g = notes.graph().unwrap();
        assert_eq!(g.backlinks("B"), &["A".to_string()]);
        assert_eq!(g.backlinks("A"), &["B".to_string()]);
        assert_eq!(g.dangling(), vec![&"ghost".to_string()]);
        assert_eq!(g.live_links("A"), vec![&"B".to_string()]);
    }

    #[test]
    fn markdown_body_preserved_verbatim() {
        let (store, _) = setup();
        let notes = Notes::new(&store);
        let md = "# H\n\n- [x] task\n\n```rust\nlet x = 1;\n```\n\n| a | b |\n|---|---|\n| 1 | 2 |";
        let n = notes.create(Note::new("T", md)).unwrap();
        assert_eq!(notes.get(&n.id).unwrap().body_md, md);
    }
}
