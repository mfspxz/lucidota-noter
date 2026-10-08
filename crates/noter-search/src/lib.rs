//! NOTER local search (noter-009).
//!
//! Full-text search over decrypted note content, with the index itself
//! encrypted at rest:
//!
//! - Tokenize `title + body` into lowercase alphanumeric tokens (len >= 2).
//! - Inverted index `term -> {note_id: term_frequency}` kept in memory.
//! - Persisted as a **single XChaCha20-Poly1305-sealed blob** in the store's
//!   `meta` table (SQLCipher file encryption underneath). No per-term rows,
//!   so the database reveals no term list and no posting frequencies — the
//!   price is O(index) decryption per query, fine for a notes app.
//! - Query: AND over query tokens, ranked by summed term frequency.
//!
//! The caller feeds **decrypted** text in; plaintext never touches SQLite.

use noter_crypto::SecretBytes;
use noter_store::{Store, StoreError};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;

const INDEX_META_KEY: &str = "search_index/v1";

#[derive(Debug, Error)]
pub enum SearchError {
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// term -> (note_id -> frequency)
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
struct Index {
    postings: HashMap<String, HashMap<String, u32>>,
    /// note_id -> tokens it contributed (for incremental removal).
    doc_terms: HashMap<String, HashSet<String>>,
}

/// Tokenize: lowercase alphanumeric runs, length >= 2.
pub fn tokenize(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            cur.extend(ch.to_lowercase());
        } else if !cur.is_empty() {
            if cur.chars().count() >= 2 {
                tokens.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.chars().count() >= 2 {
        tokens.push(cur);
    }
    tokens
}

pub struct SearchIndex<'a> {
    store: &'a Store,
    index: Index,
    dirty: bool,
}

impl<'a> SearchIndex<'a> {
    /// Load the sealed index from the store (empty if none yet).
    pub fn open(store: &'a Store, _master: &SecretBytes) -> Result<Self, SearchError> {
        let index = match store.meta_get(INDEX_META_KEY)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Index::default(),
        };
        Ok(Self {
            store,
            index,
            dirty: false,
        })
    }

    /// Index (or re-index) one note's decrypted text.
    pub fn index_note(&mut self, note_id: &str, title: &str, body_md: &str) {
        self.remove_note(note_id);
        let mut freq: HashMap<String, u32> = HashMap::new();
        for t in tokenize(&format!("{} {}", title, body_md)) {
            *freq.entry(t).or_insert(0) += 1;
        }
        let mut terms = HashSet::new();
        for (term, count) in freq {
            self.index
                .postings
                .entry(term.clone())
                .or_default()
                .insert(note_id.to_string(), count);
            terms.insert(term);
        }
        self.index.doc_terms.insert(note_id.to_string(), terms);
        self.dirty = true;
    }

    /// Drop a note from the index.
    pub fn remove_note(&mut self, note_id: &str) {
        if let Some(terms) = self.index.doc_terms.remove(note_id) {
            for t in terms {
                if let Some(posting) = self.index.postings.get_mut(&t) {
                    posting.remove(note_id);
                    if posting.is_empty() {
                        self.index.postings.remove(&t);
                    }
                }
            }
            self.dirty = true;
        }
    }

    /// Persist the sealed index if changed.
    pub fn flush(&mut self) -> Result<(), SearchError> {
        if self.dirty {
            let bytes = serde_json::to_vec(&self.index)?;
            self.store.meta_put(INDEX_META_KEY, &bytes)?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Number of distinct terms (for diagnostics).
    pub fn term_count(&self) -> usize {
        self.index.postings.len()
    }

    /// AND search: notes containing ALL query tokens, ranked by total tf desc.
    pub fn search(&self, query: &str) -> Vec<(String, u32)> {
        let tokens = tokenize(query);
        if tokens.is_empty() {
            return Vec::new();
        }
        let mut sets: Vec<&HashMap<String, u32>> = Vec::new();
        for t in &tokens {
            match self.index.postings.get(t) {
                Some(p) => sets.push(p),
                None => return Vec::new(),
            }
        }
        sets.sort_by_key(|s| s.len());
        let mut scores: HashMap<&String, u32> = HashMap::new();
        for (i, posting) in sets.iter().enumerate() {
            if i == 0 {
                for (doc, tf) in posting.iter() {
                    scores.insert(doc, *tf);
                }
            } else {
                scores.retain(|doc, _| posting.contains_key(*doc));
                for (doc, score) in scores.iter_mut() {
                    *score += posting.get(*doc).copied().unwrap_or(0);
                }
            }
        }
        let mut out: Vec<(String, u32)> = scores
            .into_iter()
            .map(|(d, s)| (d.clone(), s))
            .collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noter_crypto::SecretBytes;

    fn master() -> SecretBytes {
        SecretBytes::new([0x77u8; 32])
    }

    fn idx<'a>(store: &'a Store) -> SearchIndex<'a> {
        SearchIndex::open(store, &master()).unwrap()
    }

    #[test]
    fn tokenize_basics() {
        assert_eq!(tokenize("Hello, World!"), vec!["hello", "world"]);
        assert_eq!(tokenize("a I x"), Vec::<String>::new());
        assert_eq!(tokenize("don't"), vec!["don", "t"].into_iter().filter(|s| s.len()>=2).collect::<Vec<_>>());
        assert_eq!(tokenize("Café au lait"), vec!["café", "au", "lait"]);
    }

    #[test]
    fn search_finds_and_ranks() {
        let store = Store::open_memory(&master()).unwrap();
        let mut ix = idx(&store);
        ix.index_note("n1", "Grocery list", "buy milk and eggs");
        ix.index_note("n2", "Milk review", "milk milk milk is great");
        ix.index_note("n3", "Unrelated", "nothing to see here");
        ix.flush().unwrap();

        let r = ix.search("milk");
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].0, "n2"); // higher tf first
        assert_eq!(r[1].0, "n1");

        // AND semantics.
        let r = ix.search("milk eggs");
        assert_eq!(r, vec![("n1".to_string(), 2)]);

        // No match.
        assert!(ix.search("zebra").is_empty());
        assert!(ix.search("").is_empty());
        assert!(ix.search("a").is_empty());
    }

    #[test]
    fn reindex_replaces() {
        let store = Store::open_memory(&master()).unwrap();
        let mut ix = idx(&store);
        ix.index_note("n1", "T", "apple banana");
        ix.flush().unwrap();
        assert_eq!(ix.search("apple").len(), 1);
        ix.index_note("n1", "T", "cherry");
        ix.flush().unwrap();
        assert!(ix.search("apple").is_empty());
        assert_eq!(ix.search("cherry").len(), 1);
    }

    #[test]
    fn remove_note_drops_terms() {
        let store = Store::open_memory(&master()).unwrap();
        let mut ix = idx(&store);
        ix.index_note("n1", "T", "unique-term-xyz");
        ix.flush().unwrap();
        assert_eq!(ix.search("unique").len(), 1);
        ix.remove_note("n1");
        ix.flush().unwrap();
        assert!(ix.search("unique").is_empty());
        assert_eq!(ix.term_count(), 0);
    }

    #[test]
    fn index_persists_sealed() {
        let dir = std::env::temp_dir().join(format!("search-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.db");
        {
            let store = Store::open(&path, &master()).unwrap();
            let mut ix = idx(&store);
            ix.index_note("n1", "Secrets", "the password is hunter2 hunter2");
            ix.flush().unwrap();
        }
        // Raw file reveals no terms and no content.
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(8).any(|w| w == b"hunter2"));
        assert!(!raw.windows(7).any(|w| w == b"secrets"));
        // Reopen: index intact.
        {
            let store = Store::open(&path, &master()).unwrap();
            let ix = idx(&store);
            assert_eq!(ix.search("hunter2").len(), 1);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn case_insensitive() {
        let store = Store::open_memory(&master()).unwrap();
        let mut ix = idx(&store);
        ix.index_note("n1", "UPPER", "MiXeD Case Words");
        ix.flush().unwrap();
        assert_eq!(ix.search("upper mixed words").len(), 1);
    }
}
