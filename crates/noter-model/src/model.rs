use crate::now_ms;
use serde::{Deserialize, Serialize};

/// A descriptor for a file attached to a note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentRef {
    pub att_id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
}

/// A single note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    /// Stable id (uuid v4 hex by default).
    pub id: String,
    pub title: String,
    /// Markdown body. May contain `[[wikilinks]]`.
    pub body_md: String,
    pub tags: Vec<String>,
    pub attachments: Vec<AttachmentRef>,
    pub created_ms: i64,
    pub updated_ms: i64,
    /// Edit counter, bumped on every local edit (sync tie-break input).
    pub version: u64,
}

impl Note {
    pub fn new(title: impl Into<String>, body_md: impl Into<String>) -> Self {
        let now = now_ms();
        Self {
            id: uuid::Uuid::new_v4().simple().to_string(),
            title: title.into(),
            body_md: body_md.into(),
            tags: Vec::new(),
            attachments: Vec::new(),
            created_ms: now,
            updated_ms: now,
            version: 1,
        }
    }

    /// Wikilink targets referenced by this note's body.
    pub fn links(&self) -> Vec<String> {
        crate::extract_links(&self.body_md)
    }
}
