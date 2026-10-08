use serde::{Deserialize, Serialize};

/// Note summary for list views (no body).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteSummary {
    pub id: String,
    pub title: String,
    pub tags: Vec<String>,
    pub updated_ms: i64,
    pub attachment_count: usize,
}

/// Full note for the editor view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteView {
    pub id: String,
    pub title: String,
    pub body_md: String,
    pub tags: Vec<String>,
    pub attachments: Vec<AttachmentView>,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub version: u64,
    pub links: Vec<String>,
    pub backlinks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttachmentView {
    pub att_id: String,
    pub name: String,
    pub mime: String,
    pub size: i64,
}

/// Search hit for the results pane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchHit {
    pub id: String,
    pub title: String,
    pub score: u32,
    pub snippet: String,
}

/// Sync report after a push/pull with a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncReport {
    pub sent: usize,
    pub received: usize,
    pub applied: usize,
    pub conflicts: usize,
    pub ignored: usize,
}

/// Unlock request from the login view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnlockRequest {
    pub db_path: String,
    pub passphrase: String,
    pub salt_hex: String,
}
