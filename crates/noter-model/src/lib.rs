//! NOTER note model (noter-003).
//!
//! - [`Note`]: markdown body, tags, attachment descriptors, timestamps.
//! - Graph links: `[[note-id]]` wikilinks extracted from the markdown body;
//!   [`Notes::backlinks`] computes the reverse index. Links are by note id;
//!   dangling links are allowed (target may not exist yet).
//! - Persistence: notes serialize to JSON and are stored via [`noter_store`]
//!   with a monotonically bumped `version` per edit.

mod model;
mod notes;

pub use model::{AttachmentRef, Note};
pub use notes::{Graph, Notes};
pub use noter_store::{now_ms, StoreError};

/// Extract `[[target]]` wikilink targets from markdown text.
///
/// Rules: `[[id]]` or `[[id|label]]`; nested brackets not supported;
/// escaped `\[[` is ignored. Targets are trimmed; empty targets dropped.
pub fn extract_links(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = markdown.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() && &bytes[i + 1..i + 3] == b"[[" {
            i += 3;
            continue;
        }
        if &bytes[i..i + 2] == b"[[" && let Some(end) = markdown[i + 2..].find("]]") {
            let inner = &markdown[i + 2..i + 2 + end];
            let target = inner.split('|').next().unwrap_or("").trim();
            if !target.is_empty() {
                out.push(target.to_string());
            }
            i += 2 + end + 2;
            continue;
        }
        i += 1;
    }
    out
}
