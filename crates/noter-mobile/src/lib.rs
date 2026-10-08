//! NOTER mobile field layer (noter-008).
//!
//! Field-usable means **offline-first**: the vault is local, every edit
//! applies instantly to the encrypted store, and a sealed op-queue records
//! what still needs to reach peers. When connectivity returns, the queue
//! drains through the normal sync path (mesh/airgap).
//!
//! - [`MobileApp`]: wraps [`noter_ui::App`] with connectivity state.
//! - [`Op`]: queued intent (quick-capture friendly). Persisted sealed in the
//!   store meta table, so a dead battery loses nothing.
//! - Quick capture: [`MobileApp::quick_note`] — timestamp-titled note from a
//!   single text blob, the core field interaction.

use noter_crypto::SecretBytes;
use noter_store::{Store, StoreError};
use noter_ui::{App, AppError, NoteView};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

const OPQUEUE_META_KEY: &str = "mobile_opqueue/v1";

#[derive(Debug, Error)]
pub enum MobileError {
    #[error("app: {0}")]
    App(#[from] AppError),
    #[error("store: {0}")]
    Store(#[from] StoreError),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// A field operation waiting for connectivity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    /// Created while offline (already applied locally).
    Created { note_id: String, at_ms: i64 },
    Updated { note_id: String, at_ms: i64 },
    Deleted { note_id: String, at_ms: i64 },
    /// Quick-capture payload (redundant safety copy).
    QuickCapture { text: String, at_ms: i64 },
}

pub struct MobileApp {
    app: App,
    online: bool,
    queue: Vec<Op>,
}

impl MobileApp {
    pub fn open(db_path: &Path, master: SecretBytes) -> Result<Self, MobileError> {
        let app = App::open_with_master(db_path, master)?;
        let queue = match app.store().meta_get(OPQUEUE_META_KEY)? {
            Some(bytes) => serde_json::from_slice(&bytes)?,
            None => Vec::new(),
        };
        Ok(Self {
            app,
            online: false,
            queue,
        })
    }

    pub fn app(&self) -> &App {
        &self.app
    }

    pub fn set_online(&mut self, online: bool) {
        self.online = online;
    }

    pub fn is_online(&self) -> bool {
        self.online
    }

    fn persist_queue(&self) -> Result<(), MobileError> {
        let bytes = serde_json::to_vec(&self.queue)?;
        self.app.store().meta_put(OPQUEUE_META_KEY, &bytes)?;
        Ok(())
    }

    fn enqueue(&mut self, op: Op) -> Result<(), MobileError> {
        self.queue.push(op);
        self.persist_queue()
    }

    /// Pending ops (for the sync UI / drain).
    pub fn pending(&self) -> &[Op] {
        &self.queue
    }

    /// Quick capture: one-tap note, timestamp title, applied locally now,
    /// queued for sync. Never blocks on network.
    pub fn quick_note(&mut self, text: &str) -> Result<NoteView, MobileError> {
        let title = format!("Field {}", field_timestamp());
        let view = noter_ui::cmd_create_note(&self.app, &title, text, vec!["field".into()])?;
        let now = noter_store::now_ms();
        self.enqueue(Op::QuickCapture {
            text: text.to_string(),
            at_ms: now,
        })?;
        self.enqueue(Op::Created {
            note_id: view.id.clone(),
            at_ms: now,
        })?;
        Ok(view)
    }

    /// Full create while respecting offline mode (local-first always).
    pub fn create_note(
        &mut self,
        title: &str,
        body_md: &str,
        tags: Vec<String>,
    ) -> Result<NoteView, MobileError> {
        let view = noter_ui::cmd_create_note(&self.app, title, body_md, tags)?;
        self.enqueue(Op::Created {
            note_id: view.id.clone(),
            at_ms: noter_store::now_ms(),
        })?;
        Ok(view)
    }

    pub fn update_note(
        &mut self,
        id: &str,
        title: &str,
        body_md: &str,
        tags: Vec<String>,
    ) -> Result<NoteView, MobileError> {
        let view = noter_ui::cmd_update_note(&self.app, id, title, body_md, tags)?;
        self.enqueue(Op::Updated {
            note_id: id.to_string(),
            at_ms: noter_store::now_ms(),
        })?;
        Ok(view)
    }

    pub fn delete_note(&mut self, id: &str) -> Result<(), MobileError> {
        noter_ui::cmd_delete_note(&self.app, id)?;
        self.enqueue(Op::Deleted {
            note_id: id.to_string(),
            at_ms: noter_store::now_ms(),
        })?;
        Ok(())
    }

    /// Drain the queue after a successful sync: returns the ops that were
    /// pending (caller syncs them via mesh/airgap first, then calls this).
    pub fn mark_synced(&mut self) -> Result<Vec<Op>, MobileError> {
        let ops = std::mem::take(&mut self.queue);
        self.persist_queue()?;
        Ok(ops)
    }

    /// Export airgap frames for everything changed since `since_ms`
    /// (field fallback when there is no mesh peer around).
    pub fn export_airgap(&self, since_ms: i64) -> Result<Vec<String>, MobileError> {
        Ok(noter_ui::cmd_export_airgap(&self.app, since_ms)?)
    }
}

fn field_timestamp() -> String {
    // UTC timestamp, human-readable, no external crates.
    let ms = noter_store::now_ms();
    let secs = ms / 1000;
    let (y, mo, d, h, mi, s) = civil_from_secs(secs);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}

/// Days -> civil date (Howard Hinnant's algorithm), UTC.
fn civil_from_secs(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let mut z = secs.div_euclid(86400) + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    y += if m <= 2 { 1 } else { 0 };
    let day_secs = secs.rem_euclid(86400);
    (
        y,
        m as u32,
        d as u32,
        (day_secs / 3600) as u32,
        ((day_secs % 3600) / 60) as u32,
        (day_secs % 60) as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "noter-mobile-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn open() -> (MobileApp, PathBuf) {
        let d = dir();
        let m = MobileApp::open(&d.join("v.db"), SecretBytes::new([0xABu8; 32])).unwrap();
        (m, d)
    }

    #[test]
    fn offline_capture_queues_ops() {
        let (mut m, _d) = open();
        assert!(!m.is_online());
        let v = m.quick_note("saw a heron at the slough").unwrap();
        assert!(v.title.starts_with("Field "));
        assert_eq!(v.body_md, "saw a heron at the slough");
        // Applied locally immediately...
        assert_eq!(m.app().store().list_notes(false).unwrap().len(), 1);
        // ...and queued for sync.
        assert_eq!(m.pending().len(), 2);
        assert!(matches!(m.pending()[0], Op::QuickCapture { .. }));
    }

    #[test]
    fn queue_survives_restart() {
        let d = dir();
        let db = d.join("v.db");
        {
            let mut m = MobileApp::open(&db, SecretBytes::new([0xABu8; 32])).unwrap();
            m.quick_note("note one").unwrap();
            m.create_note("T", "body", vec![]).unwrap();
            assert_eq!(m.pending().len(), 3);
        }
        // "Reboot" the phone: queue is sealed in the store.
        {
            let m = MobileApp::open(&db, SecretBytes::new([0xABu8; 32])).unwrap();
            assert_eq!(m.pending().len(), 3);
            assert_eq!(m.app().store().list_notes(false).unwrap().len(), 2);
        }
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn update_delete_queue_and_drain() {
        let (mut m, _d) = open();
        let v = m.create_note("T", "b", vec![]).unwrap();
        m.update_note(&v.id, "T2", "b2", vec![]).unwrap();
        m.delete_note(&v.id).unwrap();
        assert_eq!(m.pending().len(), 3);
        let drained = m.mark_synced().unwrap();
        assert_eq!(drained.len(), 3);
        assert!(m.pending().is_empty());
        // Drained state persists.
        let drained2 = m.mark_synced().unwrap();
        assert!(drained2.is_empty());
    }

    #[test]
    fn online_flag_and_airgap_fallback() {
        let (mut m, _d) = open();
        m.set_online(true);
        assert!(m.is_online());
        m.quick_note("x").unwrap();
        let frames = m.export_airgap(0).unwrap();
        assert!(!frames.is_empty());
        m.set_online(false);
        assert!(!m.is_online());
    }

    #[test]
    fn field_timestamp_sane() {
        let ts = field_timestamp();
        // "2026-10-07 04:12:33Z"
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert!(ts.starts_with("2026-"));
    }
}
