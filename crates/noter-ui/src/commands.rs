//! UI command implementations. Each `cmd_*` is what a Tauri command
//! forwards to (see `tauri-app/src/main.rs`).

use crate::{App, AppError, AttachmentView, NoteSummary, NoteView, SearchHit, SyncReport};
use noter_crypto::PublicIdentity;
use noter_mesh::Session;
use noter_model::{AttachmentRef, Note};
use noter_search::SearchIndex;
use noter_share::SharedAttachment;
use noter_sync::MergeOutcome;

fn to_view(app: &App, note: &Note) -> Result<NoteView, AppError> {
    let graph = app.notes().graph().map_err(AppError::Store)?;
    Ok(NoteView {
        id: note.id.clone(),
        title: note.title.clone(),
        body_md: note.body_md.clone(),
        tags: note.tags.clone(),
        attachments: note
            .attachments
            .iter()
            .map(|a| AttachmentView {
                att_id: a.att_id.clone(),
                name: a.name.clone(),
                mime: a.mime.clone(),
                size: a.size,
            })
            .collect(),
        created_ms: note.created_ms,
        updated_ms: note.updated_ms,
        version: note.version,
        links: note.links(),
        backlinks: graph.backlinks(&note.id).to_vec(),
    })
}

fn reindex(app: &App, note: &Note) -> Result<(), AppError> {
    let mut ix = SearchIndex::open(app.store(), app.master())?;
    ix.index_note(&note.id, &note.title, &note.body_md);
    ix.flush()?;
    Ok(())
}

fn unindex(app: &App, note_id: &str) -> Result<(), AppError> {
    let mut ix = SearchIndex::open(app.store(), app.master())?;
    ix.remove_note(note_id);
    ix.flush()?;
    Ok(())
}

fn note_json(note: &Note) -> Result<Vec<u8>, AppError> {
    Ok(serde_json::to_vec(note)?)
}

/// Create a note (command: `create_note`).
pub fn cmd_create_note(
    app: &App,
    title: &str,
    body_md: &str,
    tags: Vec<String>,
) -> Result<NoteView, AppError> {
    let mut note = Note::new(title, body_md);
    note.tags = tags;
    note.updated_ms = noter_store::now_ms();
    app.engine()
        .put_local(&note.id, &note_json(&note)?, false)?;
    reindex(app, &note)?;
    to_view(app, &note)
}

/// Load a note for the editor (command: `get_note`).
pub fn cmd_get_note(app: &App, id: &str) -> Result<NoteView, AppError> {
    let note = app.notes().get(id).map_err(AppError::Store)?;
    to_view(app, &note)
}

/// Save editor contents (command: `update_note`).
pub fn cmd_update_note(
    app: &App,
    id: &str,
    title: &str,
    body_md: &str,
    tags: Vec<String>,
) -> Result<NoteView, AppError> {
    let mut note = app.notes().get(id).map_err(AppError::Store)?;
    note.title = title.to_string();
    note.body_md = body_md.to_string();
    note.tags = tags;
    note.version += 1;
    note.updated_ms = noter_store::now_ms();
    app.engine()
        .put_local(&note.id, &note_json(&note)?, false)?;
    reindex(app, &note)?;
    to_view(app, &note)
}

/// Soft-delete (command: `delete_note`).
pub fn cmd_delete_note(app: &App, id: &str) -> Result<(), AppError> {
    let mut note = app.notes().get(id).map_err(AppError::Store)?;
    note.version += 1;
    note.updated_ms = noter_store::now_ms();
    app.engine().put_local(&note.id, &note_json(&note)?, true)?;
    unindex(app, id)?;
    Ok(())
}

/// Note list for the sidebar (command: `list_notes`).
pub fn cmd_list_notes(app: &App) -> Result<Vec<NoteSummary>, AppError> {
    let mut out = Vec::new();
    for n in app.notes().list().map_err(AppError::Store)? {
        let rec = app.store().get_note(&n.id).map_err(AppError::Store)?;
        out.push(NoteSummary {
            id: n.id,
            title: n.title,
            tags: n.tags,
            updated_ms: rec.updated_ms,
            attachment_count: n.attachments.len(),
        });
    }
    Ok(out)
}

/// Full-text search (command: `search`).
pub fn cmd_search(app: &App, query: &str) -> Result<Vec<SearchHit>, AppError> {
    let ix = SearchIndex::open(app.store(), app.master())?;
    let mut hits = Vec::new();
    for (id, score) in ix.search(query).into_iter().take(50) {
        if let Ok(note) = app.notes().get(&id) {
            let snippet: String = note.body_md.chars().take(160).collect();
            hits.push(SearchHit {
                id,
                title: note.title,
                score,
                snippet,
            });
        }
    }
    Ok(hits)
}

/// Attach a file to a note (command: `attach_file`).
pub fn cmd_attach_file(
    app: &App,
    note_id: &str,
    name: &str,
    mime: &str,
    bytes: &[u8],
) -> Result<AttachmentRef, AppError> {
    let att_id = uuid::Uuid::new_v4().simple().to_string();
    app.store()
        .put_attachment(&att_id, note_id, name, mime, bytes)
        .map_err(AppError::Store)?;
    let mut note = app.notes().get(note_id).map_err(AppError::Store)?;
    let aref = AttachmentRef {
        att_id,
        name: name.to_string(),
        mime: mime.to_string(),
        size: bytes.len() as i64,
    };
    note.attachments.push(aref.clone());
    note.version += 1;
    note.updated_ms = noter_store::now_ms();
    app.engine()
        .put_local(&note.id, &note_json(&note)?, false)?;
    Ok(aref)
}

/// Read an attachment's bytes (command: `read_attachment`).
pub fn cmd_read_attachment(app: &App, att_id: &str) -> Result<Vec<u8>, AppError> {
    Ok(app
        .store()
        .get_attachment(att_id)
        .map_err(AppError::Store)?
        .1)
}

/// Export airgap frames (command: `export_airgap`).
pub fn cmd_export_airgap(app: &App, since_ms: i64) -> Result<Vec<String>, AppError> {
    let sealed = noter_airgap::export_bundle(&app.engine(), app.master(), since_ms)?;
    Ok(noter_airgap::to_frames(&sealed))
}

/// Import airgap frames (command: `import_airgap`).
pub fn cmd_import_airgap(app: &App, frames: &[String]) -> Result<SyncReport, AppError> {
    let outcomes = noter_airgap::import_frames(frames, app.master(), &app.engine())?;
    // Reindex everything touched.
    let mut ix = SearchIndex::open(app.store(), app.master())?;
    for o in &outcomes {
        let id = match o {
            MergeOutcome::Applied { note_id } => note_id,
            MergeOutcome::Conflict { note_id, .. } => note_id,
            MergeOutcome::KeptLocal { note_id } => note_id,
            MergeOutcome::Ignored { note_id, .. } => note_id,
        };
        if let Ok(note) = app.notes().get(id) {
            ix.index_note(&note.id, &note.title, &note.body_md);
        }
    }
    ix.flush()?;
    Ok(report(&outcomes))
}

/// Share a note with another user (command: `share_note`). Returns the
/// transport bytes of the share package.
pub fn cmd_share_note(
    app: &App,
    note_id: &str,
    recipient: &PublicIdentity,
) -> Result<Vec<u8>, AppError> {
    let note = app.notes().get(note_id).map_err(AppError::Store)?;
    let mut atts = Vec::new();
    for a in &note.attachments {
        let bytes = app
            .store()
            .get_attachment(&a.att_id)
            .map_err(AppError::Store)?
            .1;
        atts.push(SharedAttachment {
            name: a.name.clone(),
            mime: a.mime.clone(),
            bytes,
        });
    }
    // Build a sender identity handle from our own seed.
    let seed = app_identity_seed(app);
    let sender = noter_crypto::DeviceIdentity::from_seed_bytes(&seed)?;
    let pkg = noter_share::share_note(&note, &atts, &sender, recipient);
    Ok(pkg.to_bytes())
}

/// Receive a shared note (command: `receive_share`). Imports it as a new note.
pub fn cmd_receive_share(
    app: &App,
    pkg_bytes: &[u8],
    sender: &PublicIdentity,
) -> Result<NoteView, AppError> {
    let pkg = noter_share::SharePackage::from_bytes(pkg_bytes)?;
    let seed = app_identity_seed(app);
    let recipient = noter_crypto::DeviceIdentity::from_seed_bytes(&seed)?;
    let (mut note, atts) = noter_share::receive_package(&pkg, &recipient, sender)?;
    // Fresh id so it merges cleanly into our vault; store before attaching.
    note.id = uuid::Uuid::new_v4().simple().to_string();
    note.attachments.clear();
    note.version = 1;
    note.updated_ms = noter_store::now_ms();
    app.engine()
        .put_local(&note.id, &note_json(&note)?, false)?;
    for a in atts {
        cmd_attach_file(app, &note.id, &a.name, &a.mime, &a.bytes)?;
    }
    let note = app.notes().get(&note.id).map_err(AppError::Store)?;
    reindex(app, &note)?;
    to_view(app, &note)
}

fn app_identity_seed(app: &App) -> [u8; 64] {
    let id_sub = noter_crypto::derive_subkey(app.master(), b"noter/device-id/v1");
    let h = blake3::hash(id_sub.as_bytes());
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(&id_sub.as_bytes()[..32]);
    seed[32..].copy_from_slice(&h.as_bytes()[..32]);
    seed
}

/// Push/pull sync with a peer over an established mesh session
/// (command: `sync_with_peer`). `send_first` breaks the symmetry:
/// one side sends its envelopes, then receives; the other does the reverse.
pub fn cmd_sync_with_peer(
    app: &App,
    session: &mut Session,
    peer_id: &str,
    peer_pub: PublicIdentity,
    send_first: bool,
) -> Result<SyncReport, AppError> {
    let mut engine = app.engine();
    engine.add_peer(peer_id, peer_pub);

    let send_all = |session: &mut Session, engine: &SyncEngine| -> Result<usize, AppError> {
        let envs = engine.export(0)?;
        let n = envs.len();
        session.send(&(n as u32).to_be_bytes())?;
        for e in &envs {
            session.send(&e.to_bytes())?;
        }
        Ok(n)
    };
    let recv_all = |session: &mut Session, engine: &SyncEngine| -> Result<Vec<MergeOutcome>, AppError> {
        let n = {
            let b = session.recv()?;
            if b.len() != 4 {
                return Err(AppError::Mesh(noter_mesh::MeshError::BadFrame("bad count")));
            }
            u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize
        };
        let mut envs = Vec::with_capacity(n.min(100_000));
        for _ in 0..n {
            let b = session.recv()?;
            envs.push(
                noter_sync::Envelope::from_bytes(&b)
                    .map_err(|_| AppError::Mesh(noter_mesh::MeshError::BadFrame("bad envelope")))?,
            );
        }
        Ok(engine.import(&envs)?)
    };

    let (sent, outcomes) = if send_first {
        let sent = send_all(session, &engine)?;
        let outcomes = recv_all(session, &engine)?;
        (sent, outcomes)
    } else {
        let outcomes = recv_all(session, &engine)?;
        let sent = send_all(session, &engine)?;
        (sent, outcomes)
    };

    // Reindex touched notes.
    let mut ix = SearchIndex::open(app.store(), app.master())?;
    for o in &outcomes {
        let id = match o {
            MergeOutcome::Applied { note_id } => note_id,
            MergeOutcome::Conflict { note_id, .. } => note_id,
            MergeOutcome::KeptLocal { note_id } => note_id,
            MergeOutcome::Ignored { note_id, .. } => note_id,
        };
        if let Ok(note) = app.notes().get(id) {
            ix.index_note(&note.id, &note.title, &note.body_md);
        }
    }
    ix.flush()?;
    let mut r = report(&outcomes);
    r.sent = sent;
    Ok(r)
}

fn report(outcomes: &[MergeOutcome]) -> SyncReport {
    let mut r = SyncReport {
        sent: 0,
        received: outcomes.len(),
        applied: 0,
        conflicts: 0,
        ignored: 0,
    };
    for o in outcomes {
        match o {
            MergeOutcome::Applied { .. } => r.applied += 1,
            MergeOutcome::Conflict { .. } => r.conflicts += 1,
            MergeOutcome::KeptLocal { .. } | MergeOutcome::Ignored { .. } => r.ignored += 1,
        }
    }
    r
}

use noter_sync::SyncEngine;

#[cfg(test)]
mod tests {
    use super::*;
    use noter_crypto::{DeviceIdentity, Salt, SecretBytes};
    use std::sync::mpsc;

    fn test_app(name: &str) -> (App, tempfile_dir::Dir) {
        let dir = tempfile_dir::Dir::new();
        let db = dir.path().join("vault.db");
        let app = App::open_with_master(&db, SecretBytes::new([0x88u8; 32])).unwrap();
        assert!(app.device_id().starts_with("dev-"));
        let _ = name;
        (app, dir)
    }

    /// Reopen the same vault file as an independent handle (multi-threaded tests).
    fn reopen(dir: &tempfile_dir::Dir, master_byte: u8) -> App {
        App::open_with_master(
            &dir.path().join("vault.db"),
            SecretBytes::new([master_byte; 32]),
        )
        .unwrap()
    }

    mod tempfile_dir {
        use std::path::PathBuf;
        pub struct Dir(PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p: PathBuf = std::env::temp_dir().join(format!(
                    "noter-ui-test-{}-{}",
                    std::process::id(),
                    rand_suffix()
                ));
                std::fs::create_dir_all(&p).unwrap();
                Self(p)
            }
            pub fn path(&self) -> &PathBuf {
                &self.0
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).ok();
            }
        }
        fn rand_suffix() -> String {
            use std::time::{SystemTime, UNIX_EPOCH};
            format!("{}", SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos())
        }
    }

    #[test]
    fn full_note_lifecycle() {
        let (app, _dir) = test_app("a");
        let v = cmd_create_note(&app, "Title", "body [[x]]", vec!["t".into()]).unwrap();
        assert_eq!(v.title, "Title");
        assert_eq!(v.links, vec!["x".to_string()]);
        let v2 = cmd_update_note(&app, &v.id, "Title2", "new body", vec![]).unwrap();
        assert_eq!(v2.version, 2);
        let list = cmd_list_notes(&app).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "Title2");
        cmd_delete_note(&app, &v.id).unwrap();
        assert!(cmd_list_notes(&app).unwrap().is_empty());
        assert!(cmd_get_note(&app, &v.id).is_err());
    }

    #[test]
    fn search_command() {
        let (app, _dir) = test_app("a");
        cmd_create_note(&app, "Shopping", "buy oat milk", vec![]).unwrap();
        cmd_create_note(&app, "Other", "nothing relevant", vec![]).unwrap();
        let hits = cmd_search(&app, "oat milk").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].title, "Shopping");
        assert!(!hits[0].snippet.is_empty());
    }

    #[test]
    fn attach_roundtrip_command() {
        let (app, _dir) = test_app("a");
        let v = cmd_create_note(&app, "T", "b", vec![]).unwrap();
        let aref = cmd_attach_file(&app, &v.id, "f.txt", "text/plain", b"data123").unwrap();
        assert_eq!(aref.size, 7);
        assert_eq!(cmd_read_attachment(&app, &aref.att_id).unwrap(), b"data123");
        let v2 = cmd_get_note(&app, &v.id).unwrap();
        assert_eq!(v2.attachments.len(), 1);
    }

    #[test]
    fn backlinks_in_view() {
        let (app, _dir) = test_app("a");
        let a = cmd_create_note(&app, "A", "links [[BID]]", vec![]).unwrap();
        let mut b = cmd_create_note(&app, "B", "no links", vec![]).unwrap();
        // point B at A's real id
        b = cmd_update_note(&app, &b.id, "B", &format!("see [[{}]]", a.id), vec![]).unwrap();
        let va = cmd_get_note(&app, &a.id).unwrap();
        assert_eq!(va.backlinks, vec![b.id]);
    }

    #[test]
    fn airgap_commands() {
        let (app_a, _d1) = test_app("a");
        let (app_b, _d2) = test_app("b");
        // Same master -> same device id; pair them as peers for import.
        let v = cmd_create_note(&app_a, "T", "airgap body", vec![]).unwrap();
        let frames = cmd_export_airgap(&app_a, 0).unwrap();
        assert!(!frames.is_empty());
        // Register a as peer of b (same identity since same master).
        let mut eb = app_b.engine();
        eb.add_peer(app_a.device_id(), app_a.public_identity());
        let outcomes = noter_airgap::import_frames(&frames, app_b.master(), &eb).unwrap();
        assert_eq!(outcomes.len(), 1);
        let got = app_b.notes().get(&v.id).unwrap();
        assert_eq!(got.body_md, "airgap body");
    }

    #[test]
    fn share_commands() {
        let (app_a, _d1) = test_app("a");
        // Bob: different master.
        let dir = tempfile_dir::Dir::new();
        let app_b =
            App::open_with_master(&dir.path().join("v.db"), SecretBytes::new([0x99u8; 32])).unwrap();

        let v = cmd_create_note(&app_a, "Shared", "for bob", vec![]).unwrap();
        let pkg = cmd_share_note(&app_a, &v.id, &app_b.public_identity()).unwrap();
        let view = cmd_receive_share(&app_b, &pkg, &app_a.public_identity()).unwrap();
        assert_eq!(view.title, "Shared");
        assert_eq!(view.body_md, "for bob");
    }

    #[test]
    fn mesh_sync_commands() {
        let (app_a, _d1) = test_app("a");
        let (app_b, _d2) = test_app("b");
        cmd_create_note(&app_a, "FromA", "hello", vec![]).unwrap();

        // Loopback mesh session between the two apps.
        let ida = DeviceIdentity::generate();
        let idb = DeviceIdentity::generate();
        let na = noter_mesh::MeshNode::new("a", ida);
        let nb = noter_mesh::MeshNode::new("b", idb);
        let listener = noter_mesh::MeshNode::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            tx.send(nb.accept_one(&listener).unwrap()).unwrap();
        });
        let mut sa = na.connect(&addr).unwrap();
        let mut sb = rx.recv().unwrap();

        // Register mesh peers as sync peers: use the apps' own identities.
        // Both sides must run concurrently (each blocks on recv).
        // Independent handle on b's vault for the peer thread (rusqlite is !Sync).
        let app_b2 = reopen(&_d2, 0x88);
        let pa = app_a.public_identity();
        let pb = app_b2.public_identity();
        let id_a = app_a.device_id().to_string();
        let id_b = app_b2.device_id().to_string();
        // Move the b-side app + session into the peer thread (App is Send, !Sync).
        let (ra, rb) = std::thread::scope(|s| {
            let hb = s.spawn(move || cmd_sync_with_peer(&app_b2, &mut sb, &id_a, pa, false));
            let ra = cmd_sync_with_peer(&app_a, &mut sa, &id_b, pb, true).unwrap();
            (ra, hb.join().unwrap().unwrap())
        });
        assert_eq!(ra.sent, 1);
        assert_eq!(rb.applied, 1);
        let titles: Vec<_> = cmd_list_notes(&app_b).unwrap().into_iter().map(|s| s.title).collect();
        assert!(titles.contains(&"FromA".to_string()));
    }

    #[test]
    fn unlock_with_passphrase() {
        let dir = tempfile_dir::Dir::new();
        let db = dir.path().join("vault.db");
        let salt = Salt::generate();
        let app = App::unlock(&db, "correct horse battery staple", &salt).unwrap();
        cmd_create_note(&app, "T", "b", vec![]).unwrap();
        drop(app);
        // Wrong passphrase fails.
        assert!(App::unlock(&db, "wrong passphrase", &salt).is_err());
        // Right passphrase reopens.
        let app2 = App::unlock(&db, "correct horse battery staple", &salt).unwrap();
        assert_eq!(cmd_list_notes(&app2).unwrap().len(), 1);
    }
}
