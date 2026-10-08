// NOTER desktop shell (noter-007).
//
// Thin Tauri wiring: every command forwards to the tested noter-ui command
// layer. All app logic lives in noter-ui and is covered by its test suite;
// this file contains zero business logic by design.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use noter_ui::{App, NoteSummary, NoteView, SearchHit, SyncReport};
use std::path::PathBuf;
use std::sync::Mutex;

struct Vault(Mutex<Option<App>>);

#[tauri::command]
fn unlock(db_path: String, passphrase: String, salt_hex: String, vault: tauri::State<Vault>) -> Result<String, String> {
    let salt = noter_ui::Salt::from_hex(&salt_hex).map_err(|e| e.to_string())?;
    let app = App::unlock(&PathBuf::from(db_path), &passphrase, &salt).map_err(|e| e.to_string())?;
    let device_id = app.device_id().to_string();
    *vault.0.lock().map_err(|e| e.to_string())? = Some(app);
    Ok(device_id)
}

fn with_app<T>(vault: &tauri::State<Vault>, f: impl FnOnce(&App) -> Result<T, noter_ui::AppError>) -> Result<T, String> {
    let guard = vault.0.lock().map_err(|e| e.to_string())?;
    let app = guard.as_ref().ok_or_else(|| "vault is locked".to_string())?;
    f(app).map_err(|e| e.to_string())
}

#[tauri::command]
fn create_note(title: String, body_md: String, tags: Vec<String>, vault: tauri::State<Vault>) -> Result<NoteView, String> {
    with_app(&vault, |app| noter_ui::cmd_create_note(app, &title, &body_md, tags))
}

#[tauri::command]
fn get_note(id: String, vault: tauri::State<Vault>) -> Result<NoteView, String> {
    with_app(&vault, |app| noter_ui::cmd_get_note(app, &id))
}

#[tauri::command]
fn update_note(id: String, title: String, body_md: String, tags: Vec<String>, vault: tauri::State<Vault>) -> Result<NoteView, String> {
    with_app(&vault, |app| noter_ui::cmd_update_note(app, &id, &title, &body_md, tags))
}

#[tauri::command]
fn delete_note(id: String, vault: tauri::State<Vault>) -> Result<(), String> {
    with_app(&vault, |app| noter_ui::cmd_delete_note(app, &id))
}

#[tauri::command]
fn list_notes(vault: tauri::State<Vault>) -> Result<Vec<NoteSummary>, String> {
    with_app(&vault, noter_ui::cmd_list_notes)
}

#[tauri::command]
fn search(query: String, vault: tauri::State<Vault>) -> Result<Vec<SearchHit>, String> {
    with_app(&vault, |app| noter_ui::cmd_search(app, &query))
}

#[tauri::command]
fn export_airgap(since_ms: i64, vault: tauri::State<Vault>) -> Result<Vec<String>, String> {
    with_app(&vault, |app| noter_ui::cmd_export_airgap(app, since_ms))
}

#[tauri::command]
fn import_airgap(frames: Vec<String>, vault: tauri::State<Vault>) -> Result<SyncReport, String> {
    with_app(&vault, |app| noter_ui::cmd_import_airgap(app, &frames))
}

fn main() {
    tauri::Builder::default()
        .manage(Vault(Mutex::new(None)))
        .invoke_handler(tauri::generate_handler![
            unlock,
            create_note,
            get_note,
            update_note,
            delete_note,
            list_notes,
            search,
            export_airgap,
            import_airgap,
        ])
        .run(tauri::generate_context!())
        .expect("failed to run noter-desktop");
}
