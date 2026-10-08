//! NOTER desktop command layer (noter-007).
//!
//! Every UI operation is a plain, tested Rust function here. The Tauri shell
//! (`tauri-app/`) is a thin wiring layer: each `#[tauri::command]` forwards
//! to one of these functions. This keeps 100% of app logic testable without
//! a WebView runtime (which this build sandbox cannot link — no webkit2gtk).
//!
//! [`App`] owns the unlocked vault: store + identity + sync engine + search
//! index. Unlock flow: `App::unlock(path, passphrase, salt)` -> Argon2id ->
//! master key -> SQLCipher store.

mod app;
mod commands;
mod dto;

pub use app::{App, AppError};
pub use commands::*;
pub use dto::*;
pub use noter_crypto::{PublicIdentity, Salt};
pub use noter_model::{AttachmentRef, Note};
pub use noter_store::StoreError;
