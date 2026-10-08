# NOTER desktop shell (`tauri-app/`)

Thin Tauri wrapper around the tested `noter-ui` command layer.

## Status

- **Command layer (`../crates/noter-ui`): 8/8 tests green** — every Tauri
  command forwards to a pure function there (`cmd_create_note`,
  `cmd_search`, `cmd_sync_with_peer`, …). Zero business logic in `src/main.rs`
  by design.
- **This shell does not compile in the build sandbox**: linking Tauri needs
  `webkit2gtk-4.1` + `libsoup-3.0` system libraries, which are not installed
  here. Build it on a desktop Linux/macOS/Windows machine.

## Build (on a desktop)

```bash
# Debian/Ubuntu prerequisites:
sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev libgtk-3-dev

cd tauri-app
cargo build --release
./target/release/noter-desktop
```

## What the UI does

- Unlock screen: Argon2id passphrase -> SQLCipher vault.
- Sidebar: note list, full-text search, New/Sync/Airgap buttons.
- Editor: title + markdown textarea, save/delete, attachments via commands.
- Airgap: exports QR-sized frames to clipboard (scan with another device).
- Mesh sync: `noter-ui::cmd_sync_with_peer` over a `noter-mesh` session;
  wire discovery + session setup in `main.rs` when adding the Sync button
  flow (the protocol pieces are tested in `noter-ui`).

## Frontend

Single `frontend/index.html` (no build step). Keep it dependency-free;
it only calls the Tauri commands listed in `src/main.rs`.
