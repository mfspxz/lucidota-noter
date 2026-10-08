# NOTER mobile shell (field target)

`noter-mobile` is the field-usability layer; the native shell is a thin
host around it.

## Status

- **Field layer (`crates/noter-mobile`): 5/5 tests green** — offline-first
  op queue (sealed in the store, survives reboot), quick-capture, on-demand
  sync, airgap fallback.
- **Native shell: scaffold direction, not built here.** Target: Tauri Mobile
  (`tauri mobile init`) reusing the same `noter-ui` command functions as the
  desktop shell, with the mobile crate's `MobileApp` as the state owner.
  Building it needs Android SDK / Xcode — out of scope for this sandbox.

## Field interaction model

1. App opens straight to **quick capture** (one text field, big button).
2. Everything applies locally instantly; connectivity is never required.
3. A small badge shows pending op count; tapping it offers **Sync**
   (mesh, when a peer is near) or **Airgap** (QR frames).
4. Attachments: photo -> `cmd_attach_file` -> queued the same way.

## Why offline-first is correct here

Zackary's field reality (from the dossier): a phone being nursed back to
life, intermittent connectivity, pedicab shifts. The queue means a dead
battery or a dead zone never loses a note — the sealed op-queue is in the
same SQLCipher file as the notes.
