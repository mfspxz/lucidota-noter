# NOTER — E2EE notes (built 2026-10-07)

Rust workspace, 12 crates, **120 tests green** (`cargo test`).

| Crate | Item | What |
|---|---|---|
| noter-crypto | noter-001 | XChaCha20-Poly1305, X25519, Ed25519, Argon2id, BLAKE3; zeroize secrets. No custom crypto. |
| noter-store | noter-002 | SQLCipher whole-file encryption + sealed payloads; tombstones; rekey. |
| noter-model | noter-003 | Markdown notes, attachments, `[[wikilinks]]` + backlinks graph. |
| noter-sync | noter-004 | Signed envelopes, version vectors, deterministic LWW + conflict copies. |
| noter-mesh | noter-005 | Encrypted TCP sessions, transcript-bound identity attestation, LAN discovery. No central server. |
| noter-airgap | noter-006 | Sealed bundles → QR-sized frames (`NTR1/...`); file sneakernet. |
| noter-search | noter-009 | Full-text index persisted as one sealed blob. |
| noter-share | noter-010 | E2EE share packages (ECIES key wrap + signed). |
| noter-ui | noter-007 | Tested command layer for the Tauri shell. |
| noter-mobile | noter-008 | Offline-first field layer: sealed op queue, quick capture. |
| noter-redteam | noter-011 | 13-attack battery + `REDTEAM.md` review. |
| noter-organelle | noter-012 | Organelle-host adapter, codon `nt`. |

`tauri-app/` — desktop shell scaffold (kept out of the workspace: sandbox
lacks webkit2gtk to link Tauri; all logic is tested in `noter-ui`).
`mobile-shell.md` — field UI direction.

Key management: passphrase → Argon2id → master key → BLAKE3 domain
subkeys (sqlcipher / payload / sync / airgap / device-id contexts).
