# NAMING.md — Noter naming decision (RESOLVED Nov 19 2026)

## Decision: the notes app is NOTER. Percyphon is a separate project, not a rename.

The "Noter vs Percyphon" question (open since at least Nov 18 2026, gating the
Innovate BC microgrant trademark line) is resolved as follows:

- **Noter** = this repo: E2EE notes (XChaCha20-Poly1305, X25519, Ed25519,
  Argon2id, SQLCipher), Rust workspace, 13 crates (noter-*), public repo
  mfspxz/lucidota-noter. The name Noter is established in the repo, the
  workspace, the crates, the README, and the registry primary record.
- **Percyphon / percyphon-rs** = a DISTINCT Rust codebase: persona derivation
  (128-slot personas), organelles percyphon-rs-forge/custody/kronenberg,
  codon pg. It is not a notes app. It is not a rename candidate for Noter.
- The conflation came from two places: the public portfolio page
  (cutecity.cc/portfolio/noter, titled "Noter / Percyphon — field notebook")
  and a repomix snapshot named `added-longtail-rust-percyphon.md`.
  The Oct 6 dossier lists NOTER and Percyphonai as SEPARATE projects.

## Application
- This repo, crates, README, and public repo name stay **Noter** (no change
  needed — already consistent).
- The portfolio page title is fixed to "Noter — field notebook" (cutecity-worker
  index.js; separate builder task + deploy — see the go-ahead sweep record).
- The repomix snapshot filename is historical evidence; it is NOT renamed
  (archive-don't-delete; the registry record references it by sha).
- The microgrant trademark line is unblocked: the trademark is **Noter**.

## Sources
- Registry record "Noter naming: Noter vs Percyphon" (id f310f472…),
  ~/workspace/lucidota-ecosystem-map/registry/noter.json — verdict was
  UNRESOLVED; this decision resolves it.
- Dossier: ~/workspace/recovery/technical-dev-world-dossier-2026-10-06.md
  (NOTER and Percyphonai as separate projects).
- Repomix: ~/workspace/repomix/added-longtail-rust-percyphon.md
  (percyphon-rs persona derivation, not a notes app).

Decided by the go-ahead sweep agent, Nov 19 2026, under Zack's Nov 19 19:16
authorization of all pending go-ahead decisions (item 32).
