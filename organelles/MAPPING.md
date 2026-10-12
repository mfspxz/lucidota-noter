# noter — organelle mapping decisions

Decomposition reviewed 2026-10-10 under the corrected doctrine
(decompose ACTUAL capabilities; map-or-design per unit, justified).

## What the code actually does

`noter` is E2EE encrypted notes (12 crates). The crates fall into three
genuinely separable capability layers plus supporting libs:

## Capability units → organelles

| Unit | Source | Organelle / ops | Decision |
|---|---|---|---|
| Encrypted notes API: the unlocked vault behind the app command layer (notes CRUD, FTS search, backlinks, E2EE sharing, sync + airgap via vault) | `noter-ui` (App command layer), `noter-store` (SQLCipher), `noter-model`, `noter-sync` (vault-bound SyncEngine), `noter-share`, `noter-search` (sealed index blob in the store) | **noter-notes** (`no`): `device`, `get_note`, `list_notes`, `search`, `backlinks`, `export_airgap`, `create_note`/`update_note`/`delete_note`, `import_airgap`, `share_note`, `receive_share`. Read ops `notes.read`, write ops `notes.write`. | **Bespoke** (`no`). Pre-existing organelle, kept. Justification: an E2EE notes vault with graph links, sealed FTS, and E2EE sharing is not `ref-kv-store` (blind KV) — adopting the ref would flatten notes into key/value pairs and lose the entire security model. **Codon fixed `nt` → `no`**: `nt` collides with `ref-notify` (same class as the `fc`→`fd` fix). |
| E2EE crypto primitives, vault-independent: XChaCha20-Poly1305 AEAD, X25519/Ed25519 identities, Argon2id KDF, sealed boxes | `noter-crypto` (aead, boxcrypt, identity, kdf — pure functions) | **noter-crypto** (`ne`): `keygen`, `seal`, `unseal`, `sign`, `verify`, `fingerprint`, `seal_for`, `open_from`, `derive_master` (returns only a fingerprint, never the key). All ReadOnly/Proven. | **Bespoke** (`ne`). Justification: `ref-hash-seal` hashes/seals content; this is AEAD with key management + asymmetric identities + KDF — a different computation at a different layer. The crate boundary is the seam: pure crypto, no vault, independently callable (the existing redteam harness already tests it standalone). |
| Airgap frame codec, vault-independent: sealed bundles ↔ QR-sized frames | `noter-airgap` (`to_frames`/`from_frames`/`frames_qr_encodable` — pure) | **noter-airgap** (`na`): `to_frames`, `from_frames`, `qr_encodable`. All ReadOnly/Proven. | **Bespoke** (`na`). Justification: a transport framing codec is not crypto and not storage. The vault-bound bundle export/import stay on `noter-notes`; this unit is the pure codec. No ref organelle frames data for QR shuttles. |

## Why three organelles

- The vault (`no`) owns state (Mutex<App>, SQLCipher). The crypto (`ne`)
  and frame codec (`na`) are pure and vault-independent — folding them into
  the vault organelle would force key material and stateless codecs through
  a stateful vault authority. The seam is stateful-vault vs pure-primitive,
  the same cut the codebase already makes (noter-crypto has zero vault
  imports).
- `noter-sync`'s engine is vault-bound (`SyncEngine::new` takes `&Store` +
  master key) — it belongs with `no`, not standalone. Its deterministic
  merge outcomes are already exercised through the notes organelle's
  airgap/sync ops.

## Deliberate exclusions

- `noter-mesh` (LAN mesh transport): needs live TCP peers; cannot be tested
  here. Excluded, not Tier C — a manifest promising mesh ops without a
  live network would be valence inflation.
- `noter-mobile` (mobile field layer): device shell, needs a device.
- `noter-redteam` (adversarial harness): test harness, not a capability
  (same exclusion class as ledger-graph's bench).
- `noter-model`, `noter-store`: supporting libs of the vault organelle.

## Reference-organelle check (all 12 considered)

- `ref-kv-store`: blind KV; the notes vault is E2EE notes + graph + sealed
  FTS + sharing. Rejected (wrong data model AND wrong security model).
- `ref-hash-seal`: content hash-sealing; noter-crypto is AEAD + identities +
  KDF. Rejected (different computation).
- `ref-ledger-append`: sync envelopes are signed + merged deterministically,
  not blindly appended. Rejected.
- `ref-notify`: owns the `nt` codon — the reason for the `nt`→`no` fix.
- Others: no overlap.
- Verdict: genuinely bespoke. Nothing reinvented that already existed.

## Execution facts

- noter-notes: Candidate (stateful vault, E2EE). fs: the vault db path
  (per-call). Secrets: master key at construction only (SecretBytes,
  zeroizes); never in manifest, never in receipts. Suspend: vault lock
  held across calls is short; kill = drop (SQLCipher is crash-safe).
- noter-crypto: Proven (pure). Secrets policy: key material
  caller-supplied per call, SecretBytes-carried, zeroized on drop; receipts
  carry hashes only. `derive_master` never emits the key.
- noter-airgap: Proven (pure codec). No secrets, no state.
- Envelopes: 1 cpu / 512 MB / 60 s each.
- Receipts: content-addressed sha256, chained; `verify_chain` green in tests.
