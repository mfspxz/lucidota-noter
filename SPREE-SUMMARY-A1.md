# NOTER Spree Summary — Agent 1 of 2

Date: 2026-10-09. Task: crypto audit, bug fixes, completions, full test run.

## 1. Crypto Audit — VERDICT: REAL, not theater

Audited `noter-crypto` (630 lines) by direct code reading:

| Claim | Finding |
|---|---|
| XChaCha20-Poly1305 | ✅ PROVEN — `aead.rs`: random 24B nonce per message, wire `nonce\|\|ct+tag`, tamper → `AuthenticationFailed` |
| Argon2id KDF | ✅ PROVEN — `kdf.rs`: m=64MiB, t=3, p=4 (OWASP interactive baseline), 16B random salt |
| Subkey derivation | ✅ PROVEN — BLAKE3 keyed mode with domain separation (`len(ctx)\|\|ctx`), tested cross-context isolation |
| X25519 ECIES | ✅ PROVEN — `boxcrypt.rs`: ephemeral keys, shared secret → BLAKE3 KDF → AEAD key. Never raw DH output |
| Ed25519 identity | ✅ PROVEN — independent X25519 keypair (not converted), seed export/import roundtrips |
| Mesh handshake | ✅ PROVEN — session key = BLAKE3(shared, ctx\|\|eph_i\|\|eph_r), transcript-bound Ed25519 attestation |
| Zeroize | ✅ PROVEN — `SecretBytes` has `ZeroizeOnDrop`, `Debug` redacted, `SecretSeed` zeroizes |

**Redteam battery**: 13/13 attacks defeated (bitflip, replay, impersonation, cross-context, share rewrite, airgap splice, mesh replay, conflict flood, search tamper, KDF cost, unknown writer, payload swap, garbage VV).

**AI review**: attempted via ai-router (NVIDIA lane) — all lanes down (502/timeouts). Audit done by direct reading instead.

## 2. Code Changes

### Completed unfinished work
- **`noter-mesh` beacon wiring** (was orphaned): `beacon()` existed but was unreachable (not exported from lib.rs, nothing called it). Now:
  - Exported `beacon` from `noter-mesh` lib.rs
  - Added `MeshNode::beacon()` convenience method (uses device fingerprint automatically)

### Bug fixes / hardening
- **`agree()` footgun documented**: added WARNING doc — returns raw DH shared secret, must go through KDF. Both callers already do this correctly; now it's explicit.
- **Clippy warnings fixed** (12 total):
  - `noter-crypto`: needless borrow in `DeviceIdentity::generate`
  - `noter-model`: collapsed nested if with let-chain in `extract_links`
  - `noter-mesh`: collapsed nested if in discovery, `manual_range_contains` in session.rs
  - `noter-sync`: removed unused `now_ms` import, removed dead `Dev` test struct
  - `noter-ui`: removed 6 unused imports from app.rs
  - `noter-redteam`: removed unused `noter_crypto::*` glob
  - `noter-mobile`: removed unused `Store` import
  - `noter-airgap`: `len() > 0` → `!is_empty()` in test

### Not changed (deliberately)
- `serde_json` envelope signing: not canonical JSON, but sign/verify use identical serialization — correct for closed system. Documented as fragile if cross-implementation compat ever needed.
- Ignored UDP discovery test: legitimately needs real LAN, not a bug.
- SQLCipher "hmac check failed" log noise: expected, from negative tests (wrong-key attempts).

## 3. Test Results

`cargo test --workspace`: **120 passed, 0 failed** (was 120 before, still 120 — no regressions from changes).

| Crate | Tests |
|---|---|
| noter-crypto | 26 |
| noter-sync | 16 |
| noter-redteam (attacks) | 13 |
| noter-store | 10 |
| noter-mesh | 8 (+1 ignored) |
| noter-ui | 8 |
| noter-airgap | 7 |
| noter-model | 7 |
| noter-organelle | 7 |
| noter-share | 7 |
| noter-search | 6 |
| noter-mobile | 5 |

`cargo clippy --workspace`: clean (was 12 warnings, now 0).
`cargo build --workspace`: clean.

## 4. Residual Notes for Agent 2

- The `tauri-app/` is still a scaffold (excluded from workspace — no webkit2gtk in sandbox). All logic tested via `noter-ui`.
- Pairing UX is the trust root (documented in REDTEAM.md) — no code fix possible, needs UI work.
- Consider: `Envelope::sign_bytes` could use a canonical serialization (e.g., sorted JSON or bincode) if cross-implementation compat becomes a goal.

---
*No commits made (per task). All changes in working tree.*
