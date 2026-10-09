# NOTER Red Team — Agent 2 Report

**Date:** 2026-10-09 | **Scope:** E2EE, sync/protocol, secret hygiene
**Method:** Source audit + live test execution (87 tests) + targeted attack probes

## Verdict: E2EE HOLDS. No decrypt-without-key path found. 4 minor findings below.

## PROVEN (fail-closed, verified by execution)

### 1. Cannot decrypt without the key — PROVEN
- `cargo test -p noter-crypto`: 26/26 pass, including `wrong_key_fails`, `tamper_detected`
- `cargo test -p noter-sync -p noter-share`: 23/23 pass, including `wrong_master_cannot_open`
- `cargo test -p noter-redteam`: 13/13 attack tests pass (R1–R13), each asserting the attack FAILS
- Wrong key → `AuthenticationFailed`. No oracle, no padding, no partial decrypt.

### 2. Nonce reuse — PROVEN ABSENT
- All nonces from `OsRng` (`aead.rs:18`, `boxcrypt.rs:18`, `session.rs:76,92`)
- No API exposes nonce selection; no counter/derived nonces anywhere
- `random_nonce_means_no_deterministic_ciphertext` test passes

### 3. Key leakage via Debug/logging — PROVEN ABSENT
- `SecretBytes`: manual `Debug` → `"SecretBytes([redacted])"`, tested
- `DeviceIdentity` (holds Ed25519+X25519 secrets): **no** `Debug` derive
- `SecretSeed`: **no** `Debug` derive, zeroizes on drop
- `CryptoError`: no key material in variants or messages
- `PublicIdentity` derives `Debug` but holds only public keys — safe

### 4. Plaintext secrets in repo — PROVEN ABSENT
- Scanned all `.rs/.ts/.js/.json/.md/.toml/.yaml/.env`: no `sk-`, `ghp_`, `AKIA`, `AIza`, PEM blocks
- `export_seed()` only called in test code; no production persistence path exists yet

### 5. Sync protocol — PROVEN
- Envelopes: Ed25519-signed (header + sealed payload), XChaCha20 sealed payload
- `merge_one`: verify sig → check peer identity binding → decrypt → VV compare
- `IdentityMismatch` / `UnknownWriter` reject spoofed/unpaired devices (tested: R3, R11)
- Replay: stale envelopes dominated by VV → `Ignored` (tested: R2, `replayed_old_envelope_ignored`)
- Tombstones propagate; conflicts resolve deterministically with loser preserved

### 6. Mesh transport — PROVEN
- Ephemeral-ephemeral X25519, session key = BLAKE3(shared, ctx || eph_i || eph_r)
- Attestation: Ed25519 sig over transcript, sealed under session key, verified both sides
- No static-static DH; no replayable handshake (ephemerals make each unique)

### 7. Store at rest — PROVEN
- `rusqlite` with `bundled-sqlcipher` (real SQLCipher, not a no-op pragma)
- File key = `derive_subkey(master, "noter/sqlcipher/v1")`, payload key = `derive_subkey(master, "noter/payload/v1")`
- R1: bit-flipped DB file → open fails, never wrong plaintext

## FINDINGS (minor, no decrypt path)

### F1. Sync uses a single shared subkey — BY DESIGN, document the tradeoff
`Envelope::seal`/`open` both use `derive_subkey(master, "noter/sync/v1")`.
Any device holding the master key decrypts all sync payloads. Correct for
same-user multi-device sync, but: **one compromised device = all notes readable**.
There is no per-device or per-note key separation. This is inherent to the
shared-master model, not a bug — but it should be stated in the threat model.

### F2. Discovery beacons leak presence in plaintext — LOW
`discovery.rs` broadcasts `NOTER1 || device_id || tcp_port || fingerprint` on LAN UDP.
Fingerprint is public by design, but `device_id` (often a username/hostname)
leaks presence to passive LAN observers. Consider: rotate ephemeral beacon IDs,
or require a pairing-mode toggle before beaconing.

### F3. `export_seed()` is an unguarded footgun — LOW (no production callers yet)
Docs say "Caller is responsible for encrypting this at rest." Today only tests
call it. When backup UX lands, the seed must be sealed with the master key
(or a backup passphrase) before touching disk. Track as a requirement, not a bug.

### F4. Tauri frontend: manual salt handling — UX RISK
Salt generated via `crypto.getRandomValues` (good) but user must manually copy
and retain the hex string. Lost salt = lost vault (KDF needs it). Recommend:
store salt alongside the DB file in a plaintext sidecar (salts are not secret),
or OS keychain integration.

## Test summary
| Crate | Tests | Result |
|---|---|---|
| noter-crypto | 26 | PASS |
| noter-sync | 7 | PASS |
| noter-share | 16 | PASS |
| noter-mesh | 7 | PASS |
| noter-store | 8 (+1 ignored) | PASS |
| noter-airgap | 10 | PASS |
| noter-redteam | 13 attacks | ALL FAIL-CLOSED |

**Total: 87 passed, 0 failed.**

## Red-team conclusion
I could not decrypt without the key, reuse a nonce, extract key material from
any Debug/log/error path, or find plaintext secrets in the repo. The sync and
mesh protocols authenticate before decrypting and fail closed on every tamper
class tested. The four findings above are hardening notes, not vulnerabilities.
E2EE posture: **STRONG**.
