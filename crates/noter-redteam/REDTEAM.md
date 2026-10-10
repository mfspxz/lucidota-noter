# NOTER red-team review (noter-011)

> **R-1 instance scope (2026-10-10).** The 13 attacks below are a regression
> battery for the exact instances tested — 13/13 GREEN means those 13
> payloads fail, not that the attack class is closed. Any future fix's
> `PROVEN` verdict requires a dedicated re-attack with NEW variants, not a
> replay of these 13. Policy: never rewrite a property test's expectation
> to match a behavior change without adversarial sign-off (R-7).

Date: 2026-10-07. Method: executable attack battery
(`crates/noter-redteam/tests/attacks.rs`, 13 attacks, all defeated) plus
design review below. No custom crypto anywhere in the stack — every claim
below reduces to: XChaCha20-Poly1305, X25519, Ed25519, Argon2id, BLAKE3,
SQLCipher (AES-256-CBC+HMAC).

## Threat model

- **Attacker A (thief):** has the vault file, not the passphrase.
- **Attacker B (network):** controls the mesh LAN / relay / sneakernet
  channel; can read, drop, replay, reorder, splice messages.
- **Attacker C (peer insider):** a paired device gone rogue.
- Out of scope: endpoint compromise (attacker on the unlocked device),
  passphrase coercion, side channels below the AEAD abstraction.

## Results: 13/13 attacks fail closed

| # | Attack | Result |
|---|--------|--------|
| R1 | Bit-flip SQLCipher file | Open/read errors; AEAD second layer rejects; never wrong plaintext |
| R2 | Replay pre-delete envelope | Tombstone holds (VV dominates) |
| R3 | Paired peer impersonates another peer | Signature binds writer identity; rewrite breaks sig |
| R4 | Cross-context key misuse | Domain-separated subkeys; AEAD rejects |
| R5 | Share package sender rewrite | `SenderMismatch` / `BadSignature` |
| R6 | Airgap frame splice across bundles | Per-frame bundle checksum rejects |
| R7 | Mesh session replay / transcript forgery | Ephemeral keys (fingerprints differ); transcript-bound attestation |
| R8 | 200× conflict flood | Terminates <30s; 1 live note; ≤2 conflict copies |
| R9 | Search index tamper | Open errors; no silent wrong results |
| R10 | KDF cost | Argon2id(m=64MiB,t=3,p=4) ≥100ms measured |
| R11 | Unpaired device, valid signature | `UnknownWriter` — pairing is the trust root |
| R12 | Payload byte-swap under valid sig | Rejected before any parsing |
| R13 | Garbage / u64::MAX version vectors | Tolerated, no panic, sane ordering |

## Honest residual risks (not fixed; recorded)

> **R-2 frozen bound (2026-10-10).** The guardrails above claim only what
> the results table measures. The risks below define the boundary —
> no hardening past this bound without a new evidenced threat.
> Triage decisions (FIX vs WONT-FIX with complexity budgets) live in
> `~/workspace/noter/AUDIT-APPLICATION.md` (R-4).

1. **Pairing is the trust root.** There is no PKI: if attacker B tricks the
   user into pairing the attacker's device (QR shown on attacker's screen),
   all bets are off. Mitigation is UX: show the 16-hex device fingerprint
   at pairing time and make the user compare out-of-band. NOT YET BUILT.
2. **Mesh handshake MITM at first contact.** The ephemeral handshake has no
   prior trust; identity binding happens after. Envelope signatures + sealed
   payloads mean a MITM learns nothing and forges nothing, but it can
   *drop* traffic (DoS). Acceptable for LAN sync; documented in noter-mesh.
3. **No forward secrecy for stored data.** Compromise of the master key
   decrypts all history. By design (user wants their own history); the
   mitigation is passphrase strength + rekey support (implemented).
4. **Sync metadata leaks to a relay.** Envelopes hide content, but a relay
   sees note ids, sizes, timing, and writer ids. The threat model assumes
   relays are untrusted-but-curious; content confidentiality holds.
5. **Argon2id params are fixed**, not calibrated to the device. On a very
   weak phone, unlock may take seconds. Future: calibrated params stored
   with the salt (format supports it; not implemented).
6. **Conflict copies are unbounded in theory** (one per losing edit).
   R8 shows the per-round bound; a pathological peer could still spam
   conflicts. Future: conflict-copy GC policy (oldest-first, keep N).
7. **No audit log of security events.** Failed decryptions, rejected
   envelopes, and unknown-writer attempts are returned as errors but not
   logged anywhere the user can review. Recommended next item.

## Verdict

The crypto core and protocol layers fail closed under the tested attacks.
The weakest points are pairing UX (R-risk 1) and the missing security-event
log (R-risk 7) — both are product work, not crypto work.
