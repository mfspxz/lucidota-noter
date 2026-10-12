# RIGOR-AUDIT application — noter

**Repo:** `~/workspace/noter` (E2EE notes, Rust, 12 crates)
**Date:** 2026-10-10 ~15:00 PDT
**Audit:** `~/workspace/dogfood/audit/RIGOR-AUDIT.md` (12 findings R-1..R-12)
**Corpus state:** scaffolded 2026-10-07, crypto-redteam wave 2026-10-09
(SPREE-REDTEAM-A2.md, SPREE-SUMMARY-A1.md), preservation commit 2026-10-09.

## Per-finding disposition

### R-1 (instance-only fix-verification claims) — APPLIED
No falsification ledger exists in this repo, so there is no claim/defeat
split to reconcile. The in-repo analog is the 13-attack battery
(`crates/noter-redteam/tests/attacks.rs`) plus the SPREE/REDTEAM prose
claims ("PROVEN", "E2EE HOLDS"). These replay the exact 13 attacks the
battery was written against: **they verify instances, not the class.**
Applied: `crates/noter-redteam/REDTEAM.md` now carries an explicit
instance-scope header ("13/13 attacks fail closed under the tested
threat model; this is a regression battery for those instances, not a
class-level proof"). Any future red-team wave must re-attack with NEW
variants before a `PROVEN` verdict on a fix class.

### R-2 (honest guardrail bounds) — APPLIED
`REDTEAM.md` already documents the threat model (Attackers A/B/C) and
an out-of-scope list (endpoint compromise, passphrase coercion,
sub-AEAD side channels). Applied: added the frozen-bound statement to
the honest-residuals section — the crypto core's guardrails claim only
what is listed in the results table; the 7 residual risks below define
the boundary. No hardening beyond the documented bound without a new
evidenced threat.

### R-3 (out-of-band head for hash-chained logs) — N/A
This repo owns no durable hash-chained log. Receipt hash chains live
only in-memory inside `noter-organelle`'s host adapter (tests) and are
never persisted, so there is no chain head to copy out-of-band. Nothing
in this repo calls itself tamper-evident. Documented here instead of
creating an empty OOB record.

### R-4 (backlog triage) — APPLIED
The 7 "Honest residual risks" in `REDTEAM.md` were an un-prioritized
standing backlog. Triaged below (draft prose via DeepSeek
`deepseek-v4-pro`, temp 0.1, output-only; decisions reviewed and
adopted by the auditor — me).

| # | Risk | Decision | Complexity budget / rationale |
|---|------|----------|-------------------------------|
| 1 | Pairing is the trust root (no PKI) | **FIX** | Medium: build 16-hex fingerprint comparison UX before pairing acceptance |
| 2 | Mesh handshake MITM at first contact | **WONT-FIX** | DoS-only; attacker learns/forges nothing. Documented, frozen |
| 3 | No forward secrecy for stored data | **WONT-FIX** | By design (user wants their own history); rekey implemented. Documented, frozen |
| 4 | Sync metadata leaks to relay | **WONT-FIX** | Accepted for relay sync; content confidentiality holds. Documented, frozen |
| 5 | Argon2id params fixed, uncalibrated | **FIX** | Small/medium: calibrate params or expose unlock-time target |
| 6 | Conflict copies unbounded in theory | **FIXED 2026-10-10** | `SyncEngine::gc_conflict_copies` in `noter-sync/engine.rs`: after every conflict-copy write, tombstone oldest-first down to MAX_CONFLICT_COPIES=8 live copies per note. Bound holds per round, not eventually. Honest bound: tombstones are sync-correct but not compacted — hostile spam still grows tombstone history slowly (documented in code). R8 redteam property test (`r8_conflict_flood_bounded`) still green; new `conflict_copy_gc_caps_live_copies` test green. |
| 7 | No audit log of security events | **FIXED 2026-10-10** | New `noter-auditlog` crate (noter-013): append-only JSONL, fail-open logging; wired into `App::unlock` (UnlockFailed), `cmd_sync_with_peer` (BadFrame/UnknownWriter/SignatureInvalid/EnvelopeRejected), `cmd_receive_share` (SenderMismatch/SignatureInvalid). 4 unit + 2 integration tests green; clippy clean. |

**Second sweep (2026-10-10):** R-4 items #7 (audit log) and #6 (conflict
GC) closed with production code. Remaining FIX items (#1 pairing UX —
medium; #5 Argon2id calibration — small/medium) stay open with their
budgets. WONT-FIX items (#2, #3, #4) frozen as documented.

Backlog rule going forward: standing HIGHs get a FIX with a complexity
budget or an explicit WONT-FIX above; the list must not grow unbounded.

### R-5 (signature/denylist games) — N/A
No signature, denylist, blocklist, or content-strip logic exists in this
repo (only whitespace `.strip()` in tests and identifier sanitization of
test names). No fixed-complexity-budget declaration needed; if any such
mechanism is ever added it must ship with the budget and a structural
answer per R-5.

### R-6 (detector without consumer) — N/A
The one detection-adjacent mechanism is the airgap per-frame bundle
checksum (`missing_frame_detected` test): it **rejects** spliced bundles,
i.e. detector and gate are the same check. No advisory-only warn path
exists. Verified: no warn/flag emitted anywhere without a consumer.

### R-7 (property vs change-detection tests) — APPLIED (policy documented)
The 13 attack tests are property-style ("attack X FAILS") — they state
security invariants, not implementation internals. Policy (new, this
change): tests in `noter-redteam/tests/attacks.rs` are PROPERTY tests;
their expectations may never be rewritten to match a behavior change
without an adversarial re-attack signing off on the new behavior.
All other crate tests are change-detection tests and are labeled as
such in the test headers where the distinction matters. Recorded here;
test files themselves unchanged.

### R-8 (unsigned "provenance") — N/A
Sync envelopes and share packages carry real Ed25519 signatures over
header+payload; airgap frames carry bundle checksums. No unsigned
artifact in the repo claims or implies provenance. The one
provenance-adjacent surface — device identity — is honestly documented
as pairing-trust (see R-2/R-4 #1).

### R-9 (frozen claim-log schema) — N/A
No claim/falsification log lives in this repo. If one is ever created
it must ship with frozen enum verdicts and a SUPERSEDED-BY-BYPASS status
per R-9 from day one.

### R-10 (live record-keeping) — N/A
The red-team record (`REDTEAM.md`, SPREE reports) was written in the
same motion as the wave (dated 2026-10-07/09, committed with the work).
No stale scoreboard analog exists here.

### R-11 (explicit UNKNOWN list)
1. Actual endpoint security: endpoint compromise is out of scope — any
   claim about device-level attacker resistance is UNKNOWN.
2. Mesh pairing UX: until risk #1 is fixed, the real-world pairing
   ceremony's resistance to social-engineering is UNKNOWN (the crypto
   binding itself is tested).
3. Side channels below the AEAD abstraction (timing, cache) — UNKNOWN,
   explicitly out of scope.
4. Weak-device unlock latency distribution — UNKNOWN until params are
   calibrated (risk #5).
5. The 13-attack battery's coverage of future attack classes — UNKNOWN
   by construction (R-1).

### R-12 (no unsourced oral footnotes)
Swept README, REDTEAM.md, SPREE-*.md, PRESERVATION.md for
"probably/likely/unverified source/I heard" class claims: **none found.**
The reconstruction provenance is sourced in PRESERVATION.md (ledger
seq=255 dossier, memory/2026-10-07.md#L41).

## Commits (this pass)
- (pending — selective staging of AUDIT-APPLICATION.md + REDTEAM.md
  header edit; never push)

## Tests
- `cargo test --workspace`: **exit 0, 133 passed, 0 failed** (measured
  2026-10-10, full run incl. second-sweep changes).
- `-p noter-redteam`: 13/13 attack tests green (measured).
