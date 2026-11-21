//! NOTER red-team (noter-011).
//!
//! Adversarial review as executable tests. Every test is an ATTACK: it
//! succeeds (test passes) only if the attack FAILS against the system.
//!
//! Attack catalogue (see `../REDTEAM.md` for the written review):
//! - R1: SQLCipher file bit-flip -> must not decrypt to wrong plaintext.
//! - R2: envelope replay after delete -> tombstone must hold.
//! - R3: forged envelope (valid sig, inflated VV) -> applied?? (documents VV trust)
//! - R4: cross-context key misuse (payload key on sync envelope) -> fails.
//! - R5: share package sender-field rewrite -> fails closed.
//! - R6: airgap frame from another bundle spliced in -> rejected.
//! - R7: mesh attestation replay across sessions -> rejected.
//! - R8: conflict-copy flood (1000 concurrent) -> bounded, deterministic.
//! - R9: search index tamper (sealed blob flip) -> query fails closed, no panic.
//! - R10: passphrase brute-force cost sanity (KDF params as configured).
//! - R11: envelope with valid signature but unknown writer -> rejected.
//! - R12: tampered note JSON inside valid envelope -> AEAD rejects before parse.
//! - R13: garbage / u64::MAX version vectors -> tolerated, no panic.
//! Legallibrary battery (2026-11-20):
//! - R14: forged corpus (fake text + recomputed id + real provenance) without
//!   a valid signature under the trusted key -> rejected at open.
//! - R15: tampered text with stale id -> load_corpus rejects.
//! - R16: provenance hash mismatch vs raw manifest -> rejected at open.
//! - R17: fake official URL (not in raw manifest) -> rejected at open.
//! - R18: duplicate source ids -> load_corpus rejects.
//! - R19: tier-confusion at rank_authority (tier disagrees with URL) -> rejected.
//! - R20: hostile resolve queries -> answer, never error or panic.
//! - R21: wrong corpus version (validly signed) -> rejected.

// Re-exported for the attack modules.
pub use noter_airgap as airgap;
pub use noter_mesh as mesh;
pub use noter_model as model;
pub use noter_search as search;
pub use noter_share as share;
pub use noter_store as store;
pub use noter_sync as sync;
pub use noter_ui as ui;
