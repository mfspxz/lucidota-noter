# TEST CLASSIFICATION — noter (R-7 rollout, 2026-10-10)

Tags: **PROPERTY** = security invariant stated without implementation
terms (rewrite of the expectation needs adversarial sign-off).
**CHANGE-DETECTION** = pins current behavior; update freely.
**MIXED** = invariant + mechanism pin in one test.

No tests were rewritten or reclassified by editing this round: noter
tests already state most invariants without label-string coupling (Rust
`assert!`/`assert_eq!` on behavior, not on drift-label vocabulary).
Classification is recorded here; inline docstring declarations are
queued.

## crates/noter-airgap/src/lib.rs (7)

| test | class |
|---|---|
| airgap_roundtrip_shuffled_frames | PROPERTY (reordered frames still reassemble) |
| missing_frame_detected | PROPERTY |
| tampered_chunk_rejected | PROPERTY |
| mixed_bundle_frames_rejected | PROPERTY |
| wrong_master_cannot_import | PROPERTY |
| file_sneakernet_roundtrip | CHANGE-DETECTION |
| frames_are_qr_encodable | CHANGE-DETECTION (format pin) |

## crates/noter-crypto/src/aead.rs (7)

| test | class |
|---|---|
| roundtrip | CHANGE-DETECTION |
| random_nonce_means_no_deterministic_ciphertext | PROPERTY (semantic security) |
| tamper_detected | PROPERTY |
| wrong_key_fails | PROPERTY |
| truncated_blob_rejected | PROPERTY |
| empty_plaintext_ok | CHANGE-DETECTION |
| large_plaintext_roundtrip | CHANGE-DETECTION |

## crates/noter-crypto/src/boxcrypt.rs (5)

| test | class |
|---|---|
| seal_open_roundtrip | CHANGE-DETECTION |
| wrong_recipient_cannot_open | PROPERTY |
| sealed_is_randomized | PROPERTY |
| tampered_box_rejected | PROPERTY |
| empty_plaintext_box | CHANGE-DETECTION |

## crates/noter-crypto/src/identity.rs (6)

| test | class |
|---|---|
| sign_verify_roundtrip | CHANGE-DETECTION |
| verify_rejects_tampered_message | PROPERTY |
| verify_rejects_wrong_device | PROPERTY |
| x25519_agreement_matches_both_sides | PROPERTY (key-agreement correctness) |
| seed_export_import_preserves_identity | PROPERTY (identity preservation) |
| fingerprint_is_stable_hex16 | MIXED (stability = PROPERTY; 16-hex length = CHANGE-DETECTION pin) |

## crates/noter-crypto/src/kdf.rs (6)

| test | class |
|---|---|
| kdf_deterministic | PROPERTY (determinism) |
| kdf_salt_matters | PROPERTY |
| kdf_passphrase_matters | PROPERTY |
| subkeys_domain_separated | PROPERTY |
| salt_hex_roundtrip | CHANGE-DETECTION (format pin) |
| fingerprint_stable_and_short | MIXED (stability = PROPERTY; length = pin) |

## crates/noter-crypto/src/secret.rs (2)

| test | class |
|---|---|
| debug_does_not_leak_key | MIXED (no key material in Debug = PROPERTY; exact `"SecretBytes([redacted])"` string = CHANGE-DETECTION) |
| generate_is_random | PROPERTY |

## crates/noter-mesh/src/discovery.rs (2 + 1 ignored)

| test | class |
|---|---|
| beacon_codec_roundtrip | CHANGE-DETECTION |
| decode_rejects_garbage | PROPERTY |
| discover_finds_local_beacon | IGNORED in sandbox (needs real UDP); CHANGE-DETECTION when run |

## crates/noter-mesh/src/session.rs (6)

| test | class |
|---|---|
| session_roundtrip | CHANGE-DETECTION |
| identities_attested_both_sides | PROPERTY |
| session_keys_match_and_fingerprints_agree | PROPERTY |
| large_message_roundtrip | CHANGE-DETECTION |
| tampered_frame_rejected | PROPERTY |
| oversize_send_rejected | PROPERTY |

## crates/noter-mobile/src/lib.rs (5)

All CHANGE-DETECTION (offline queue behavior pins):
offline_capture_queues_ops, queue_survives_restart,
update_delete_queue_and_drain, online_flag_and_airgap_fallback,
field_timestamp_sane.

## crates/noter-model/src/notes.rs (7)

| test | class |
|---|---|
| create_get_roundtrip | CHANGE-DETECTION |
| update_bumps_version | CHANGE-DETECTION |
| delete_tombstones | PROPERTY (deletion is durable: get fails, list empty) |
| attach_and_read | CHANGE-DETECTION |
| wikilink_extraction | CHANGE-DETECTION |
| graph_backlinks_and_dangling | CHANGE-DETECTION |
| markdown_body_preserved_verbatim | CHANGE-DETECTION |

## crates/noter-organelle/src/airgap.rs (3), src/crypto.rs (3), src/lib.rs (7)

- static_manifest_validates, rust_manifest_matches_static_json:
  CHANGE-DETECTION (manifest/schema sync pins).
- frame_codec_roundtrips_through_host_with_receipts,
  crypto_roundtrips_through_host_with_receipts: MIXED (round-trip =
  CHANGE-DETECTION; receipt presence = PROPERTY).
- manifest_registers_clean, search_and_backlinks_through_host,
  share_roundtrip_through_host: CHANGE-DETECTION.
- read_op_needs_read_cap, write_op_needs_write_cap: PROPERTY
  (capability enforcement).
- input_schema_rejects_bad_input: PROPERTY (input validation).
- receipts_chain_verifies: PROPERTY (receipt chain integrity).

## crates/noter-redteam/tests/attacks.rs (13)

All PROPERTY -- adversarial invariants ("attack X never succeeds"):
r1_file_bitflip_never_yields_wrong_plaintext,
r2_replay_cannot_resurrect_tombstone,
r3_peer_cannot_impersonate_peer,
r4_cross_context_keys_do_not_interoperate,
r5_share_sender_rewrite_rejected,
r6_airgap_splice_rejected,
r7_mesh_sessions_ephemeral_and_bound,
r8_conflict_flood_bounded,
r9_search_index_tamper_fails_closed,
r10_kdf_is_expensive,
r11_unpaired_valid_signature_rejected,
r12_payload_swap_rejected_before_parse,
r13_garbage_vv_bytes_tolerated.

## crates/noter-search/src/lib.rs (6)

| test | class |
|---|---|
| tokenize_basics | CHANGE-DETECTION |
| search_finds_and_ranks | CHANGE-DETECTION |
| reindex_replaces | CHANGE-DETECTION |
| remove_note_drops_terms | CHANGE-DETECTION |
| index_persists_sealed | PROPERTY (index at rest stays sealed) |
| case_insensitive | CHANGE-DETECTION |

## crates/noter-share/src/lib.rs (7)

| test | class |
|---|---|
| share_receive_roundtrip | CHANGE-DETECTION |
| package_serializes_for_transport | CHANGE-DETECTION |
| wrong_recipient_cannot_open | PROPERTY |
| tampered_payload_fails | PROPERTY |
| sender_spoof_fails | PROPERTY |
| share_key_is_fresh_per_package | PROPERTY (per-package key freshness) |
| empty_attachments_ok | CHANGE-DETECTION |

## crates/noter-store/src/store.rs (10)

| test | class |
|---|---|
| roundtrip_note | CHANGE-DETECTION |
| missing_note_errors | CHANGE-DETECTION |
| upsert_updates | CHANGE-DETECTION |
| tombstone_and_list_filtering | CHANGE-DETECTION |
| changed_since_cursor | CHANGE-DETECTION |
| attachment_roundtrip | CHANGE-DETECTION |
| file_persists_encrypted | PROPERTY (confidentiality at rest) |
| wrong_key_rejected | PROPERTY |
| rekey_rotates_both_layers | PROPERTY (rekey completeness across layers) |
| payload_tamper_detected | PROPERTY |

## crates/noter-sync/src/engine.rs (8)

| test | class |
|---|---|
| two_way_sync | CHANGE-DETECTION |
| concurrent_edits_resolve_deterministically_with_conflict_copy | PROPERTY (deterministic resolution) |
| simultaneous_conflict_both_sides_agree_then_converge | PROPERTY (convergence) |
| replayed_old_envelope_ignored | PROPERTY |
| unknown_writer_rejected | PROPERTY |
| identity_spoof_rejected | PROPERTY |
| tombstone_propagates | PROPERTY (deletion durability across sync) |
| conflict_copy_gc_caps_live_copies | CHANGE-DETECTION (GC bound pin) |

## crates/noter-sync/src/envelope.rs (5)

| test | class |
|---|---|
| seal_verify_open_roundtrip | CHANGE-DETECTION |
| tampered_payload_fails_verify | PROPERTY |
| tampered_header_fails_verify | PROPERTY |
| wrong_master_cannot_open | PROPERTY |
| bytes_roundtrip | CHANGE-DETECTION |

## crates/noter-sync/src/vector.rs (4)

| test | class |
|---|---|
| bump_and_compare | PROPERTY (version-vector ordering) |
| concurrent_detected | PROPERTY (concurrency detection) |
| merge_is_join | PROPERTY (CRDT join semantics) |
| bytes_roundtrip | CHANGE-DETECTION |

## crates/noter-ui/src/commands.rs (10)

| test | class |
|---|---|
| full_note_lifecycle | CHANGE-DETECTION |
| search_command | CHANGE-DETECTION |
| attach_roundtrip_command | CHANGE-DETECTION |
| backlinks_in_view | CHANGE-DETECTION |
| airgap_commands | CHANGE-DETECTION |
| share_commands | CHANGE-DETECTION |
| mesh_sync_commands | CHANGE-DETECTION |
| unlock_with_passphrase | MIXED (auth accept/reject = PROPERTY; wiring = CHANGE-DETECTION) |
| unlock_failure_is_logged | PROPERTY (auth failures are audit-logged) |
| share_sender_mismatch_is_logged | PROPERTY (spoof attempts are audit-logged) |

## crates/noter-auditlog/src/lib.rs (4)

All CHANGE-DETECTION (append/format behavior pins):
creates_and_roundtrips, appends_across_reopens,
malformed_lines_skipped, kind_names_stable (wire-format pin).

## Totals

134 tests (1 ignored in sandbox): **67 PROPERTY / 61
CHANGE-DETECTION / 6 MIXED.** No rewrites this round; no expectation
changes. The redteam attacks.rs suite (13/13 PROPERTY) is the model
citizen: adversarial invariants with no mechanism coupling.
