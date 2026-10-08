use crate::{Envelope, VectorCmp, VersionVector};
use noter_crypto::{DeviceIdentity, PublicIdentity, SecretBytes};
use noter_store::{now_ms, Store, StoreError};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("crypto error: {0}")]
    Crypto(#[from] noter_crypto::CryptoError),
    #[error("unknown writer device: {0}")]
    UnknownWriter(String),
    #[error("writer identity mismatch for device {0}")]
    IdentityMismatch(String),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
}

/// Result of merging one incoming envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    Applied { note_id: String },
    KeptLocal { note_id: String },
    /// Concurrent edits resolved deterministically; loser preserved.
    Conflict { note_id: String, winner: String, conflict_copy: String },
    Ignored { note_id: String, reason: &'static str },
}

/// Sync engine for one device.
pub struct SyncEngine<'a> {
    device_id: String,
    identity: DeviceIdentity,
    master: SecretBytes,
    store: &'a Store,
    /// device_id -> expected public identity. Fail-closed: unknown writers rejected.
    peers: HashMap<String, PublicIdentity>,
}

impl<'a> SyncEngine<'a> {
    pub fn new(
        device_id: &str,
        identity: DeviceIdentity,
        master: SecretBytes,
        store: &'a Store,
    ) -> Self {
        Self {
            device_id: device_id.to_string(),
            identity,
            master,
            store,
            peers: HashMap::new(),
        }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// Register a peer device's identity (out-of-band pairing).
    pub fn add_peer(&mut self, device_id: &str, ident: PublicIdentity) {
        self.peers.insert(device_id.to_string(), ident);
    }

    /// Record a local edit: bump our VV counter and store the note JSON.
    pub fn put_local(
        &self,
        note_id: &str,
        note_json: &[u8],
        deleted: bool,
    ) -> Result<(), SyncError> {
        let mut vv = self.local_vv(note_id)?;
        vv.bump(&self.device_id);
        self.store
            .put_note(note_id, note_json, &vv.to_bytes(), deleted)?;
        Ok(())
    }

    fn local_vv(&self, note_id: &str) -> Result<VersionVector, SyncError> {
        match self.store.get_note(note_id) {
            Ok(rec) => Ok(VersionVector::from_bytes(&rec.vv)),
            Err(StoreError::NotFound(_)) => Ok(VersionVector::new()),
            Err(e) => Err(e.into()),
        }
    }

    /// Export all notes changed since `since_ms` as signed envelopes.
    pub fn export(&self, since_ms: i64) -> Result<Vec<Envelope>, SyncError> {
        let mut out = Vec::new();
        for rec in self.store.changed_since(since_ms)? {
            let plain = self.store.open_payload(&rec.payload_sealed)?;
            let vv = VersionVector::from_bytes(&rec.vv);
            out.push(Envelope::seal(
                &self.identity,
                &self.device_id,
                &self.master,
                &rec.note_id,
                &plain,
                vv,
                rec.updated_ms,
                rec.deleted,
            ));
        }
        Ok(out)
    }

    /// Merge incoming envelopes. Deterministic; never drops data silently.
    pub fn import(&self, envelopes: &[Envelope]) -> Result<Vec<MergeOutcome>, SyncError> {
        let mut outcomes = Vec::new();
        for env in envelopes {
            outcomes.push(self.merge_one(env)?);
        }
        Ok(outcomes)
    }

    fn merge_one(&self, env: &Envelope) -> Result<MergeOutcome, SyncError> {
        let h = &env.header;
        // 1. Signature must verify (fail closed).
        env.verify()?;
        // 2. Writer must be a registered peer with matching identity.
        match self.peers.get(&h.writer_id) {
            Some(expected) if *expected == h.writer_pub => {}
            Some(_) => return Err(SyncError::IdentityMismatch(h.writer_id.clone())),
            None => return Err(SyncError::UnknownWriter(h.writer_id.clone())),
        }
        // 3. Decrypt payload.
        let plain = env.open(&self.master)?;

        let local_vv = self.local_vv(&h.note_id)?;
        match h.vv.compare(&local_vv) {
            VectorCmp::Dominated | VectorCmp::Equal => Ok(MergeOutcome::Ignored {
                note_id: h.note_id.clone(),
                reason: "incoming dominated or equal",
            }),
            VectorCmp::Dominates => {
                self.store
                    .put_note(&h.note_id, &plain, &h.vv.to_bytes(), h.deleted)?;
                Ok(MergeOutcome::Applied {
                    note_id: h.note_id.clone(),
                })
            }
            VectorCmp::Concurrent => {
                let local_rec = self.store.get_note(&h.note_id).ok();
                let winner = pick_winner(
                    &h.writer_id,
                    h.vv.total(),
                    h.updated_ms,
                    &self.device_id,
                    local_vv.total(),
                    local_rec.as_ref().map(|r| r.updated_ms).unwrap_or(0),
                );
                if winner == h.writer_id {
                    // Incoming wins; preserve local as conflict copy.
                    let conflict_id = conflict_copy_id(&h.note_id, &self.device_id, local_vv.total());
                    if let Some(rec) = local_rec {
                        let local_plain = self.store.open_payload(&rec.payload_sealed)?;
                        self.store.put_note(
                            &conflict_id,
                            &local_plain,
                            &local_vv.to_bytes(),
                            false,
                        )?;
                    }
                    let mut merged_vv = h.vv.merge(&local_vv);
                    merged_vv.bump(&h.writer_id);
                    self.store
                        .put_note(&h.note_id, &plain, &merged_vv.to_bytes(), h.deleted)?;
                    Ok(MergeOutcome::Conflict {
                        note_id: h.note_id.clone(),
                        winner: h.writer_id.clone(),
                        conflict_copy: conflict_id,
                    })
                } else {
                    // Local wins; preserve incoming as conflict copy.
                    let conflict_id =
                        conflict_copy_id(&h.note_id, &h.writer_id, h.vv.total());
                    self.store
                        .put_note(&conflict_id, &plain, &h.vv.to_bytes(), h.deleted)?;
                    let mut merged_vv = local_vv.merge(&h.vv);
                    merged_vv.bump(&self.device_id); // == winner here
                    // Re-stamp local record with merged vv so the conflict resolves next round.
                    if let Ok(rec) = self.store.get_note(&h.note_id) {
                        let local_plain = self.store.open_payload(&rec.payload_sealed)?;
                        self.store.put_note(
                            &h.note_id,
                            &local_plain,
                            &merged_vv.to_bytes(),
                            rec.deleted,
                        )?;
                    }
                    Ok(MergeOutcome::Conflict {
                        note_id: h.note_id.clone(),
                        winner: self.device_id.clone(),
                        conflict_copy: conflict_id,
                    })
                }
            }
        }
    }
}

/// Deterministic winner for concurrent edits.
/// Higher total edits wins; then later timestamp; then lexicographically
/// smaller writer id. Same inputs -> same winner on every device.
fn pick_winner(
    w1: &str,
    total1: u64,
    ts1: i64,
    w2: &str,
    total2: u64,
    ts2: i64,
) -> String {
    let k1 = (std::cmp::Reverse(total1), std::cmp::Reverse(ts1), w1);
    let k2 = (std::cmp::Reverse(total2), std::cmp::Reverse(ts2), w2);
    if k1 <= k2 {
        w1.to_string()
    } else {
        w2.to_string()
    }
}

fn conflict_copy_id(note_id: &str, writer: &str, total: u64) -> String {
    format!("{}/conflict/{}/{}", note_id, writer, total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use noter_crypto::SecretBytes;

    fn master() -> SecretBytes {
        SecretBytes::new([0x55u8; 32])
    }

    struct Dev<'a> {
        eng: SyncEngine<'a>,
        _id: DeviceIdentity,
    }

    fn device<'a>(name: &str, store: &'a Store) -> (DeviceIdentity, SyncEngine<'a>) {
        let id = DeviceIdentity::generate();
        let eng = SyncEngine::new(name, id_clone(&id), master(), store);
        (id, eng)
    }

    fn id_clone(id: &DeviceIdentity) -> DeviceIdentity {
        let seed = id.export_seed();
        DeviceIdentity::import_seed(&seed).unwrap()
    }

    fn pair(a: &mut SyncEngine, b: &mut SyncEngine, ida: &DeviceIdentity, idb: &DeviceIdentity) {
        a.add_peer(b.device_id(), idb.public());
        b.add_peer(a.device_id(), ida.public());
    }

    #[test]
    fn two_way_sync() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let (ida, mut ea) = device("a", &sa);
        let (idb, mut eb) = device("b", &sb);
        pair(&mut ea, &mut eb, &ida, &idb);

        ea.put_local("n1", b"{\"body\":\"hello\"}", false).unwrap();
        let envs = ea.export(0).unwrap();
        assert_eq!(envs.len(), 1);
        let out = eb.import(&envs).unwrap();
        assert_eq!(out, vec![MergeOutcome::Applied { note_id: "n1".into() }]);
        let rec = sb.get_note("n1").unwrap();
        assert_eq!(sb.open_payload(&rec.payload_sealed).unwrap(), b"{\"body\":\"hello\"}");

        // Edit on b, sync back to a.
        eb.put_local("n1", b"{\"body\":\"world\"}", false).unwrap();
        let envs = eb.export(0).unwrap();
        let out = ea.import(&envs).unwrap();
        assert!(matches!(out[0], MergeOutcome::Applied { .. }));
        let rec = sa.get_note("n1").unwrap();
        assert_eq!(sa.open_payload(&rec.payload_sealed).unwrap(), b"{\"body\":\"world\"}");
    }

    #[test]
    fn concurrent_edits_resolve_deterministically_with_conflict_copy() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let (ida, mut ea) = device("a", &sa);
        let (idb, mut eb) = device("b", &sb);
        pair(&mut ea, &mut eb, &ida, &idb);

        // Seed n1 on both via sync.
        ea.put_local("n1", b"v0", false).unwrap();
        eb.import(&ea.export(0).unwrap()).unwrap();

        // Concurrent edits: a -> "va", b -> "vb".
        ea.put_local("n1", b"va", false).unwrap();
        eb.put_local("n1", b"vb", false).unwrap();
        let envs_b = eb.export(0).unwrap();
        assert_eq!(envs_b.len(), 1);

        // ea imports first: sees the conflict, resolves deterministically.
        let out_a = ea.import(&envs_b).unwrap();
        assert_eq!(out_a.len(), 1);
        let (winner_a, cc_a) = match &out_a[0] {
            MergeOutcome::Conflict { winner, conflict_copy, .. } => {
                (winner.clone(), conflict_copy.clone())
            }
            o => panic!("expected conflict, got {:?}", o),
        };

        // eb imports ea's resolution (conflict copy + resolved note, either order):
        // no new conflict — the resolution dominates.
        let out_b = eb.import(&ea.export(0).unwrap()).unwrap();
        assert!(out_b.iter().all(|o| matches!(o, MergeOutcome::Applied { .. })));
        assert_eq!(out_b.len(), 2);

        // Converged: identical live content on both devices.
        let pa = sa.open_payload(&sa.get_note("n1").unwrap().payload_sealed).unwrap();
        let pb = sb.open_payload(&sb.get_note("n1").unwrap().payload_sealed).unwrap();
        assert_eq!(pa, pb);
        let winner_body = if winner_a == "a" { b"va".as_slice() } else { b"vb".as_slice() };
        assert_eq!(pa, winner_body);

        // Loser preserved as conflict copy on both devices.
        let loser = if winner_a == "a" { "b" } else { "a" };
        assert!(cc_a.contains(loser));
        for store in [&sa, &sb] {
            let copies: Vec<_> = store
                .list_notes(true)
                .unwrap()
                .into_iter()
                .filter(|r| r.note_id.contains("/conflict/"))
                .collect();
            assert_eq!(copies.len(), 1);
            assert!(copies[0].note_id.contains(loser));
            let loser_body = if loser == "a" { b"va".as_slice() } else { b"vb".as_slice() };
            assert_eq!(
                store.open_payload(&copies[0].payload_sealed).unwrap(),
                loser_body
            );
        }
    }

    #[test]
    fn simultaneous_conflict_both_sides_agree_then_converge() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let (ida, mut ea) = device("a", &sa);
        let (idb, mut eb) = device("b", &sb);
        pair(&mut ea, &mut eb, &ida, &idb);

        ea.put_local("n1", b"v0", false).unwrap();
        eb.import(&ea.export(0).unwrap()).unwrap();
        ea.put_local("n1", b"va", false).unwrap();
        eb.put_local("n1", b"vb", false).unwrap();

        // Capture both sides' envelopes BEFORE either imports (simultaneous).
        let envs_a = ea.export(0).unwrap();
        let envs_b = eb.export(0).unwrap();

        // Both see the conflict...
        let out_a = ea.import(&envs_b).unwrap();
        let out_b = eb.import(&envs_a).unwrap();
        let w_a = match &out_a[0] {
            MergeOutcome::Conflict { winner, .. } => winner.clone(),
            o => panic!("a: expected conflict, got {:?}", o),
        };
        let w_b = match &out_b[0] {
            MergeOutcome::Conflict { winner, .. } => winner.clone(),
            o => panic!("b: expected conflict, got {:?}", o),
        };
        // ...and agree on the winner with identical resolution vectors.
        assert_eq!(w_a, w_b);
        let va = VersionVector::from_bytes(&sa.get_note("n1").unwrap().vv);
        let vb = VersionVector::from_bytes(&sb.get_note("n1").unwrap().vv);
        assert_eq!(va, vb);

        // Cross-sync after: idempotent, no flapping, no new conflicts.
        let out_a2 = ea.import(&eb.export(0).unwrap()).unwrap();
        let out_b2 = eb.import(&ea.export(0).unwrap()).unwrap();
        assert!(out_a2.iter().all(|o| !matches!(o, MergeOutcome::Conflict { .. })));
        assert!(out_b2.iter().all(|o| !matches!(o, MergeOutcome::Conflict { .. })));
        let pa = sa.open_payload(&sa.get_note("n1").unwrap().payload_sealed).unwrap();
        let pb = sb.open_payload(&sb.get_note("n1").unwrap().payload_sealed).unwrap();
        assert_eq!(pa, pb);
    }

    #[test]
    fn replayed_old_envelope_ignored() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let (ida, mut ea) = device("a", &sa);
        let (idb, mut eb) = device("b", &sb);
        pair(&mut ea, &mut eb, &ida, &idb);

        ea.put_local("n1", b"v1", false).unwrap();
        let old = ea.export(0).unwrap();
        eb.import(&old).unwrap();
        ea.put_local("n1", b"v2", false).unwrap();
        eb.import(&ea.export(0).unwrap()).unwrap();
        // Replay the stale envelope: dominated -> ignored.
        let out = eb.import(&old).unwrap();
        assert!(matches!(out[0], MergeOutcome::Ignored { .. }));
        let rec = sb.get_note("n1").unwrap();
        assert_eq!(sb.open_payload(&rec.payload_sealed).unwrap(), b"v2");
    }

    #[test]
    fn unknown_writer_rejected() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let (ida, mut ea) = device("a", &sa);
        let (_idb, mut eb) = device("b", &sb);
        // NOT paired.
        ea.put_local("n1", b"v1", false).unwrap();
        let envs = ea.export(0).unwrap();
        let _ = (&ida, &mut ea, &mut eb);
        assert!(matches!(
            eb.import(&envs),
            Err(SyncError::UnknownWriter(_))
        ));
    }

    #[test]
    fn identity_spoof_rejected() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let (ida, mut ea) = device("a", &sa);
        let (idb, mut eb) = device("b", &sb);
        pair(&mut ea, &mut eb, &ida, &idb);

        ea.put_local("n1", b"v1", false).unwrap();
        let mut envs = ea.export(0).unwrap();
        // Attacker swaps the claimed writer identity bytes but can't forge the sig.
        envs[0].header.writer_pub = idb.public();
        assert!(eb.import(&envs).is_err());
    }

    #[test]
    fn tombstone_propagates() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let (ida, mut ea) = device("a", &sa);
        let (idb, mut eb) = device("b", &sb);
        pair(&mut ea, &mut eb, &ida, &idb);

        ea.put_local("n1", b"v1", false).unwrap();
        eb.import(&ea.export(0).unwrap()).unwrap();
        ea.put_local("n1", b"v1", true).unwrap();
        let out = eb.import(&ea.export(0).unwrap()).unwrap();
        assert!(matches!(out[0], MergeOutcome::Applied { .. }));
        assert!(sb.get_note("n1").unwrap().deleted);
    }
}
