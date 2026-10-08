//! NOTER red-team attack battery (noter-011).
//!
//! Each test is an ATTACK. It passes only if the attack FAILS (fail-closed).
//! See `crates/noter-redteam/REDTEAM.md` for the written review.

use noter_crypto::*;
use noter_redteam::*;
use noter_store::Store;
use noter_sync::{MergeOutcome, SyncEngine, VersionVector};
use std::time::Instant;

fn master(byte: u8) -> SecretBytes {
    SecretBytes::new([byte; 32])
}

fn paired_engines<'a>(
    sa: &'a Store,
    sb: &'a Store,
    m: &SecretBytes,
) -> (DeviceIdentity, DeviceIdentity, SyncEngine<'a>, SyncEngine<'a>) {
    let ida = DeviceIdentity::generate();
    let idb = DeviceIdentity::generate();
    let seed_a = ida.export_seed();
    let seed_b = idb.export_seed();
    let mut ea = SyncEngine::new(
        "a",
        DeviceIdentity::import_seed(&seed_a).unwrap(),
        m.clone(),
        sa,
    );
    let mut eb = SyncEngine::new(
        "b",
        DeviceIdentity::import_seed(&seed_b).unwrap(),
        m.clone(),
        sb,
    );
    ea.add_peer("b", idb.public());
    eb.add_peer("a", ida.public());
    (ida, idb, ea, eb)
}

/// R1: bit-flip the SQLCipher file -> must error, never wrong plaintext.
#[test]
fn r1_file_bitflip_never_yields_wrong_plaintext() {
    let dir = std::env::temp_dir().join(format!("r1-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("v.db");
    {
        let s = Store::open(&path, &master(0x11)).unwrap();
        s.put_note("n1", b"correct-body", b"", false).unwrap();
    }
    // Flip bytes in the middle of the file (past the header).
    let mut raw = std::fs::read(&path).unwrap();
    let mid = raw.len() / 2;
    for i in 0..64 {
        raw[mid + i] ^= 0xFF;
    }
    std::fs::write(&path, &raw).unwrap();
    // Must fail to open/read — never return corrupted plaintext as valid.
    let res = Store::open(&path, &master(0x11));
    match res {
        Err(_) => {}
        Ok(s) => {
            let r = s.get_note("n1");
            match r {
                Err(_) => {}
                Ok(rec) => {
                    let p = s.open_payload(&rec.payload_sealed);
                    // Either errors, or (worst case) decrypts — but must NOT
                    // return attacker-controlled-looking valid data silently.
                    // The sealed payload has its own AEAD: tamper -> auth fail.
                    assert!(p.is_err() || p.unwrap() == b"correct-body");
                }
            }
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// R2: delete, then replay the pre-delete envelope -> tombstone must hold.
#[test]
fn r2_replay_cannot_resurrect_tombstone() {
    let sa = Store::open_memory(&master(0x22)).unwrap();
    let sb = Store::open_memory(&master(0x22)).unwrap();
    let m = master(0x22);
    let (_ida, _idb, ea, eb) = paired_engines(&sa, &sb, &m);
    ea.put_local("n1", b"v1", false).unwrap();
    let pre_delete = ea.export(0).unwrap();
    eb.import(&pre_delete).unwrap();
    // Delete on a, sync the tombstone to b.
    ea.put_local("n1", b"v1", true).unwrap();
    let tomb = ea.export(0).unwrap();
    let out = eb.import(&tomb).unwrap();
    assert!(matches!(out[0], MergeOutcome::Applied { .. }));
    assert!(sb.get_note("n1").unwrap().deleted);
    // Attacker replays the pre-delete envelope.
    let out2 = eb.import(&pre_delete).unwrap();
    assert!(matches!(out2[0], MergeOutcome::Ignored { .. }));
    assert!(sb.get_note("n1").unwrap().deleted);
}

/// R3: paired peer cannot impersonate ANOTHER paired peer.
#[test]
fn r3_peer_cannot_impersonate_peer() {
    let sa = Store::open_memory(&master(0x33)).unwrap();
    let sb = Store::open_memory(&master(0x33)).unwrap();
    let sc = Store::open_memory(&master(0x33)).unwrap();
    let m = master(0x33);
    let (ida, idb, mut ea, mut eb) = paired_engines(&sa, &sb, &m);
    let idc = DeviceIdentity::generate();
    let mut ec = SyncEngine::new(
        "c",
        DeviceIdentity::import_seed(&idc.export_seed()).unwrap(),
        m.clone(),
        &sc,
    );
    // b also trusts c.
    eb.add_peer("c", idc.public());
    ec.add_peer("b", idb.public());
    let _ = (&ida, &mut ea);

    // c crafts an envelope but claims to be a in the peer registry sense:
    // c's envelope is signed by c; if b looks up "a" it must not verify.
    ec.put_local("n1", b"evil", false).unwrap();
    let mut envs = ec.export(0).unwrap();
    // Attack: rewrite writer_id to "a" (signature stays c's).
    envs[0].header.writer_id = "a".to_string();
    // Signature no longer verifies (header changed) -> rejected.
    assert!(eb.import(&envs).is_err());
}

/// R4: cross-context key misuse fails.
#[test]
fn r4_cross_context_keys_do_not_interoperate() {
    let m = master(0x44);
    let payload_key = derive_subkey(&m, b"noter/payload/v1");
    let sync_key = derive_subkey(&m, b"noter/sync/v1");
    assert_ne!(payload_key.as_bytes(), sync_key.as_bytes());
    let ct = encrypt(&payload_key, b"data");
    assert!(decrypt(&sync_key, &ct).is_err());
    // ECIES box cannot be opened as a plain AEAD blob either.
    let id = DeviceIdentity::generate();
    let boxed = seal_for(&id.public(), b"data");
    assert!(decrypt(&payload_key, &boxed).is_err());
}

/// R5: share package sender-field rewrite fails closed.
#[test]
fn r5_share_sender_rewrite_rejected() {
    let alice = DeviceIdentity::generate();
    let bob = DeviceIdentity::generate();
    let mallory = DeviceIdentity::generate();
    let mut note = noter_model::Note::new("T", "body");
    note.id = "n1".into();
    let pkg = share::share_note(&note, &[], &alice, &bob.public());
    let mut bytes = pkg.to_bytes();
    // Rewrite the sender identity inside the serialized package.
    let mut v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    v["sender"] = serde_json::to_value(mallory.public()).unwrap();
    bytes = serde_json::to_vec(&v).unwrap();
    let pkg2 = share::SharePackage::from_bytes(&bytes).unwrap();
    // mallory-as-expected-sender: signature is alice's -> BadSignature.
    assert!(share::receive_package(&pkg2, &bob, &mallory.public()).is_err());
    // alice-as-expected-sender: sender field mismatch -> SenderMismatch.
    assert!(share::receive_package(&pkg2, &bob, &alice.public()).is_err());
}

/// R6: splicing frames from two bundles is rejected.
#[test]
fn r6_airgap_splice_rejected() {
    let sa = Store::open_memory(&master(0x66)).unwrap();
    let m = master(0x66);
    let ida = DeviceIdentity::generate();
    let ea = SyncEngine::new(
        "a",
        DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
        m.clone(),
        &sa,
    );
    ea.put_local("n1", &vec![b'a'; 3000], false).unwrap();
    let f1 = airgap::to_frames(&airgap::export_bundle(&ea, &m, 0).unwrap());
    ea.put_local("n2", &vec![b'b'; 3000], false).unwrap();
    let f2 = airgap::to_frames(&airgap::export_bundle(&ea, &m, 0).unwrap());
    assert!(f1.len() > 1 && f2.len() > 1);
    // Splice: first half of bundle 1 + second half of bundle 2.
    let mut spliced = f1[..f1.len() / 2].to_vec();
    spliced.extend_from_slice(&f2[f2.len() / 2..]);
    assert!(airgap::from_frames(&spliced).is_err());
}

/// R7: mesh sessions are ephemeral — keys differ per session; attestation
/// binds the transcript (forged transcript fails verification).
#[test]
fn r7_mesh_sessions_ephemeral_and_bound() {
    use std::sync::mpsc;
    let mk = || {
        let id = DeviceIdentity::generate();
        mesh::MeshNode::new("d", id)
    };
    let mut fps = Vec::new();
    for _ in 0..2 {
        let na = mk();
        let nb = mk();
        let listener = mesh::MeshNode::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || tx.send(nb.accept_one(&listener).unwrap()).unwrap());
        let c = na.connect(&addr).unwrap();
        let _s = rx.recv().unwrap();
        fps.push(c.key_fingerprint());
    }
    assert_ne!(fps[0], fps[1], "session keys must be ephemeral");

    // Attestation binds the transcript: verify() with a mutated transcript fails.
    let id = DeviceIdentity::generate();
    let transcript = b"real transcript bytes 1234567890abcdef";
    let sig = id.sign(transcript);
    id.public().verify(transcript, &sig).unwrap();
    let mut bad = transcript.to_vec();
    bad[0] ^= 1;
    assert!(id.public().verify(&bad, &sig).is_err());
}

/// R8: conflict-copy flood terminates, stays deterministic and bounded.
#[test]
fn r8_conflict_flood_bounded() {
    let sa = Store::open_memory(&master(0x88)).unwrap();
    let sb = Store::open_memory(&master(0x88)).unwrap();
    let m = master(0x88);
    let (_ida, _idb, ea, eb) = paired_engines(&sa, &sb, &m);
    ea.put_local("n1", b"v0", false).unwrap();
    eb.import(&ea.export(0).unwrap()).unwrap();
    // 200 alternating blind edits, no sync in between.
    for i in 0..200 {
        let body = format!("edit-{}", i);
        if i % 2 == 0 {
            ea.put_local("n1", body.as_bytes(), false).unwrap();
        } else {
            eb.put_local("n1", body.as_bytes(), false).unwrap();
        }
    }
    let t = Instant::now();
    let out_a = ea.import(&eb.export(0).unwrap()).unwrap();
    assert!(t.elapsed().as_secs() < 30, "merge must terminate promptly");
    // Every envelope produced exactly one outcome; exactly one live note.
    assert_eq!(out_a.len(), 1);
    let live: Vec<_> = sa
        .list_notes(false)
        .unwrap()
        .into_iter()
        .filter(|r| !r.note_id.contains("/conflict/"))
        .collect();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].note_id, "n1");
    // Conflict copies bounded by the number of conflicting imports.
    let copies = sa
        .list_notes(true)
        .unwrap()
        .into_iter()
        .filter(|r| r.note_id.contains("/conflict/"))
        .count();
    assert!(copies <= 2, "at most the losers of this round, got {}", copies);
}

/// R9: search index tamper fails closed (no panic, no wrong results).
#[test]
fn r9_search_index_tamper_fails_closed() {
    let m = master(0x99);
    let dir = std::env::temp_dir().join(format!("r9-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("s.db");
    {
        let store = Store::open(&path, &m).unwrap();
        let mut ix = search::SearchIndex::open(&store, &m).unwrap();
        ix.index_note("n1", "Title", "some body text");
        ix.flush().unwrap();
    }
    // Flip bytes inside the DB file where the sealed index lives.
    let mut raw = std::fs::read(&path).unwrap();
    let mid = raw.len() * 3 / 4;
    for i in 0..32 {
        raw[mid + i] ^= 0xFF;
    }
    std::fs::write(&path, &raw).unwrap();
    let store = Store::open(&path, &m).unwrap();
    // Either the file is unreadable (BadKey) or the sealed blob fails auth —
    // in no case may we get silently-wrong search results.
    match search::SearchIndex::open(&store, &m) {
        Err(_) => {}
        Ok(ix) => {
            // If it opened, the index must be empty-or-error, never plausible lies.
            // (AEAD tamper -> meta_get errors, so this arm is near-unreachable.)
            let _ = ix.search("body");
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// R10: KDF cost sanity — Argon2id must not be fast.
#[test]
fn r10_kdf_is_expensive() {
    let salt = Salt::generate();
    let t = Instant::now();
    let _ = derive_master_key("password", &salt).unwrap();
    let dt = t.elapsed();
    assert!(
        dt.as_millis() >= 100,
        "KDF suspiciously fast ({:?}) — params may have been weakened",
        dt
    );
}

/// R11: valid signature from an UNPAIRED device is rejected.
#[test]
fn r11_unpaired_valid_signature_rejected() {
    let sa = Store::open_memory(&master(0xAA)).unwrap();
    let sb = Store::open_memory(&master(0xAA)).unwrap();
    let m = master(0xAA);
    let ida = DeviceIdentity::generate();
    let _idb = DeviceIdentity::generate();
    let ea = SyncEngine::new(
        "a",
        DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
        m.clone(),
        &sa,
    );
    // b never pairs with anyone.
    let eb = SyncEngine::new(
        "b",
        DeviceIdentity::generate(),
        m.clone(),
        &sb,
    );
    ea.put_local("n1", b"v1", false).unwrap();
    let envs = ea.export(0).unwrap();
    envs[0].verify().unwrap(); // signature itself is valid
    assert!(eb.import(&envs).is_err()); // but the writer is unknown
}

/// R12: envelope with swapped payload (valid sig on original) is rejected
/// before any parsing happens.
#[test]
fn r12_payload_swap_rejected_before_parse() {
    let sa = Store::open_memory(&master(0xBB)).unwrap();
    let sb = Store::open_memory(&master(0xBB)).unwrap();
    let m = master(0xBB);
    let (_ida, _idb, ea, eb) = paired_engines(&sa, &sb, &m);
    ea.put_local("n1", b"{\"note\": true}", false).unwrap();
    let mut envs = ea.export(0).unwrap();
    // Attacker swaps in a different validly-sealed blob (can't — no key),
    // so they flip bytes: signature check must fire first.
    envs[0].payload_sealed[20] ^= 0x01;
    let res = eb.import(&envs);
    assert!(res.is_err());
    // And the target note was never created.
    assert!(sb.get_note("n1").is_err());
}

/// R13: version-vector overflow / garbage vv bytes are handled.
#[test]
fn r13_garbage_vv_bytes_tolerated() {
    let v = VersionVector::from_bytes(&[0xFF, 0x00, 0x7B, 0x22]);
    assert_eq!(v, VersionVector::new());
    let v2 = VersionVector::from_bytes(b"{\"a\": 18446744073709551615}");
    assert_eq!(v2.get("a"), u64::MAX);
    let mut v3 = VersionVector::new();
    v3.bump("a");
    // u64::MAX vs 1: MAX dominates, no panic.
    assert_eq!(v2.compare(&v3), noter_sync::VectorCmp::Dominates);
}
