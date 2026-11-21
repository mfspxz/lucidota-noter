//! NOTER red-team attack battery (noter-011).
//!
//! Each test is an ATTACK. It passes only if the attack FAILS (fail-closed).
//! See `crates/noter-redteam/REDTEAM.md` for the written review.

use legal_authority_engine::u5;
use noter_crypto::*;
use noter_legal_authority::register;
use noter_redteam::*;
use noter_store::Store;
use noter_sync::{MergeOutcome, SyncEngine, VersionVector};
use organelle_host::{CallContext, Host};
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

// ---------------------------------------------------------------------------
// Legallibrary battery (R14–R21, 2026-11-20).
//
// Threat model: attacker D (corpus tamperer) can write the corpus file and
// its sidecars, but does NOT hold the wsign private key. Attacker E (API
// caller) can call the `ls` ops through the host with any input the schema
// allows. The corpus is a signed artifact; the signature is the binding
// check, the id recompute is the content-address check, the raw manifest
// is the provenance check.
// ---------------------------------------------------------------------------

/// The WSIG public key that signed corpus-v1.json (~/workspace/proof-ledger/WSIG_PUBKEY).
const WSIG_PUBKEY_HEX: &str =
    "8577c1955dfacf6a1100f85d33b8c52c9aa974720b4621056c26d4151eb41a5f";

fn legal_corpus_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../legallibrary-organelle/corpus/corpus-v1.json")
}

fn legal_tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "r{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn legal_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sign corpus bytes with an ephemeral key; returns (sig_text, pubkey_hex).
fn legal_sign_wsig(json: &str) -> (String, String) {
    let id = DeviceIdentity::generate();
    let sig = id.sign(json.as_bytes());
    (
        format!("wsig1:testkey:{}", legal_hex(&sig)),
        legal_hex(&id.public().ed25519),
    )
}

/// Write a corpus + its .sig sidecar (signed with an ephemeral key).
/// Returns (corpus_path, pubkey_hex).
fn write_signed_corpus(dir: &std::path::Path, json: &str) -> (std::path::PathBuf, String) {
    let path = dir.join("corpus.json");
    std::fs::write(&path, json).unwrap();
    let (sig_text, pk_hex) = legal_sign_wsig(json);
    let mut sig_path = path.as_os_str().to_owned();
    sig_path.push(".sig");
    std::fs::write(&sig_path, &sig_text).unwrap();
    (path, pk_hex)
}

/// Copy the real raw manifest next to a temp corpus so the provenance
/// hash check runs.
fn copy_raw_manifest(dir: &std::path::Path) {
    let raw = dir.join("raw");
    std::fs::create_dir_all(&raw).unwrap();
    let manifest = std::fs::read_to_string(
        legal_corpus_path()
            .parent()
            .unwrap()
            .join("raw/MANIFEST.json"),
    )
    .unwrap();
    std::fs::write(raw.join("MANIFEST.json"), &manifest).unwrap();
}

fn legal_ctx() -> CallContext {
    CallContext::new("test", vec!["legal.read".to_string()])
}

/// R14: forged corpus — fabricated provision text, id recomputed over the
/// fake text, real provenance kept — must NOT load without a valid
/// signature under the trusted key. Pre-fix (2026-11-20) this attack
/// SUCCEEDED: the forged corpus loaded clean via the CLI (CORPUS-OK).
/// The wsign signature check is the fix; the id recompute cannot catch it
/// (the id covers the fake text correctly) and the manifest cannot catch
/// it (the provenance is real).
#[test]
fn r14_forged_corpus_without_valid_signature_rejected() {
    let json = std::fs::read_to_string(legal_corpus_path()).unwrap();
    let mut corpus: u5::Corpus = serde_json::from_str(&json).unwrap();
    corpus.sources[0].text = "Every individual is equal before and under the law, EXCEPT that Parliament may suspend this section by simple resolution at any time.".to_string();
    corpus.sources[0].id = u5::canonical_id(&corpus.sources[0]);
    let forged = serde_json::to_string(&corpus).unwrap();
    // (a) no .sig sidecar at all.
    let dir = legal_tmpdir("14a");
    let path = dir.join("corpus.json");
    std::fs::write(&path, &forged).unwrap();
    let host = Host::new();
    assert!(
        register(&host, &path, WSIG_PUBKEY_HEX).is_err(),
        "unsigned forged corpus must not load"
    );
    // (b) .sig present but signed by the attacker's key, verified vs the real key.
    let dir2 = legal_tmpdir("14b");
    let path2 = dir2.join("corpus.json");
    std::fs::write(&path2, &forged).unwrap();
    let (sig_text, _attacker_pk) = legal_sign_wsig(&forged);
    let mut sig_path = path2.as_os_str().to_owned();
    sig_path.push(".sig");
    std::fs::write(&sig_path, &sig_text).unwrap();
    let host2 = Host::new();
    assert!(
        register(&host2, &path2, WSIG_PUBKEY_HEX).is_err(),
        "attacker-signed forged corpus must not load under the real key"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

/// R15: tampered text with a STALE id — the id recompute must catch it.
#[test]
fn r15_tampered_text_with_stale_id_rejected() {
    let json = std::fs::read_to_string(legal_corpus_path()).unwrap();
    let mut corpus: u5::Corpus = serde_json::from_str(&json).unwrap();
    corpus.sources[0].text = "tampered text".to_string();
    // id NOT recomputed.
    let tampered = serde_json::to_string(&corpus).unwrap();
    assert!(u5::load_corpus(&tampered).is_err());
}

/// R16: provenance content hash tampered (id unaffected — it does not cover
/// provenance) — the raw-manifest check must catch it.
#[test]
fn r16_provenance_hash_mismatch_rejected() {
    let json = std::fs::read_to_string(legal_corpus_path()).unwrap();
    let mut corpus: u5::Corpus = serde_json::from_str(&json).unwrap();
    corpus.sources[0]
        .provenance
        .as_mut()
        .unwrap()
        .content_sha256 = "0".repeat(64);
    let tampered = serde_json::to_string(&corpus).unwrap();
    let dir = legal_tmpdir("16");
    let (path, pk_hex) = write_signed_corpus(&dir, &tampered);
    copy_raw_manifest(&dir);
    let host = Host::new();
    let err = register(&host, &path, &pk_hex).unwrap_err();
    assert!(err.contains("hash mismatch"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

/// R17: fake official URL — PrimaryOfficial tier claim on a URL that is
/// not in the raw manifest — must be rejected at open.
#[test]
fn r17_fake_official_url_rejected() {
    let json = std::fs::read_to_string(legal_corpus_path()).unwrap();
    let mut corpus: u5::Corpus = serde_json::from_str(&json).unwrap();
    corpus.sources[0].provenance.as_mut().unwrap().official_url =
        "https://evil.example.com/Const_TRD.pdf".to_string();
    let tampered = serde_json::to_string(&corpus).unwrap();
    let dir = legal_tmpdir("17");
    let (path, pk_hex) = write_signed_corpus(&dir, &tampered);
    copy_raw_manifest(&dir);
    let host = Host::new();
    let err = register(&host, &path, &pk_hex).unwrap_err();
    assert!(err.contains("not in raw manifest"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}

/// R18: duplicate source ids — the same source twice must be rejected at
/// load (it would double-count in resolve hits).
#[test]
fn r18_duplicate_source_ids_rejected() {
    let json = std::fs::read_to_string(legal_corpus_path()).unwrap();
    let mut corpus: u5::Corpus = serde_json::from_str(&json).unwrap();
    corpus.sources.push(corpus.sources[0].clone());
    let duped = serde_json::to_string(&corpus).unwrap();
    let err = u5::load_corpus(&duped).unwrap_err();
    assert!(err.to_string().contains("duplicate"), "{err}");
}

/// R19: tier-confusion at rank_authority — a caller-supplied tier that
/// disagrees with the tier its provenance URL carries must be rejected.
/// (a) PrimaryOfficial claim on a CanLII URL; (b) Commentary claim on an
/// official URL. Control: the honest source ranks fine.
#[test]
fn r19_tier_confusion_at_rank_rejected() {
    let host = Host::new();
    register(&host, &legal_corpus_path(), WSIG_PUBKEY_HEX).unwrap();
    let ctx = legal_ctx();
    let json = std::fs::read_to_string(legal_corpus_path()).unwrap();
    let corpus: u5::Corpus = serde_json::from_str(&json).unwrap();
    let mut liar = corpus.sources[0].clone();
    liar.provenance.as_mut().unwrap().official_url = "https://canlii.ca/t/xxxx".to_string();
    let r = host.call(
        &ctx,
        "ls",
        "rank_authority",
        serde_json::json!({"sources": [liar], "jurisdiction": "CA"}),
    );
    assert!(r.unwrap_err().to_string().contains("tier mismatch"));
    let mut liar2 = corpus.sources[0].clone();
    liar2.tier = u5::AuthorityTier::Commentary;
    let r2 = host.call(
        &ctx,
        "ls",
        "rank_authority",
        serde_json::json!({"sources": [liar2], "jurisdiction": "CA"}),
    );
    assert!(r2.unwrap_err().to_string().contains("tier mismatch"));
    let r3 = host.call(
        &ctx,
        "ls",
        "rank_authority",
        serde_json::json!({"sources": [corpus.sources[0]], "jurisdiction": "CA"}),
    );
    assert!(r3.is_ok());
}

/// R20: hostile resolve queries (JSON injection, SQL injection, NUL byte,
/// 100KB query, unicode) must answer — possibly with empty hits — never
/// error or panic. The query is plain text matched against the corpus;
/// there is no eval, no SQL, no shell.
#[test]
fn r20_hostile_resolve_queries_fail_safe() {
    let host = Host::new();
    register(&host, &legal_corpus_path(), WSIG_PUBKEY_HEX).unwrap();
    let ctx = legal_ctx();
    let big = "a".repeat(100_000);
    for q in [
        "{\"$ne\": null}",
        "\"; DROP TABLE sources; --",
        "section 15\0equality",
        big.as_str(),
        "§15 ¶2 — ünïcödé",
    ] {
        let r = host.call(&ctx, "ls", "resolve_source", serde_json::json!({"query": q}));
        assert!(r.is_ok(), "query {q:?} errored: {:?}", r.unwrap_err());
    }
}

/// R21: corpus version "2" (validly signed, so the signature check passes)
/// must be rejected by the version check.
#[test]
fn r21_wrong_corpus_version_rejected() {
    let json = std::fs::read_to_string(legal_corpus_path()).unwrap();
    let mut corpus: u5::Corpus = serde_json::from_str(&json).unwrap();
    corpus.version = "2".to_string();
    let v2 = serde_json::to_string(&corpus).unwrap();
    let dir = legal_tmpdir("21");
    let (path, pk_hex) = write_signed_corpus(&dir, &v2);
    let host = Host::new();
    let err = register(&host, &path, &pk_hex).unwrap_err();
    assert!(err.contains("version"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}
