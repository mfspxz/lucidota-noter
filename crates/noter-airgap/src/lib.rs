//! NOTER airgap export/import (noter-006).
//!
//! Move notes between devices with **no network at all**: the sync envelopes
//! are sealed into one bundle (airgap subkey `noter/airgap/v1`), base64'd,
//! and split into QR-sized frames:
//!
//! ```text
//! NTR1/<seq:05>/<total:05>/<cksum8>/<base64 chunk>
//! ```
//!
//! - Each frame is plain ASCII, QR-encodable (byte mode), ≤ ~1.3KB.
//! - `cksum8` = first 8 hex chars of BLAKE3(whole sealed bundle); every frame
//!   carries it, so a frame from a different bundle is rejected on sight.
//! - Frames can be scanned in any order; import reassembles, verifies the
//!   checksum, decrypts, and feeds the envelopes to [`SyncEngine::import`].
//! - File transfer is the degenerate case: the whole bundle as one frame
//!   (or raw bytes) written to disk / USB stick.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use noter_crypto::{decrypt, derive_subkey, encrypt, SecretBytes};
use noter_sync::{Envelope, MergeOutcome, SyncEngine};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const AIRGAP_CTX: &[u8] = b"noter/airgap/v1";
/// Base64 chars per frame — keeps each frame comfortably QR-scannable.
pub const CHUNK: usize = 1200;
const MAGIC: &str = "NTR1";

#[derive(Debug, Error)]
pub enum AirgapError {
    #[error("crypto: {0}")]
    Crypto(#[from] noter_crypto::CryptoError),
    #[error("sync: {0}")]
    Sync(#[from] noter_sync::SyncError),
    #[error("frame error: {0}")]
    Frame(&'static str),
    #[error("checksum mismatch: frames from different bundles mixed")]
    ChecksumMismatch,
    #[error("missing {0} of {1} frames")]
    Incomplete(usize, usize),
    #[error("serialization: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Serialize, Deserialize)]
struct Bundle {
    v: u8,
    from_device: String,
    envelopes: Vec<Envelope>,
}

/// Export envelopes changed since `since_ms` as an airgap bundle.
pub fn export_bundle(
    engine: &SyncEngine,
    master: &SecretBytes,
    since_ms: i64,
) -> Result<Vec<u8>, AirgapError> {
    let envelopes = engine.export(since_ms)?;
    let bundle = Bundle {
        v: 1,
        from_device: engine.device_id().to_string(),
        envelopes,
    };
    let json = serde_json::to_vec(&bundle)?;
    let key = derive_subkey(master, AIRGAP_CTX);
    Ok(encrypt(&key, &json))
}

fn checksum(sealed: &[u8]) -> String {
    let h = blake3::hash(sealed);
    h.to_hex()[..8].to_string()
}

/// Split a sealed bundle into QR-sized text frames.
pub fn to_frames(sealed_bundle: &[u8]) -> Vec<String> {
    let b64 = B64.encode(sealed_bundle);
    let ck = checksum(sealed_bundle);
    let chunks: Vec<&str> = b64
        .as_bytes()
        .chunks(CHUNK)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    let total = chunks.len().max(1);
    if chunks.is_empty() {
        return vec![format!("{}/{:05}/{:05}/{}/", MAGIC, 0, 1, ck)];
    }
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, c)| format!("{}/{:05}/{:05}/{}/{}", MAGIC, i, total, ck, c))
        .collect()
}

/// Parse + reassemble frames (any order) into the sealed bundle.
pub fn from_frames(frames: &[String]) -> Result<Vec<u8>, AirgapError> {
    if frames.is_empty() {
        return Err(AirgapError::Frame("no frames"));
    }
    let mut total: Option<usize> = None;
    let mut ck: Option<String> = None;
    let mut parts: Vec<Option<String>> = Vec::new();
    for f in frames {
        let mut it = f.splitn(5, '/');
        let magic = it.next().ok_or(AirgapError::Frame("bad frame"))?;
        if magic != MAGIC {
            return Err(AirgapError::Frame("bad magic"));
        }
        let seq: usize = it
            .next()
            .ok_or(AirgapError::Frame("bad seq"))?
            .parse()
            .map_err(|_| AirgapError::Frame("bad seq"))?;
        let tot: usize = it
            .next()
            .ok_or(AirgapError::Frame("bad total"))?
            .parse()
            .map_err(|_| AirgapError::Frame("bad total"))?;
        let c = it.next().ok_or(AirgapError::Frame("bad checksum"))?.to_string();
        let chunk = it.next().ok_or(AirgapError::Frame("bad chunk"))?.to_string();
        match total {
            Some(t) if t != tot => return Err(AirgapError::Frame("total mismatch")),
            Some(_) => {}
            None => {
                total = Some(tot);
                parts = vec![None; tot];
            }
        }
        match &ck {
            Some(k) if *k != c => return Err(AirgapError::ChecksumMismatch),
            Some(_) => {}
            None => ck = Some(c),
        }
        if seq >= tot {
            return Err(AirgapError::Frame("seq out of range"));
        }
        if parts[seq].is_some() {
            return Err(AirgapError::Frame("duplicate frame"));
        }
        parts[seq] = Some(chunk);
    }
    let total = total.unwrap();
    let missing = parts.iter().filter(|p| p.is_none()).count();
    if missing > 0 {
        return Err(AirgapError::Incomplete(missing, total));
    }
    let b64: String = parts.into_iter().map(|p| p.unwrap()).collect();
    let sealed = B64.decode(b64.as_bytes())?;
    if checksum(&sealed) != ck.unwrap() {
        return Err(AirgapError::ChecksumMismatch);
    }
    Ok(sealed)
}

/// Decrypt a reassembled bundle and import its envelopes.
pub fn import_bundle(
    sealed_bundle: &[u8],
    master: &SecretBytes,
    engine: &SyncEngine,
) -> Result<Vec<MergeOutcome>, AirgapError> {
    let key = derive_subkey(master, AIRGAP_CTX);
    let json = decrypt(&key, sealed_bundle)?;
    let bundle: Bundle = serde_json::from_slice(&json)?;
    if bundle.v != 1 {
        return Err(AirgapError::Frame("unsupported bundle version"));
    }
    Ok(engine.import(&bundle.envelopes)?)
}

/// Full airgap round: frames -> bundle -> import.
pub fn import_frames(
    frames: &[String],
    master: &SecretBytes,
    engine: &SyncEngine,
) -> Result<Vec<MergeOutcome>, AirgapError> {
    let sealed = from_frames(frames)?;
    import_bundle(&sealed, master, engine)
}

/// Write frames to a file (USB-stick sneakernet), one per line.
pub fn write_file(frames: &[String], path: &std::path::Path) -> Result<(), AirgapError> {
    Ok(std::fs::write(path, frames.join("\n"))?)
}

/// Read frames back from a file.
pub fn read_file(path: &std::path::Path) -> Result<Vec<String>, AirgapError> {
    let text = std::fs::read_to_string(path)?;
    Ok(text.lines().map(|l| l.to_string()).collect())
}

/// Check every frame QR-encodes (byte mode). Used by tests to prove
/// QR-transferability without shipping an image pipeline.
pub fn frames_qr_encodable(frames: &[String]) -> bool {
    use qrcode::QrCode;
    frames.iter().all(|f| QrCode::new(f.as_bytes()).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use noter_crypto::{DeviceIdentity, SecretBytes};
    use noter_store::Store;

    fn master() -> SecretBytes {
        SecretBytes::new([0x66u8; 32])
    }

    fn paired<'a>(a: &mut SyncEngine<'a>, b: &mut SyncEngine<'a>, ia: &DeviceIdentity, ib: &DeviceIdentity) {
        a.add_peer(b.device_id(), ib.public());
        b.add_peer(a.device_id(), ia.public());
    }

    #[test]
    fn airgap_roundtrip_shuffled_frames() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let ida = DeviceIdentity::generate();
        let idb = DeviceIdentity::generate();
        let mut ea = SyncEngine::new(
            "a",
            DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
            master(),
            &sa,
        );
        let mut eb = SyncEngine::new(
            "b",
            DeviceIdentity::import_seed(&idb.export_seed()).unwrap(),
            master(),
            &sb,
        );
        paired(&mut ea, &mut eb, &ida, &idb);

        for i in 0..5 {
            ea.put_local(&format!("n{}", i), format!("{{\"i\":{}}}", i).as_bytes(), false)
                .unwrap();
        }
        let sealed = export_bundle(&ea, &master(), 0).unwrap();
        let mut frames = to_frames(&sealed);
        assert!(frames.len() >= 2);
        // Shuffle: import must not care about order.
        frames.reverse();
        let outcomes = import_frames(&frames, &master(), &eb).unwrap();
        assert_eq!(outcomes.len(), 5);
        assert!(outcomes.iter().all(|o| matches!(o, MergeOutcome::Applied { .. })));
        for i in 0..5 {
            let rec = sb.get_note(&format!("n{}", i)).unwrap();
            let plain = sb.open_payload(&rec.payload_sealed).unwrap();
            assert_eq!(plain, format!("{{\"i\":{}}}", i).as_bytes());
        }
    }

    #[test]
    fn missing_frame_detected() {
        let sa = Store::open_memory(&master()).unwrap();
        let ida = DeviceIdentity::generate();
        let ea = SyncEngine::new(
            "a",
            DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
            master(),
            &sa,
        );
        ea.put_local("n1", &vec![b'x'; 5000], false).unwrap();
        let sealed = export_bundle(&ea, &master(), 0).unwrap();
        let mut frames = to_frames(&sealed);
        assert!(frames.len() > 1);
        frames.pop();
        assert!(matches!(
            from_frames(&frames),
            Err(AirgapError::Incomplete(_, _))
        ));
    }

    #[test]
    fn tampered_chunk_rejected() {
        let sa = Store::open_memory(&master()).unwrap();
        let ida = DeviceIdentity::generate();
        let ea = SyncEngine::new(
            "a",
            DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
            master(),
            &sa,
        );
        ea.put_local("n1", b"hello", false).unwrap();
        let sealed = export_bundle(&ea, &master(), 0).unwrap();
        let mut frames = to_frames(&sealed);
        // Corrupt a chunk's base64 body (keep structure valid).
        let f = frames[0].clone();
        let mut parts: Vec<&str> = f.splitn(5, '/').collect();
        let mut chunk = parts[4].to_string().into_bytes();
        chunk[10] ^= 1;
        parts[4] = std::str::from_utf8(&chunk).unwrap_or(parts[4]);
        frames[0] = parts.join("/");
        assert!(from_frames(&frames).is_err());
    }

    #[test]
    fn mixed_bundle_frames_rejected() {
        let sa = Store::open_memory(&master()).unwrap();
        let ida = DeviceIdentity::generate();
        let ea = SyncEngine::new(
            "a",
            DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
            master(),
            &sa,
        );
        ea.put_local("n1", b"one", false).unwrap();
        let f1 = to_frames(&export_bundle(&ea, &master(), 0).unwrap());
        ea.put_local("n2", b"two", false).unwrap();
        let f2 = to_frames(&export_bundle(&ea, &master(), 0).unwrap());
        let mut mixed = vec![f1[0].clone(), f2[0].clone()];
        mixed.sort();
        mixed.dedup();
        // Different checksums -> mismatch (unless single-frame bundles coincide).
        if f1.len() > 0 && f2.len() > 0 {
            let r = from_frames(&[f1[0].clone(), f2[0].clone()]);
            assert!(r.is_err());
        }
    }

    #[test]
    fn wrong_master_cannot_import() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let ida = DeviceIdentity::generate();
        let idb = DeviceIdentity::generate();
        let mut ea = SyncEngine::new(
            "a",
            DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
            master(),
            &sa,
        );
        let mut eb = SyncEngine::new(
            "b",
            DeviceIdentity::import_seed(&idb.export_seed()).unwrap(),
            master(),
            &sb,
        );
        paired(&mut ea, &mut eb, &ida, &idb);
        ea.put_local("n1", b"secret", false).unwrap();
        let frames = to_frames(&export_bundle(&ea, &master(), 0).unwrap());
        let wrong = SecretBytes::new([0x77u8; 32]);
        assert!(import_frames(&frames, &wrong, &eb).is_err());
    }

    #[test]
    fn file_sneakernet_roundtrip() {
        let sa = Store::open_memory(&master()).unwrap();
        let sb = Store::open_memory(&master()).unwrap();
        let ida = DeviceIdentity::generate();
        let idb = DeviceIdentity::generate();
        let mut ea = SyncEngine::new(
            "a",
            DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
            master(),
            &sa,
        );
        let mut eb = SyncEngine::new(
            "b",
            DeviceIdentity::import_seed(&idb.export_seed()).unwrap(),
            master(),
            &sb,
        );
        paired(&mut ea, &mut eb, &ida, &idb);
        ea.put_local("n1", b"via usb stick", false).unwrap();
        let frames = to_frames(&export_bundle(&ea, &master(), 0).unwrap());
        let dir = std::env::temp_dir().join(format!("airgap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bundle.ntr");
        write_file(&frames, &path).unwrap();
        let back = read_file(&path).unwrap();
        assert_eq!(back, frames);
        let outcomes = import_frames(&back, &master(), &eb).unwrap();
        assert_eq!(outcomes.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn frames_are_qr_encodable() {
        let sa = Store::open_memory(&master()).unwrap();
        let ida = DeviceIdentity::generate();
        let ea = SyncEngine::new(
            "a",
            DeviceIdentity::import_seed(&ida.export_seed()).unwrap(),
            master(),
            &sa,
        );
        ea.put_local("n1", &vec![b'y'; 3000], false).unwrap();
        let frames = to_frames(&export_bundle(&ea, &master(), 0).unwrap());
        assert!(frames.len() >= 2);
        assert!(frames_qr_encodable(&frames));
        // And every frame is comfortably small for real scanners.
        assert!(frames.iter().all(|f| f.len() <= 1400));
    }
}
