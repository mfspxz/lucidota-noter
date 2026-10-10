//! NOTER-013: append-only JSONL security-event log.
//!
//! Records what the crypto core *rejects*: failed unlocks, failed
//! decryptions, rejected envelopes, unknown writers, invalid signatures,
//! malformed frames. Append-only; one JSON object per line:
//! `{"ts":<unix_secs>,"kind":"<EventKind>","detail":"<free text>"}`.
//!
//! The log is a user-reviewable audit trail, not a control: logging
//! failures must NEVER break the operation being logged (callers use
//! `record()` and ignore its `Err`, or the `log()` convenience).

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Security-relevant events. Serialized as their variant name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventKind {
    /// Vault open failed (wrong passphrase or corrupt/tampered file).
    UnlockFailed,
    /// AEAD decryption rejected (wrong key, bit-flip, tamper).
    DecryptFailed,
    /// Sync envelope failed verification (bad sig, stale, malformed).
    EnvelopeRejected,
    /// Envelope signed by a device that is not paired.
    UnknownWriter,
    /// Signature present but invalid for the claimed writer.
    SignatureInvalid,
    /// Share package sender does not match the package signature.
    SenderMismatch,
    /// Mesh/airgap frame could not be parsed.
    BadFrame,
}

/// One recorded event, as stored on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub ts: u64,
    pub kind: EventKind,
    pub detail: String,
}

/// Append-only security-event log. Internally synchronized so an `&App`
/// can record from shared references.
pub struct AuditLog {
    file: Mutex<File>,
}

impl AuditLog {
    /// Open (creating if needed) the log file for appending.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Mutex::new(file),
        })
    }

    /// Record one event. Fails only on IO errors; callers logging from
    /// error paths should ignore the result (fail-open logging).
    pub fn record(&self, kind: EventKind, detail: &str) -> io::Result<()> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let rec = Record {
            ts,
            kind,
            detail: detail.to_string(),
        };
        let mut line = serde_json::to_vec(&rec)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        line.push(b'\n');
        let mut f = self.file.lock().map_err(|_| io::Error::other("audit log mutex poisoned"))?;
        f.write_all(&line)?;
        f.flush()?;
        Ok(())
    }

    /// Convenience: record and swallow errors (fail-open).
    pub fn log(&self, kind: EventKind, detail: &str) {
        let _ = self.record(kind, detail);
    }
}

/// Read back every well-formed record in a log file. Malformed lines
/// are skipped (the log is an audit trail, not a trust root).
pub fn read_all(path: &Path) -> io::Result<Vec<Record>> {
    let f = File::open(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(rec) = serde_json::from_str::<Record>(&line) {
            out.push(rec);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmp(name: &str) -> std::path::PathBuf {
        env::temp_dir().join(format!("auditlog-test-{name}.jsonl"))
    }

    #[test]
    fn creates_and_roundtrips() {
        let p = tmp("roundtrip");
        let _ = std::fs::remove_file(&p);
        let log = AuditLog::open(&p).unwrap();
        log.record(EventKind::UnlockFailed, "wrong passphrase").unwrap();
        log.record(EventKind::UnknownWriter, "dev-9f3c").unwrap();
        let recs = read_all(&p).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].kind, EventKind::UnlockFailed);
        assert_eq!(recs[0].detail, "wrong passphrase");
        assert_eq!(recs[1].kind, EventKind::UnknownWriter);
        assert!(recs[1].ts >= recs[0].ts);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn appends_across_reopens() {
        let p = tmp("append");
        let _ = std::fs::remove_file(&p);
        AuditLog::open(&p).unwrap().log(EventKind::BadFrame, "a");
        AuditLog::open(&p).unwrap().log(EventKind::BadFrame, "b");
        let recs = read_all(&p).unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].detail, "a");
        assert_eq!(recs[1].detail, "b");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn malformed_lines_skipped() {
        let p = tmp("malformed");
        std::fs::write(&p, "not json\n{\"ts\":1,\"kind\":\"BadFrame\",\"detail\":\"x\"}\n").unwrap();
        let recs = read_all(&p).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].detail, "x");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn kind_names_stable() {
        // Wire format stability: variant names are the on-disk kind strings.
        let s = serde_json::to_string(&EventKind::SenderMismatch).unwrap();
        assert_eq!(s, "\"SenderMismatch\"");
    }
}
