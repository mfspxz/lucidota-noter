use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Per-note version vector: device_id -> edit counter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionVector(pub HashMap<String, u64>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VectorCmp {
    /// self has every counter >= other and at least one strictly greater.
    Dominates,
    /// other dominates self.
    Dominated,
    /// equal vectors.
    Equal,
    /// neither dominates: concurrent edits.
    Concurrent,
}

impl VersionVector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one local edit by `device`.
    pub fn bump(&mut self, device: &str) -> u64 {
        let e = self.0.entry(device.to_string()).or_insert(0);
        *e += 1;
        *e
    }

    pub fn get(&self, device: &str) -> u64 {
        self.0.get(device).copied().unwrap_or(0)
    }

    /// Element-wise maximum (join).
    pub fn merge(&self, other: &Self) -> Self {
        let mut out = self.0.clone();
        for (k, v) in &other.0 {
            let e = out.entry(k.clone()).or_insert(0);
            if *v > *e {
                *e = *v;
            }
        }
        Self(out)
    }

    pub fn compare(&self, other: &Self) -> VectorCmp {
        let mut self_greater = false;
        let mut other_greater = false;
        let mut keys: Vec<&String> = self.0.keys().chain(other.0.keys()).collect();
        keys.sort();
        keys.dedup();
        for k in keys {
            let a = self.get(k);
            let b = other.get(k);
            if a > b {
                self_greater = true;
            } else if b > a {
                other_greater = true;
            }
        }
        match (self_greater, other_greater) {
            (false, false) => VectorCmp::Equal,
            (true, false) => VectorCmp::Dominates,
            (false, true) => VectorCmp::Dominated,
            (true, true) => VectorCmp::Concurrent,
        }
    }

    /// Sum of counters — total edits seen.
    pub fn total(&self) -> u64 {
        self.0.values().sum()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("vv serializes")
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        if b.is_empty() {
            return Self::new();
        }
        serde_json::from_slice(b).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_and_compare() {
        let mut a = VersionVector::new();
        a.bump("d1");
        let mut b = VersionVector::new();
        b.bump("d1");
        b.bump("d1");
        assert_eq!(a.compare(&b), VectorCmp::Dominated);
        assert_eq!(b.compare(&a), VectorCmp::Dominates);
        assert_eq!(a.compare(&a), VectorCmp::Equal);
    }

    #[test]
    fn concurrent_detected() {
        let mut a = VersionVector::new();
        a.bump("d1");
        let mut b = VersionVector::new();
        b.bump("d2");
        assert_eq!(a.compare(&b), VectorCmp::Concurrent);
    }

    #[test]
    fn merge_is_join() {
        let mut a = VersionVector::new();
        a.bump("d1");
        a.bump("d1");
        let mut b = VersionVector::new();
        b.bump("d2");
        let m = a.merge(&b);
        assert_eq!(m.get("d1"), 2);
        assert_eq!(m.get("d2"), 1);
    }

    #[test]
    fn bytes_roundtrip() {
        let mut v = VersionVector::new();
        v.bump("d1");
        let v2 = VersionVector::from_bytes(&v.to_bytes());
        assert_eq!(v, v2);
        assert_eq!(VersionVector::from_bytes(&[]), VersionVector::new());
    }
}
