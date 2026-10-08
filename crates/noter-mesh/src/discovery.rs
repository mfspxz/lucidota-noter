use crate::MeshError;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

/// Magic + version prefix for discovery beacons.
pub const BEACON_MAGIC: &[u8] = b"NOTER1";
pub const DISCOVERY_PORT: u16 = 48771;

/// A discovered peer on the LAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    pub device_id: String,
    pub tcp_port: u16,
    pub fingerprint: String,
    pub addr: std::net::IpAddr,
}

impl Beacon {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(BEACON_MAGIC);
        v.extend_from_slice(self.device_id.as_bytes());
        v.push(0);
        v.extend_from_slice(&self.tcp_port.to_be_bytes());
        v.push(0);
        v.extend_from_slice(self.fingerprint.as_bytes());
        v
    }

    fn decode(buf: &[u8], addr: std::net::IpAddr) -> Option<Self> {
        if buf.len() < BEACON_MAGIC.len() + 3 || &buf[..6] != BEACON_MAGIC {
            return None;
        }
        let rest = &buf[6..];
        let mut parts = rest.split(|b| *b == 0);
        let device_id = String::from_utf8(parts.next()?.to_vec()).ok()?;
        let port_b: Vec<u8> = parts.next()?.to_vec();
        if port_b.len() != 2 {
            return None;
        }
        let tcp_port = u16::from_be_bytes([port_b[0], port_b[1]]);
        let fingerprint = String::from_utf8(parts.next()?.to_vec()).ok()?;
        Some(Beacon {
            device_id,
            tcp_port,
            fingerprint,
            addr,
        })
    }
}

/// Broadcast our presence on the LAN until `stop_after` elapses.
/// Runs in the calling thread; spawn it for background beaconing.
pub fn beacon(
    device_id: &str,
    tcp_port: u16,
    fingerprint: &str,
    stop_after: Duration,
) -> Result<(), MeshError> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.set_broadcast(true)?;
    let b = Beacon {
        device_id: device_id.to_string(),
        tcp_port,
        fingerprint: fingerprint.to_string(),
        addr: "0.0.0.0".parse().unwrap(),
    };
    let pkt = b.encode();
    let target = format!("255.255.255.255:{}", DISCOVERY_PORT);
    let end = Instant::now() + stop_after;
    while Instant::now() < end {
        let _ = sock.send_to(&pkt, &target);
        std::thread::sleep(Duration::from_millis(400));
    }
    Ok(())
}

/// Listen for beacons for `window` and return the peers seen (deduplicated).
pub fn discover(window: Duration) -> Result<Vec<Beacon>, MeshError> {
    discover_on(DISCOVERY_PORT, window)
}

fn discover_on(port: u16, window: Duration) -> Result<Vec<Beacon>, MeshError> {
    let sock = UdpSocket::bind(format!("0.0.0.0:{}", port))?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))?;
    let end = Instant::now() + window;
    let mut seen: Vec<Beacon> = Vec::new();
    let mut buf = [0u8; 512];
    while Instant::now() < end {
        match sock.recv_from(&mut buf) {
            Ok((n, src)) => {
                if let Some(b) = Beacon::decode(&buf[..n], src.ip()) {
                    if !seen.iter().any(|x| x.device_id == b.device_id) {
                        seen.push(b);
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => return Err(MeshError::Io(e)),
        }
    }
    Ok(seen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beacon_codec_roundtrip() {
        let b = Beacon {
            device_id: "dev-1".into(),
            tcp_port: 1234,
            fingerprint: "abcd".into(),
            addr: "127.0.0.1".parse().unwrap(),
        };
        let pkt = b.encode();
        let d = Beacon::decode(&pkt, "127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(d.device_id, "dev-1");
        assert_eq!(d.tcp_port, 1234);
        assert_eq!(d.fingerprint, "abcd");
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(Beacon::decode(b"GARBAGE", "127.0.0.1".parse().unwrap()).is_none());
        assert!(Beacon::decode(b"NOTER1", "127.0.0.1".parse().unwrap()).is_none());
    }

    /// Requires real UDP loopback; the build sandbox blocks UDP send
    /// (EPERM), so this is verified on device/on LAN, not in CI here.
    #[test]
    #[ignore = "sandbox blocks UDP send; run on real LAN"]
    fn discover_finds_local_beacon() {
        // Bind discovery on an ephemeral port to avoid clashing with other tests.
        let probe = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let beacon_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        beacon_sock.set_broadcast(true).ok();
        let b = Beacon {
            device_id: "test-dev".into(),
            tcp_port: 9999,
            fingerprint: "ff".into(),
            addr: "0.0.0.0".parse().unwrap(),
        };
        let pkt = b.encode();
        let target = format!("127.0.0.1:{}", port);
        let handle = std::thread::spawn(move || {
            for _ in 0..10 {
                let _ = beacon_sock.send_to(&pkt, &target);
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let found = discover_on(port, Duration::from_secs(2)).unwrap();
        handle.join().unwrap();
        assert!(found.iter().any(|x| x.device_id == "test-dev" && x.tcp_port == 9999));
    }
}
