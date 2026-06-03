//! # `pcap::correlator`
//!
//! **Purpose**: Maps `FiveTuple` → PID for correlating NDIS frames with TCPIP events.
//! **Public API**: `struct Correlator`
//! **Dependencies**: `parser::types`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 242 / 260

use std::{collections::HashMap, sync::Mutex};

use crate::parser::types::{FiveTuple, NetEvent, Protocol};

const DEFAULT_MAX_MAPPINGS: usize = 20_000;

// ---------------------------------------------------------------------------
// Correlator
// ---------------------------------------------------------------------------

/// Thread-safe map from `FiveTuple` to PID.
///
/// TCPIP events call `register_connection` to populate the map.
/// NDIS events call `resolve_pid` to look up the owning process.
pub struct Correlator {
    map: Mutex<HashMap<FiveTuple, u32>>,
    max_mappings: usize,
}

impl Correlator {
    /// Creates an empty correlator.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_mappings(DEFAULT_MAX_MAPPINGS)
    }

    /// Creates an empty correlator with a maximum mapping count.
    #[must_use]
    pub fn with_max_mappings(max_mappings: usize) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max_mappings,
        }
    }

    /// Registers a connection from a TCPIP event.
    pub fn register_connection(&self, pid: u32, tuple: FiveTuple) {
        if self.max_mappings < 2 {
            return;
        }
        let Ok(mut map) = self.map.lock() else {
            eprintln!("[etwarden] dropped correlator mapping: correlator lock poisoned");
            return;
        };
        let reverse = reverse_tuple(&tuple);
        let is_new = !map.contains_key(&tuple) && !map.contains_key(&reverse);
        if is_new {
            evict_until(
                &mut map,
                self.max_mappings.saturating_sub(2),
                &tuple,
                &reverse,
            );
        }
        map.insert(tuple, pid);
        map.insert(reverse, pid);
    }

    /// Registers tuple-bearing connection events, ignoring non-flow event kinds.
    pub fn register_event(&self, event: &NetEvent) {
        let Some((pid, proto, src, dst)) = event_tuple_parts(event) else {
            return;
        };
        if let Some(tuple) = parse_tuple_from_event(src, dst, proto) {
            self.register_connection(pid, tuple);
        }
    }

    /// Resolves the PID for a given five-tuple.
    pub fn resolve_pid(&self, tuple: &FiveTuple) -> Option<u32> {
        let Ok(map) = self.map.lock() else {
            eprintln!("[etwarden] failed correlator lookup: correlator lock poisoned");
            return None;
        };
        map.get(tuple).copied()
    }

    /// Returns the number of registered tuple mappings.
    pub fn len(&self) -> usize {
        let Ok(map) = self.map.lock() else {
            eprintln!("[etwarden] skipped correlator len: correlator lock poisoned");
            return 0;
        };
        map.len()
    }

    /// Returns `true` if no connections are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn event_tuple_parts(event: &NetEvent) -> Option<(u32, Protocol, &str, &str)> {
    match event {
        NetEvent::Connect {
            pid,
            proto,
            src,
            dst,
            ..
        }
        | NetEvent::Send {
            pid,
            proto,
            src,
            dst,
            ..
        }
        | NetEvent::Recv {
            pid,
            proto,
            src,
            dst,
            ..
        } => Some((*pid, *proto, src, dst)),
        NetEvent::Disconnect { .. }
        | NetEvent::RawCapture { .. }
        | NetEvent::DnsQuery { .. }
        | NetEvent::DnsResponse { .. } => None,
    }
}

fn evict_until(
    map: &mut HashMap<FiveTuple, u32>,
    target_len: usize,
    keep_a: &FiveTuple,
    keep_b: &FiveTuple,
) {
    while map.len() > target_len {
        let Some(key) = map.keys().find(|k| *k != keep_a && *k != keep_b).cloned() else {
            break;
        };
        let reverse = reverse_tuple(&key);
        map.remove(&key);
        map.remove(&reverse);
    }
}

fn reverse_tuple(tuple: &FiveTuple) -> FiveTuple {
    FiveTuple {
        src_ip: tuple.dst_ip.clone(),
        src_port: tuple.dst_port,
        dst_ip: tuple.src_ip.clone(),
        dst_port: tuple.src_port,
        protocol: tuple.protocol,
    }
}

fn parse_tuple_from_event(src: &str, dst: &str, proto: Protocol) -> Option<FiveTuple> {
    let (src_ip, src_port) = parse_addr_port(src)?;
    let (dst_ip, dst_port) = parse_addr_port(dst)?;
    Some(FiveTuple {
        src_ip,
        src_port,
        dst_ip,
        dst_port,
        protocol: proto,
    })
}

fn parse_addr_port(addr: &str) -> Option<(String, u16)> {
    if addr.starts_with('[') {
        let close = addr.find(']')?;
        if addr.get(close + 1..close + 2)? != ":" {
            return None;
        }
        let ip: std::net::IpAddr = addr[1..close].parse().ok()?;
        let port = addr.get(close + 2..)?.parse().ok()?;
        return Some((ip.to_string(), port));
    }
    if addr.contains('[') || addr.contains(']') {
        return None;
    }

    let colon = addr.rfind(':')?;
    if addr[..colon].contains(':') {
        return None;
    }
    let ip: std::net::IpAddr = addr[..colon].parse().ok()?;
    let port = addr[colon + 1..].parse().ok()?;
    Some((ip.to_string(), port))
}

impl Default for Correlator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::types::Protocol;

    fn tuple(src: &str, sport: u16, dst: &str, dport: u16) -> FiveTuple {
        FiveTuple {
            src_ip: src.into(),
            src_port: sport,
            dst_ip: dst.into(),
            dst_port: dport,
            protocol: Protocol::Tcp,
        }
    }

    #[test]
    fn register_and_resolve() {
        let corr = Correlator::new();
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        corr.register_connection(42, t.clone());
        assert_eq!(corr.resolve_pid(&t), Some(42));
    }

    #[test]
    fn register_resolves_reverse_direction() {
        let corr = Correlator::new();
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        let r = tuple("10.0.0.2", 80, "10.0.0.1", 1234);
        corr.register_connection(42, t);
        assert_eq!(corr.resolve_pid(&r), Some(42));
    }

    #[test]
    fn register_event_from_connect() {
        let corr = Correlator::new();
        let event = NetEvent::Connect {
            timestamp: chrono::Utc::now(),
            pid: 42,
            proto: Protocol::Tcp,
            src: "10.0.0.1:1234".into(),
            dst: "10.0.0.2:80".into(),
            bytes_out: 0,
            bytes_in: 0,
        };
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        corr.register_event(&event);
        assert_eq!(corr.resolve_pid(&t), Some(42));
    }

    #[test]
    fn register_event_from_udp_send() {
        let corr = Correlator::new();
        let event = NetEvent::Send {
            timestamp: chrono::Utc::now(),
            pid: 77,
            proto: Protocol::Udp,
            src: "10.0.0.1:1234".into(),
            dst: "8.8.8.8:53".into(),
            bytes_out: 32,
            bytes_in: 0,
        };
        let t = FiveTuple {
            src_ip: "10.0.0.1".into(),
            src_port: 1234,
            dst_ip: "8.8.8.8".into(),
            dst_port: 53,
            protocol: Protocol::Udp,
        };
        corr.register_event(&event);
        assert_eq!(corr.resolve_pid(&t), Some(77));
    }

    #[test]
    fn unknown_tuple_returns_none() {
        let corr = Correlator::new();
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        assert_eq!(corr.resolve_pid(&t), None);
    }

    #[test]
    fn parse_addr_port_rejects_malformed_ipv6_brackets() {
        assert!(parse_addr_port("[::1]").is_none());
        assert!(parse_addr_port("x]::1:443").is_none());
        assert!(parse_addr_port("::1:443").is_none());
        assert!(parse_addr_port("not-ip:443").is_none());
        assert!(parse_addr_port("[not-ip]:443").is_none());
    }

    #[test]
    fn overwrite_updates_pid() {
        let corr = Correlator::new();
        let t = tuple("10.0.0.1", 1234, "10.0.0.2", 80);
        corr.register_connection(42, t.clone());
        corr.register_connection(99, t.clone());
        assert_eq!(corr.resolve_pid(&t), Some(99));
    }

    #[test]
    fn len_and_is_empty() {
        let corr = Correlator::new();
        assert!(corr.is_empty());
        corr.register_connection(1, tuple("a", 1, "b", 2));
        assert_eq!(corr.len(), 2);
        assert!(!corr.is_empty());
    }

    #[test]
    fn max_mappings_caps_new_pairs() {
        let corr = Correlator::with_max_mappings(4);
        let first = tuple("10.0.0.1", 1000, "10.0.0.2", 80);
        let second = tuple("10.0.0.3", 1001, "10.0.0.4", 80);
        let third = tuple("10.0.0.5", 1002, "10.0.0.6", 80);

        corr.register_connection(1, first.clone());
        corr.register_connection(2, second.clone());
        corr.register_connection(3, third.clone());

        assert!(corr.len() <= 4);
        assert_eq!(corr.resolve_pid(&third), Some(3));
        let first_pid = corr.resolve_pid(&first);
        let second_pid = corr.resolve_pid(&second);
        assert!(first_pid.is_none() || second_pid.is_none());
        assert!(first_pid.is_some() || second_pid.is_some());
    }

    #[test]
    fn max_mappings_still_updates_existing_pair() {
        let corr = Correlator::with_max_mappings(2);
        let t = tuple("10.0.0.1", 1000, "10.0.0.2", 80);

        corr.register_connection(1, t.clone());
        corr.register_connection(2, t.clone());

        assert_eq!(corr.len(), 2);
        assert_eq!(corr.resolve_pid(&t), Some(2));
    }
}
