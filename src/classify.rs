//! # `classify`
//!
//! **Purpose**: Classify IP addresses into routing scopes (loopback, private, public, etc.).
//! **Public API**: `enum Scope`, `fn classify(IpAddr) -> Scope`
//! **Dependencies**: (none)
//! **Platform**: `cross-platform`
//! **Privilege**: `none`
//! **Line budget**: 165 / 200

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

/// Routing/usage scope of an IP address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Scope {
    Public,
    Loopback,
    Private,
    LinkLocal,
    Cgnat,
    Multicast,
    Broadcast,
    Documentation,
    Benchmarking,
    Unspecified,
    Reserved,
    UniqueLocal,
    Discard,
    Ipv4Mapped,
}

impl Scope {
    /// Short all-caps label for display.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Loopback => "LOOPBACK",
            Self::Private => "PRIVATE",
            Self::LinkLocal => "LINK-LOCAL",
            Self::Cgnat => "CGNAT",
            Self::Multicast => "MULTICAST",
            Self::Broadcast => "BROADCAST",
            Self::Documentation => "DOCUMENTATION",
            Self::Benchmarking => "BENCHMARKING",
            Self::Unspecified => "UNSPECIFIED",
            Self::Reserved => "RESERVED",
            Self::UniqueLocal => "UNIQUE-LOCAL",
            Self::Discard => "DISCARD",
            Self::Ipv4Mapped => "IPV4-MAPPED",
        }
    }

    /// Returns `true` for addresses that never leave the host.
    #[must_use]
    pub const fn is_loopback(self) -> bool {
        matches!(self, Self::Loopback)
    }

    /// Returns `true` for RFC 1918 / unique-local / CGNAT ranges.
    #[must_use]
    pub const fn is_private(self) -> bool {
        matches!(self, Self::Private | Self::UniqueLocal | Self::Cgnat)
    }
}

/// Classify an IP address into its routing scope.
#[must_use]
pub fn classify(ip: IpAddr) -> Scope {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> Scope {
    let octets = ip.octets();
    let [a, b, _, _] = octets;

    if ip.is_unspecified() {
        return Scope::Unspecified;
    }
    if a == 127 {
        return Scope::Loopback;
    }
    // RFC 1918
    if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
        return Scope::Private;
    }
    if a == 169 && b == 254 {
        return Scope::LinkLocal;
    }
    // RFC 6598 carrier-grade NAT: 100.64.0.0/10
    if a == 100 && (64..=127).contains(&b) {
        return Scope::Cgnat;
    }
    // Documentation: TEST-NET-1/2/3
    if (a == 192 && b == 0 && octets[2] == 2)
        || (a == 198 && b == 51 && octets[2] == 100)
        || (a == 203 && b == 0 && octets[2] == 113)
    {
        return Scope::Documentation;
    }
    // RFC 2544 benchmarking: 198.18.0.0/15
    if a == 198 && (b == 18 || b == 19) {
        return Scope::Benchmarking;
    }
    if octets == [255, 255, 255, 255] {
        return Scope::Broadcast;
    }
    // 224.0.0.0/4 multicast
    if (224..=239).contains(&a) {
        return Scope::Multicast;
    }
    // 240.0.0.0/4 reserved
    if a >= 240 {
        return Scope::Reserved;
    }
    Scope::Public
}

fn classify_v6(ip: Ipv6Addr) -> Scope {
    if ip.is_unspecified() {
        return Scope::Unspecified;
    }
    if ip.is_loopback() {
        return Scope::Loopback;
    }
    let segs = ip.segments();
    // ::ffff:0:0/96 IPv4-mapped
    if segs[0..5] == [0, 0, 0, 0, 0] && segs[5] == 0xffff {
        return Scope::Ipv4Mapped;
    }
    // 100::/64 discard (RFC 6666)
    if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
        return Scope::Discard;
    }
    // 2001:db8::/32 documentation
    if segs[0] == 0x2001 && segs[1] == 0x0db8 {
        return Scope::Documentation;
    }
    // ff00::/8 multicast
    if (segs[0] >> 8) == 0xff {
        return Scope::Multicast;
    }
    // fe80::/10 link-local
    if (segs[0] & 0xffc0) == 0xfe80 {
        return Scope::LinkLocal;
    }
    // fc00::/7 unique-local
    if (segs[0] & 0xfe00) == 0xfc00 {
        return Scope::UniqueLocal;
    }
    Scope::Public
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().expect("valid test IP")
    }

    fn v6(s: &str) -> IpAddr {
        s.parse().expect("valid test IP")
    }

    #[test]
    fn rfc1918_is_private() {
        assert_eq!(classify(v4("10.0.0.1")), Scope::Private);
        assert_eq!(classify(v4("172.16.0.1")), Scope::Private);
        assert_eq!(classify(v4("192.168.1.1")), Scope::Private);
        assert_eq!(classify(v4("172.32.0.1")), Scope::Public);
    }

    #[test]
    fn loopback_v4_v6() {
        assert_eq!(classify(v4("127.0.0.1")), Scope::Loopback);
        assert_eq!(classify(v6("::1")), Scope::Loopback);
        assert!(classify(v4("127.0.0.1")).is_loopback());
    }

    #[test]
    fn link_local() {
        assert_eq!(classify(v4("169.254.1.1")), Scope::LinkLocal);
        assert_eq!(classify(v6("fe80::1")), Scope::LinkLocal);
    }

    #[test]
    fn cgnat() {
        assert_eq!(classify(v4("100.64.0.1")), Scope::Cgnat);
        assert_eq!(classify(v4("100.128.0.1")), Scope::Public);
        assert!(classify(v4("100.64.0.1")).is_private());
    }

    #[test]
    fn multicast() {
        assert_eq!(classify(v4("224.0.0.251")), Scope::Multicast);
        assert_eq!(classify(v6("ff02::1")), Scope::Multicast);
    }

    #[test]
    fn unspecified() {
        assert_eq!(classify(v4("0.0.0.0")), Scope::Unspecified);
        assert_eq!(classify(v6("::")), Scope::Unspecified);
    }

    #[test]
    fn ipv4_mapped() {
        assert_eq!(classify(v6("::ffff:192.168.1.1")), Scope::Ipv4Mapped);
    }

    #[test]
    fn unique_local() {
        assert_eq!(classify(v6("fd00::1")), Scope::UniqueLocal);
        assert!(classify(v6("fd00::1")).is_private());
    }

    #[test]
    fn public_is_not_private() {
        assert_eq!(classify(v4("8.8.8.8")), Scope::Public);
        assert!(!classify(v4("8.8.8.8")).is_private());
        assert!(!classify(v4("8.8.8.8")).is_loopback());
    }

    #[test]
    fn broadcast() {
        assert_eq!(classify(v4("255.255.255.255")), Scope::Broadcast);
    }

    #[test]
    fn documentation() {
        assert_eq!(classify(v4("192.0.2.1")), Scope::Documentation);
        assert_eq!(classify(v6("2001:db8::1")), Scope::Documentation);
    }

    #[test]
    fn scope_label() {
        assert_eq!(Scope::Loopback.label(), "LOOPBACK");
        assert_eq!(Scope::Private.label(), "PRIVATE");
        assert_eq!(Scope::Public.label(), "PUBLIC");
    }
}
