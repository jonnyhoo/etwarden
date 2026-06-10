//! # `mitm::transparent::map_tests`
//!
//! **Purpose**: Covers transparent redirect map peer validation.
//! **Public API**: test-only
//! **Dependencies**: `mitm::transparent`, `divert`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 39 / 80

use std::net::{Ipv4Addr, SocketAddr};

use super::redirect_dest_from_peer;
use crate::divert::{OriginalDest, RedirectMap};

#[test]
fn transparent_map_lookup_rejects_wrong_peer_ip() {
    let map = RedirectMap::new();
    let original_ip = Ipv4Addr::new(93, 184, 216, 34);
    map.insert(51000, original_dest(original_ip));

    let wrong_peer = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 51000));
    assert!(redirect_dest_from_peer(&map, wrong_peer).is_none());

    let original_peer = SocketAddr::from((original_ip, 51000));
    assert_eq!(
        redirect_dest_from_peer(&map, original_peer).map(|d| d.ip),
        Some(original_ip)
    );
}

fn original_dest(ip: Ipv4Addr) -> OriginalDest {
    OriginalDest {
        local_ip: Ipv4Addr::new(192, 168, 1, 100),
        ip,
        port: 443,
        pid: 4242,
    }
}
