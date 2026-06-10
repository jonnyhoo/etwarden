//! # `divert::redirect_map`
//!
//! **Purpose**: Thread-safe map from local proxy port → original destination.
//! **Public API**: `RedirectMap`, `OriginalDest`
//! **Dependencies**: `std`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 198 / 200

use std::{collections::HashMap, net::Ipv4Addr, sync::RwLock};

/// Original destination before WinDivert redirect.
#[derive(Debug, Clone)]
pub struct OriginalDest {
    pub local_ip: Ipv4Addr,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub pid: u32,
}

/// Thread-safe map: client source port → original destination.
/// Used by the MITM proxy to determine where to forward the connection.
pub struct RedirectMap {
    inner: RwLock<HashMap<u16, OriginalDest>>,
}

impl RedirectMap {
    /// Creates an empty redirect map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    /// Stores a redirect mapping for a client source port.
    pub fn insert(&self, src_port: u16, dest: OriginalDest) {
        self.inner
            .write()
            .expect("redirect map lock poisoned")
            .insert(src_port, dest);
    }

    /// Looks up and removes the original destination for a source port.
    /// Returns `None` if not found.
    pub fn take(&self, src_port: u16) -> Option<OriginalDest> {
        self.inner
            .write()
            .expect("redirect map lock poisoned")
            .remove(&src_port)
    }

    /// Removes a source-port entry only when its full origin tuple still matches.
    pub fn take_if_origin(
        &self,
        src_port: u16,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<OriginalDest> {
        let mut inner = self.inner.write().expect("redirect map lock poisoned");
        let matches = inner.get(&src_port).is_some_and(|dest| {
            dest.local_ip == local_ip && dest.ip == remote_ip && dest.port == remote_port
        });
        matches.then(|| inner.remove(&src_port)).flatten()
    }

    /// Looks up the original destination without removing it.
    pub fn get(&self, src_port: u16) -> Option<OriginalDest> {
        self.inner
            .read()
            .expect("redirect map lock poisoned")
            .get(&src_port)
            .cloned()
    }

    /// Looks up by reflected proxy peer/local endpoint and returns client source port.
    pub fn get_by_origin(
        &self,
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        remote_port: u16,
    ) -> Option<(u16, OriginalDest)> {
        let inner = self.inner.read().expect("redirect map lock poisoned");
        inner
            .iter()
            .find(|(_, dest)| {
                dest.local_ip == local_ip && dest.ip == remote_ip && dest.port == remote_port
            })
            .map(|(src_port, dest)| (*src_port, dest.clone()))
    }

    /// Returns the number of active redirect entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().expect("redirect map lock poisoned").len()
    }

    /// Returns `true` if there are no active redirects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for RedirectMap {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_take() {
        let map = RedirectMap::new();
        let dest = OriginalDest {
            local_ip: Ipv4Addr::new(192, 168, 1, 100),
            ip: Ipv4Addr::new(93, 184, 216, 34),
            port: 443,
            pid: 1234,
        };
        map.insert(51000, dest.clone());
        assert_eq!(map.len(), 1);

        let taken = map.take(51000).expect("should find entry");
        assert_eq!(taken.ip, dest.ip);
        assert_eq!(taken.port, dest.port);
        assert_eq!(taken.pid, dest.pid);
        assert!(map.is_empty());
    }

    #[test]
    fn take_missing_returns_none() {
        let map = RedirectMap::new();
        assert!(map.take(9999).is_none());
    }

    #[test]
    fn get_does_not_remove() {
        let map = RedirectMap::new();
        map.insert(
            51000,
            OriginalDest {
                local_ip: Ipv4Addr::new(192, 168, 1, 100),
                ip: Ipv4Addr::LOCALHOST,
                port: 80,
                pid: 1,
            },
        );
        assert!(map.get(51000).is_some());
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn get_by_origin_returns_client_source_port() {
        let map = RedirectMap::new();
        let local_ip = Ipv4Addr::new(192, 168, 1, 100);
        let remote_ip = Ipv4Addr::new(93, 184, 216, 34);
        map.insert(
            51000,
            OriginalDest {
                local_ip,
                ip: remote_ip,
                port: 80,
                pid: 1,
            },
        );

        let (src_port, dest) = map
            .get_by_origin(local_ip, remote_ip, 80)
            .expect("origin match");
        assert_eq!(src_port, 51000);
        assert_eq!(dest.ip, remote_ip);
    }

    #[test]
    fn get_by_origin_rejects_wrong_local_ip() {
        let map = RedirectMap::new();
        let remote_ip = Ipv4Addr::new(93, 184, 216, 34);
        map.insert(
            51000,
            OriginalDest {
                local_ip: Ipv4Addr::new(192, 168, 1, 100),
                ip: remote_ip,
                port: 80,
                pid: 1,
            },
        );

        assert!(map
            .get_by_origin(Ipv4Addr::new(192, 168, 1, 101), remote_ip, 80)
            .is_none());
    }
}
