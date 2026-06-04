//! # `parser::ndis::frame`
//!
//! **Purpose**: Normalizes NDIS link-layer fragments into Ethernet frames.
//! **Public API**: `normalize_frame`
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 135 / 180

const ETH_HDR_LEN: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xDD];
const IEEE80211_ADDR_LEN: usize = 6;
const IEEE80211_BASE_HDR_LEN: usize = 24;
const IEEE80211_QOS_LEN: usize = 2;
const IEEE80211_HT_CONTROL_LEN: usize = 4;
const SNAP_HDR_LEN: usize = 8;
const SNAP_RFC1042_PREFIX: [u8; 6] = [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00];

/// Normalizes NDIS link-layer fragments into Ethernet frames for parsing/pcapng.
pub fn normalize_frame(frame: Vec<u8>) -> Option<Vec<u8>> {
    if is_supported_ethernet_frame(&frame) {
        return Some(frame);
    }
    ieee80211_snap_to_ethernet(&frame)
}

fn is_supported_ethernet_frame(frame: &[u8]) -> bool {
    frame.len() >= ETH_HDR_LEN + 20
        && frame
            .get(12..14)
            .is_some_and(|eth_type| eth_type == ETHERTYPE_IPV4 || eth_type == ETHERTYPE_IPV6)
}

fn ieee80211_snap_to_ethernet(frame: &[u8]) -> Option<Vec<u8>> {
    let frame_control = read_frame_control(frame)?;
    if !is_ieee80211_data_frame(frame_control) {
        return None;
    }

    let (dst, src, mut snap_offset) = ieee80211_addresses(frame, frame_control)?;
    snap_offset = advance_for_qos(frame_control, snap_offset)?;
    snap_offset = advance_for_ht_control(frame_control, snap_offset)?;

    let snap = frame.get(snap_offset..snap_offset.checked_add(SNAP_HDR_LEN)?)?;
    if snap.get(..SNAP_RFC1042_PREFIX.len())? != SNAP_RFC1042_PREFIX {
        return None;
    }

    let eth_type = snap.get(6..8)?;
    if eth_type != ETHERTYPE_IPV4 && eth_type != ETHERTYPE_IPV6 {
        return None;
    }

    let payload = frame.get(snap_offset + SNAP_HDR_LEN..)?;
    let mut ethernet = Vec::with_capacity(ETH_HDR_LEN + payload.len());
    ethernet.extend_from_slice(dst);
    ethernet.extend_from_slice(src);
    ethernet.extend_from_slice(eth_type);
    ethernet.extend_from_slice(payload);
    Some(ethernet)
}

fn ieee80211_addresses(frame: &[u8], frame_control: u16) -> Option<(&[u8], &[u8], usize)> {
    let to_ds = frame_control & 0x0100 != 0;
    let from_ds = frame_control & 0x0200 != 0;
    let addr1 = frame.get(4..10)?;
    let addr2 = frame.get(10..16)?;
    let addr3 = frame.get(16..22)?;

    match (to_ds, from_ds) {
        (false, false) => Some((addr1, addr2, IEEE80211_BASE_HDR_LEN)),
        (true, false) => Some((addr3, addr2, IEEE80211_BASE_HDR_LEN)),
        (false, true) => Some((addr1, addr3, IEEE80211_BASE_HDR_LEN)),
        (true, true) => Some((
            addr3,
            frame.get(24..24 + IEEE80211_ADDR_LEN)?,
            IEEE80211_BASE_HDR_LEN + IEEE80211_ADDR_LEN,
        )),
    }
}

const fn advance_for_qos(frame_control: u16, offset: usize) -> Option<usize> {
    if ieee80211_subtype(frame_control) & 0x08 == 0 {
        return Some(offset);
    }
    offset.checked_add(IEEE80211_QOS_LEN)
}

const fn advance_for_ht_control(frame_control: u16, offset: usize) -> Option<usize> {
    if frame_control & 0x8000 == 0 {
        return Some(offset);
    }
    offset.checked_add(IEEE80211_HT_CONTROL_LEN)
}

const fn is_ieee80211_data_frame(frame_control: u16) -> bool {
    (frame_control >> 2) & 0b11 == 0b10
}

const fn ieee80211_subtype(frame_control: u16) -> u16 {
    (frame_control >> 4) & 0x0F
}

fn read_frame_control(frame: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes([*frame.first()?, *frame.get(1)?]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ndis::test_support::{
        build_ethernet_ipv4_tcp, build_ieee80211_snap_from_ethernet,
    };

    #[test]
    fn normalize_ieee80211_snap_ipv4_frame() {
        let ethernet = build_ethernet_ipv4_tcp(10);
        let wifi = build_ieee80211_snap_from_ethernet(&ethernet);

        let normalized = normalize_frame(wifi).expect("normalized frame");

        assert_eq!(normalized, ethernet);
    }

    #[test]
    fn normalize_keeps_supported_ethernet_frame() {
        let ethernet = build_ethernet_ipv4_tcp(10);

        let normalized = normalize_frame(ethernet.clone()).expect("ethernet frame");

        assert_eq!(normalized, ethernet);
    }

    #[test]
    fn normalize_rejects_non_snap_wifi_frame() {
        let mut ethernet = build_ethernet_ipv4_tcp(10);
        ethernet[12..14].copy_from_slice(&[0x08, 0x06]);
        let wifi = build_ieee80211_snap_from_ethernet(&ethernet);

        assert!(normalize_frame(wifi).is_none());
    }
}
