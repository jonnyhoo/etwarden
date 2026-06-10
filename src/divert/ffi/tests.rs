//! # `divert::ffi::tests`
//!
//! **Purpose**: WinDivert address ABI and accessor boundary tests.
//! **Public API**: test-only
//! **Dependencies**: `divert::ffi`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 58 / 80

use std::mem::{align_of, size_of};

use super::{WinDivertAddress, WINDIVERT_EVENT_FLOW_ESTABLISHED, WINDIVERT_LAYER_FLOW};

#[test]
fn windivert_address_abi_matches_c_layout() {
    assert_eq!(size_of::<WinDivertAddress>(), 80);
    assert_eq!(align_of::<WinDivertAddress>(), 8);
}

#[test]
fn common_bitfield_accessors_use_documented_offsets() {
    let mut addr = WinDivertAddress { buf: [0; 80] };
    addr.buf[8] = WINDIVERT_LAYER_FLOW as u8;
    addr.buf[9] = WINDIVERT_EVENT_FLOW_ESTABLISHED;
    addr.buf[10] = 0x04;

    assert_eq!(addr.layer(), WINDIVERT_LAYER_FLOW as u8);
    assert_eq!(addr.event(), WINDIVERT_EVENT_FLOW_ESTABLISHED);
    assert!(!addr.outbound());
    assert!(addr.loopback());

    addr.set_outbound(true);
    assert!(addr.outbound());
    assert!(addr.loopback());

    addr.set_outbound(false);
    assert!(!addr.outbound());
    assert!(addr.loopback());
}

#[test]
fn flow_accessors_use_win_divert_2_2_offsets() {
    let mut addr = WinDivertAddress { buf: [0; 80] };
    addr.buf[32..36].copy_from_slice(&0x0102_0304_u32.to_le_bytes());
    addr.buf[36..40].copy_from_slice(&0xC000_0201_u32.to_le_bytes());
    addr.buf[52..56].copy_from_slice(&0xC633_6402_u32.to_le_bytes());
    addr.buf[68..70].copy_from_slice(&49152_u16.to_le_bytes());
    addr.buf[70..72].copy_from_slice(&443_u16.to_le_bytes());
    addr.buf[72] = 6;

    assert_eq!(addr.flow_process_id(), 0x0102_0304);
    assert_eq!(addr.flow_local_addr_v4(), [192, 0, 2, 1]);
    assert_eq!(addr.flow_remote_addr_v4(), [198, 51, 100, 2]);
    assert_eq!(addr.flow_local_port(), 49152);
    assert_eq!(addr.flow_remote_port(), 443);
    assert_eq!(addr.flow_protocol(), 6);
}
