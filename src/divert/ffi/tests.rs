//! # `divert::ffi::tests`
//!
//! **Purpose**: WinDivert address ABI and accessor boundary tests.
//! **Public API**: test-only
//! **Dependencies**: `divert::ffi`
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 195 / 200

use std::{
    ffi::c_void,
    mem::{align_of, size_of},
};

use super::{
    FnCalcChecksums, FnRecv, FnSend, WinDivertAddress, WinDivertDllShallow, WinDivertHandle,
    WINDIVERT_EVENT_FLOW_ESTABLISHED, WINDIVERT_LAYER_FLOW,
};

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

#[test]
fn recv_rejects_success_length_beyond_buffer() {
    let handle = handle_with(recv_len_past_buffer, ok_send, ok_calc_checksums);
    let mut buf = [0_u8; 4];

    let err = handle
        .recv(&mut buf)
        .err()
        .expect("recv accepted oversized reported length");

    assert!(err
        .to_string()
        .contains("WinDivertRecv returned length 5 beyond buffer 4"));
}

#[test]
fn send_rejects_successful_partial_packet_write() {
    let handle = handle_with(ok_recv, partial_send, ok_calc_checksums);

    let err = handle
        .send(&[1, 2, 3, 4], &WinDivertAddress::zeroed())
        .expect_err("partial send should fail");

    assert!(err.to_string().contains("WinDivertSend wrote 3 of 4 bytes"));
}

#[test]
fn calc_checksums_reports_helper_failure() {
    let mut packet = [0_u8; 20];
    let handle = handle_with(ok_recv, ok_send, fail_calc_checksums);

    let err = handle
        .calc_checksums(&mut packet, &WinDivertAddress::zeroed(), 0)
        .expect_err("checksum failure should fail");

    assert!(err
        .to_string()
        .contains("WinDivertHelperCalcChecksums failed"));
}

fn handle_with(recv: FnRecv, send: FnSend, calc_checksums: FnCalcChecksums) -> WinDivertHandle {
    WinDivertHandle {
        handle: std::ptr::NonNull::<c_void>::dangling().as_ptr(),
        dll: WinDivertDllShallow {
            recv,
            send,
            close: ok_close,
            shutdown: ok_shutdown,
            calc_checksums,
        },
    }
}

unsafe extern "system" fn recv_len_past_buffer(
    _handle: *mut c_void,
    _packet: *mut u8,
    packet_len: u32,
    recv_len: *mut u32,
    _addr: *mut WinDivertAddress,
) -> i32 {
    unsafe {
        *recv_len = packet_len + 1;
    }
    1
}

unsafe extern "system" fn ok_recv(
    _handle: *mut c_void,
    _packet: *mut u8,
    _packet_len: u32,
    recv_len: *mut u32,
    _addr: *mut WinDivertAddress,
) -> i32 {
    unsafe {
        *recv_len = 0;
    }
    1
}

unsafe extern "system" fn partial_send(
    _handle: *mut c_void,
    _packet: *const u8,
    packet_len: u32,
    send_len: *mut u32,
    _addr: *const WinDivertAddress,
) -> i32 {
    unsafe {
        *send_len = packet_len.saturating_sub(1);
    }
    1
}

unsafe extern "system" fn ok_send(
    _handle: *mut c_void,
    _packet: *const u8,
    packet_len: u32,
    send_len: *mut u32,
    _addr: *const WinDivertAddress,
) -> i32 {
    unsafe {
        *send_len = packet_len;
    }
    1
}

unsafe extern "system" fn ok_close(_handle: *mut c_void) -> i32 {
    1
}

unsafe extern "system" fn ok_shutdown(_handle: *mut c_void, _how: u32) -> i32 {
    1
}

unsafe extern "system" fn ok_calc_checksums(
    _packet: *mut u8,
    _packet_len: u32,
    _addr: *const WinDivertAddress,
    _flags: u64,
) -> u32 {
    1
}

unsafe extern "system" fn fail_calc_checksums(
    _packet: *mut u8,
    _packet_len: u32,
    _addr: *const WinDivertAddress,
    _flags: u64,
) -> u32 {
    0
}
