//! # `parser::tcpip::ids`
//!
//! **Purpose**: Kernel-Network TCP/UDP ETW event ID constants.
//! **Public API**: module-private constants
//! **Dependencies**: (none)
//! **Platform**: `windows-only`
//! **Privilege**: `none`
//! **Line budget**: 30 / 60

// Event IDs from the Microsoft-Windows-Kernel-Network manifest.
// ESTABLISHED IDs are included for manifest completeness but not yet used in parsing.
pub const EVENT_ID_TCP_SEND_IPV4: u16 = 10;
pub const EVENT_ID_TCP_RECV_IPV4: u16 = 11;
pub const EVENT_ID_TCP_CONNECT_IPV4: u16 = 12;
pub const EVENT_ID_TCP_DISCONNECT_IPV4: u16 = 13;
pub const EVENT_ID_TCP_RETRANSMIT_IPV4: u16 = 14;
pub const EVENT_ID_TCP_ESTABLISHED_IPV4: u16 = 15;
pub const EVENT_ID_TCP_SEND_IPV6: u16 = 26;
pub const EVENT_ID_TCP_RECV_IPV6: u16 = 27;
pub const EVENT_ID_TCP_CONNECT_IPV6: u16 = 28;
pub const EVENT_ID_TCP_DISCONNECT_IPV6: u16 = 29;
pub const EVENT_ID_TCP_RETRANSMIT_IPV6: u16 = 30;
pub const EVENT_ID_TCP_ESTABLISHED_IPV6: u16 = 31;
pub const EVENT_ID_UDP_SEND_IPV4: u16 = 42;
pub const EVENT_ID_UDP_RECV_IPV4: u16 = 43;
pub const EVENT_ID_UDP_SEND_IPV6: u16 = 58;
pub const EVENT_ID_UDP_RECV_IPV6: u16 = 59;
