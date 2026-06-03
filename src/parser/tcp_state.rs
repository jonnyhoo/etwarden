//! # `parser::tcp_state`
//!
//! **Purpose**: TCP connection state machine (RFC 793) — track connection lifecycle
//!   from SYN through ESTABLISHED to CLOSED.
//! **Public API**: `enum TcpState`, `fn update_tcp_state()`
//! **Dependencies**: (none)
//! **Platform**: `cross-platform`
//! **Privilege**: `none`
//! **Line budget**: 120 / 160

use serde::Serialize;

/// TCP connection state per RFC 793.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
    Closing,
    Closed,
    Unknown,
}

impl std::fmt::Display for TcpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::SynSent => "SYN_SENT",
            Self::SynReceived => "SYN_RECV",
            Self::Established => "ESTABLISHED",
            Self::FinWait1 => "FIN_WAIT1",
            Self::FinWait2 => "FIN_WAIT2",
            Self::CloseWait => "CLOSE_WAIT",
            Self::LastAck => "LAST_ACK",
            Self::TimeWait => "TIME_WAIT",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{name}")
    }
}

impl TcpState {
    /// Returns `true` if the connection is in an active data-transfer state.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(self, Self::Established | Self::SynSent | Self::SynReceived)
    }

    /// Returns `true` if the connection has terminated.
    #[must_use]
    pub const fn is_closed(self) -> bool {
        matches!(self, Self::Closed | Self::TimeWait)
    }
}

/// TCP header flags relevant to state transitions.
#[derive(Debug, Clone, Copy)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
}

impl TcpFlags {
    /// Parse TCP flags from the 9-bit flag field (offset after data offset field).
    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self {
            fin: (bits & 0x01) != 0,
            syn: (bits & 0x02) != 0,
            rst: (bits & 0x04) != 0,
            ack: (bits & 0x10) != 0,
        }
    }
}

/// Advance TCP state based on observed flags and direction.
///
/// Implements the core RFC 793 state machine transitions.
/// `is_outgoing` indicates whether the packet was sent by the local host.
#[must_use]
pub const fn update_tcp_state(current: TcpState, flags: &TcpFlags, is_outgoing: bool) -> TcpState {
    match (current, flags.syn, flags.ack, flags.fin, flags.rst) {
        // Connection establishment — three-way handshake
        (TcpState::Unknown, true, false, false, false) if !is_outgoing => TcpState::SynReceived,
        (TcpState::Unknown, true, false, false, false) if is_outgoing => TcpState::SynSent,
        (TcpState::SynSent, true, true, false, false) if !is_outgoing => TcpState::Established,
        (TcpState::SynReceived, false, true, false, false) if is_outgoing => TcpState::Established,

        // Late join — missed SYN, saw ACK
        (TcpState::Unknown, false, true, ..) => TcpState::Established,

        // Connection termination — normal close
        (TcpState::Established, false, _, true, false) if is_outgoing => TcpState::FinWait1,
        (TcpState::Established, false, _, true, false) if !is_outgoing => TcpState::CloseWait,
        (TcpState::FinWait1, false, true, false, false) if !is_outgoing => TcpState::FinWait2,
        (TcpState::FinWait1, false, _, true, false) if !is_outgoing => TcpState::Closing,
        (TcpState::CloseWait, false, _, true, false) if is_outgoing => TcpState::LastAck,
        (TcpState::LastAck, false, true, false, false) if !is_outgoing => TcpState::Closed,
        (TcpState::FinWait2, false, _, true, false)
        | (TcpState::Closing, false, true, false, false)
            if !is_outgoing =>
        {
            TcpState::TimeWait
        }

        // RST — immediate close from any state
        (_, _, _, _, true) => TcpState::Closed,

        // No transition
        _ => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn flags(syn: bool, ack: bool, fin: bool, rst: bool) -> TcpFlags {
        TcpFlags { syn, ack, fin, rst }
    }

    #[test]
    fn syn_sent_outgoing() {
        let next = update_tcp_state(TcpState::Unknown, &flags(true, false, false, false), true);
        assert_eq!(next, TcpState::SynSent);
    }

    #[test]
    fn syn_received_incoming() {
        let next = update_tcp_state(TcpState::Unknown, &flags(true, false, false, false), false);
        assert_eq!(next, TcpState::SynReceived);
    }

    #[test]
    fn three_way_handshake() {
        let s = update_tcp_state(TcpState::Unknown, &flags(true, false, false, false), true);
        assert_eq!(s, TcpState::SynSent);
        let s = update_tcp_state(s, &flags(true, true, false, false), false);
        assert_eq!(s, TcpState::Established);
    }

    #[test]
    fn late_join_ack() {
        let s = update_tcp_state(TcpState::Unknown, &flags(false, true, false, false), true);
        assert_eq!(s, TcpState::Established);
    }

    #[test]
    fn fin_from_established() {
        let s = update_tcp_state(
            TcpState::Established,
            &flags(false, false, true, false),
            true,
        );
        assert_eq!(s, TcpState::FinWait1);
        let s = update_tcp_state(s, &flags(false, true, false, false), false);
        assert_eq!(s, TcpState::FinWait2);
        let s = update_tcp_state(s, &flags(false, false, true, false), false);
        assert_eq!(s, TcpState::TimeWait);
    }

    #[test]
    fn close_wait_path() {
        let s = update_tcp_state(
            TcpState::Established,
            &flags(false, false, true, false),
            false,
        );
        assert_eq!(s, TcpState::CloseWait);
        let s = update_tcp_state(s, &flags(false, false, true, false), true);
        assert_eq!(s, TcpState::LastAck);
        let s = update_tcp_state(s, &flags(false, true, false, false), false);
        assert_eq!(s, TcpState::Closed);
    }

    #[test]
    fn rst_closes_any_state() {
        for state in [
            TcpState::SynSent,
            TcpState::Established,
            TcpState::FinWait1,
            TcpState::CloseWait,
        ] {
            let s = update_tcp_state(state, &flags(false, false, false, true), true);
            assert_eq!(s, TcpState::Closed, "RST from {state:?}");
        }
    }

    #[test]
    fn no_transition_stays() {
        let s = update_tcp_state(
            TcpState::Established,
            &flags(false, true, false, false),
            true,
        );
        assert_eq!(s, TcpState::Established);
    }

    #[test]
    fn state_predicates() {
        assert!(TcpState::Established.is_active());
        assert!(TcpState::SynSent.is_active());
        assert!(!TcpState::Closed.is_active());
        assert!(TcpState::Closed.is_closed());
        assert!(TcpState::TimeWait.is_closed());
        assert!(!TcpState::Established.is_closed());
    }

    #[test]
    fn from_bits() {
        let f = TcpFlags::from_bits(0x12); // SYN+ACK
        assert!(f.syn && f.ack && !f.fin && !f.rst);
        let f = TcpFlags::from_bits(0x01); // FIN
        assert!(!f.syn && !f.ack && f.fin && !f.rst);
        let f = TcpFlags::from_bits(0x04); // RST
        assert!(!f.syn && !f.ack && !f.fin && f.rst);
    }

    #[test]
    fn display() {
        assert_eq!(TcpState::Established.to_string(), "ESTABLISHED");
        assert_eq!(TcpState::SynSent.to_string(), "SYN_SENT");
        assert_eq!(TcpState::Closed.to_string(), "CLOSED");
    }
}
