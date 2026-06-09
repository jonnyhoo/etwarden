//! # `divert::ffi`
//!
//! **Purpose**: Dynamic `WinDivert` DLL loading and raw FFI function pointers.
//! **Public API**: `WinDivertDll`, `WinDivertAddress`
//! **Dependencies**: `windows`, `error`
//! **Platform**: `windows-only`
//! **Privilege**: `requires-admin`
//! **Line budget**: 318 / 340

#![expect(
    unsafe_code,
    reason = "WinDivert dynamic FFI requires raw handles and calls"
)]

use std::ffi::c_void;

use windows::Win32::{
    Foundation::GetLastError,
    System::LibraryLoader::{GetProcAddress, LoadLibraryW},
};

use crate::error::{EtwardenError, Result};

// ---------------------------------------------------------------------------
// WinDivert constants
// ---------------------------------------------------------------------------

/// NETWORK layer — captures IP packets.
pub const WINDIVERT_LAYER_NETWORK: u32 = 0;

/// FLOW layer — captures flow establish/delete events with PID.
pub const WINDIVERT_LAYER_FLOW: u32 = 2;

/// SOCKET layer — captures socket connect events with PID before packet SYN.
pub const WINDIVERT_LAYER_SOCKET: u32 = 3;

/// Shutdown both send and recv.
pub const WINDIVERT_SHUTDOWN_BOTH: u32 = 0x03;

/// Checksum flag: recalculate all checksums.
pub const WINDIVERT_HELPER_CALC_CHECKSUM_ALL: u64 = 0x0000;

/// Sniff mode: capture packets without blocking.
pub const WINDIVERT_FLAG_SNIFF: u64 = 0x0001;

/// Recv-only mode: receive but cannot send.
pub const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;

/// FLOW event: new flow established.
pub const WINDIVERT_EVENT_FLOW_ESTABLISHED: u8 = 1;

/// FLOW event: flow deleted (closed).
pub const WINDIVERT_EVENT_FLOW_DELETED: u8 = 2;

/// SOCKET event: outbound socket connect operation.
pub const WINDIVERT_EVENT_SOCKET_CONNECT: u8 = 4;

// ---------------------------------------------------------------------------
// WinDivertAddress — 80-byte raw buffer (WinDivert 2.2 layout)
// ---------------------------------------------------------------------------
//
// Offset  0: INT64  Timestamp          (8 bytes)
// Offset  8: UINT32 Bitfield           (4 bytes)
//           bits 0-7:   Layer
//           bits 8-15:  Event
//           bit 16:     Sniffed
//           bit 17:     Outbound
//           bit 18:     Loopback
//           bit 19:     Impostor
//           bit 20:     IPv6
//           bit 21:     IPChecksum
//           bit 22:     TCPChecksum
//           bit 23:     UDPChecksum
//           bits 24-31: Reserved1
// Offset 12: UINT32 Reserved2          (4 bytes)
// Offset 16: Union  (64 bytes)
//   FLOW variant (WINDIVERT_DATA_FLOW):
//     +0:  UINT64 EndpointId           (8)
//     +8:  UINT64 ParentEndpointId     (8)
//     +16: UINT32 ProcessId            (4)
//     +20: UINT32 LocalAddr[4]         (16) — IPv4 in [0], host byte order
//     +36: UINT32 RemoteAddr[4]        (16) — IPv4 in [0], host byte order
//     +52: UINT16 LocalPort            (2) — host byte order
//     +54: UINT16 RemotePort           (2) — host byte order
//     +56: UINT8  Protocol             (1)
// Total: 80 bytes

/// Packet metadata returned by `WinDivertRecv`.
/// Stored as a raw 80-byte buffer matching WinDivert 2.2 `WINDIVERT_ADDRESS`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WinDivertAddress {
    buf: [u8; 80],
}

impl WinDivertAddress {
    /// Returns an all-zero address.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self { buf: [0u8; 80] }
    }

    // -- Common header accessors --

    /// Layer value (offset 8, byte 0 of bitfield UINT32).
    #[must_use]
    pub const fn layer(&self) -> u8 {
        self.buf[8]
    }

    /// Event value (offset 9, byte 1 of bitfield UINT32).
    #[must_use]
    pub const fn event(&self) -> u8 {
        self.buf[9]
    }

    /// Outbound flag (bit 17 of bitfield = bit 1 of byte 10).
    #[must_use]
    pub const fn outbound(&self) -> bool {
        (self.buf[10] & 0x02) != 0
    }

    /// Sets the NETWORK injection direction.
    pub const fn set_outbound(&mut self, outbound: bool) {
        self.buf[10] = if outbound {
            self.buf[10] | 0x02
        } else {
            self.buf[10] & !0x02
        };
    }

    /// Loopback flag (bit 18 of bitfield = bit 2 of byte 10).
    #[must_use]
    pub const fn loopback(&self) -> bool {
        (self.buf[10] & 0x04) != 0
    }

    // -- FLOW data accessors (valid when layer == WINDIVERT_LAYER_FLOW) --
    // Union starts at offset 16.

    /// Process ID from FLOW data (offset 16+16 = 32).
    #[must_use]
    pub const fn flow_process_id(&self) -> u32 {
        u32::from_le_bytes([self.buf[32], self.buf[33], self.buf[34], self.buf[35]])
    }

    /// Local IPv4 address from FLOW data (offset 16+20 = 36, host byte order u32).
    /// Converts from host byte order to network byte order octets for Ipv4Addr.
    #[must_use]
    pub const fn flow_local_addr_v4(&self) -> [u8; 4] {
        // Host byte order u32 → network byte order octets (little-endian swap).
        let [b0, b1, b2, b3] = [self.buf[36], self.buf[37], self.buf[38], self.buf[39]];
        [b3, b2, b1, b0]
    }

    /// Remote IPv4 address from FLOW data (offset 16+36 = 52, host byte order u32).
    /// Converts from host byte order to network byte order octets for Ipv4Addr.
    #[must_use]
    pub const fn flow_remote_addr_v4(&self) -> [u8; 4] {
        let [b0, b1, b2, b3] = [self.buf[52], self.buf[53], self.buf[54], self.buf[55]];
        [b3, b2, b1, b0]
    }

    /// Local port from FLOW data (offset 16+52 = 68, host byte order).
    #[must_use]
    pub const fn flow_local_port(&self) -> u16 {
        u16::from_le_bytes([self.buf[68], self.buf[69]])
    }

    /// Remote port from FLOW data (offset 16+54 = 70, host byte order).
    #[must_use]
    pub const fn flow_remote_port(&self) -> u16 {
        u16::from_le_bytes([self.buf[70], self.buf[71]])
    }

    /// Protocol from FLOW data (offset 16+56 = 72).
    #[must_use]
    pub const fn flow_protocol(&self) -> u8 {
        self.buf[72]
    }
}

// ---------------------------------------------------------------------------
// FFI function pointer types
// ---------------------------------------------------------------------------

type FnOpen = unsafe extern "system" fn(
    filter: *const i8,
    layer: u32,
    priority: i16,
    flags: u64,
) -> *mut c_void;

type FnRecv = unsafe extern "system" fn(
    handle: *mut c_void,
    packet: *mut u8,
    packet_len: u32,
    recv_len: *mut u32,
    addr: *mut WinDivertAddress,
) -> i32;

type FnSend = unsafe extern "system" fn(
    handle: *mut c_void,
    packet: *const u8,
    packet_len: u32,
    send_len: *mut u32,
    addr: *const WinDivertAddress,
) -> i32;

type FnClose = unsafe extern "system" fn(handle: *mut c_void) -> i32;

type FnShutdown = unsafe extern "system" fn(handle: *mut c_void, how: u32) -> i32;

type FnCalcChecksums = unsafe extern "system" fn(
    packet: *mut u8,
    packet_len: u32,
    addr: *const WinDivertAddress,
    flags: u64,
) -> u32;

// ---------------------------------------------------------------------------
// Dynamic DLL wrapper
// ---------------------------------------------------------------------------

/// Dynamically loaded WinDivert.dll function pointers.
pub struct WinDivertDll {
    open: FnOpen,
    recv: FnRecv,
    send: FnSend,
    close: FnClose,
    shutdown: FnShutdown,
    calc_checksums: FnCalcChecksums,
}

impl WinDivertDll {
    /// Loads `WinDivert.dll` from the executable's directory or system PATH.
    ///
    /// # Errors
    /// Returns [`EtwardenError::Divert`] if the DLL cannot be loaded or any
    /// required export is missing.
    pub fn load() -> Result<Self> {
        let dll_name = windows::core::HSTRING::from("WinDivert.dll");
        let module = unsafe { LoadLibraryW(&dll_name) }
            .map_err(|e| EtwardenError::Divert(format!("failed to load WinDivert.dll: {e}")))?;

        // Diagnostic: print loaded DLL path
        let mut path_buf = [0u16; 512];
        let len = unsafe {
            windows::Win32::System::LibraryLoader::GetModuleFileNameW(module, &mut path_buf)
        };
        let dll_path = String::from_utf16_lossy(&path_buf[..len as usize]);
        crate::output::diagnostic::info(format_args!("WinDivert.dll loaded from: {dll_path}"));

        let open = unsafe {
            GetProcAddress(module, windows::core::s!("WinDivertOpen"))
                .ok_or_else(|| EtwardenError::Divert("WinDivertOpen not found".into()))?
        };
        let recv = unsafe {
            GetProcAddress(module, windows::core::s!("WinDivertRecv"))
                .ok_or_else(|| EtwardenError::Divert("WinDivertRecv not found".into()))?
        };
        let send = unsafe {
            GetProcAddress(module, windows::core::s!("WinDivertSend"))
                .ok_or_else(|| EtwardenError::Divert("WinDivertSend not found".into()))?
        };
        let close = unsafe {
            GetProcAddress(module, windows::core::s!("WinDivertClose"))
                .ok_or_else(|| EtwardenError::Divert("WinDivertClose not found".into()))?
        };
        let shutdown = unsafe {
            GetProcAddress(module, windows::core::s!("WinDivertShutdown"))
                .ok_or_else(|| EtwardenError::Divert("WinDivertShutdown not found".into()))?
        };
        let calc_checksums = unsafe {
            GetProcAddress(module, windows::core::s!("WinDivertHelperCalcChecksums")).ok_or_else(
                || EtwardenError::Divert("WinDivertHelperCalcChecksums not found".into()),
            )?
        };

        Ok(Self {
            open: unsafe { std::mem::transmute::<_, FnOpen>(open) },
            recv: unsafe { std::mem::transmute::<_, FnRecv>(recv) },
            send: unsafe { std::mem::transmute::<_, FnSend>(send) },
            close: unsafe { std::mem::transmute::<_, FnClose>(close) },
            shutdown: unsafe { std::mem::transmute::<_, FnShutdown>(shutdown) },
            calc_checksums: unsafe { std::mem::transmute::<_, FnCalcChecksums>(calc_checksums) },
        })
    }

    /// Opens a WinDivert handle with the given BPF filter.
    ///
    /// # Errors
    /// Returns [`EtwardenError::Divert`] if `WinDivertOpen` returns `INVALID_HANDLE_VALUE`.
    pub fn open(
        &self,
        filter: &str,
        layer: u32,
        priority: i16,
        flags: u64,
    ) -> Result<WinDivertHandle> {
        let c_filter = std::ffi::CString::new(filter)
            .map_err(|e| EtwardenError::Divert(format!("invalid filter string: {e}")))?;
        let handle = unsafe { (self.open)(c_filter.as_ptr(), layer, priority, flags) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let os_err = unsafe { GetLastError() }.0;
            return Err(EtwardenError::Divert(format!(
                "WinDivertOpen failed (layer={layer}, filter={filter:?}, os_error={os_err})"
            )));
        }
        Ok(WinDivertHandle {
            handle,
            dll: WinDivertDllShallow {
                recv: self.recv,
                send: self.send,
                close: self.close,
                shutdown: self.shutdown,
                calc_checksums: self.calc_checksums,
            },
        })
    }
}

/// Subset of function pointers stored inside `WinDivertHandle` (no ownership).
struct WinDivertDllShallow {
    recv: FnRecv,
    send: FnSend,
    close: FnClose,
    shutdown: FnShutdown,
    calc_checksums: FnCalcChecksums,
}

const INVALID_HANDLE_VALUE: *mut c_void = (-1isize) as *mut c_void;

/// RAII handle to an open WinDivert capture session.
pub struct WinDivertHandle {
    handle: *mut c_void,
    dll: WinDivertDllShallow,
}

// SAFETY: WinDivert handles are kernel objects. Packet receive/send uses each
// handle from one worker thread; shutdown may be called from the owner thread
// to unblock a pending recv during stop.
unsafe impl Send for WinDivertHandle {}
unsafe impl Sync for WinDivertHandle {}

impl WinDivertHandle {
    /// Receives one matching packet. Blocks until a packet is available.
    ///
    /// # Errors
    /// Returns [`EtwardenError::Divert`] on WinDivert error or shutdown.
    pub fn recv(&self, buf: &mut [u8]) -> Result<(usize, WinDivertAddress)> {
        let mut recv_len: u32 = 0;
        let mut addr = WinDivertAddress::zeroed();
        let ok = unsafe {
            (self.dll.recv)(
                self.handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut recv_len,
                &mut addr,
            )
        };
        if ok == 0 {
            return Err(EtwardenError::Divert("WinDivertRecv failed".into()));
        }
        Ok((recv_len as usize, addr))
    }

    /// Sends (re-injects) a modified packet.
    ///
    /// # Errors
    /// Returns [`EtwardenError::Divert`] on WinDivert error.
    pub fn send(&self, packet: &[u8], addr: &WinDivertAddress) -> Result<()> {
        let mut send_len: u32 = 0;
        let ok = unsafe {
            (self.dll.send)(
                self.handle,
                packet.as_ptr(),
                packet.len() as u32,
                &mut send_len,
                addr,
            )
        };
        if ok == 0 {
            return Err(EtwardenError::Divert("WinDivertSend failed".into()));
        }
        Ok(())
    }

    /// Recalculates IP and TCP checksums after packet modification.
    pub fn calc_checksums(&self, packet: &mut [u8], addr: &WinDivertAddress, flags: u64) {
        unsafe {
            (self.dll.calc_checksums)(packet.as_mut_ptr(), packet.len() as u32, addr, flags);
        }
    }

    /// Signals shutdown to unblock a pending `recv`. Called from another thread
    /// to gracefully stop the capture loop.
    pub fn shutdown(&self) {
        unsafe {
            (self.dll.shutdown)(self.handle, WINDIVERT_SHUTDOWN_BOTH);
        }
    }
}

impl Drop for WinDivertHandle {
    fn drop(&mut self) {
        unsafe {
            (self.dll.shutdown)(self.handle, WINDIVERT_SHUTDOWN_BOTH);
            (self.dll.close)(self.handle);
        }
    }
}
