# WinDivert Redirect Handoff

## Current status

- Critical global-proxy defect is mitigated: `--mitm-system-proxy` is opt-in and requires `--no-divert`.
- Default MITM config does **not** mutate Windows system proxy settings.
- WinDivert redirect is implemented but experimental; it only runs with explicit `--divert`.
- Transparent MITM upstream resolution has an initial implementation in `src/mitm/transparent.rs`; it is compile/unit covered, but not live/admin verified.
- Full static gate and admin/release gate now pass locally.
- WinDivert runtime binaries are local artifacts and are ignored, not vendored; they are currently absent from workspace/PATH, so live divert validation is blocked.

## What changed

- `src/cli.rs`
  - Added `--divert` opt-in for experimental active redirect.
  - Kept `--no-divert` for legacy global system-proxy mode gating.
  - `--mitm-system-proxy` now requires `--no-divert` and conflicts with `--no-mitm`.
- `src/main.rs`
  - MITM system proxy is disabled by default.
  - Active redirect only runs when MITM is enabled and `--divert` is set.
- `src/capture/mod.rs`
  - Builds one shared `RedirectMap` before MITM/divert startup.
  - Bootstraps existing TCP connections for selected PIDs.
  - Starts WinDivert only when `enable_divert` is true.
- `src/divert/`
  - Added FLOW + NETWORK WinDivert implementation.
  - FLOW tracks target PID TCP flows.
  - NETWORK rewrites matching outbound TCP SYN packets to the local MITM proxy.
  - FLOW table now preserves PID into `RedirectMap` entries.
- `src/process/network.rs`
  - Existing TCP inventory supports startup flow bootstrap.
- `src/mitm/mod.rs`
  - Reads accepted client source port from `RemoteAddr` and consumes matching `RedirectMap` entry.
  - Delegates transparent socket handling and upstream forwarding to `src/mitm/transparent.rs`.
- `src/mitm/transparent.rs` and `src/mitm/transparent/`
  - Handle transparent HTTP directly and transparent TLS via `LazyConfigAcceptor` without requiring explicit proxy CONNECT.
  - Rebuild absolute upstream URI from Host/authority/SNI hint plus original destination.
  - Dial original destination IP:port for transparent upstream forwarding.
- `Cargo.toml` / `Cargo.lock`
  - Added direct `webpki-roots` dependency for transparent TLS upstream validation.

## Remaining validation gap

Transparent proxy upstream resolution is implemented but not live/admin verified.

The new path bypasses `http-mitm-proxy` CONNECT handling for transparently redirected sockets: it takes the original destination from `RedirectMap`, accepts raw HTTP/TLS, reconstructs the upstream URI, and forwards to the original IP:port.

Current blocker: admin privileges are available, but `WinDivert.dll` is not present in the workspace or PATH, and the previously documented `E:\VIBE_CODING_WORK\WinDivert-2.2.2-A` path is absent on this machine.

Keep `--divert` experimental until this is tested live with admin privileges and local WinDivert runtime artifacts.

## Recommended next validation

1. Run live/admin integration test plan for:
   - FLOW events for target PID.
   - NETWORK SYN rewrite.
   - MITM request/response emitted after transparent redirect.
2. Verify protocol edge cases:
   - HTTPS with SNI + trusted generated CA.
   - HTTP Host header reconstruction.
   - Non-default destination ports.
   - HTTP/2 client-side requests over transparent TLS.
3. Keep static regression coverage passing:
   - Default run does not enable global system proxy.
   - `--mitm-system-proxy` only works with `--no-divert`.
   - `--divert` is explicit opt-in.
   - Existing IPv4 TCP tuples seed WinDivert flow keys.
   - Transparent authority reconstruction and upstream origin-form forwarding.

## Local artifact policy

Do not commit:

- `etwarden-mitm-ca.key`
- `etwarden-mitm-ca.crt`
- `*.log`
- `spawn_test*.txt`
- `WinDivert.dll`
- `WinDivert32.sys`
- `WinDivert64.sys`

These are covered by `.gitignore`. WinDivert binary vendoring still needs a license/provenance decision before any release packaging change.

## Useful files

| File | Role |
|------|------|
| `src/cli.rs` | CLI flags for MITM, legacy proxy, experimental divert |
| `src/main.rs` | Top-level routing into capture config |
| `src/capture/mod.rs` | MITM/divert startup orchestration |
| `src/divert/redirect.rs` | FLOW + NETWORK worker loops |
| `src/divert/ffi.rs` | Dynamic WinDivert FFI |
| `src/divert/packet.rs` | IPv4/TCP parsing and destination rewrite |
| `src/divert/redirect_map.rs` | Local source port to original destination map |
| `src/process/network.rs` | Startup TCP connection inventory |
| `src/mitm/mod.rs` | MITM proxy entrypoint and request/response event capture |
| `src/mitm/transparent.rs` | Transparent redirect routing facade |
| `src/mitm/transparent/` | Transparent HTTP/TLS socket handling, URI rebuild, and origin upstream forwarding |

## WinDivert reference

- Local docs: `E:\VIBE_CODING_WORK\WinDivert-2.2.2-A\doc\WinDivert.html`
- Header: `E:\VIBE_CODING_WORK\WinDivert-2.2.2-A\include\windivert.h`
- FLOW layer requires `WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY`.
- FLOW address IPv4 fields are host-byte-order u32; packet headers use network byte order.
