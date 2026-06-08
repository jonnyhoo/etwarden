# WinDivert Redirect Handoff

## Current status

- Critical global-proxy defect is mitigated: `--mitm-system-proxy` is opt-in and requires `--no-divert`.
- Default MITM config does **not** mutate Windows system proxy settings.
- WinDivert redirect is implemented but experimental; it only runs with explicit `--divert`.
- `RedirectMap` is wired into MITM config, but transparent upstream resolution is not complete in `src/mitm/mod.rs`.
- WinDivert runtime binaries are local artifacts and are ignored, not vendored.

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
- `src/process/network.rs`
  - Existing TCP inventory supports startup flow bootstrap.

## Remaining product gap

Transparent proxy upstream resolution is still incomplete.

Current `http-mitm-proxy` behavior forwards CONNECT traffic using the CONNECT authority. After WinDivert rewrites a raw TCP destination to `127.0.0.1:proxy_port`, the proxy can receive traffic, but it still needs a complete path to recover and use the original destination from `RedirectMap` when no explicit proxy CONNECT authority exists.

Keep `--divert` experimental until this is implemented and tested live.

## Recommended next implementation

1. Implement transparent upstream resolution in MITM:
   - Read accepted client source port from `RemoteAddr`.
   - Lookup original destination in `RedirectMap`.
   - Forward TLS/HTTP upstream using the original destination when the request was transparently redirected.
2. Add regression coverage for:
   - Default run does not enable global system proxy.
   - `--mitm-system-proxy` only works with `--no-divert`.
   - `--divert` is explicit opt-in.
   - Existing IPv4 TCP tuples seed WinDivert flow keys.
3. Add live/admin integration test plan for:
   - FLOW events for target PID.
   - NETWORK SYN rewrite.
   - MITM request/response emitted after transparent redirect.

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
| `src/mitm/mod.rs` | MITM proxy; still needs transparent upstream completion |

## WinDivert reference

- Local docs: `E:\VIBE_CODING_WORK\WinDivert-2.2.2-A\doc\WinDivert.html`
- Header: `E:\VIBE_CODING_WORK\WinDivert-2.2.2-A\include\windivert.h`
- FLOW layer requires `WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY`.
- FLOW address IPv4 fields are host-byte-order u32; packet headers use network byte order.
