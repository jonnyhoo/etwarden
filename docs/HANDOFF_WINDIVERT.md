# WinDivert Redirect Handoff

## Current status

- Critical global-proxy defect is mitigated: `--mitm-system-proxy` is opt-in and requires `--no-divert`.
- Default MITM config does **not** mutate Windows system proxy settings.
- WinDivert redirect is implemented but experimental; it only runs with explicit `--divert`.
- Transparent HTTP redirect is now live/admin verified against the packaged release folder.
- Current redirect architecture is process-first: `--pid` targets the selected process exactly, WinDivert keeps loopback eligible, and the transparent proxy sniffs client bytes before choosing HTTP, TLS MITM, or raw TCP.
- Claude hot-attach validation no longer breaks `claude.exe` network when non-HTTP/TLS traffic is transparently tunneled instead of actively parsed.
- Request/response data capture is implemented:
  - decrypted HTTP events include bounded base64 request/response headers and payloads.
  - decrypted HTTP events also expose agent-friendly plaintext fields: `headers[]`, `body_format`, `body_text`, `body_json`, and `sse_events[]` when bytes are UTF-8/JSON/SSE.
  - raw transparent TCP tunnels emit bounded `tunnel_data` request/response payload chunks.
  - default HTTPS tunnel payloads are encrypted TLS bytes; true HTTP headers/payloads require `--divert-tls-mitm` plus trusted MITM CA.
- Full static gate and admin/release gate passed locally in the previous handoff.
- WinDivert runtime binaries must be bundled in Windows release packages; repo-root ad-hoc copies remain ignored, and release output is generated under `dist/`.
- Release packaging is now verified with official WinDivert `2.2.2-A` runtime: `dist/etwarden-windows-x64/` contains `etwarden.exe`, `WinDivert.dll`, `WinDivert64.sys`, `LICENSE.WinDivert`, `README.WinDivert`, and `THIRD_PARTY_NOTICES.txt`.

## What changed

- `src/cli.rs`
  - Added `--divert` opt-in for experimental active redirect.
  - Added `--divert-tls-mitm` opt-in for active transparent HTTPS MITM.
  - Kept `--no-divert` for legacy global system-proxy mode gating.
  - `--mitm-system-proxy` now requires `--no-divert` and conflicts with `--no-mitm`.
- `src/main.rs`
  - MITM system proxy is disabled by default.
  - Active redirect only runs when MITM is enabled and `--divert` is set.
- `src/cli.rs`
  - Default `--mitm-body-limit` is `1048576` bytes so large agent request bodies such as Claude/ccs JSON can be emitted and parsed into `body_json` by default.
- `src/target.rs`
  - PID targets now capture only the selected PID. This prevents `--pid claude.exe` from drifting to parent/delegated `node.exe` upstream TLS flows when the useful plaintext flow is `claude.exe` loopback HTTP.
  - Spawn targets still use the discovered process tree because command launch wrappers may hide the real network child.
- `src/capture/mod.rs`
  - Builds one shared `RedirectMap` before MITM/divert startup.
  - Bootstraps existing TCP connections for selected PIDs.
  - Starts WinDivert only when `enable_divert` is true.
- `src/divert/`
  - Added SOCKET + FLOW + NETWORK WinDivert implementation.
  - SOCKET records target PID connect tuples before the NETWORK SYN race.
  - FLOW tracks target PID TCP flows.
  - NETWORK keeps loopback eligible, reflects matching outbound TCP packets into the local MITM proxy, and rewrites proxy replies back to the original destination tuple.
  - FLOW/SOCKET attribution now preserves PID into `RedirectMap` entries.
- `src/process/network.rs`
  - Existing TCP inventory supports startup flow bootstrap.
- `src/mitm/mod.rs`
  - Reads accepted client source port from `RemoteAddr` and resolves matching `RedirectMap` entry.
  - Delegates transparent socket handling and upstream forwarding to `src/mitm/transparent.rs`.
  - Emits bounded base64 `headers_base64` and payload fields for decrypted HTTP request/response events.
- `src/mitm/body.rs`
  - Adds bounded raw-byte base64 capture helper shared by HTTP and tunnel capture.
- `src/output/schema/convert/http_payload.rs`
  - Projects captured HTTP `headers_base64` / `body_base64` into agent-friendly plaintext structure where possible.
  - Adds ordered `headers[]`, UTF-8 `body_text`, parsed JSON `body_json`, and parsed SSE `sse_events[]` while preserving base64 compatibility fields.
- `src/mitm/transparent.rs` and `src/mitm/transparent/`
  - Sniff redirected client bytes before choosing transparent handling.
  - Handle HTTP directly on any destination port, including loopback local-agent proxies such as `http://127.0.0.1:<port>/v1/messages?beta=true`.
  - Actively handle TLS only when `--divert-tls-mitm` is set; otherwise HTTPS/custom/TLS traffic falls back to raw TCP tunneling.
  - Tunnel non-HTTP transparent redirects as raw TCP so HTTPS, HTTP/2, SSE MCP, and custom protocols are not broken by forced HTTP/TLS parsing.
  - Rebuild absolute upstream URI from Host/authority/SNI hint plus original destination.
  - Dial original destination IP:port for transparent upstream forwarding.
- `src/mitm/transparent/protocol.rs`
  - Adds bounded first-byte sniffing with timeout; HTTP is recognized independent of port, TLS requires explicit `--divert-tls-mitm`, and unknown/server-first flows fall back to TCP.
- `src/mitm/transparent/tcp.rs`
  - Captures request/response tunnel bytes with the configured byte limit and emits `tunnel_data` after tunnel close.
- `src/parser/types/event.rs` and `src/output/schema/`
  - Add `TunnelData` / `TunnelDataEventLine` plus header fields on decrypted HTTP schema lines.
- `scripts/package-release.ps1`
  - Builds `dist/etwarden-windows-x64/` with `etwarden.exe`, `WinDivert.dll`, `WinDivert64.sys`, `LICENSE.WinDivert`, and `THIRD_PARTY_NOTICES.txt`.
  - Requires an official signed WinDivert release or signed build root containing runtime binaries; source checkout alone is not enough.
  - Skips unchanged locked files and removes unmanaged files from the default package output before listing package contents.
- `.repo-control-plane/static-gates/artifact-policy.json`
  - Records WinDivert release-package requirements and LGPLv3 notice mode.
- `Cargo.toml` / `Cargo.lock`
  - Added direct `webpki-roots` dependency for transparent TLS upstream validation.

## Live/admin validation result

HTTP transparent redirect is live/admin verified from an elevated shell using packaged `dist/etwarden-windows-x64/` runtime files.

Validated behavior:

- Admin shell confirmed: `IsAdmin=True`.
- `WinDivert.dll` loaded from `dist/etwarden-windows-x64/WinDivert.dll`.
- MITM listened on local interface `192.168.254.61:3003`.
- SOCKET saw target connect: `PID=8572 local:19219 -> remote:172.66.147.243:80`.
- NETWORK emitted redirect: `REDIRECT 192.168.254.61:19219 -> 172.66.147.243:80 to proxy :3003`.
- NDJSON emitted `decrypted_http_request` and `decrypted_http_response` for `example.com:80`.
- Client got `STATUS=200`, `LEN=528`.
- Summary emitted `connections_total=1`, `bytes_out_total=170`, `bytes_in_total=610`.

Root cause fixed during live validation: destination-only SYN rewrite reached neither the local MITM nor the original TCP client correctly. Current implementation reflects client packets into an inbound local-proxy connection and rewrites proxy replies back to the original destination tuple.

Loopback HTTP redirect is also live/admin verified after the process-first refactor:

- Packaged runtime: `dist/etwarden-windows-x64/etwarden.exe --pid 14548 --divert --mitm-listen 127.0.0.1:3003`.
- WinDivert NETWORK filter kept loopback eligible: `outbound and ip and tcp and tcp.DstPort != 3003`.
- SOCKET saw target connect: `PID=14548 local:64946 -> remote:127.0.0.1:37145`.
- NETWORK emitted redirect: `REDIRECT 127.0.0.1:64946 -> 127.0.0.1:37145 to proxy :3003`.
- FLOW confirmed establishment: `FLOW + established PID=14548 local:64946 -> remote:127.0.0.1:37145`.
- Client got `STATUS=200` for `POST /v1/messages?beta=true`.
- NDJSON emitted `decrypted_http_request` and `decrypted_http_response` for `127.0.0.1:37145`.
- Summary emitted `connections_total=1`, `bytes_out_total=261`, `bytes_in_total=189`.

Loopback-specific root cause fixed during this validation: rewritten loopback packets must preserve WinDivert loopback direction instead of forcing `addr.set_outbound(false)`. Non-loopback redirects still flip direction to reflect packets into the local proxy.

Packaging status: the user-provided path `D:\vibe_koding_pro\WinDivert-master\WinDivert-master` exists, but it is a source checkout only: no `WinDivert.dll` or `WinDivert64.sys` was found there. Official WinDivert `2.2.2-A` was downloaded from `https://reqrypt.org/download/WinDivert-2.2.2-A.zip` into the ignored repo cache, extracted, and used for packaging. `WinDivert64.sys` Authenticode signature verified as valid during packaging.

Keep `--divert` experimental until HTTPS, HTTP/2, and non-default-port cases are live/admin covered.

Claude hot-attach validation after the raw TCP tunnel change:

- Target: already-running `claude.exe` PID `9188`.
- Packaged runtime: `dist/etwarden-windows-x64/etwarden.exe --pid 9188 --divert --mitm-listen 192.168.254.61:3003 --duration 300`.
- WinDivert loaded from packaged `dist/etwarden-windows-x64/WinDivert.dll`.
- Redirect active for process tree including `claude.exe` PID `9188` and parent `node.exe` PID `18612`.
- User sent a prompt while capture was active.
- Captured loopback prompt flow: `claude.exe` `127.0.0.1:16851 -> 127.0.0.1:23100`, `bytes_out=141976`, repeated recv chunks, then disconnect.
- Captured remote Claude/network flow: `node.exe` PID `18612`, `192.168.254.61:16852 -> 119.23.85.51:443`, redirected to local proxy and tunneled as TCP.
- Tunnel result: `transparent TCP tunnel closed pid=18612 target=119.23.85.51:443 up=143394 down=8561`.
- Previous failure (`transparent TLS accept failed: tls handshake eof`) is absent in this run.

Claude request/response data validation after `tunnel_data` implementation:

- Target: already-running `claude.exe` PID `9188`; delegated remote traffic owned by parent `node.exe` PID `18612`.
- Packaged runtime: `dist/etwarden-windows-x64/etwarden.exe --pid 9188 --divert --mitm-listen 192.168.254.61:3003 --duration 240`.
- Capture started only after stderr confirmed SOCKET, FLOW, and NETWORK redirect workers were active.
- User sent a prompt while capture was active.
- Redirect confirmed: `REDIRECT 192.168.254.61:14354 -> 119.23.85.51:443 to proxy :3003`.
- Tunnel result: `transparent TCP tunnel closed pid=18612 target=119.23.85.51:443 up=144429 down=9911`.
- NDJSON emitted two `tunnel_data` lines for PID `18612`:
  - request: `encrypted=true`, `payload_base64` present, `bytes_seen=144429`, `bytes_captured=65536`, `payload_truncated=true`.
  - response: `encrypted=true`, `payload_base64` present, `bytes_seen=9911`, `bytes_captured=9911`.
- HTTP headers were absent because default Claude HTTPS was raw-tunneled, not actively decrypted. This is expected safe behavior. Use `--divert-tls-mitm` with a trusted MITM CA to expose real HTTPS request/response headers and payloads.

Claude/ccs architectural correction:

- User-verified SunnyNet process capture for `claude.exe` showed plaintext local HTTP: `http://127.0.0.1:37144/v1/messages?beta=true`.
- Previous etwarden attempts targeted `node.exe`/ccs upstream TLS (`119.23.85.51:443`) and `--divert-tls-mitm` broke connectivity with `transparent TLS accept failed: tls handshake eof`.
- Current decision: `--pid claude.exe --divert` should prioritize `claude.exe -> 127.0.0.1:<ccs-port>` HTTP capture, not parent `node.exe -> upstream 443` TLS MITM.
- New expected live validation command should use a loopback-capable listener, e.g. default `--mitm-listen 127.0.0.1:3003` for Claude local proxy capture. Use `0.0.0.0:3003` only when deliberately validating both loopback and non-loopback redirects.
- Latest exact-PID Claude live run used `claude.exe` PID `13832` with `--pid 13832 --divert --mitm-listen 127.0.0.1:3003 --duration 180`.
- That run activated WinDivert for `[13832]` but emitted no SOCKET/FLOW/NETWORK redirect events and ended with summary `connections_total=0`, `bytes_out_total=0`, `bytes_in_total=0`.
- Follow-up TCP inventory showed `claude.exe` PID `13832` only had `0.0.0.0:37149 Bound`, while ccs `node.exe` PID `18524` was listening on `127.0.0.1:37144`.
- Interpretation: the new exact-PID path did not break Claude, but the run did not observe a fresh Claude -> ccs request during the capture window. Actual Claude/ccs proof still needs a fresh prompt or Claude restart while capture is active.

Actual Claude/ccs loopback HTTP validation is now complete:

- Target: already-running `claude.exe` PID `13832`.
- Packaged runtime: `dist/etwarden-windows-x64/etwarden.exe --pid 13832 --divert --mitm-listen 127.0.0.1:3003 --duration 600`.
- WinDivert loaded from packaged `dist/etwarden-windows-x64/WinDivert.dll`.
- Redirect active for exact PID list `[13832]`.
- User sent a prompt while capture was active.
- SOCKET saw target connect: `PID=13832 local:49270 -> remote:127.0.0.1:37144`.
- NETWORK emitted redirect: `REDIRECT 127.0.0.1:49270 -> 127.0.0.1:37144 to proxy :3003`.
- FLOW confirmed establishment: `FLOW + established PID=13832 local:49270 -> remote:127.0.0.1:37144`.
- NDJSON emitted `decrypted_http_request` with `method=POST`, `path=/v1/messages?beta=true`, `host=127.0.0.1:37144`, `content_type=application/json`, and request `body_base64` present.
- NDJSON emitted `decrypted_http_response` with `HTTP/1.1 200 OK`, `content_type=text/event-stream; charset=utf-8`, and SSE response `body_base64` present.
- This matches the SunnyNet-observed plaintext interception point and validates that default Claude capture must stay on local loopback HTTP, not upstream TLS MITM.

## Release packaging decision

Windows release packages must include WinDivert runtime files next to `etwarden.exe`; otherwise `--divert` breaks on a clean machine.

Use:

```powershell
pwsh -NoProfile -File scripts/repo-control.ps1 package:release -WinDivertRoot <official-release-or-build-root>
```

The package script expects one runtime directory containing:

- `WinDivert.dll`
- `WinDivert64.sys`

It writes/copies:

- `dist/etwarden-windows-x64/etwarden.exe`
- `dist/etwarden-windows-x64/WinDivert.dll`
- `dist/etwarden-windows-x64/WinDivert64.sys`
- `dist/etwarden-windows-x64/LICENSE.WinDivert`
- `dist/etwarden-windows-x64/THIRD_PARTY_NOTICES.txt`

WinDivert is LGPLv3/GPLv2 dual-licensed. Package under LGPLv3 terms, keep the current dynamic DLL loading, ship `LICENSE.WinDivert`, and preserve user ability to replace `WinDivert.dll`/`WinDivert64.sys` with an interface-compatible build. Prefer official signed WinDivert runtime binaries for release; use `-AllowUnsignedDriver` only for local admin validation.

## Remaining validation

1. Verify protocol edge cases:
   - Controlled loopback HTTP selftest is already verified against packaged runtime with `STATUS=200` and decrypted request/response events.
   - Actual Claude/ccs loopback HTTP is already verified with decrypted request/response events without `--divert-tls-mitm`.
   - Agent-friendly plaintext HTTP output is covered by schema snapshots for JSON request bodies and SSE response bodies.
   - HTTP Host header reconstruction.
   - Explicit active HTTPS MITM opt-in with SNI + trusted generated CA remains experimental and must not be the default Claude path.
   - Non-default destination ports beyond the Claude/SSE-MCP case.
   - HTTP/2 client-side requests in raw tunnel mode and any future active MITM mode.
2. Keep static regression coverage passing:
   - Default run does not enable global system proxy.
   - `--mitm-system-proxy` only works with `--no-divert`.
   - `--divert` is explicit opt-in.
   - Existing IPv4 TCP tuples seed WinDivert flow keys.
   - Transparent authority reconstruction and upstream origin-form forwarding.
   - WinDivert packet reflection/reverse rewrite helpers.
3. Verify release packaging:
   - Run `scripts/repo-control.ps1 package:release` against an official release or signed build root containing `WinDivert.dll` + `WinDivert64.sys`.
   - Confirm clean-machine package runs `etwarden.exe --divert ...` without requiring PATH/workspace WinDivert artifacts.

## Local artifact policy

Do not commit repo-root ad-hoc copies:

- `etwarden-mitm-ca.key`
- `etwarden-mitm-ca.crt`
- `*.log`
- `spawn_test*.txt`
- `WinDivert.dll`
- `WinDivert32.sys`
- `WinDivert64.sys`

Repo-root ad-hoc copies are covered by `.gitignore`. Release bundles are written under ignored `dist/` by `scripts/package-release.ps1` and must include WinDivert license/notice files.

## Useful files

| File | Role |
|------|------|
| `src/cli.rs` | CLI flags for MITM, legacy proxy, experimental divert |
| `src/main.rs` | Top-level routing into capture config |
| `src/capture/mod.rs` | MITM/divert startup orchestration |
| `src/divert/redirect.rs` | SOCKET + FLOW + NETWORK worker loops |
| `src/divert/ffi.rs` | Dynamic WinDivert FFI |
| `src/divert/packet.rs` | IPv4/TCP parsing and address/port rewrite |
| `src/divert/redirect_map.rs` | Client source port to original destination map |
| `src/process/network.rs` | Startup TCP connection inventory |
| `src/mitm/mod.rs` | MITM proxy entrypoint and request/response event capture |
| `src/mitm/transparent.rs` | Transparent redirect routing facade |
| `src/mitm/transparent/` | Transparent protocol sniffing, HTTP/TLS socket handling, URI rebuild, raw tunnel fallback, and origin upstream forwarding |
| `scripts/package-release.ps1` | Release bundle creation with WinDivert runtime and notices |
| `.repo-control-plane/static-gates/artifact-policy.json` | Runtime artifact packaging policy |

## WinDivert reference

- Local docs: `D:\vibe_koding_pro\WinDivert-master\WinDivert-master\doc\windivert.html`
- Header: `D:\vibe_koding_pro\WinDivert-master\WinDivert-master\include\windivert.h`
- Source checkout version file: `2.2.0`
- Packaged runtime version: official WinDivert `2.2.2-A` under `.repo-control-plane/cache/windivert/` (ignored)
- FLOW layer requires `WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY`.
- FLOW address IPv4 fields are host-byte-order u32; packet headers use network byte order.
