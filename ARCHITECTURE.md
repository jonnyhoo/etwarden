# etwarden — Architecture

> Process-level network capture CLI for agent runtime consumption.
> Windows-only. Requires administrator privileges.

---

## System Purpose

`etwarden` captures per-process network activity via Windows ETW and outputs
structured NDJSON to stdout. It provides:

- **Connection tracking**: TCP connect/disconnect/send/recv per PID via TCPIP ETW
- **DNS monitoring**: Query/response events with hostname, type, status, and resolved IPs via DNS Client ETW
- **Raw packet capture**: NDIS-level frames with PID correlation and pcapng export
- **DPI (Deep Packet Inspection)**: Protocol identification from raw NDIS frames — TLS ClientHello SNI/JA3/JA4, HTTP methods/headers
- **IP classification**: Public/private/link-local/multicast scope classification
- **TCP state machine**: SYN/SYN-ACK/FIN/RST state tracking per flow
- **Connection tracker**: Flow-level aggregation with byte counters, idle timeout, and cleanup
- **HTTPS MITM proxy**: Active decryption via `http-mitm-proxy` + `rcgen` CA, emitting HTTP request/response metadata
- **Traffic control rules**: Block/replace/intercept/hosts rules engine with JSON config

Designed as a machine-readable CLI tool for agent runtimes — the JSON contract
is the primary API surface.

```
etwarden --pid 1234 --duration 10
etwarden --spawn "curl.exe https://example.com"
etwarden --spawn "cmd /C claude -p prompt --output-format json" --spawn-stdout captures/claude-result.json --spawn-stderr captures/claude-stderr.log
etwarden browse --headless --browser edge --timeout 15 --after-load 3 https://example.com
```

Spawned child output never enters etwarden stdout. Use `--spawn-stdout <path>` and
`--spawn-stderr <path>` for autonomous result capture while etwarden stdout stays NDJSON-only.

---

## Directory Layout

```
etwarden/
├── src/
│   ├── main.rs                    # Entry point. CLI parse + assemble + run.
│   ├── cli.rs                     # clap definitions.
│   ├── error.rs                   # Unified Error type.
│   ├── lib.rs                     # Crate root re-exports.
│   ├── classify.rs                # IP scope classification (Public/Private/LinkLocal/etc).
│   ├── target.rs                  # CLI target resolution + stop signal. Binary-only.
│   ├── tracker.rs                 # Connection flow tracker with byte counters + DPI.
│   │
│   ├── capture/                   # Deep module: ETW session lifecycle
│   │   ├── mod.rs                 # CaptureConfig, run_capture orchestration.
│   │   ├── session.rs             # StartTrace / StopTrace lifecycle.
│   │   ├── provider.rs            # Re-exports for provider submodules.
│   │   ├── provider/common.rs     # Shared provider builder helpers.
│   │   ├── provider/tcpip.rs      # TCPIP provider builder.
│   │   ├── provider/tcpip_endpoint.rs  # TCPIP endpoint event builder.
│   │   ├── provider/tcpip/connection.rs  # TCPIP connection event builder.
│   │   ├── provider/tcpip/event.rs      # TCPIP event dispatch.
│   │   ├── provider/ndis.rs       # NDIS provider builder.
│   │   ├── event_loop.rs          # ProcessTrace consume loop + dispatch.
│   │   ├── event_loop/drain.rs    # Event drain helpers.
│   │   ├── event_loop/tests.rs    # Event loop tests.
│   │   └── timestamp.rs           # ETW timestamp conversion.
│   │
│   ├── parser/                    # Hot-swap seam: one impl per ETW provider
│   │   ├── mod.rs                 # EventParser trait + static registry.
│   │   ├── types.rs               # RawEvent, NetEvent, FiveTuple, Protocol.
│   │   ├── types/event.rs         # NetEvent variant definitions.
│   │   ├── types/event/accessors.rs  # NetEvent field accessor helpers.
│   │   ├── tcpip.rs               # Microsoft-Windows-TCPIP parser.
│   │   ├── tcpip/events.rs        # TCPIP event ID dispatch.
│   │   ├── tcpip/fields.rs        # TCPIP field extraction.
│   │   ├── tcpip/layout.rs        # TCPIP struct layouts.
│   │   ├── ndis.rs                # Microsoft-Windows-NDIS-PacketCapture parser.
│   │   ├── ndis/frame.rs          # NDIS frame parsing.
│   │   ├── ndis/packet.rs         # NDIS packet extraction.
│   │   ├── ndis/transport.rs      # Transport layer parsing.
│   │   ├── ndis/test_support.rs   # NDIS test helpers.
│   │   ├── dns.rs                 # DNS wire-format parser (question/answer).
│   │   ├── dns/name.rs            # DNS name decompression.
│   │   ├── dns/records.rs         # DNS record parsing.
│   │   ├── dns/types.rs           # DNS type definitions.
│   │   ├── dns_codes.rs           # IANA DNS type/status lookup tables.
│   │   ├── dpi.rs                 # DPI dispatcher: protocol identification.
│   │   ├── dpi/http.rs            # HTTP method/header extraction.
│   │   ├── dpi/tls.rs             # TLS ClientHello parsing + SNI/ALPN.
│   │   ├── dpi/tls/extensions.rs  # TLS extension parsing.
│   │   ├── dpi/tls/fingerprint.rs # JA3/JA4 fingerprint computation.
│   │   ├── endpoint.rs            # Endpoint resolution helpers.
│   │   └── tcp_state.rs           # TCP FSM: SYN/SYN-ACK/FIN/RST transitions.
│   │
│   ├── filter/                    # Hot-swap seam: drop/allow per event
│   │   ├── mod.rs                 # Filter trait.
│   │   ├── pid.rs                 # PID allowlist filter.
│   │   └── tree.rs                # Process-tree PID filter (root + descendants).
│   │
│   ├── pcap/                      # Raw packet correlation + pcapng write
│   │   ├── mod.rs                 # PcapSink trait + re-exports.
│   │   ├── writer.rs              # pcapng block writer.
│   │   ├── writer_block.rs        # pcapng block serialization helpers.
│   │   ├── correlator.rs          # 5-tuple → TargetPid mapping.
│   │   └── correlator/tuple.rs    # FiveTuple key type for correlator.
│   │
│   ├── process/                   # Subprocess spawn + lifecycle + name lookup
│   │   ├── mod.rs                 # Re-exports.
│   │   ├── spawn.rs               # --spawn mode: launch + PID extract.
│   │   ├── spawn/output.rs        # Spawn stdout/stderr capture.
│   │   ├── spawn/tests.rs         # Spawn tests.
│   │   ├── spawn_capture.rs       # --spawn-capture target resolution.
│   │   ├── monitor.rs             # Child process alive-check + exit notify.
│   │   ├── lookup.rs              # PID → process name cache.
│   │   ├── network.rs             # TCP socket inventory (netstat-esr).
│   │   ├── tree.rs                # Process tree cache (sysinfo).
│   │   └── tree/tests.rs          # Process tree tests.
│   │
│   ├── runtime/                    # Browse subcommand runtime
│   │   ├── mod.rs                 # Module re-exports.
│   │   ├── which.rs               # Browser discovery: registry, common paths, PATH.
│   │   ├── cdp.rs                 # CDP client: HTTP discovery, WebSocket page-load wait.
│   │   └── browse.rs              # Browse lifecycle: launch → CDP → capture → cleanup.
│   │
│   ├── mitm/                      # HTTPS MITM proxy
│   │   ├── mod.rs                 # MitmCaptureConfig, MitmProxyConfig, proxy loop.
│   │   ├── ca.rs                  # CA certificate generation (rcgen).
│   │   ├── body.rs                # gzip/br/deflate body decoding.
│   │   ├── pid.rs                 # PID resolution for MITM connections.
│   │   └── system_proxy.rs        # Windows system proxy set/restore.
│   │
│   ├── rules/                     # Traffic control rule engine
│   │   ├── mod.rs                 # Module re-exports.
│   │   ├── matcher.rs             # URL/pattern matching engine.
│   │   ├── ruleset.rs             # RuleSet: ordered rule evaluation.
│   │   ├── block.rs               # Block module re-exports.
│   │   ├── block/http.rs          # HTTP request blocking.
│   │   ├── block/socket.rs        # TCP/UDP socket blocking.
│   │   ├── block/websocket.rs     # WebSocket frame blocking.
│   │   ├── replace.rs             # Body/URL replacement rules.
│   │   ├── intercept.rs           # Intercept module re-exports.
│   │   ├── intercept/rule.rs      # Intercept rule evaluation.
│   │   ├── intercept/types.rs     # Intercept direction/target/operator types.
│   │   ├── hosts.rs               # Hosts DNS redirection rules.
│   │   ├── config.rs              # Config module re-exports.
│   │   ├── config/build.rs        # Rule config builder.
│   │   ├── config/value.rs        # Config value types.
│   │   ├── config/block.rs        # Block rule config.
│   │   ├── config/replace.rs      # Replace rule config.
│   │   ├── config/intercept.rs    # Intercept rule config.
│   │   ├── config/hosts.rs        # Hosts rule config.
│   │   └── config/*.rs tests      # Per-module test files.
│   │
│   └── output/                    # Hot-swap seam: serialization format
│       ├── mod.rs                 # Emitter trait.
│       ├── json.rs                # NDJSON lines to stdout.
│       ├── diagnostic.rs          # Stderr diagnostic output helpers.
│       ├── schema.rs              # Re-exports from schema submodules.
│       ├── schema/convert.rs      # NetEvent → OutputLine conversion.
│       ├── schema/convert/dns.rs  # DNS event conversion.
│       ├── schema/convert/dpi.rs  # DPI result conversion.
│       ├── schema/convert/event.rs # Event conversion dispatcher.
│       ├── schema/convert/network.rs # Network event conversion.
│       ├── schema/convert/process.rs # Process info conversion.
│       ├── schema/convert/event/dns.rs    # DNS event line builder.
│       ├── schema/convert/event/dpi.rs    # DPI event line builder.
│       ├── schema/convert/event/network.rs # Network event line builder.
│       ├── schema/line/mod.rs     # Line type re-exports.
│       ├── schema/line/event.rs   # EventLine, DnsEventLine, HttpEventLine, TlsEventLine, RuleHitEventLine.
│       ├── schema/line/meta.rs    # SummaryLine, ErrorLine, OutputLine enum.
│       └── schema/scope.rs        # IP scope string formatting.
│
├── target/                        # Binary-only: target resolution (not in lib.rs)
│   ├── spawn.rs                   # Spawn target helpers.
│   └── tests.rs                   # Target tests.
│
├── tests/
│   └── schema_compat.rs           # Schema regression: no breaking changes
│
├── benches/
│   └── event_throughput.rs        # criterion: ETW event parse throughput
│
├── docs/
│   ├── DEV_STANDARDS.md           # Toolchain, CI gate, lint policy, file rules
│   ├── ROADMAP.md                 # Full research + implementation plan
│   └── TASK_PLAN.md               # Task tracking
│
├── Cargo.toml
├── rustfmt.toml
├── deny.toml
├── ARCHITECTURE.md                # This file
├── CONTEXT.md                     # Domain glossary
├── AGENTS.md                      # Agent entry point
└── CLAUDE.md                      # Identical copy for Claude-family agents
```

---

## Data Flow

```
ETW Session (capture/session.rs)
  │
  ├─ Microsoft-Windows-TCPIP
  │    └─ parser/tcpip.rs → NetEvent::{Connect, Disconnect, Send, Recv}
  │              │
  │         filter/pid.rs ──► drop if not TargetPid
  │         filter/tree.rs ──► drop if not in process tree
  │              │
  │         tracker.rs ──► ingest into flow table, apply DPI on payload
  │              │
  │         pcap/correlator.rs ── register 5-tuple
  │              │
  │         output/json.rs ──► stdout NDJSON line (EventLine)
  │
  ├─ Microsoft-Windows-DNS-Client
  │    └─ parser/dns_codes.rs + provider.rs → NetEvent::{DnsQuery, DnsResponse}
  │              │
  │         filter/pid.rs ──► drop if not TargetPid
  │              │
  │         output/json.rs ──► stdout NDJSON line (DnsEventLine)
  │
  ├─ Microsoft-Windows-NDIS-PacketCapture
  │    └─ parser/ndis.rs → RawFrame{bytes, timestamp}
  │              │
  │         parser/dpi.rs ──► protocol identification (TLS SNI/JA3/JA4, HTTP, DNS)
  │              │
  │         pcap/correlator.rs ── 5-tuple match → assign TargetPid
  │              │
  │         pcap/writer.rs ──► .pcapng file (--pcap-out flag)
  │
  ├─ Microsoft-Windows-Networking-Correlation
  │    └─ parser/correlation.rs → ActivityId map update
  │
  └─ MITM Proxy (mitm/mod.rs) [optional, --mitm flag]
       │
       ├─ system_proxy.rs ──► set Windows system proxy → localhost:PORT
       ├─ ca.rs ──► generate per-host TLS certificates (rcgen)
       ├─ body.rs ──► decode gzip/br/deflate response bodies
       ├─ pid.rs ──► resolve PID from ETW connection table
       │
       ├─ rules/ruleset.rs ──► evaluate block/replace/intercept/hosts rules
       │
       └─ output/json.rs ──► stdout NDJSON line (HttpEventLine, TlsEventLine, RuleHitEventLine)
```

---

## Hot-Swap Seams

Three traits define all extension points. New providers, filters, or output
formats require only a new impl — no changes to other modules.

```rust
// parser/mod.rs
pub trait EventParser: Send + Sync {
    fn provider_guid(&self) -> windows::core::GUID;
    fn parse(&self, raw: &RawEvent) -> Option<NetEvent>;
}

// filter/mod.rs
pub trait Filter: Send + Sync {
    fn allow(&self, event: &NetEvent) -> bool;
}

// output/mod.rs
pub trait Emitter: Send {
    fn emit(&mut self, event: &NetEvent) -> anyhow::Result<()>;
    fn flush(&mut self) -> anyhow::Result<()>;
}
```

All three are assembled statically at startup in `main.rs`. No runtime
dynamic loading — deterministic, auditable, no unsafe plugin surface.

---

## JSON Output Contract (agent API)

Every `NetEvent` produces one NDJSON line. Stdout is the stable API surface.

### EventLine (Connect/Disconnect/Send/Recv)

```json
{"t":"2025-01-01T00:00:00.000Z","pid":1234,"proto":"TCP","src":"192.168.1.1:50234","dst":"93.184.216.34:443","event":"connect","bytes_out":0,"bytes_in":0}
```

### DnsEventLine (DnsQuery/DnsResponse)

```json
{"t":"2025-01-01T00:00:00.000Z","pid":1234,"event":"dns_query","hostname":"example.com","query_type":"A","query_results":"","status":"0"}
{"t":"2025-01-01T00:00:01.000Z","pid":1234,"event":"dns_response","hostname":"example.com","query_type":"A","query_results":"93.184.216.34","status":"0"}
```

### HttpEventLine (MITM decrypted HTTP)

```json
{"t":"2025-01-01T00:00:00.000Z","pid":1234,"event":"http_request","method":"GET","url":"https://example.com/api","host":"example.com","headers":{...},"body_preview":null}
{"t":"2025-01-01T00:00:00.500Z","pid":1234,"event":"http_response","status":200,"content_type":"application/json","headers":{...},"body_preview":"{\"key\":\"value\"}"}
```

### TlsEventLine (TLS ClientHello)

```json
{"t":"2025-01-01T00:00:00.000Z","pid":1234,"event":"tls_hello","sni":"example.com","alpn":["h2","http/1.1"],"tls_version":"TLS 1.3","ja3_hash":"a0e1f2d3...","ja4":"t13d1515h2_..."}
```

### RuleHitEventLine (rule engine match)

```json
{"t":"2025-01-01T00:00:00.000Z","event":"rule_hit","rule_type":"block","rule_name":"Block Ads","action":"close_request","url":"https://ads.example.com/banner.js","pid":1234}
```

### SummaryLine (final line — always present)

```json
{"type":"summary","pid":1234,"duration_ms":10000,"connections_total":3,"bytes_out_total":1024,"bytes_in_total":8192,"pcap_written":true}
```

### ErrorLine (terminal error before exit)

```json
{"type":"error","message":"Administrator privileges required"}
```

### OutputLine enum (schema/line/meta.rs)

```rust
pub enum OutputLine {
    Event(EventLine),
    DnsEvent(DnsEventLine),
    HttpEvent(HttpEventLine),
    TlsEvent(TlsEventLine),
    RuleHit(RuleHitEventLine),
    Summary(SummaryLine),
    Error(ErrorLine),
}
```

Stderr receives diagnostic/error output. Stdout is exclusively NDJSON.

`schema.rs` types are the contract. They MUST NOT have breaking changes.
Use `schema_compat.rs` regression test to enforce this.

---

## Module Line Budgets

### Core modules

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `main.rs` | 180 | 151 | ✅ |
| `lib.rs` | 40 | 22 | ✅ |
| `cli.rs` | 180 | 151 | ✅ |
| `error.rs` | 120 | 104 | ✅ |
| `classify.rs` | 250 | 221 | ✅ |
| `target.rs` | 180 | 123 | ✅ |
| `tracker.rs` | 350 | 314 | ✅ |

### capture/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `capture/mod.rs` | 200 | 152 | ✅ |
| `capture/session.rs` | 120 | 92 | ✅ |
| `capture/provider.rs` | 30 | 14 | ✅ |
| `capture/provider/common.rs` | 30 | 13 | ✅ |
| `capture/provider/tcpip.rs` | 50 | 36 | ✅ |
| `capture/provider/tcpip_endpoint.rs` | 100 | 72 | ✅ |
| `capture/provider/tcpip/connection.rs` | 80 | 64 | ✅ |
| `capture/provider/tcpip/event.rs` | 180 | 150 | ✅ |
| `capture/provider/ndis.rs` | 120 | 102 | ✅ |
| `capture/event_loop.rs` | 120 | 87 | ✅ |
| `capture/event_loop/drain.rs` | 100 | 69 | ✅ |
| `capture/event_loop/tests.rs` | 200 | 147 | ✅ |
| `capture/timestamp.rs` | 80 | 48 | ✅ |

### parser/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `parser/mod.rs` | 180 | 144 | ✅ |
| `parser/types.rs` | 200 | 154 | ✅ |
| `parser/types/event.rs` | 220 | 187 | ✅ |
| `parser/types/event/accessors.rs` | 100 | 68 | ✅ |
| `parser/tcpip.rs` | 280 | 239 | ✅ |
| `parser/tcpip/events.rs` | 200 | 161 | ✅ |
| `parser/tcpip/fields.rs` | 80 | 52 | ✅ |
| `parser/tcpip/layout.rs` | 100 | 81 | ✅ |
| `parser/ndis.rs` | 550 | 519 | ✅ |
| `parser/ndis/frame.rs` | 150 | 119 | ✅ |
| `parser/ndis/packet.rs` | 280 | 250 | ✅ |
| `parser/ndis/transport.rs` | 80 | 58 | ✅ |
| `parser/ndis/test_support.rs` | 180 | 149 | ✅ |
| `parser/dns.rs` | 300 | 269 | ✅ |
| `parser/dns/name.rs` | 100 | 68 | ✅ |
| `parser/dns/records.rs` | 150 | 119 | ✅ |
| `parser/dns/types.rs` | 100 | 84 | ✅ |
| `parser/dns_codes.rs` | 250 | 224 | ✅ |
| `parser/dpi.rs` | 120 | 89 | ✅ |
| `parser/dpi/http.rs` | 260 | 235 | ✅ |
| `parser/dpi/tls.rs` | 380 | 336 | ✅ |
| `parser/dpi/tls/extensions.rs` | 180 | 142 | ✅ |
| `parser/dpi/tls/fingerprint.rs` | 260 | 235 | ✅ |
| `parser/endpoint.rs` | 100 | 85 | ✅ |
| `parser/tcp_state.rs` | 250 | 209 | ✅ |

### filter/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `filter/mod.rs` | 40 | 22 | ✅ |
| `filter/pid.rs` | 180 | 144 | ✅ |
| `filter/tree.rs` | 140 | 99 | ✅ |

### pcap/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `pcap/mod.rs` | 40 | 25 | ✅ |
| `pcap/writer.rs` | 220 | 180 | ✅ |
| `pcap/writer_block.rs` | 150 | 113 | ✅ |
| `pcap/correlator.rs` | 280 | 236 | ✅ |
| `pcap/correlator/tuple.rs` | 80 | 59 | ✅ |

### process/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `process/mod.rs` | 40 | 26 | ✅ |
| `process/spawn.rs` | 160 | 128 | ✅ |
| `process/spawn/output.rs` | 80 | 63 | ✅ |
| `process/spawn/tests.rs` | 160 | 129 | ✅ |
| `process/spawn_capture.rs` | 160 | 131 | ✅ |
| `process/monitor.rs` | 80 | 47 | ✅ |
| `process/lookup.rs` | 150 | 125 | ✅ |
| `process/network.rs` | 250 | 203 | ✅ |
| `process/tree.rs` | 280 | 225 | ✅ |
| `process/tree/tests.rs` | 120 | 96 | ✅ |

### runtime/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `runtime/mod.rs` | 80 | 13 | ✅ |
| `runtime/which.rs` | 350 | 299 | ✅ |
| `runtime/cdp.rs` | 200 | 160 | ✅ |
| `runtime/browse.rs` | 280 | 242 | ✅ |

### mitm/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `mitm/mod.rs` | 750 | 686 | ✅ |
| `mitm/ca.rs` | 160 | 127 | ✅ |
| `mitm/body.rs` | 160 | 129 | ✅ |
| `mitm/pid.rs` | 80 | 49 | ✅ |
| `mitm/system_proxy.rs` | 220 | 177 | ✅ |

### rules/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `rules/mod.rs` | 30 | 17 | ✅ |
| `rules/matcher.rs` | 140 | 108 | ✅ |
| `rules/ruleset.rs` | 100 | 72 | ✅ |
| `rules/block.rs` | 30 | 14 | ✅ |
| `rules/block/http.rs` | 170 | 137 | ✅ |
| `rules/block/socket.rs` | 180 | 147 | ✅ |
| `rules/block/websocket.rs` | 170 | 139 | ✅ |
| `rules/replace.rs` | 200 | 164 | ✅ |
| `rules/intercept.rs` | 30 | 17 | ✅ |
| `rules/intercept/rule.rs` | 160 | 130 | ✅ |
| `rules/intercept/types.rs` | 120 | 94 | ✅ |
| `rules/hosts.rs` | 180 | 155 | ✅ |
| `rules/config.rs` | 60 | 42 | ✅ |
| `rules/config/build.rs` | 60 | 44 | ✅ |
| `rules/config/value.rs` | 100 | 78 | ✅ |

### output/

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `output/mod.rs` | 40 | 28 | ✅ |
| `output/json.rs` | 220 | 189 | ✅ |
| `output/diagnostic.rs` | 40 | 24 | ✅ |
| `output/schema.rs` | 220 | 187 | ✅ |
| `output/schema/convert.rs` | 350 | 313 | ✅ |
| `output/schema/convert/dns.rs` | 100 | 81 | ✅ |
| `output/schema/convert/dpi.rs` | 300 | 262 | ✅ |
| `output/schema/convert/event.rs` | 80 | 55 | ✅ |
| `output/schema/convert/network.rs` | 80 | 52 | ✅ |
| `output/schema/convert/process.rs` | 60 | 35 | ✅ |
| `output/schema/convert/event/dns.rs` | 80 | 54 | ✅ |
| `output/schema/convert/event/dpi.rs` | 200 | 171 | ✅ |
| `output/schema/convert/event/network.rs` | 120 | 99 | ✅ |
| `output/schema/line/mod.rs` | 30 | 12 | ✅ |
| `output/schema/line/event.rs` | 300 | 267 | ✅ |
| `output/schema/line/meta.rs` | 90 | 60 | ✅ |
| `output/schema/scope.rs` | 100 | 68 | ✅ |

Exceeding budget = module is doing too much = split required.

---

## Privilege & Platform

- **Platform**: Windows only (`#[cfg(target_os = "windows")]` at crate root)
- **Privilege**: Administrator required for ETW session creation and NDIS capture
- **Runtime check**: `capture/session.rs` verifies elevation at startup; exits with
  code 2 and JSON error line if not elevated

---

## Build Targets

| Command | Purpose |
|---------|---------|
| `cargo build --release` | Production binary |
| `cargo test` | Unit tests (no admin required) |
| `cargo test --features integration` | Integration tests (admin required) |
| `cargo bench` | Throughput benchmarks |
| `cargo deny check` | Supply chain audit |

---

## Phase Roadmap

All phases are part of the canonical design. See `docs/ROADMAP.md` for full detail.

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | TCPIP provider → connection-level NDJSON | ✅ Done |
| 2 | NDIS provider + pcap/correlator → .pcapng output | ✅ Done |
| 3 | `--spawn` mode: launch child process + track PID | ✅ Done |
| 3.5 | DNS Client ETW → DnsQuery/DnsResponse NDJSON | ✅ Done |
| 3.6 | DPI, TCP state machine, connection tracker, IP classification | ✅ Done |
| 4 | TLS SNI/JA3/JA4 fingerprinting, HTTP DPI, process name enrichment | ✅ Done |
| 5 | HTTPS decryption (MITM proxy + rule engine) | ✅ Done |
| 5.5 | `browse` subcommand: browser discovery, headless launch, CDP page-load detection | ✅ Done |
| 6 | WinDivert active capture layer | Planned |
| 7 | Advanced (Protobuf output, search, scripting) | Planned |

Phases 1–5 are shipped. Phase 6+ follows the ROADMAP.
All module seams are designed for all phases from day one.
