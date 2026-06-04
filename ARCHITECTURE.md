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
- **DPI (Deep Packet Inspection)**: Protocol identification from raw NDIS frames
- **IP classification**: Public/private/link-local/multicast scope classification
- **TCP state machine**: SYN/SYN-ACK/FIN/RST state tracking per flow
- **Connection tracker**: Flow-level aggregation with byte counters, idle timeout, and cleanup

Designed as a machine-readable CLI tool for agent runtimes — the JSON contract
is the primary API surface.

```
etwarden --pid 1234 --duration 10
etwarden --spawn "curl.exe https://example.com"
etwarden --spawn "cmd /C claude -p prompt --output-format json" --spawn-stdout captures/claude-result.json --spawn-stderr captures/claude-stderr.log
```

Spawned child output never enters etwarden stdout. Use `--spawn-stdout <path>` and
`--spawn-stderr <path>` for autonomous result capture while etwarden stdout stays NDJSON-only.

---

## Directory Layout

```
etwarden/
├── src/
│   ├── main.rs                    # Entry point. CLI parse + assemble + run. ≤80 lines
│   ├── cli.rs                     # clap definitions. ≤100 lines
│   ├── error.rs                   # Unified Error type. ≤80 lines
│   ├── lib.rs                     # Crate root re-exports. ≤30 lines
│   ├── classify.rs                # IP scope classification (Public/Private/LinkLocal/etc). ≤250 lines
│   ├── tracker.rs                 # Connection flow tracker with byte counters + DPI. ≤450 lines
│   │
│   ├── capture/                   # Deep module: ETW session lifecycle
│   │   ├── mod.rs                 # pub interface only. ≤100 lines
│   │   ├── session.rs             # StartTrace / StopTrace lifecycle. ≤200 lines
│   │   ├── provider.rs            # EnableTraceEx2 per provider. ≤400 lines
│   │   └── event_loop.rs          # ProcessTrace consume loop + dispatch. ≤200 lines
│   │
│   ├── parser/                    # Hot-swap seam: one impl per ETW provider
│   │   ├── mod.rs                 # EventParser trait + static registry. ≤100 lines
│   │   ├── types.rs               # RawEvent, NetEvent, RawFrame, FiveTuple, Protocol. ≤300 lines
│   │   ├── tcpip.rs               # Microsoft-Windows-TCPIP parser. ≤450 lines
│   │   ├── ndis.rs                # Microsoft-Windows-NDIS-PacketCapture parser. ≤350 lines
│   │   ├── correlation.rs         # Networking-Correlation ActivityId map. ≤200 lines
│   │   ├── dns.rs                 # DNS wire-format parser (question/answer extraction). ≤350 lines
│   │   ├── dns_codes.rs           # IANA DNS type/status lookup tables + parse_query_results. ≤250 lines
│   │   ├── dpi.rs                 # Deep packet inspection: protocol identification from payload. ≤350 lines
│   │   └── tcp_state.rs           # TCP FSM: SYN/SYN-ACK/FIN/RST state transitions. ≤250 lines
│   │
│   ├── filter/                    # Hot-swap seam: drop/allow per event
│   │   ├── mod.rs                 # Filter trait. ≤60 lines
│   │   └── pid.rs                 # PID allowlist filter. ≤150 lines
│   │
│   ├── pcap/                      # Raw packet correlation + pcapng write
│   │   ├── mod.rs                 # pub interface. ≤60 lines
│   │   ├── writer.rs              # pcapng block writer. ≤200 lines
│   │   └── correlator.rs          # 5-tuple → TargetPid mapping. ≤200 lines
│   │
│   ├── process/                   # Subprocess spawn + lifecycle + name lookup
│   │   ├── mod.rs                 # pub interface. ≤60 lines
│   │   ├── spawn.rs               # --spawn mode: launch + PID extract. ≤150 lines
│   │   ├── monitor.rs             # Child process alive-check + exit notify. ≤100 lines
│   │   └── lookup.rs              # PID → process name cache (OpenProcess + QueryFullProcessImageName). ≤150 lines
│   │
│   └── output/                    # Hot-swap seam: serialization format
│       ├── mod.rs                 # Emitter trait. ≤60 lines
│       ├── json.rs                # NDJSON lines to stdout. ≤200 lines
│       └── schema.rs              # Stable agent-contract serde types. ≤550 lines
│
├── tests/
│   ├── integration.rs             # Admin-required. feature = "integration"
│   └── schema_compat.rs           # Schema regression: no breaking changes
│
├── benches/
│   └── event_throughput.rs        # criterion: ETW event parse throughput
│
├── docs/
│   ├── DEV_STANDARDS.md           # Toolchain, CI gate, lint policy, file rules
│   ├── ROADMAP.md                 # Full research + 4-phase implementation plan
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
  │         parser/dpi.rs ──► protocol identification (TLS SNI, DNS, HTTP, etc.)
  │              │
  │         pcap/correlator.rs ── 5-tuple match → assign TargetPid
  │              │
  │         pcap/writer.rs ──► .pcapng file (--pcap-out flag)
  │
  └─ Microsoft-Windows-Networking-Correlation
       └─ parser/correlation.rs → ActivityId map update
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

### SummaryLine (final line — always present)

```json
{"type":"summary","pid":1234,"duration_ms":10000,"connections_total":3,"bytes_out_total":1024,"bytes_in_total":8192,"pcap_written":true}
```

### OutputLine enum (schema.rs)

```rust
pub enum OutputLine {
    Event(EventLine),
    DnsEvent(DnsEventLine),
    Summary(SummaryLine),
}
```

Stderr receives diagnostic/error output. Stdout is exclusively NDJSON.

`schema.rs` types are the contract. They MUST NOT have breaking changes.
Use `schema_compat.rs` regression test to enforce this.

---

## Module Line Budgets

| File | Budget | Actual | Status |
|------|--------|--------|--------|
| `main.rs` | 80 | 66 | ✅ |
| `lib.rs` | 30 | 19 | ✅ |
| `cli.rs` | 100 | 84 | ✅ |
| `error.rs` | 80 | 86 | ⚠ over |
| `classify.rs` | 250 | 221 | ✅ |
| `tracker.rs` | 450 | 401 | ✅ |
| `capture/mod.rs` | 100 | 83 | ✅ |
| `capture/session.rs` | 200 | 92 | ✅ |
| `capture/provider.rs` | 400 | 353 | ✅ |
| `capture/event_loop.rs` | 200 | 133 | ✅ |
| `parser/mod.rs` | 100 | 82 | ✅ |
| `parser/types.rs` | 300 | 257 | ✅ |
| `parser/tcpip.rs` | 450 | 419 | ✅ |
| `parser/ndis.rs` | 350 | 323 | ✅ |
| `parser/correlation.rs` | 200 | 160 | ✅ |
| `parser/dns.rs` | 350 | 318 | ✅ |
| `parser/dns_codes.rs` | 250 | 224 | ✅ |
| `parser/dpi.rs` | 350 | 331 | ✅ |
| `parser/tcp_state.rs` | 250 | 209 | ✅ |
| `filter/mod.rs` | 60 | 21 | ✅ |
| `filter/pid.rs` | 150 | 138 | ✅ |
| `pcap/mod.rs` | 60 | 24 | ✅ |
| `pcap/writer.rs` | 200 | 163 | ✅ |
| `pcap/correlator.rs` | 200 | 99 | ✅ |
| `process/mod.rs` | 60 | 14 | ✅ |
| `process/spawn.rs` | 150 | 131 | ✅ |
| `process/monitor.rs` | 100 | 47 | ✅ |
| `process/lookup.rs` | 150 | 100 | ✅ |
| `output/mod.rs` | 60 | 27 | ✅ |
| `output/json.rs` | 200 | 186 | ✅ |
| `output/schema.rs` | 550 | 488 | ✅ |

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
| 5 | HTTPS decryption (rustls-mitm) | ✅ Done |
| 6 | Traffic control (rule engine, WinDivert) | Planned |
| 7 | Advanced (Protobuf output, search, scripting) | Planned |

Phases 1–5 are shipped. Phase 6+ follows the ROADMAP.
All module seams are designed for all phases from day one.
