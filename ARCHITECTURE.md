# etwarden — Architecture

> Process-level network capture CLI for agent runtime consumption.
> Windows-only. Requires administrator privileges.

---

## System Purpose

`etwarden` captures per-process network activity via Windows ETW and outputs
structured NDJSON to stdout. Designed as a machine-readable CLI tool for agent
runtimes — the JSON contract is the primary API surface.

```
etwarden --pid 1234 --duration 10
etwarden --spawn "curl.exe https://example.com"
```

---

## Directory Layout

```
etwarden/
├── src/
│   ├── main.rs                    # Entry point. CLI parse + assemble + run. ≤80 lines
│   ├── cli.rs                     # clap definitions. ≤100 lines
│   ├── error.rs                   # Unified Error type. ≤80 lines
│   │
│   ├── capture/                   # Deep module: ETW session lifecycle
│   │   ├── mod.rs                 # pub interface only. ≤60 lines
│   │   ├── session.rs             # StartTrace / StopTrace lifecycle. ≤200 lines
│   │   ├── provider.rs            # EnableTraceEx2 per provider. ≤150 lines
│   │   └── event_loop.rs          # ProcessTrace consume loop + dispatch. ≤200 lines
│   │
│   ├── parser/                    # Hot-swap seam: one impl per ETW provider
│   │   ├── mod.rs                 # EventParser trait + static registry. ≤80 lines
│   │   ├── types.rs               # RawEvent, NetEvent, RawFrame enums. ≤150 lines
│   │   ├── tcpip.rs               # Microsoft-Windows-TCPIP parser. ≤200 lines
│   │   ├── ndis.rs                # Microsoft-Windows-NDIS-PacketCapture parser. ≤200 lines
│   │   └── correlation.rs         # Networking-Correlation ActivityId map. ≤150 lines
│   │
│   ├── filter/                    # Hot-swap seam: drop/allow per event
│   │   ├── mod.rs                 # Filter trait. ≤60 lines
│   │   └── pid.rs                 # PID allowlist filter. ≤100 lines
│   │
│   ├── pcap/                      # Raw packet correlation + pcapng write
│   │   ├── mod.rs                 # pub interface. ≤60 lines
│   │   ├── writer.rs              # pcapng block writer. ≤200 lines
│   │   └── correlator.rs          # 5-tuple → TargetPid mapping. ≤200 lines
│   │
│   ├── process/                   # Subprocess spawn + lifecycle
│   │   ├── mod.rs                 # pub interface. ≤60 lines
│   │   ├── spawn.rs               # --spawn mode: launch + PID extract. ≤150 lines
│   │   └── monitor.rs             # Child process alive-check + exit notify. ≤100 lines
│   │
│   └── output/                    # Hot-swap seam: serialization format
│       ├── mod.rs                 # Emitter trait. ≤60 lines
│       ├── json.rs                # NDJSON lines to stdout. ≤100 lines
│       └── schema.rs              # Stable agent-contract serde types. ≤200 lines
│
├── tests/
│   ├── integration.rs             # Admin-required. feature = "integration"
│   └── schema_compat.rs           # Schema regression: no breaking changes
│
├── benches/
│   └── event_throughput.rs        # criterion: ETW event parse throughput
│
├── Cargo.toml
├── rustfmt.toml
├── deny.toml
├── ARCHITECTURE.md                # This file
└── CONTEXT.md                     # Domain glossary
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
  │         pcap/correlator.rs ── register 5-tuple
  │              │
  │         output/json.rs ──► stdout NDJSON line
  │
  ├─ Microsoft-Windows-NDIS-PacketCapture
  │    └─ parser/ndis.rs → RawFrame{bytes, timestamp}
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

```json
{"t":"2025-01-01T00:00:00.000Z","pid":1234,"proto":"TCP","src":"192.168.1.1:50234","dst":"93.184.216.34:443","event":"connect","bytes_out":0,"bytes_in":0}
{"t":"2025-01-01T00:00:01.123Z","pid":1234,"proto":"TCP","src":"192.168.1.1:50234","dst":"93.184.216.34:443","event":"disconnect","bytes_out":512,"bytes_in":2048}
```

Final line on exit — always present:

```json
{"type":"summary","pid":1234,"duration_ms":10000,"connections_total":3,"bytes_out_total":1024,"bytes_in_total":8192,"pcap_written":true}
```

Stderr receives diagnostic/error output. Stdout is exclusively NDJSON.

`schema.rs` types are the contract. They MUST NOT have breaking changes.
Use `schema_compat.rs` regression test to enforce this.

---

## Module Line Budgets

| File | Budget |
|------|--------|
| `main.rs` | 80 |
| Any `mod.rs` | 80 |
| `cli.rs` | 100 |
| `error.rs` | 80 |
| `schema.rs` | 200 |
| All other `.rs` | 200 |

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

All phases are part of the canonical design. There are no optional phases.

| Phase | Deliverable |
|-------|-------------|
| 1 | TCPIP provider → connection-level NDJSON (no raw packets) |
| 2 | NDIS provider + pcap/correlator → .pcapng output |
| 3 | process/spawn → `--spawn` mode with child PID tracking |

Phase 1 is the first shipped artifact. Phases 2 and 3 follow in order.
All module seams are designed for all three phases from day one.
