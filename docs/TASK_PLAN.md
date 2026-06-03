# etwarden — Atomic Task Plan

> One task = one file. Each task has: ID, file, depends-on, public symbols, acceptance command.
> Status: `[ ]` pending | `[x]` done | `[~]` in-progress | `[!]` blocked

---

## Legend

| Field | Meaning |
|-------|---------|
| **ID** | Task identifier, used in `Depends` |
| **File** | Exact file path to create/write |
| **Depends** | Task IDs that must be `[x]` first |
| **Exports** | Every `pub` symbol this file must expose |
| **Verify** | Exact command(s) that must pass when done |

---

## Phase 0 — Scaffold (no logic, compile only)

### T01
- **File**: `src/lib.rs` (crate root, re-exports only)
- **Depends**: —
- **Exports**: `pub mod error`, `pub mod cli`, `pub mod capture`, `pub mod parser`, `pub mod filter`, `pub mod pcap`, `pub mod process`, `pub mod output`
- **Verify**: `cargo check`

---

## Phase 1 — Types & Errors (pure, no ETW)

### T02
- **File**: `src/error.rs`
- **Depends**: T01
- **Exports**: `enum etwardenError`, `type Result<T>`
- **Notes**: `thiserror::Error` derive. Variants: `EtwSession`, `Privilege`, `ProcessSpawn`, `PcapWrite`, `OutputWrite`
- **Verify**: `cargo check`, `cargo test -p etwarden error`

### T03
- **File**: `src/parser/types.rs`
- **Depends**: T01
- **Exports**: `struct RawEvent`, `struct RawFrame`, `enum NetEvent`, `enum Protocol`, `struct FiveTuple`, `struct Timestamp`
- **Notes**: All `serde::Serialize`. `NetEvent` variants: `Connect`, `Disconnect`, `Send`, `Recv`. No ETW imports here — pure types.
- **Verify**: `cargo check`, `cargo test -p etwarden parser::types`

### T04
- **File**: `src/output/schema.rs`
- **Depends**: T03
- **Exports**: `struct EventLine`, `struct SummaryLine`, `enum OutputLine`
- **Notes**: Agent contract. `serde::Serialize` + `serde::Deserialize`. `EventLine` wraps `NetEvent` with `t: DateTime<Utc>`. `SummaryLine` has duration/counts/pcap_written. These types MUST NOT have breaking changes.
- **Verify**: `cargo check`, `cargo test -p etwarden output::schema`, snapshot baseline: `cargo insta test`

---

## Phase 2 — Traits (interfaces, no impl)

### T05
- **File**: `src/parser/mod.rs`
- **Depends**: T03
- **Exports**: `trait EventParser`, `struct ParserRegistry`
- **Notes**: `EventParser::provider_guid() -> windows::core::GUID`, `EventParser::parse(&RawEvent) -> Option<NetEvent>`. `ParserRegistry` holds `Vec<Box<dyn EventParser>>`, has `fn register` and `fn dispatch`.
- **Verify**: `cargo check`

### T06
- **File**: `src/filter/mod.rs`
- **Depends**: T03
- **Exports**: `trait Filter`
- **Notes**: `Filter::allow(&NetEvent) -> bool`. Single method.
- **Verify**: `cargo check`

### T07
- **File**: `src/output/mod.rs`
- **Depends**: T04
- **Exports**: `trait Emitter`
- **Notes**: `Emitter::emit(&NetEvent) -> Result<()>`, `Emitter::flush() -> Result<()>`.
- **Verify**: `cargo check`

### T08
- **File**: `src/capture/mod.rs`
- **Depends**: T03, T05
- **Exports**: `struct CaptureConfig`, `fn run_capture`
- **Notes**: `CaptureConfig` holds `target_pid: u32`, `duration: Option<Duration>`, `parsers: ParserRegistry`, `filters: Vec<Box<dyn Filter>>`, `emitter: Box<dyn Emitter>`. `run_capture(config: CaptureConfig) -> Result<SummaryLine>` — signature only, stub body.
- **Verify**: `cargo check`

### T09
- **File**: `src/pcap/mod.rs`
- **Depends**: T03
- **Exports**: `trait PcapSink`
- **Notes**: `PcapSink::write_frame(&RawFrame, pid: u32) -> Result<()>`. Optional sink — `Option<Box<dyn PcapSink>>` used in `CaptureConfig`.
- **Verify**: `cargo check`

### T10
- **File**: `src/process/mod.rs`
- **Depends**: T02
- **Exports**: `struct SpawnResult`
- **Notes**: `SpawnResult { pid: u32, handle: ... }`. Placeholder types OK.
- **Verify**: `cargo check`

---

## Phase 3 — CLI & Entry

### T11
- **File**: `src/cli.rs`
- **Depends**: T01
- **Exports**: `struct Cli`, `enum TargetMode`
- **Notes**: `clap::Parser`. `TargetMode::Pid { pid: u32 }` and `TargetMode::Spawn { cmd: String }`. Flags: `--duration <secs>`, `--pcap-out <path>`, `--json-pretty`. No ETW imports.
- **Verify**: `cargo check`, `cargo test -p etwarden cli`

### T12
- **File**: `src/main.rs`
- **Depends**: T08, T11, T04
- **Exports**: (binary entry, no pub symbols)
- **Notes**: Parse CLI → build `CaptureConfig` with stub impls → call `run_capture` → print `SummaryLine`. Compiles and runs (even if ETW calls are stubs). ≤80 lines.
- **Verify**: `cargo build`, `cargo clippy --all-targets -- -D warnings`

---

## Phase 4 — Phase 1 Impl: TCPIP provider (connection-level NDJSON)

### T13
- **File**: `src/output/json.rs`
- **Depends**: T07, T04
- **Exports**: `struct JsonEmitter`
- **Notes**: Implements `Emitter`. Writes `serde_json::to_string(&OutputLine::Event(...))` + `\n` to stdout via `std::io::Write`. `flush` flushes stdout. No `println!`.
- **Verify**: `cargo test -p etwarden output::json`, snapshot: `cargo insta test`

### T14
- **File**: `src/filter/pid.rs`
- **Depends**: T06
- **Exports**: `struct PidFilter`
- **Notes**: Implements `Filter`. Holds `allowed: HashSet<u32>`. `allow` returns true if `event.pid` in set.
- **Verify**: `cargo test -p etwarden filter::pid`

### T15
- **File**: `src/parser/tcpip.rs`
- **Depends**: T05
- **Exports**: `struct TcpIpParser`
- **Notes**: Implements `EventParser`. GUID = `PROVIDER_TCPIP`. Parses `ferrisetw` event records for event IDs: `EVENT_ID_TCP_CONNECT_IPV4` (10), `EVENT_ID_TCP_CONNECT_IPV6` (26), `EVENT_ID_TCP_DISCONNECT` (11/27), `EVENT_ID_TCP_SEND` (14), `EVENT_ID_TCP_RECV` (15). Extracts PID, src/dst IP+port, bytes. Returns `NetEvent`.
- **Verify**: `cargo test -p etwarden parser::tcpip` (unit tests use fixture `RawEvent` structs)

### T16
- **File**: `src/capture/session.rs`
- **Depends**: T02, T08
- **Exports**: `struct EtwSession`
- **Notes**: Wraps `ferrisetw::provider::Provider` + `ferrisetw::trace::UserTrace`. Methods: `fn new(name: &str) -> Result<Self>`, `fn enable_provider(&mut self, guid: GUID) -> Result<()>`, `fn start(self) -> Result<RunningSession>`. Checks admin elevation via `windows::Win32::Security` before start.
- **Verify**: `cargo check` (ETW calls can't unit test without admin — compile check only)

### T17
- **File**: `src/capture/provider.rs`
- **Depends**: T16
- **Exports**: `fn build_tcpip_provider() -> ferrisetw::provider::Provider`
- **Notes**: Configures TCPIP provider with keyword/level masks for TCP connect/disconnect/send/recv events only. Returns ready-to-enable `Provider`.
- **Verify**: `cargo check`

### T18
- **File**: `src/capture/event_loop.rs`
- **Depends**: T05, T06, T07, T16
- **Exports**: `fn run_event_loop(session: RunningSession, registry: ParserRegistry, filters: Vec<Box<dyn Filter>>, emitter: Box<dyn Emitter>) -> Result<SummaryLine>`
- **Notes**: Calls `ProcessTrace` via ferrisetw callback. In callback: dispatch `RawEvent` through `registry`, filter, emit. Handles Ctrl+C via `ctrlc` crate. Returns `SummaryLine` on exit.
- **Verify**: `cargo check`

### T19 — Phase 1 integration wiring
- **File**: `src/capture/mod.rs` (update)
- **Depends**: T16, T17, T18, T13, T14, T15
- **Exports**: same as T08 — implement `run_capture` body
- **Notes**: Body: build session → enable TCPIP provider → build registry with `TcpIpParser` → build filters with `PidFilter` → run event loop → return summary.
- **Verify**: `cargo build --release`, `cargo clippy --all-targets -- -D warnings`, `cargo test`

### T20 — Phase 1 gate
- **File**: (no new file — run full CI gate)
- **Depends**: T19
- **Notes**: —
- **Verify**:
  ```
  cargo fmt --check
  cargo clippy --all-targets -- -D warnings
  cargo deny check
  cargo audit
  cargo machete
  cargo test
  cargo doc --no-deps
  cargo bench --no-run
  ```

---

## Phase 5 — Phase 2: NDIS + pcapng

### T21
- **File**: `src/pcap/writer.rs`
- **Depends**: T09
- **Exports**: `struct PcapNgWriter`
- **Notes**: Implements `PcapSink`. Uses `pcap-file` crate to write pcapng blocks to a `File`. `write_frame` appends an EPB (Enhanced Packet Block) with timestamp, PID in comment option.
- **Verify**: `cargo test -p etwarden pcap::writer`

### T22
- **File**: `src/pcap/correlator.rs`
- **Depends**: T03, T09
- **Exports**: `struct Correlator`
- **Notes**: `fn register_connection(pid: u32, tuple: FiveTuple)` — called from TCPIP event. `fn resolve_pid(tuple: &FiveTuple) -> Option<u32>` — called from NDIS callback. Holds `HashMap<FiveTuple, u32>`. Thread-safe via `Mutex`.
- **Verify**: `cargo test -p etwarden pcap::correlator`

### T23
- **File**: `src/parser/ndis.rs`
- **Depends**: T05, T22
- **Exports**: `struct NdisParser`
- **Notes**: Implements `EventParser`. GUID = `PROVIDER_NDIS`. Parses raw frame bytes from ETW event. Returns `NetEvent::RawCapture { frame: RawFrame }` (new variant added to `NetEvent`). Calls `Correlator::resolve_pid`.
- **Verify**: `cargo test -p etwarden parser::ndis`

### T24
- **File**: `src/parser/correlation.rs`
- **Depends**: T05, T03
- **Exports**: `struct CorrelationParser`, `struct ActivityMap`
- **Notes**: Implements `EventParser`. GUID = `PROVIDER_CORRELATION`. Maintains `HashMap<ActivityId, FiveTuple>`. Used to correlate cross-provider events. `ActivityMap` is `Arc<Mutex<...>>` shared with other parsers.
- **Verify**: `cargo check`

### T25
- **File**: `src/capture/provider.rs` (update)
- **Depends**: T23, T24, T17
- **Exports**: add `fn build_ndis_provider()`, `fn build_correlation_provider()`
- **Verify**: `cargo check`

### T26 — Phase 2 wiring
- **File**: `src/capture/mod.rs` (update)
- **Depends**: T21, T22, T23, T24, T25
- **Notes**: Add `pcap_sink: Option<Box<dyn PcapSink>>` to `CaptureConfig`. Wire `NdisParser` + `CorrelationParser` into registry when sink present. Wire `Correlator` shared ref between TCPIP and NDIS parsers.
- **Verify**: `cargo build`, `cargo test`

### T27 — Phase 2 CLI wiring
- **File**: `src/cli.rs` (update)
- **Depends**: T26
- **Notes**: Add `--pcap-out <path>` flag (already stubbed). Wire to `PcapNgWriter` in `main.rs`.
- **Verify**: `cargo build`, `cargo clippy -- -D warnings`

### T28 — Phase 2 gate
- **File**: (no new file)
- **Depends**: T27
- **Verify**: full CI gate (same as T20)

---

## Phase 6 — Phase 3: --spawn mode

### T29
- **File**: `src/process/spawn.rs`
- **Depends**: T10, T02
- **Exports**: `fn spawn_and_get_pid(cmd: &str) -> Result<SpawnResult>`
- **Notes**: Uses `std::process::Command`. Extracts child PID. Returns `SpawnResult`. Does not wait — caller monitors.
- **Verify**: `cargo test -p etwarden process::spawn`

### T30
- **File**: `src/process/monitor.rs`
- **Depends**: T10
- **Exports**: `struct ProcessMonitor`
- **Notes**: `fn new(pid: u32) -> Self`, `fn is_alive(&self) -> bool`, `fn wait_exit(&self) -> Result<ExitStatus>`. Uses `windows::Win32::System::Threading::WaitForSingleObject`.
- **Verify**: `cargo check`

### T31 — Phase 3 wiring
- **File**: `src/main.rs` (update)
- **Depends**: T29, T30, T12
- **Notes**: When `TargetMode::Spawn`: call `spawn_and_get_pid` → get PID → build `CaptureConfig` → start capture in thread → `monitor.wait_exit()` → signal capture stop → print summary.
- **Verify**: `cargo build`, `cargo clippy -- -D warnings`

### T32 — Phase 3 gate
- **File**: (no new file)
- **Depends**: T31
- **Verify**: full CI gate

---

## Phase 7 — Tests & Schema Compat

### T33
- **File**: `tests/schema_compat.rs`
- **Depends**: T04, T13
- **Notes**: Snapshot test every `OutputLine` variant via `insta::assert_json_snapshot!`. Run: `cargo insta test` to accept baselines. These snapshots are the schema regression guard.
- **Verify**: `cargo test --test schema_compat`, `cargo insta test`

### T34
- **File**: `benches/event_throughput.rs`
- **Depends**: T15, T13
- **Notes**: criterion benchmark: parse 100k fixture `RawEvent` structs through `TcpIpParser` + `PidFilter` + `JsonEmitter` (writing to `Vec<u8>`). Baseline must be committed.
- **Verify**: `cargo bench --no-run`, `cargo bench 2>&1 | grep "event_throughput"`

---

## Dependency Graph (critical path)

```
T01 → T02, T03
T03 → T04, T05, T06, T09, T10
T04 → T07
T05 → T08
T08 → T12
T11 → T12
T07 → T13
T06 → T14
T05 → T15
T02 → T16
T16 → T17, T18
T13, T14, T15, T16, T17, T18 → T19 → T20

T19 → T21, T22, T23, T24, T25 → T26 → T27 → T28

T28 → T29, T30 → T31 → T32

T04, T13 → T33
T15, T13 → T34
```

**Minimum path to first working binary (Phase 1):**
T01 → T02 → T03 → T04 → T05 → T06 → T07 → T08 → T09 → T10 → T11 → T12 → T13 → T14 → T15 → T16 → T17 → T18 → T19 → T20

---

## Current Status

| Phase | Tasks | Status |
|-------|-------|--------|
| 0 — Scaffold | T01 | `[ ]` |
| 1 — Types & Errors | T02–T04 | `[ ]` |
| 2 — Traits | T05–T10 | `[ ]` |
| 3 — CLI & Entry | T11–T12 | `[ ]` |
| 4 — Phase 1 Impl | T13–T20 | `[ ]` |
| 5 — Phase 2 NDIS+pcap | T21–T28 | `[ ]` |
| 6 — Phase 3 spawn | T29–T32 | `[ ]` |
| 7 — Tests & Bench | T33–T34 | `[ ]` |
