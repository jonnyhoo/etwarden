# etwarden — Domain Glossary (CONTEXT.md)

Canonical terms for this codebase. Use exact names in code, comments, and docs.

---

## Core Terms

**NetEvent**
A single parsed network event produced by the TCPIP ETW provider.
Variants: `Connect`, `Disconnect`, `Send`, `Recv`.
_Avoid_: network event, connection event, packet event

**RawEvent**
Unparsed bytes and metadata received in an ETW callback.
Produced by `event_loop.rs`, consumed by `EventParser` impls.
_Avoid_: ETW event, raw callback, event record

**RawFrame**
Raw Ethernet frame bytes captured by the NDIS ETW provider,
with a timestamp but no PID attribution yet.
_Avoid_: packet, raw packet, frame bytes

**Session**
One ETW trace session lifecycle object: created, running, stopped.
Maps 1:1 to a Windows `TRACEHANDLE`.
_Avoid_: trace, ETW session, capture session

**TargetPid**
The process ID being monitored. Either passed via `--pid` or produced
by `process/spawn.rs` when using `--spawn`.
_Avoid_: monitored PID, watched process, target process ID

**Correlator**
The `pcap/correlator.rs` component that maps NDIS `RawFrame` objects to a
`TargetPid` by matching IP/port 5-tuples registered from `NetEvent::Connect`.
_Avoid_: frame matcher, packet mapper, pcap correlator

**Emitter**
An impl of the `output::Emitter` trait that serializes `NetEvent` to an
output sink. The production impl writes NDJSON to stdout.
_Avoid_: writer, serializer, output handler

**EventParser**
An impl of the `parser::EventParser` trait bound to one ETW provider GUID.
Converts `RawEvent` into `Option<NetEvent>` or `Option<RawFrame>`.
_Avoid_: provider parser, ETW parser, event handler

**Filter**
An impl of the `filter::Filter` trait that decides whether a `NetEvent`
should be passed downstream or dropped.
_Avoid_: event filter, process filter, PID filter

**ActivityId**
A Windows ETW GUID used to correlate events across providers within the
same logical operation. Tracked in `parser/correlation.rs`.
_Avoid_: correlation ID, trace ID, activity GUID

**FiveTuple**
The combination of (src IP, src port, dst IP, dst port, protocol) used
by `Correlator` to match `RawFrame` to a `TargetPid`.
_Avoid_: 5-tuple, connection tuple, socket tuple

---

## Output Terms

**NDJSON**
Newline-delimited JSON. Each `NetEvent` produces exactly one line.
The summary line is the final line. Stdout only.
_Avoid_: JSON lines, jsonl, streaming JSON

**Summary Line**
The final JSON line written to stdout when the capture session ends.
Contains aggregate counts and flags. Always present, even on error.
_Avoid_: final output, summary event, exit JSON

**Agent Contract**
The stable schema defined in `output/schema.rs`. Must not have breaking
changes between versions. Validated by `tests/schema_compat.rs`.
_Avoid_: output format, JSON schema, API contract

---

## Provider GUIDs (reference)

| Constant | Provider | GUID |
|----------|----------|------|
| `PROVIDER_TCPIP` | Microsoft-Windows-TCPIP | `{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}` |
| `PROVIDER_NDIS` | Microsoft-Windows-NDIS-PacketCapture | `{2ED6006E-4729-4609-B423-3EE7BCD678EF}` |
| `PROVIDER_CORRELATION` | Microsoft-Windows-Networking-Correlation | `{83ED54F0-4D48-4E45-B16E-726FFD1FA4AF}` |

---

## Constraints

- Windows only. No cross-platform abstraction layer.
- Administrator privilege required at runtime.
- Stdout = NDJSON only. Stderr = diagnostics/errors only.
- No `unsafe {}` in business logic. ETW unsafe is contained in `windows-rs` / `ferrisetw`.
- No `println!` outside `output/` module.
- No `std::process::exit` — errors propagate via `anyhow::Result` to `main`.
