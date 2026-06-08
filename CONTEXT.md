# etwarden — Domain Glossary (CONTEXT.md)

Canonical terms for this codebase. Use exact names in code, comments, and docs.

---

## Core Terms

**NetEvent**
A single parsed network event produced by ETW providers.
Variants: `Connect`, `Disconnect`, `Send`, `Recv`, `DnsQuery`, `DnsResponse`.
_Avoid_: network event, connection event, packet event

**RawEvent**
Unparsed bytes and metadata received in an ETW callback.
Produced by `event_loop.rs`, consumed by `EventParser` impls.
_Avoid_: ETW event, raw callback, event record

**RawFrame**
Raw Ethernet frame bytes captured by the NDIS ETW provider,
with a timestamp but no PID attribution yet. Also fed into DPI
for protocol identification.
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
Converts `RawEvent` into `Option<NetEvent>`.
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
by `Correlator` and `Tracker` to identify unique network flows.
_Avoid_: 5-tuple, connection tuple, socket tuple

---

## DNS Terms

**DnsQuery**
A `NetEvent` variant produced by the DNS Client ETW provider (EventID 3006).
Contains: PID, hostname, query type (A/AAAA/MX/etc), query results string.
_Avoid_: DNS request, DNS lookup event

**DnsResponse**
A `NetEvent` variant produced by the DNS Client ETW provider (EventID 3008).
Contains: PID, hostname, query type, resolved IPs, DNS status code.
_Avoid_: DNS answer, DNS reply event

**DnsEventLine**
The NDJSON output line type for DNS events. Fields: `t`, `pid`, `event`
(`dns_query` or `dns_response`), `hostname`, `query_type`, `query_results`, `status`.
_Avoid_: DNS line, DNS JSON

**dns_codes**
The `parser/dns_codes.rs` module. IANA DNS type/status `const fn` lookup tables
and `parse_query_results()` for extracting IPs from the query results string.
_Avoid_: DNS lookup, DNS constants

**dns**
The `parser/dns.rs` module. Wire-format DNS parser that extracts question names,
query types, and A/AAAA answer records from raw DNS payloads. Used by DPI.
_Avoid_: DNS parser module, DNS wire parser

---

## DPI Terms

**DPI**
Deep Packet Inspection. The `parser/dpi.rs` module identifies application-layer
protocols from raw packet payloads (TLS ClientHello SNI, HTTP methods, DNS, etc.).
Applied by `tracker.rs` on NDIS frames.
_Avoid_: protocol detection, packet inspection, L7 analysis

**TcpState**
TCP finite state machine enum in `parser/tcp_state.rs`. Tracks connection state
through SYN/SYN-ACK/FIN/RST transitions: `Closed`, `SynSent`, `SynReceived`,
`Established`, `FinWait1`, `FinWait2`, `CloseWait`, `Closing`, `LastAck`,
`TimeWait`.
_Avoid_: TCP FSM, TCP status, connection state

**TcpFlags**
Bitfield struct in `parser/tcp_state.rs` extracted from TCP header flags:
`syn`, `ack`, `fin`, `rst`. Used by `update_tcp_state()` for FSM transitions.
_Avoid_: TCP control bits, TCP header flags

---

## Tracker Terms

**Tracker**
The `tracker.rs` module. `ConnectionTracker` maintains a `DashMap<FiveTuple, TrackedConnection>`
that ingests `NetEvent`s to build per-flow state: byte counters, timestamps, TCP state,
DPI results. Provides `cleanup()` for idle eviction and `snapshot()` for current state.
_Avoid_: flow table, connection manager, connection state store

**TrackedConnection**
A single tracked flow in `tracker.rs`. Contains: FiveTuple, PID, protocol,
TCP state, bytes in/out, first/last timestamp, DPI result, remote classification.
_Avoid_: tracked flow, connection record

**Scope**
IP address classification enum in `classify.rs`. Variants: `Public`, `Private`,
`LinkLocal`, `Loopback`, `Multicast`, `Unspecified`, `CarrierGradeNAT`,
`Documentation`, `Reserved`, `Benchmarking`, `Shared`, `UniqueLocal`.
_Avoid_: IP class, address scope, network scope

---

## Process Terms

**ProcessLookup**
The `process/lookup.rs` module. `ProcessNameCache` maps PID → process name
via `sysinfo`. Used by `output/json.rs` to enrich NDJSON lines with `process_name` field.
_Avoid_: process resolver, PID resolver, process name cache

**ProcessTreeCache**
The `process/tree.rs` module. Maintains a periodically-refreshed snapshot of the
system process tree via `sysinfo`. Maps PID → `ProcessInfo` (name, ppid, command_line, tree_path).
Used by `filter/tree.rs` for process-tree filtering.
_Avoid_: process tree resolver, tree snapshot

**ProcessTreeFilter**
The `filter/tree.rs` component. Allows events from a root PID and all its
discovered descendants. Used for `--spawn` mode to track child processes.
_Avoid_: tree filter, descendant filter

---

## MITM Terms

**MITM**
Man-in-the-Middle. The `mitm/mod.rs` module runs an HTTPS proxy that intercepts
traffic, decrypts it with dynamically-generated TLS certificates, and emits HTTP
metadata as NDJSON. Uses `http-mitm-proxy` + `rcgen`.
_Avoid_: proxy module, HTTPS proxy, SSL proxy

**MitmCaptureConfig**
Configuration for the MITM proxy: listen address, CA settings, rule set reference.
Passed to `start_mitm_proxy()`.
_Avoid_: proxy config, MITM config

**CertificateAuthority**
The `mitm/ca.rs` module. Generates a root CA certificate and per-host leaf
certificates using `rcgen`. The root CA must be trusted by the target process.
_Avoid_: CA module, cert generator

**SystemProxy**
The `mitm/system_proxy.rs` module. Sets/restores the Windows system proxy
via registry to redirect traffic through the MITM proxy.
_Avoid_: proxy settings, Windows proxy

---

## Rules Terms

**RuleSet**
The `rules/ruleset.rs` module. Ordered collection of rules evaluated against
each request/response. Contains block, replace, intercept, and hosts rules.
_Avoid_: rule collection, rule list

**BlockRule**
Traffic blocking rule. Variants: HTTP (`block/http.rs`), socket (`block/socket.rs`),
WebSocket (`block/websocket.rs`). Actions: close connection, drop frame.
_Avoid_: deny rule, filter rule

**ReplaceRule**
The `rules/replace.rs` module. URL/body content replacement. Supports string
and regex patterns.
_Avoid_: rewrite rule, substitution rule

**InterceptRule**
The `rules/intercept/rule.rs` module. Pauses traffic for inspection. Matches
on URL, header, body, PID, or process name with various operators.
_Avoid_: breakpoint rule, pause rule

**HostsRule**
The `rules/hosts.rs` module. DNS-level host redirection. Redirects matching
domain patterns to specified IP addresses.
_Avoid_: DNS redirect, hosts file rule

**Matcher**
The `rules/matcher.rs` module. Pattern matching engine supporting contains,
equals, prefix, suffix, and regex operators.
_Avoid_: pattern matcher, match engine

---

## Target Terms

**ResolvedTarget**
The `target.rs` struct. Fully resolved target process with its PID and a stop
signal (`AtomicBool`). Produced by `target::resolve()`.
_Avoid_: target info, process target

**SpawnCaptureTarget**
The `process/spawn_capture.rs` struct. Resolves `--spawn-capture` targets with
stdout/stderr capture paths.
_Avoid_: capture target, spawn config

---

## Output Terms

**NDJSON**
Newline-delimited JSON. Each `NetEvent` produces exactly one line.
The summary line is the final line. Stdout only.
_Avoid_: JSON lines, jsonl, streaming JSON

**EventLine**
NDJSON output type for TCPIP events (Connect/Disconnect/Send/Recv).
Fields: `t`, `pid`, `proto`, `src`, `dst`, `event`, `bytes_out`, `bytes_in`,
optional `process_name`, `scope`.
_Avoid_: network line, connection line

**DnsEventLine**
NDJSON output type for DNS events (DnsQuery/DnsResponse).
Fields: `t`, `pid`, `event`, `hostname`, `query_type`, `query_results`, `status`.
_Avoid_: DNS line, DNS JSON

**HttpEventLine**
NDJSON output type for MITM-decrypted HTTP events.
Fields: `t`, `pid`, `event` (`http_request`/`http_response`), `method`, `url`,
`host`, `status`, `headers`, `body_preview`.
_Avoid_: HTTP line, HTTP JSON

**TlsEventLine**
NDJSON output type for TLS ClientHello events from DPI.
Fields: `t`, `pid`, `event` (`tls_hello`), `sni`, `alpn`, `tls_version`,
`ja3_hash`, `ja4`, cipher/extension counts.
_Avoid_: TLS line, TLS JSON

**RuleHitEventLine**
NDJSON output type for rule engine matches.
Fields: `t`, `event` (`rule_hit`), `rule_type`, `rule_name`, `action`, `url`, `pid`.
_Avoid_: rule line, rule JSON

**SummaryLine**
The final JSON line written to stdout when the capture session ends.
Contains aggregate counts and flags. Always present, even on error.
_Avoid_: final output, summary event, exit JSON

**ErrorLine**
Terminal error line written to stdout before returning an error.
Fields: `type` (always `"error"`), `message`.
_Avoid_: error output, error JSON

**OutputLine**
The top-level enum in `schema/line/meta.rs`: `Event(EventLine)`,
`DnsEvent(DnsEventLine)`, `HttpEvent(HttpEventLine)`, `TlsEvent(TlsEventLine)`,
`RuleHit(RuleHitEventLine)`, `Summary(SummaryLine)`, `Error(ErrorLine)`.
Each variant serializes to one NDJSON line.
_Avoid_: output enum, line type

**Agent Contract**
The stable schema defined in `output/schema/`. Must not have breaking
changes between versions. Validated by `tests/schema_compat.rs`.
_Avoid_: output format, JSON schema, API contract

---

## Provider GUIDs (reference)

| Constant | Provider | GUID |
|----------|----------|------|
| `PROVIDER_TCPIP` | Microsoft-Windows-TCPIP | `{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}` |
| `PROVIDER_NDIS` | Microsoft-Windows-NDIS-PacketCapture | `{2ED6006E-4729-4609-B423-3EE7BCD678EF}` |
| `PROVIDER_CORRELATION` | Microsoft-Windows-Networking-Correlation | `{83ED54F0-4D48-4E45-B16E-726FFD1FA4AF}` |
| `PROVIDER_DNS_CLIENT` | Microsoft-Windows-DNS-Client | `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}` |

---

## Constraints

- Windows only. No cross-platform abstraction layer.
- Administrator privilege required at runtime.
- Stdout = NDJSON only. Stderr = diagnostics/errors only.
- No `unsafe {}` in business logic. ETW unsafe is contained in `windows-rs` / `ferrisetw`.
- No `println!` outside `output/` module.
- No `std::process::exit` — errors propagate via `anyhow::Result` to `main`.
- Edition 2021 — no `let chains`.
- `panic = "deny"`, `unsafe_code = "forbid"` in `Cargo.toml`.
- No `#[allow(...)]` attributes in source — use `Cargo.toml` `[lints.clippy]` instead.
