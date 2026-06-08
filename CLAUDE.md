# AGENTS.md

Entry point for all LLM agents working on this repository.
Read this file first. No exceptions.

---

## What is this repo?

`etwarden` — A Windows-only CLI tool that captures per-process network activity
via ETW (Event Tracing for Windows) and outputs structured NDJSON to stdout.
Provides connection tracking, DNS monitoring, raw packet capture with DPI,
IP classification, TCP state machine, and flow-level aggregation.
Designed as a machine-readable tool for agent runtimes.

Platform: **Windows only** (x86_64-pc-windows-msvc)
Privilege: **Administrator required** at runtime
Language: **Rust (stable ≥ 1.75, edition 2021)**

---

## Zero-context start

Read in this order:

1. `AGENTS.md` ← you are here
2. `ARCHITECTURE.md` — module layout, data flow, seam design, phase roadmap
3. `CONTEXT.md` — domain glossary, provider GUIDs, canonical terms
4. `docs/DEV_STANDARDS.md` — toolchain, CI gate, lint policy, file rules, LLM conventions
5. `docs/ROADMAP.md` — full research + implementation plan for all future phases

---

## Document Map

| Document | Purpose |
|----------|---------|
| `AGENTS.md` | Agent entry point. First file to read. |
| `CLAUDE.md` | Identical copy of `AGENTS.md` for Claude-family agents. |
| `ARCHITECTURE.md` | Full system architecture: modules, data flow, seams, JSON contract. |
| `CONTEXT.md` | Domain glossary. Canonical term definitions. Provider GUIDs. |
| `docs/DEV_STANDARDS.md` | Dev standards: toolchain, CI, lint, naming, file budget, unsafe policy. |
| `docs/ROADMAP.md` | Full research: competitor analysis, 4-phase plan, algorithms, data structures. |
| `docs/TASK_PLAN.md` | Task tracking. |
| `Cargo.toml` | Dependencies, lints, features, release profile. |
| `rustfmt.toml` | Code format config. |
| `deny.toml` | Supply chain audit config. |
| `.coupling.toml` | cargo-coupling analysis thresholds. |

---

## Source of Truth

| Question | Answer location |
|---------|----------------|
| What does this tool do? | `ARCHITECTURE.md` → System Purpose |
| What does a term mean? | `CONTEXT.md` |
| What is the module layout? | `ARCHITECTURE.md` → Directory Layout |
| What does data flow look like? | `ARCHITECTURE.md` → Data Flow |
| What are the extension points? | `ARCHITECTURE.md` → Hot-Swap Seams |
| What is the JSON output format? | `ARCHITECTURE.md` → JSON Output Contract |
| What are the CI gates? | `docs/DEV_STANDARDS.md` → CI Gate |
| What lint rules apply? | `docs/DEV_STANDARDS.md` → Clippy / Lint Policy |
| What goes in each file header? | `docs/DEV_STANDARDS.md` → File Header |
| How do I handle errors? | `docs/DEV_STANDARDS.md` → Error Handling |
| What are the line budgets? | `ARCHITECTURE.md` → Module Line Budgets |
| What are the naming rules? | `docs/DEV_STANDARDS.md` → Naming Conventions |
| What is the implementation plan? | `docs/ROADMAP.md` |

---

## CI Gate (run before every commit)

Rules:
- Use `&&` between gate commands. Never use PowerShell `;` for gates; it can hide earlier failures.
- Stop at the first failing command. Fix root cause before continuing.
- Run a focused gate after small edits, then one full static gate before commit.
- Do not rerun an unchanged passing gate for reassurance; rerun only after edits or external changes.

Focused gate for small slices:
```
cargo +nightly fmt --check && cargo test -p etwarden <module-or-filter> && cargo clippy --all-targets -- -D warnings
```

Full static gate before commit:
```
cargo +nightly fmt --check && cargo clippy --all-targets -- -D warnings && cargo audit && cargo deny check && cargo machete && cargo coupling --check --no-git --max-circular 5 && cargo test && cargo doc --no-deps && git diff --check && git status --short
```

Admin/release gate:
```
cargo test --features integration
cargo llvm-cov --summary-only
cargo bench --no-run
```

---

## Git Hook Policy

**`--no-verify` is permanently banned.**

Rationale: hooks enforce the CI gate locally. Bypassing them means broken code
enters the repo. There are no exceptions.

Rules:
- Never run `git commit --no-verify`
- Never run `git push --no-verify`
- Never suggest `--no-verify` as a workaround
- If a hook fails: fix the underlying issue, do not bypass the hook
- If a hook is broken: fix the hook, do not disable it
- Expected duplicate: full static gate runs `fmt`/`clippy`; pre-commit repeats them as final guard.
- This duplicate is intentional and bounded. Do not add ad hoc extra reruns unless files changed.

Pre-commit hook must run at minimum:
```
cargo +nightly fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Pre-push hook must run at minimum:
```
cargo deny check
cargo audit
```

To install hooks: `cargo run --bin install-hooks` (once implemented) or
manually copy from `.githooks/` to `.git/hooks/`.

---

## Phase Roadmap

All phases are canonical. See `docs/ROADMAP.md` for full detail.

| Phase | Deliverable | Status |
|-------|-------------|--------|
| 1 | TCPIP provider → connection-level NDJSON | ✅ Done |
| 2 | NDIS provider + correlator → .pcapng output | ✅ Done |
| 3 | `--spawn` mode: launch child process + track PID | ✅ Done |
| 3.5 | DNS Client ETW → DnsQuery/DnsResponse NDJSON | ✅ Done |
| 3.6 | DPI, TCP state machine, connection tracker, IP classification | ✅ Done |
| 4 | TLS SNI/JA3/JA4 fingerprinting, HTTP DPI, process name enrichment | ✅ Done |
| 5 | HTTPS decryption (MITM proxy + rule engine) | ✅ Done |
| 5.5 | `browse` subcommand: browser discovery, headless launch, CDP page-load detection | ✅ Done |
| 6 | WinDivert active capture layer | Planned |
| 7 | Advanced (Protobuf output, search, scripting) | Planned |

---

## Key Invariants

1. `stdout` = NDJSON only. `stderr` = diagnostics only. Never mix.
2. `unsafe_code = "forbid"` at crate root. No exceptions in business logic.
3. No `unwrap()` in non-test code. No `println!` outside `src/output/`.
4. Every file has a mandatory header block (see `docs/DEV_STANDARDS.md`).
5. Every file respects its line budget. Exceed budget → split, not expand.
6. `output/schema.rs` types are the stable agent contract. No breaking changes.
7. `--no-verify` is banned on all git operations.
8. Edition 2021 — no `let chains`.
9. No `#[allow(...)]` in source — use `Cargo.toml` `[lints.clippy]` instead.
10. `panic = "deny"`, `unsafe_code = "forbid"` in `Cargo.toml`.

---

## Quick Reference: Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `capture/` | ETW session lifecycle, provider enable (TCPIP + NDIS + Correlation + DNS Client), event loop |
| `parser/` | Convert RawEvent → NetEvent per provider; DNS wire parsing, DPI (TLS/HTTP), TCP state machine |
| `filter/` | Drop events not belonging to TargetPid or its process tree |
| `pcap/` | Correlate RawFrame to TargetPid, write .pcapng |
| `process/` | Spawn child process, monitor lifecycle, PID → process name lookup, process tree cache, TCP socket inventory |
| `runtime/` | Browse subcommand: browser discovery (registry/paths/PATH), headless launch, CDP page-load detection, capture orchestration |
| `mitm/` | HTTPS MITM proxy: CA cert generation, system proxy, body decoding, PID resolution |
| `rules/` | Traffic control: block/replace/intercept/hosts rules, pattern matching, config loading |
| `output/` | Serialize NetEvent to NDJSON stdout (EventLine + DnsEventLine + HttpEventLine + TlsEventLine + RuleHitEventLine + SummaryLine + ErrorLine) |
| `tracker.rs` | Connection flow tracker: DashMap<FiveTuple, TrackedConnection>, byte counters, DPI, idle cleanup |
| `classify.rs` | IP scope classification: Public/Private/LinkLocal/Loopback/Multicast/etc |
| `target.rs` | CLI target resolution (PID or spawn), stop signal, process tree filter setup |
| `cli.rs` | clap argument definitions |
| `error.rs` | Unified error types |
| `main.rs` | Assemble modules, run capture loop |
