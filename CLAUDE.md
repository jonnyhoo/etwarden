# AGENTS.md

Entry point for all LLM agents working on this repository.
Read this file first. No exceptions.

---

## What is this repo?

`etwarden` — A Windows-only CLI tool that captures per-process network activity
via ETW (Event Tracing for Windows) and outputs structured NDJSON to stdout.
Designed as a machine-readable tool for agent runtimes.

Platform: **Windows only** (x86_64-pc-windows-msvc)
Privilege: **Administrator required** at runtime
Language: **Rust (stable ≥ 1.75)**

---

## Zero-context start

Read in this order:

1. `AGENTS.md` ← you are here
2. `ARCHITECTURE.md` — module layout, data flow, seam design, phase roadmap
3. `CONTEXT.md` — domain glossary, provider GUIDs, canonical terms
4. `docs/DEV_STANDARDS.md` — toolchain, CI gate, lint policy, file rules, LLM conventions

---

## Document Map

| Document | Purpose |
|----------|---------|
| `AGENTS.md` | Agent entry point. First file to read. |
| `CLAUDE.md` | Identical copy of `AGENTS.md` for Claude-family agents. |
| `ARCHITECTURE.md` | Full system architecture: modules, data flow, seams, JSON contract. |
| `CONTEXT.md` | Domain glossary. Canonical term definitions. Provider GUIDs. |
| `docs/DEV_STANDARDS.md` | Dev standards: toolchain, CI, lint, naming, file budget, unsafe policy. |
| `Cargo.toml` | Dependencies, lints, features, release profile. |
| `rustfmt.toml` | Code format config. |
| `deny.toml` | Supply chain audit config. |

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
| What are the line budgets? | `docs/DEV_STANDARDS.md` → Module Line Budgets |
| What are the naming rules? | `docs/DEV_STANDARDS.md` → Naming Conventions |

---

## CI Gate (run before every commit)

```
cargo +nightly fmt --check
cargo clippy --all-targets -- -D warnings
cargo deny check
cargo audit
cargo machete
cargo test
cargo doc --no-deps
```

Full gate (requires admin runner):
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

All phases are canonical. There are no optional phases.

| Phase | Deliverable |
|-------|-------------|
| 1 | TCPIP provider → connection-level NDJSON |
| 2 | NDIS provider + correlator → .pcapng output |
| 3 | `--spawn` mode: launch child process + track PID |

---

## Key Invariants

1. `stdout` = NDJSON only. `stderr` = diagnostics only. Never mix.
2. `unsafe_code = "forbid"` at crate root. No exceptions in business logic.
3. No `unwrap()` in non-test code. No `println!` outside `src/output/`.
4. Every file has a mandatory header block (see `docs/DEV_STANDARDS.md`).
5. Every file respects its line budget. Exceed budget → split, not expand.
6. `output/schema.rs` types are the stable agent contract. No breaking changes.
7. `--no-verify` is banned on all git operations.

---

## Quick Reference: Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `capture/` | ETW session lifecycle, provider enable, event loop |
| `parser/` | Convert RawEvent → NetEvent per provider |
| `filter/` | Drop events not belonging to TargetPid |
| `pcap/` | Correlate RawFrame to TargetPid, write .pcapng |
| `process/` | Spawn child process, monitor lifecycle |
| `output/` | Serialize NetEvent to NDJSON stdout |
| `cli.rs` | clap argument definitions |
| `error.rs` | Unified error types |
| `main.rs` | Assemble modules, run capture loop |
