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

## Two planes

This repo has two independent planes that never cross-depend:

| Plane | Roots | Owns | Invariant |
|-------|-------|------|-----------|
| **Product** | `src/`, `tests/`, `benches/` | ETW, NDIS, MITM, WinDivert, NDJSON contract | Never depends on control-plane scripts |
| **Control** | `.repo-control-plane/`, `scripts/`, `.githooks/` | Gates, hooks, doctor, artifact policy | Never mutates product runtime behavior |

---

## Zero-context start

Read in this order:

1. `AGENTS.md` ← you are here
2. `ARCHITECTURE.md` — module layout, data flow, seam design, phase roadmap
3. `CONTEXT.md` — domain glossary, provider GUIDs, canonical terms
4. `docs/DEV_STANDARDS.md` — toolchain, lint policy, file rules, LLM conventions
5. `docs/ROADMAP.md` — full research + implementation plan for all future phases

---

## Document Map

| Document | Purpose |
|----------|---------|
| `AGENTS.md` | Agent entry point. First file to read. |
| `CLAUDE.md` | Identical copy of `AGENTS.md` for Claude-family agents. |
| `ARCHITECTURE.md` | Full system architecture: modules, data flow, seams, JSON contract. |
| `CONTEXT.md` | Domain glossary. Canonical term definitions. Provider GUIDs. |
| `docs/DEV_STANDARDS.md` | Dev standards: toolchain, lint, naming, file budget, unsafe policy. |
| `docs/ROADMAP.md` | Full research: competitor analysis, 4-phase plan, algorithms, data structures. |
| `docs/TASK_PLAN.md` | Task tracking. |
| `docs/HANDOFF_WINDIVERT.md` | WinDivert redirect handoff status and validation gaps. |
| `.repo-control-plane/manifest.json` | Control plane registry: canonical docs, hook lanes, commands, managed files. |
| `.repo-control-plane/hook-lanes.json` | Hook lane ownership and dedup rules (global vs repo vs manual). |
| `.repo-control-plane/static-gates/artifact-policy.json` | WinDivert / runtime artifact ignore policy. |
| `scripts/repo-control.ps1` | Single entry point for all control-plane commands. |
| `scripts/package-release.ps1` | Builds Windows release folder with bundled WinDivert runtime files and notices. |
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
| What are the local gates? | This file → Pipeline |
| What lint rules apply? | `docs/DEV_STANDARDS.md` → Clippy / Lint Policy |
| What goes in each file header? | `docs/DEV_STANDARDS.md` → File Header |
| How do I handle errors? | `docs/DEV_STANDARDS.md` → Error Handling |
| What are the line budgets? | `ARCHITECTURE.md` → Module Line Budgets |
| What are the naming rules? | `docs/DEV_STANDARDS.md` → Naming Conventions |
| What is the implementation plan? | `docs/ROADMAP.md` |
| What hook lane owns what? | `.repo-control-plane/hook-lanes.json` |

---

## Pipeline

The control plane owns the complete development pipeline. Use it.

### Control plane entry point

All control-plane commands go through `scripts/repo-control.ps1`:

```
pwsh -NoProfile -File scripts/repo-control.ps1 <command>
```

### Step 1: Environment check (run once per session)

```
pwsh -NoProfile -File scripts/repo-control.ps1 doctor
```

Checks: required tools, nightly toolchain, advisory DB, hook integration.
Fix any reported issues before proceeding.

### Step 2: Verify after edits

After small edits (single module or focused change):

```
pwsh -NoProfile -File scripts/repo-control.ps1 verify:focused
```

Runs: `fmt --check` → `nextest run` → `clippy -D warnings`.

Or manually:
```
cargo +nightly fmt --check && cargo nextest run -p etwarden <filter> && cargo clippy --all-targets -- -D warnings
```

### Step 3: Full gate before commit

Before every commit, run the repo pre-commit gate:

```
pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-commit
```

Runs: `check-control-plane` → `check-docs` → `cargo check -p etwarden` → `git diff --check`.

Before every push, run the repo pre-push/full gate:

```
pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-push
```

Runs: `check-control-plane` → `check-docs` → `fmt --all --check` → `check` → `clippy` → `audit` → `deny` → `machete` → `udeps` → `hack` → `semver-checks` → `coupling` → `nextest run` → `test --doc` → `doc --no-deps` → `git diff --check`.

Or manually:
```
cargo +nightly fmt --all --check && cargo check -p etwarden && cargo clippy --all-targets --all-features -- -D warnings && cargo audit --no-fetch --stale && cargo deny check --disable-fetch && cargo machete && cargo +nightly udeps --all-targets --all-features && cargo hack check --all-targets --feature-powerset && cargo semver-checks --baseline-rev <latest-tag> && cargo coupling --check --no-git --max-circular 5 && cargo nextest run && cargo test --doc && cargo doc --no-deps && git diff --check && git status --short
```

### Step 4: Commit

```
git add <files> && git commit -m "<message>"
```

Hooks fire automatically:
1. Global pre-commit: `cargo fmt` (auto-fix), text guards, language lanes
2. Repo pre-commit: `check-control-plane`, `check-docs`, `cargo check -p etwarden`, `git diff --check`

### Step 5: Push

```
git push
```

Hooks fire automatically:
1. Global pre-push: generic/language guards; Rust fallback only when repo pre-push is absent
2. Repo pre-push: `fmt`, `check`, `clippy`, `audit`, `deny`, `machete`, `udeps`, `hack`, `semver-checks`, `coupling`, `nextest run`, `test --doc`, `doc --no-deps`

### Step 6: Admin / release gate (manual, requires admin runner)

```
pwsh -NoProfile -File scripts/repo-control.ps1 verify:admin
```

Runs: `nextest run --features integration` → `llvm-cov` → `bench --no-run`.

### Windows release packaging

`--divert` depends on WinDivert runtime files. Windows release packages must ship
these next to `etwarden.exe`:

- `WinDivert.dll`
- `WinDivert64.sys`
- `LICENSE.WinDivert`
- `THIRD_PARTY_NOTICES.txt`

Packaging command:

```
pwsh -NoProfile -File scripts/repo-control.ps1 package:release -WinDivertRoot <official-release-or-build-root>
```

Use an official signed WinDivert release or a signed local build. A source
checkout such as `WinDivert-master` is not enough until it produces
`WinDivert.dll` + `WinDivert64.sys`. Repo-root ad-hoc copies stay ignored;
release bundles are written under ignored `dist/`.

### Diagnostic commands

| Command | Purpose |
|---------|---------|
| `pwsh -NoProfile -File scripts/repo-control.ps1 status` | Show repo status: files, docs, tools, hooks |
| `pwsh -NoProfile -File scripts/repo-control.ps1 doctor` | Check toolchain and environment health |
| `pwsh -NoProfile -File scripts/repo-control.ps1 check-control-plane` | Validate control-plane structure |
| `pwsh -NoProfile -File scripts/repo-control.ps1 check-docs` | Validate canonical docs presence |
| `pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-commit` | Run repo pre-commit gate |
| `pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-push` | Run repo pre-push/full gate |
| `pwsh -NoProfile -File scripts/repo-control.ps1 hooks:doctor` | Diagnose hook integration |

---

## Hook lanes

Hook gates are partitioned by owner. No lane duplicates another lane's work.

| Lane | Owner | Phase | Runs | Does NOT run |
|------|-------|-------|------|-------------|
| Global pre-commit | fortress | pre-commit | `cargo fmt` (auto-fix), text guards, language lanes | — |
| Global pre-push | fortress | pre-push | generic/language guards; Rust fallback only when repo pre-push is absent | repo-owned Rust gates |
| Repo pre-commit | repo | pre-commit | `check-control-plane`, `check-docs`, `cargo check -p etwarden`, `git diff --check` | fmt, clippy, tests |
| Repo pre-push | repo | pre-push | `fmt`, `check`, `clippy`, `audit`, `deny`, `machete`, `udeps`, `hack`, `semver-checks`, `coupling`, `nextest run`, `test --doc`, `doc --no-deps` | global generic guards |
| Admin/release | repo | manual | `nextest --features integration`, `llvm-cov`, `bench --no-run` | pre-commit/pre-push |

Full lane spec: `.repo-control-plane/hook-lanes.json`.

---

## Rules

### Gate rules

- Use `&&` between gate commands. Never use PowerShell `;` for gates.
- Stop at first failure. Fix root cause before continuing.
- Do not rerun an unchanged passing gate for reassurance.
- Test runner: `cargo nextest run` is canonical. Fallback to `cargo test` only when nextest is absent.
- Doctests: `cargo test --doc` (nextest does not run doctests).
- Audit DB: keep `~/.cargo/advisory-db` updated when network is available; gates use local DB.

### Git hook rules

**`--no-verify` is permanently banned.** No exceptions.

- Never run `git commit --no-verify`
- Never run `git push --no-verify`
- Never suggest `--no-verify` as a workaround
- If a hook fails: fix the underlying issue, do not bypass the hook
- If a hook is broken: fix the hook, do not disable it

Repo hooks (`.githooks/`) are auto-invoked by global fortress hooks (`~/.githooks/`).
No separate install step needed when global fortress hooks are active.

Install global fortress hooks: `powershell -File ~/.githooks/install_global_fortress_hooks.ps1`

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
