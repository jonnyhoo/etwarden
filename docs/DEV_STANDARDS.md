# etwarden — Development Standards

> LLM-first. Every file is written to be read and modified by an LLM agent.
> Humans review. Agents implement.

---

## Toolchain

| Tool | Install | Purpose |
|------|---------|---------|
| rustc stable ≥1.75 | rustup | Compiler |
| rustc nightly | `rustup toolchain install nightly --component rustfmt` | Formatting only (unstable rustfmt features) |
| rustfmt | rustup component | Format |
| clippy | rustup component | Lint |
| cargo-nextest | `cargo install cargo-nextest --locked` | Test runner (canonical, replaces `cargo test`) |
| cargo-deny | `cargo install cargo-deny` | License + supply chain |
| cargo-audit | `cargo install cargo-audit` | CVE advisory scan |
| cargo-machete | `cargo install cargo-machete` | Unused dependency cleanup |
| cargo-coupling | `cargo install cargo-coupling` | Coupling health gate |
| cargo-udeps | `cargo install cargo-udeps --locked` | Unused dependency check |
| cargo-hack | `cargo install cargo-hack --locked` | Feature matrix check |
| cargo-semver-checks | `cargo install cargo-semver-checks --locked` | Public API compatibility |
| cargo-llvm-cov | `cargo install cargo-llvm-cov` | Coverage (Windows-friendly) |
| cargo-criterion | `cargo install cargo-criterion` | Benchmarks |
| signed WinDivert release/build | upstream release or local MSBuild+WDK build | Release packaging for `--divert` runtime |

---

## Local Hook Gates (must all pass, in order)

Use `&&` between commands so the gate stops on first failure. Do not use
PowerShell `;` for gate chains; it can hide an earlier failure behind a later
success.

There is no GitHub CI workflow. Static gates run locally through global hooks
plus repo hooks. See `.repo-control-plane/hook-lanes.json` for lane ownership.

Hook lane split:
- Global pre-commit: generic text guards, Rust `cargo fmt` auto-fix, language lanes.
- Repo pre-commit: `check-control-plane`, `check-docs`, `cargo check -p etwarden`, `git diff --check`.
- Global pre-push: generic/language guards; Rust fmt/clippy fallback only when repo pre-push is absent.
- Repo pre-push: complete Rust/static push gate, including fmt/clippy.

Test runner: `cargo nextest run` is canonical. Fallback to `cargo test` only
when nextest is absent. Doctests require separate `cargo test --doc`.

Control plane commands (preferred):
```
pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-commit
pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-push
pwsh -NoProfile -File scripts/repo-control.ps1 verify:focused
pwsh -NoProfile -File scripts/repo-control.ps1 verify:full
```

Focused gate for small slices:
```
cargo +nightly fmt --check && cargo nextest run -p etwarden <module-or-filter> && cargo clippy --all-targets -- -D warnings
```

Pre-commit gate:
```
pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-commit
```

Full static gate before push:
```
pwsh -NoProfile -File scripts/repo-control.ps1 gate:pre-push
```

Manual equivalent:
```
cargo +nightly fmt --all --check && cargo check -p etwarden && cargo clippy --all-targets --all-features -- -D warnings && cargo audit --no-fetch --stale && cargo deny check --disable-fetch && cargo machete && cargo +nightly udeps --all-targets --all-features && cargo hack check --all-targets --feature-powerset && cargo semver-checks --baseline-rev <latest-tag> && cargo coupling --check --no-git --max-circular 5 && cargo nextest run && cargo test --doc && cargo doc --no-deps && git diff --check && git status --short
```

`cargo semver-checks` needs a git tag baseline. If no tag exists yet,
`scripts/repo-control.ps1` skips semver-checks and prints a warning.

`cargo audit --no-fetch --stale` and `cargo deny check --disable-fetch` use the local RustSec advisory DB. Update `~/.cargo/advisory-db` separately when network is available; do not let transient advisory DB fetch failures block unrelated local commits.

Admin/release gate:
```
cargo nextest run --features integration       # requires admin runner
cargo llvm-cov --summary-only                  # coverage report
cargo bench --no-run                           # bench compile check
```

No push unless repo pre-commit and repo pre-push gates pass. Admin/release gate
is required before release or admin-runner integration changes.

Windows release packaging:
```
pwsh -NoProfile -File scripts/repo-control.ps1 package:release -WinDivertRoot <official-release-or-build-root>
```

`--divert` release packages must include `WinDivert.dll`, `WinDivert64.sys`,
`LICENSE.WinDivert`, and `THIRD_PARTY_NOTICES.txt` next to `etwarden.exe`.
Use official signed WinDivert runtime binaries or a signed local build. A source
checkout alone is not a runtime package.

Duplicate policy:
- Repo hook files are thin shims; gate logic lives in `scripts/repo-control.ps1`.
- Repo pre-commit does not duplicate global Rust formatting.
- Repo pre-push owns Rust fmt/clippy because global pre-push delegates Rust checks when `.githooks/pre-push` exists.
- If a gate fails, fix root cause. Do not bypass or reorder checks to get green output.

**Not in hook gate (run manually):**
- `cargo mutants` — valuable but slow, run before releases
- `cargo miri` — incompatible with windows-rs / ETW FFI
- `cargo coupling --json -o logs/coupling.json` — full churn-aware report for refactor planning

---

## Coupling Baseline (cargo-coupling)

Repo pre-push uses a structural, deterministic gate:

```
cargo coupling --check --no-git --max-circular 5
```

Rationale:

- `--no-git` avoids failing local push gates on short-term churn while the project is still evolving.
- `--max-circular 5` records the current module-cycle budget; do not increase it.
- Lower `--max-circular` only after an intentional refactor removes cycles.
- Do not add facade traits only to satisfy the report; refactor only when the module boundary is real.
- Full churn-aware reports are manual planning input, not a merge gate.

---

## rustfmt.toml

```toml
edition = "2021"
max_width = 100
imports_granularity = "Crate"
group_imports = "StdExternalCrate"
fn_single_line = false
trailing_comma = "Vertical"
```

---

## Clippy / Lint Policy

Declared in `Cargo.toml` `[lints]` section:

```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
all         = { level = "deny",  priority = -1 }
pedantic    = { level = "warn",  priority = -1 }
nursery     = { level = "warn",  priority = -1 }
unwrap_used = "deny"
expect_used = "allow"
panic       = "deny"
```

Suppress a lint only with `#[allow(...)]` + mandatory comment explaining why.
No blanket `#[allow(clippy::all)]`.

---

## deny.toml (cargo-deny)

```toml
[graph]
targets = [{ triple = "x86_64-pc-windows-msvc" }]

[licenses]
allow = [
    "MIT",
    "MIT-0",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-3-Clause",
    "CDLA-Permissive-2.0",
    "ISC",
    "Unicode-3.0",
]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards         = "deny"

[advisories]
vulnerability = "deny"
unmaintained  = "warn"
yanked        = "deny"

[sources]
unknown-registry = "deny"
unknown-git      = "deny"
```

---

## Test Strategy (3 layers)

```
Unit tests        → #[cfg(test)] in each file. Pure logic, no ETW, no admin.
Integration tests → tests/ dir, #[cfg(feature = "integration")]. Requires admin.
Schema compat     → tests/schema_compat.rs. No feature gate. Always runs.
Snapshot tests    → insta crate. JSON output regression for schema.rs types.
Benchmarks        → benches/event_throughput.rs. criterion. 10% regression = block merge.
```

Coverage target: ≥ 80% on `parser/` and `output/` modules (pure logic, measurable).
ETW session code excluded from coverage requirement (integration-only).

---

## File Header (mandatory on every .rs file)

```rust
//! # `module_name`
//!
//! **Purpose**: One sentence — what this module does.
//! **Public API**: List every `pub` symbol exported.
//! **Dependencies**: List every intra-crate module used.
//! **Platform**: `windows-only` | `all`
//! **Privilege**: `requires-admin` | `none`
//! **Line budget**: <current> / <max>
```

LLM agents MUST update `Line budget` after every edit.

---

## Function Rules

Every `pub fn` must have a doc comment with these sections:

```rust
/// One-line summary.
///
/// # Arguments
/// * `foo` — description
///
/// # Returns
/// Description of return value.
///
/// # Errors
/// Conditions under which this returns `Err`.
```

`# Errors` is mandatory on any function returning `Result`.
`# Safety` is mandatory on any `unsafe fn`.

---

## Error Handling

- All errors propagate via `anyhow::Result<T>` or a module-local `thiserror::Error` enum.
- Never use `Box<dyn std::error::Error>`.
- Never use `unwrap()` in non-test code.
- Use `expect()` only in tests, with a string explaining the invariant.
- `main` returns `anyhow::Result<()>`. On error, print JSON error line to stdout then return `Err`.
- Use `thiserror` for typed errors in library-facing modules (`parser/`, `capture/`).
- Use `anyhow` for top-level orchestration (`main.rs`, `process/`).

---

## Output Discipline

- `stdout` = NDJSON only. Zero exceptions.
- `stderr` = diagnostics, progress, warnings.
- Never use `println!` outside `src/output/`.
- Use `eprintln!` for debug/diagnostic in other modules during development; remove before merge.

---

## Naming Conventions

| Kind | Convention | Example |
|------|------------|---------|
| Types | PascalCase | `NetEvent`, `RawFrame` |
| Functions | snake_case | `parse_event`, `start_session` |
| Variables | snake_case | `target_pid`, `raw_bytes` |
| Constants | SCREAMING_SNAKE_CASE | `MAX_SESSION_DURATION` |
| Provider GUIDs | `PROVIDER_` prefix | `PROVIDER_TCPIP` |
| ETW event IDs | `EVENT_ID_` prefix | `EVENT_ID_TCP_CONNECT` |
| Feature flags | kebab-case | `integration` |
| Snapshot test names | `module__function__case` | `tcpip__parse__connect_v4` |

---

## Module Line Budgets

| File | Max lines |
|------|-----------|
| `main.rs` | 80 |
| Any `mod.rs` | 80 |
| `cli.rs` | 100 |
| `error.rs` | 80 |
| `schema.rs` | 200 |
| All other `.rs` | 200 |

When a file exceeds budget: split the file, not the budget.

---

## Unsafe Policy

- `#[forbid(unsafe_code)]` at crate root.
- ETW unsafe lives inside `ferrisetw` and `windows-rs` — not our code.
- If a Windows API requires unsafe FFI not covered by `windows-rs`:
  1. Isolate in a dedicated `ffi.rs` file with `#[allow(unsafe_code)]`
  2. Write a safe public wrapper function
  3. Document `# Safety` invariants on every unsafe block

---

## Snapshot Testing (insta)

Used for schema regression. Pattern:

```rust
#[test]
fn test_connect_event_serializes() {
    let event = NetEvent::connect_fixture();
    insta::assert_json_snapshot!("connect_event", event);
}
```

Snapshots live in `src/output/snapshots/`. Committed to git.
On change: `cargo insta review` → human approves → commit.

---

## LLM Agent Conventions

When an LLM agent edits a file:

1. Read the file header first.
2. Update `Line budget` in the header after the edit.
3. Never exceed the line budget — split instead.
4. Keep the `**Public API**` list in the header accurate.
5. Do not add new `pub` symbols without updating the header.
6. Do not introduce new dependencies without updating `Cargo.toml` and `deny.toml`.
7. All new `pub fn` must have complete doc comments before the PR.
8. After adding snapshot tests, run `cargo insta review` to accept baselines.
