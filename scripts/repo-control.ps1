# repo-control.ps1 — etwarden repo control plane
# Single entry point for all repo governance commands.
# Usage: pwsh -NoProfile -File scripts/repo-control.ps1 <command> [args]

param(
    [Parameter(Position = 0)]
    [string]$Command = '',

    [Parameter(Position = 1, ValueFromRemainingArguments)]
    [string[]]$CommandArgs = @()
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$ManifestPath = Join-Path $RepoRoot '.repo-control-plane' 'manifest.json'

# --- helpers ---

function Read-Manifest {
    if (-not (Test-Path $ManifestPath)) {
        Write-Error "[repo-control] manifest not found: $ManifestPath"
        exit 1
    }
    Get-Content $ManifestPath -Raw | ConvertFrom-Json
}

function Test-ToolPresent {
    param([string]$Name)
    [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Invoke-Gate {
    param([string]$Label, [scriptblock]$Block)
    Write-Host "[repo-control] $Label..." -ForegroundColor Cyan
    $result = & $Block
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    if ($code -ne 0) {
        Write-Error "[repo-control] FAILED: $Label (exit $code)"
        exit $code
    }
}

function Get-TestRunner {
    if (Test-ToolPresent 'cargo-nextest') { return 'nextest' }
    Write-Warning "[repo-control] cargo-nextest not found; falling back to cargo test."
    return 'legacy'
}

function Run-Tests {
    $runner = Get-TestRunner
    if ($runner -eq 'nextest') {
        & cargo nextest run @CommandArgs
    } else {
        & cargo test @CommandArgs
    }
}

# --- commands ---

function Cmd-Entry {
    $m = Read-Manifest
    Write-Host "=== etwarden repo control plane ===" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Repo: $($m.repoName) ($($m.repoKind))"
    Write-Host ""
    Write-Host "Canonical docs:" -ForegroundColor Cyan
    $m.canonicalDocs.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name) -> $($_.Value)"
    }
    Write-Host ""
    Write-Host "Hook lanes:" -ForegroundColor Cyan
    $m.hookLanes.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name) [$($_.Value.owner)]"
    }
    Write-Host ""
    Write-Host "Test runner: $($m.testRunner.primary) (fallback: $($m.testRunner.fallback))"
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor Cyan
    $m.commands.PSObject.Properties | ForEach-Object {
        Write-Host "  $($_.Name)"
    }
}

function Cmd-Status {
    $m = Read-Manifest
    Write-Host "=== repo status ===" -ForegroundColor Yellow

    # control plane files
    $cpFiles = @(
        '.repo-control-plane/manifest.json',
        '.repo-control-plane/hook-lanes.json',
        '.repo-control-plane/static-gates/artifact-policy.json',
        'scripts/repo-control.ps1',
        'scripts/package-release.ps1',
        '.githooks/pre-commit',
        '.githooks/pre-push',
        '.github/workflows/ci.yml'
    )
    Write-Host ""
    Write-Host "Control-plane files:" -ForegroundColor Cyan
    foreach ($f in $cpFiles) {
        $full = Join-Path $RepoRoot $f
        $exists = Test-Path $full
        $mark = if ($exists) { 'OK' } else { 'MISSING' }
        $color = if ($exists) { 'Green' } else { 'Red' }
        Write-Host "  [$mark] $f" -ForegroundColor $color
    }

    # canonical docs
    Write-Host ""
    Write-Host "Canonical docs:" -ForegroundColor Cyan
    $m.canonicalDocs.PSObject.Properties | ForEach-Object {
        $full = Join-Path $RepoRoot $_.Value
        $exists = Test-Path $full
        $mark = if ($exists) { 'OK' } else { 'MISSING' }
        $color = if ($exists) { 'Green' } else { 'Red' }
        Write-Host "  [$mark] $($_.Name) -> $($_.Value)" -ForegroundColor $color
    }

    # tools
    Write-Host ""
    Write-Host "Required tools:" -ForegroundColor Cyan
    foreach ($tool in $m.requiredTools) {
        $present = Test-ToolPresent $tool
        $mark = if ($present) { 'OK' } else { 'MISSING' }
        $color = if ($present) { 'Green' } else { 'Red' }
        Write-Host "  [$mark] $tool" -ForegroundColor $color
    }

    # hook integration
    Write-Host ""
    Write-Host "Hook integration:" -ForegroundColor Cyan
    $hooksPath = ''
    $hp = git config --get core.hooksPath 2>$null
    if ($LASTEXITCODE -eq 0 -and $hp) {
        $hooksPath = $hp.Trim()
    }
    if ($hooksPath) {
        Write-Host "  core.hooksPath = $hooksPath" -ForegroundColor Green
        $globalManifest = Join-Path $hooksPath 'global_fortress_gate_manifest.json'
        if (Test-Path $globalManifest) {
            Write-Host "  [OK] Global fortress manifest present" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] No global fortress manifest at $hooksPath" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [WARN] core.hooksPath not set" -ForegroundColor Yellow
    }

    $repoPreCommit = Join-Path $RepoRoot '.githooks' 'pre-commit'
    $repoPrePush = Join-Path $RepoRoot '.githooks' 'pre-push'
    Write-Host "  [$(if (Test-Path $repoPreCommit) {'OK'} else {'MISSING'})] .githooks/pre-commit" -ForegroundColor $(if (Test-Path $repoPreCommit) {'Green'} else {'Red'})
    Write-Host "  [$(if (Test-Path $repoPrePush) {'OK'} else {'MISSING'})] .githooks/pre-push" -ForegroundColor $(if (Test-Path $repoPrePush) {'Green'} else {'Red'})

    # git status
    Write-Host ""
    & git status --short
}

function Cmd-Doctor {
    $m = Read-Manifest
    $errors = @()

    Write-Host "=== repo doctor ===" -ForegroundColor Yellow

    # required tools
    foreach ($tool in $m.requiredTools) {
        if (-not (Test-ToolPresent $tool)) {
            $errors += "MISSING tool: $tool"
            Write-Host "  [MISSING] $tool" -ForegroundColor Red
        } else {
            Write-Host "  [OK] $tool" -ForegroundColor Green
        }
    }

    # optional tools
    foreach ($tool in $m.optionalTools) {
        if (Test-ToolPresent $tool) {
            Write-Host "  [OK] $tool (optional)" -ForegroundColor Green
        } else {
            Write-Host "  [--] $tool (optional, not installed)" -ForegroundColor Yellow
        }
    }

    # nightly toolchain (needed for fmt)
    $nightly = rustup toolchain list 2>$null | Select-String 'nightly'
    if ($nightly) {
        Write-Host "  [OK] nightly toolchain present" -ForegroundColor Green
    } else {
        $errors += 'MISSING nightly toolchain (needed for cargo +nightly fmt)'
        Write-Host "  [MISSING] nightly toolchain" -ForegroundColor Red
    }

    # advisory DB
    $advDb = Join-Path $env:USERPROFILE '.cargo' 'advisory-db'
    if (Test-Path $advDb) {
        Write-Host "  [OK] advisory DB present" -ForegroundColor Green
    } else {
        $errors += 'MISSING advisory DB (~/.cargo/advisory-db)'
        Write-Host "  [MISSING] advisory DB" -ForegroundColor Red
        Write-Host "    Fix: cargo audit fetch (when network available)" -ForegroundColor Yellow
    }

    # hook integration
    $hooksPath = ''
    $hp = git config --get core.hooksPath 2>$null
    if ($LASTEXITCODE -eq 0 -and $hp) { $hooksPath = $hp.Trim() }
    if ($hooksPath) {
        Write-Host "  [OK] core.hooksPath = $hooksPath" -ForegroundColor Green
    } else {
        $errors += 'core.hooksPath not set; global hooks not active'
        Write-Host "  [WARN] core.hooksPath not set" -ForegroundColor Yellow
    }

    # summary
    Write-Host ""
    if ($errors.Count -eq 0) {
        Write-Host "Doctor: all clear." -ForegroundColor Green
    } else {
        Write-Host "Doctor: $($errors.Count) issue(s) found:" -ForegroundColor Red
        foreach ($e in $errors) {
            Write-Host "  - $e" -ForegroundColor Red
        }
        exit 1
    }
}

function Cmd-CheckControlPlane {
    $errors = @()
    Write-Host "=== check control-plane ===" -ForegroundColor Yellow

    # manifest exists and valid JSON
    if (-not (Test-Path $ManifestPath)) {
        Write-Error '[check-control-plane] manifest.json missing'
        exit 1
    }
    try { $null = Get-Content $ManifestPath -Raw | ConvertFrom-Json }
    catch { Write-Error '[check-control-plane] manifest.json invalid JSON'; exit 1 }
    Write-Host "  [OK] manifest.json" -ForegroundColor Green

    # hook-lanes.json
    $hlPath = Join-Path $RepoRoot '.repo-control-plane' 'hook-lanes.json'
    if (Test-Path $hlPath) {
        try { $null = Get-Content $hlPath -Raw | ConvertFrom-Json }
        catch { $errors += 'hook-lanes.json invalid JSON' }
        Write-Host "  [OK] hook-lanes.json" -ForegroundColor Green
    } else {
        $errors += 'hook-lanes.json missing'
    }

    # artifact-policy.json
    $apPath = Join-Path $RepoRoot '.repo-control-plane' 'static-gates' 'artifact-policy.json'
    if (Test-Path $apPath) {
        Write-Host "  [OK] artifact-policy.json" -ForegroundColor Green
    } else {
        $errors += 'artifact-policy.json missing'
    }

    # cache and runtime dirs
    foreach ($dir in @('cache', 'runtime')) {
        $dp = Join-Path $RepoRoot '.repo-control-plane' $dir
        if (Test-Path $dp) {
            Write-Host "  [OK] .repo-control-plane/$dir/" -ForegroundColor Green
        } else {
            $errors += ".repo-control-plane/$dir/ missing"
        }
    }

    # scripts
    foreach ($script in @('repo-control.ps1', 'package-release.ps1')) {
        $scriptPath = Join-Path (Join-Path $RepoRoot 'scripts') $script
        if (Test-Path $scriptPath) {
            Write-Host "  [OK] scripts/$script" -ForegroundColor Green
        } else {
            $errors += "scripts/$script missing"
        }
    }

    # repo hooks
    foreach ($hook in @('pre-commit', 'pre-push')) {
        $hp = Join-Path $RepoRoot '.githooks' $hook
        if (Test-Path $hp) {
            Write-Host "  [OK] .githooks/$hook" -ForegroundColor Green
        } else {
            $errors += ".githooks/$hook missing"
        }
    }

    # CI workflow
    $ciPath = Join-Path $RepoRoot '.github' 'workflows' 'ci.yml'
    if (Test-Path $ciPath) {
        Write-Host "  [OK] .github/workflows/ci.yml" -ForegroundColor Green
    } else {
        $errors += '.github/workflows/ci.yml missing'
    }

    # .gitignore covers runtime artifacts
    $gitignore = Get-Content (Join-Path $RepoRoot '.gitignore') -Raw
    $requiredPatterns = @('WinDivert.dll', '*.log', '/target', '/dist')
    foreach ($pat in $requiredPatterns) {
        if ($gitignore -notmatch [regex]::Escape($pat)) {
            $errors += ".gitignore missing pattern: $pat"
        }
    }
    Write-Host "  [OK] .gitignore artifact patterns" -ForegroundColor Green

    # summary
    Write-Host ""
    if ($errors.Count -eq 0) {
        Write-Host "check-control-plane: PASS" -ForegroundColor Green
    } else {
        Write-Host "check-control-plane: $($errors.Count) error(s)" -ForegroundColor Red
        foreach ($e in $errors) { Write-Host "  - $e" -ForegroundColor Red }
        exit 1
    }
}

function Cmd-CheckDocs {
    $errors = @()
    Write-Host "=== check docs ===" -ForegroundColor Yellow

    $m = Read-Manifest
    $m.canonicalDocs.PSObject.Properties | ForEach-Object {
        $full = Join-Path $RepoRoot $_.Value
        if (Test-Path $full) {
            Write-Host "  [OK] $($_.Value)" -ForegroundColor Green
        } else {
            $errors += "canonical doc missing: $($_.Value)"
            Write-Host "  [MISSING] $($_.Value)" -ForegroundColor Red
        }
    }

    # AGENTS.md and CLAUDE.md should be in sync
    $agentsHash = (Get-FileHash (Join-Path $RepoRoot 'AGENTS.md') -Algorithm SHA256).Hash
    $claudeHash = (Get-FileHash (Join-Path $RepoRoot 'CLAUDE.md') -Algorithm SHA256).Hash
    if ($agentsHash -eq $claudeHash) {
        Write-Host "  [OK] AGENTS.md == CLAUDE.md" -ForegroundColor Green
    } else {
        $errors += 'AGENTS.md and CLAUDE.md differ'
        Write-Host "  [WARN] AGENTS.md != CLAUDE.md" -ForegroundColor Yellow
    }

    Write-Host ""
    if ($errors.Count -eq 0) {
        Write-Host "check-docs: PASS" -ForegroundColor Green
    } else {
        Write-Host "check-docs: $($errors.Count) error(s)" -ForegroundColor Red
        foreach ($e in $errors) { Write-Host "  - $e" -ForegroundColor Red }
        exit 1
    }
}

function Cmd-VerifyFocused {
    Invoke-Gate 'cargo +nightly fmt --check' { & cargo +nightly fmt --check }
    Invoke-Gate "cargo nextest run ($($CommandArgs -join ' '))" { Run-Tests }
    Invoke-Gate 'cargo clippy --all-targets -- -D warnings' { & cargo clippy --all-targets -- -D warnings }
    Write-Host ""
    Write-Host "verify:focused PASS" -ForegroundColor Green
}

function Cmd-VerifyFull {
    Invoke-Gate 'check-control-plane' { Cmd-CheckControlPlane }
    Invoke-Gate 'check-docs' { Cmd-CheckDocs }
    Invoke-Gate 'cargo +nightly fmt --check' { & cargo +nightly fmt --check }
    Invoke-Gate 'cargo clippy --all-targets -- -D warnings' { & cargo clippy --all-targets -- -D warnings }
    Invoke-Gate 'cargo audit --no-fetch --stale' { & cargo audit --no-fetch --stale }
    Invoke-Gate 'cargo deny check --disable-fetch' { & cargo deny check --disable-fetch }
    Invoke-Gate 'cargo machete' { & cargo machete }
    Invoke-Gate 'cargo coupling --check --no-git --max-circular 5' { & cargo coupling --check --no-git --max-circular 5 }
    Invoke-Gate 'cargo nextest run' { Run-Tests }
    Invoke-Gate 'cargo test --doc' { & cargo test --doc }
    Invoke-Gate 'cargo doc --no-deps' { & cargo doc --no-deps }
    Invoke-Gate 'git diff --check' { & git diff --check }
    Write-Host ""
    Write-Host "verify:full PASS" -ForegroundColor Green
}

function Cmd-VerifyAdmin {
    Invoke-Gate 'cargo nextest run --features integration' { & cargo nextest run --features integration }
    Invoke-Gate 'cargo llvm-cov --summary-only' { & cargo llvm-cov --summary-only }
    Invoke-Gate 'cargo bench --no-run' { & cargo bench --no-run }
    Write-Host ""
    Write-Host "verify:admin PASS" -ForegroundColor Green
}

function Cmd-PackageRelease {
    $scriptPath = Join-Path $RepoRoot 'scripts' 'package-release.ps1'
    & pwsh -NoProfile -File $scriptPath @CommandArgs
    $code = $LASTEXITCODE
    if ($null -ne $code -and $code -ne 0) { exit $code }
}

function Cmd-HooksInstall {
    Write-Host "=== hooks:install ===" -ForegroundColor Yellow
    Write-Host "Repo hooks (.githooks/) are auto-invoked by global fortress hooks." -ForegroundColor Cyan
    Write-Host "No separate install step is needed." -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Global fortress hooks are installed at:" -ForegroundColor Cyan
    $hp = git config --get core.hooksPath 2>$null
    if ($LASTEXITCODE -eq 0 -and $hp) {
        Write-Host "  core.hooksPath = $($hp.Trim())" -ForegroundColor Green
    } else {
        Write-Host "  core.hooksPath not set" -ForegroundColor Red
        Write-Host "  Run: powershell -File ~\.githooks\install_global_fortress_hooks.ps1" -ForegroundColor Yellow
    }
}

function Cmd-HooksDoctor {
    Write-Host "=== hooks:doctor ===" -ForegroundColor Yellow

    # global hooks
    $hp = git config --get core.hooksPath 2>$null
    if ($LASTEXITCODE -eq 0 -and $hp) {
        $hooksPath = $hp.Trim()
        Write-Host "  [OK] core.hooksPath = $hooksPath" -ForegroundColor Green

        $globalPreCommit = Join-Path $hooksPath 'pre-commit'
        $globalPrePush = Join-Path $hooksPath 'pre-push'
        $globalManifest = Join-Path $hooksPath 'global_fortress_gate_manifest.json'

        foreach ($f in @($globalPreCommit, $globalPrePush, $globalManifest)) {
            if (Test-Path $f) {
                Write-Host "  [OK] $(Split-Path $f -Leaf)" -ForegroundColor Green
            } else {
                Write-Host "  [MISSING] $(Split-Path $f -Leaf)" -ForegroundColor Red
            }
        }

        # verify global hooks call repo hooks
        $globalPreCommitContent = Get-Content $globalPreCommit -Raw -ErrorAction SilentlyContinue
        if ($globalPreCommitContent -and $globalPreCommitContent -match '\.githooks/pre-commit') {
            Write-Host "  [OK] global pre-commit calls repo .githooks/pre-commit" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] global pre-commit may not call repo .githooks/pre-commit" -ForegroundColor Yellow
        }

        $globalPrePushContent = Get-Content $globalPrePush -Raw -ErrorAction SilentlyContinue
        if ($globalPrePushContent -and $globalPrePushContent -match '\.githooks/pre-push') {
            Write-Host "  [OK] global pre-push calls repo .githooks/pre-push" -ForegroundColor Green
        } else {
            Write-Host "  [WARN] global pre-push may not call repo .githooks/pre-push" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [WARN] core.hooksPath not set" -ForegroundColor Yellow
    }

    # repo hooks
    $repoPreCommit = Join-Path $RepoRoot '.githooks' 'pre-commit'
    $repoPrePush = Join-Path $RepoRoot '.githooks' 'pre-push'

    if (Test-Path $repoPreCommit) {
        Write-Host "  [OK] .githooks/pre-commit" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] .githooks/pre-commit" -ForegroundColor Red
    }

    if (Test-Path $repoPrePush) {
        Write-Host "  [OK] .githooks/pre-push" -ForegroundColor Green
    } else {
        Write-Host "  [MISSING] .githooks/pre-push" -ForegroundColor Red
    }
}

# --- dispatch ---

switch ($Command) {
    'entry'               { Cmd-Entry }
    'status'              { Cmd-Status }
    'doctor'              { Cmd-Doctor }
    'check-control-plane' { Cmd-CheckControlPlane }
    'check-docs'          { Cmd-CheckDocs }
    'verify:focused'      { Cmd-VerifyFocused }
    'verify:full'         { Cmd-VerifyFull }
    'verify:admin'        { Cmd-VerifyAdmin }
    'package:release'     { Cmd-PackageRelease }
    'hooks:install'       { Cmd-HooksInstall }
    'hooks:doctor'        { Cmd-HooksDoctor }
    default {
        Write-Host "Usage: pwsh -NoProfile -File scripts/repo-control.ps1 <command>" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Commands:"
        Write-Host "  entry               Show repo control plane entry info"
        Write-Host "  status              Show repo status (files, docs, tools, hooks)"
        Write-Host "  doctor              Check toolchain and environment health"
        Write-Host "  check-control-plane Validate control-plane structure"
        Write-Host "  check-docs          Validate canonical docs presence"
        Write-Host "  verify:focused      Run focused gate (fmt + nextest + clippy)"
        Write-Host "  verify:full         Run full static gate"
        Write-Host "  verify:admin        Run admin/release gate"
        Write-Host "  package:release     Build Windows release folder with WinDivert runtime"
        Write-Host "  hooks:install       Show hook install instructions"
        Write-Host "  hooks:doctor        Diagnose hook integration"
        if ($Command -ne '') {
            Write-Host ""
            Write-Host "Unknown command: $Command" -ForegroundColor Red
            exit 1
        }
    }
}
