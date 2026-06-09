# package-release.ps1 — build a Windows release folder with WinDivert runtime files.
# Usage: pwsh -NoProfile -File scripts/package-release.ps1 -WinDivertRoot <official-release-or-build-root>

param(
    [string]$WinDivertRoot = $env:WINDIVERT_HOME,
    [string]$OutDir = '',
    [switch]$SkipCargoBuild,
    [switch]$AllowUnsignedDriver,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

function Write-Usage {
    Write-Host 'Usage:' -ForegroundColor Yellow
    Write-Host '  pwsh -NoProfile -File scripts/package-release.ps1 -WinDivertRoot <path>'
    Write-Host ''
    Write-Host 'Required WinDivert runtime files, in the same x64/amd64 runtime directory:' -ForegroundColor Cyan
    Write-Host '  WinDivert.dll'
    Write-Host '  WinDivert64.sys'
    Write-Host ''
    Write-Host 'The package also copies WinDivert LICENSE as LICENSE.WinDivert and writes THIRD_PARTY_NOTICES.txt.'
    Write-Host 'Use an official signed WinDivert release or a signed build. A source checkout alone is not enough.'
}

if ($Help) {
    Write-Usage
    exit 0
}

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path (Join-Path $RepoRoot 'dist') 'etwarden-windows-x64'
}

function Invoke-External {
    param([string]$Label, [scriptblock]$Block)

    Write-Host "[package-release] $Label..." -ForegroundColor Cyan
    & $Block
    $code = $LASTEXITCODE
    if ($null -eq $code) { $code = 0 }
    if ($code -ne 0) {
        throw "[package-release] FAILED: $Label (exit $code)"
    }
}

function Find-FirstFile {
    param([string]$Root, [string]$Name)

    $direct = Join-Path $Root $Name
    if (Test-Path $direct) { return (Resolve-Path $direct).Path }

    $found = Get-ChildItem -Path $Root -Filter $Name -File -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($found) { return $found.FullName }
    return $null
}

function Find-WinDivertRuntime {
    param([string]$Root)

    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw 'WinDivert root missing. Pass -WinDivertRoot <path> or set WINDIVERT_HOME.'
    }

    $rootPath = (Resolve-Path $Root -ErrorAction Stop).Path
    $dlls = Get-ChildItem -Path $rootPath -Filter 'WinDivert.dll' -File -Recurse -ErrorAction SilentlyContinue

    foreach ($dll in $dlls) {
        $dir = $dll.Directory.FullName
        $driver64 = Join-Path $dir 'WinDivert64.sys'
        if (Test-Path $driver64) {
            $license = Find-FirstFile -Root $rootPath -Name 'LICENSE'
            if (-not $license) {
                throw "WinDivert LICENSE not found under $rootPath; cannot create redistributable package."
            }

            $readme = Find-FirstFile -Root $rootPath -Name 'README'
            $version = 'unknown'
            $versionPath = Find-FirstFile -Root $rootPath -Name 'VERSION'
            if ($versionPath) {
                $version = (Get-Content $versionPath -TotalCount 1).Trim()
            }

            return [pscustomobject]@{
                Root = $rootPath
                RuntimeDir = $dir
                Dll = $dll.FullName
                Driver64 = (Resolve-Path $driver64).Path
                License = $license
                Readme = $readme
                Version = $version
            }
        }
    }

    $sourceHint = ''
    if ((Test-Path (Join-Path (Join-Path $rootPath 'dll') 'windivert.vcxproj')) -and
        (Test-Path (Join-Path (Join-Path $rootPath 'sys') 'windivert.vcxproj'))) {
        $sourceHint = ' This looks like a source checkout only. Build it with MSBuild+WDK or use an official signed WinDivert release zip.'
    }

    throw "WinDivert runtime not found under $rootPath. Need one directory containing WinDivert.dll and WinDivert64.sys.$sourceHint"
}

function Assert-SignedDriver {
    param([string]$Path)

    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
        Write-Warning '[package-release] Get-AuthenticodeSignature unavailable; driver signature not checked.'
        return
    }

    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -eq 'Valid') {
        Write-Host "[package-release] Driver signature OK: $Path" -ForegroundColor Green
        return
    }

    $msg = "WinDivert driver signature is not valid: $Path (status=$($sig.Status)). Use official signed binaries for release."
    if ($AllowUnsignedDriver) {
        Write-Warning "[package-release] $msg Allowing only because -AllowUnsignedDriver was set."
    } else {
        throw "$msg For local-only admin validation, rerun with -AllowUnsignedDriver."
    }
}

function Copy-ReleaseFile {
    param([string]$Path, [string]$Name)

    $destination = Join-Path $OutDir $Name
    if (Test-Path $destination) {
        $sourceHash = (Get-FileHash -Path $Path -Algorithm SHA256).Hash
        $destinationHash = (Get-FileHash -Path $destination -Algorithm SHA256).Hash
        if ($sourceHash -eq $destinationHash) {
            Write-Host "[package-release] Skipping unchanged $Name" -ForegroundColor DarkGray
            return
        }
    }

    Copy-Item -Path $Path -Destination $destination -Force
}

function Clear-ReleaseDirectory {
    param([string[]]$KeepNames)

    $distRoot = (Join-Path $RepoRoot 'dist')
    $resolvedOut = (Resolve-Path $OutDir).Path
    $resolvedDist = (Resolve-Path $distRoot -ErrorAction SilentlyContinue).Path
    $insideDist = $resolvedDist -and (
        $resolvedOut.Equals($resolvedDist, [System.StringComparison]::OrdinalIgnoreCase) -or
        $resolvedOut.StartsWith(($resolvedDist + [System.IO.Path]::DirectorySeparatorChar), [System.StringComparison]::OrdinalIgnoreCase)
    )
    if (-not $insideDist) {
        Write-Warning "[package-release] Skipping package cleanup for custom OutDir: $OutDir"
        return
    }

    Get-ChildItem -Path $OutDir -Force | Where-Object { $KeepNames -notcontains $_.Name } | ForEach-Object {
        Write-Host "[package-release] Removing unmanaged package file $($_.Name)" -ForegroundColor DarkGray
        Remove-Item -Path $_.FullName -Recurse -Force
    }
}

$runtime = Find-WinDivertRuntime -Root $WinDivertRoot
Assert-SignedDriver -Path $runtime.Driver64

if (-not $SkipCargoBuild) {
    Invoke-External 'cargo build --release' { & cargo build --release }
}

$releaseDir = Join-Path (Join-Path $RepoRoot 'target') 'release'
$exe = Join-Path $releaseDir 'etwarden.exe'
if (-not (Test-Path $exe)) {
    throw "Release executable not found: $exe. Run cargo build --release or omit -SkipCargoBuild."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$packageFiles = @(
    'etwarden.exe',
    'WinDivert.dll',
    'WinDivert64.sys',
    'LICENSE.WinDivert',
    'README.WinDivert',
    'THIRD_PARTY_NOTICES.txt'
)
Clear-ReleaseDirectory -KeepNames $packageFiles

Copy-ReleaseFile -Path $exe -Name 'etwarden.exe'
Copy-ReleaseFile -Path $runtime.Dll -Name 'WinDivert.dll'
Copy-ReleaseFile -Path $runtime.Driver64 -Name 'WinDivert64.sys'
Copy-ReleaseFile -Path $runtime.License -Name 'LICENSE.WinDivert'
if ($runtime.Readme) {
    Copy-ReleaseFile -Path $runtime.Readme -Name 'README.WinDivert'
}

$notice = @"
etwarden third-party notices
=============================

WinDivert
---------
Version: $($runtime.Version)
Runtime source/build root used for this package: $($runtime.Root)
Runtime directory: $($runtime.RuntimeDir)
Upstream: https://github.com/basil00/Divert
Homepage: https://reqrypt.org/windivert.html
License: LGPLv3-or-GPLv2. This package conveys WinDivert under LGPLv3 terms.

Packaged files:
- WinDivert.dll
- WinDivert64.sys
- LICENSE.WinDivert

etwarden loads WinDivert.dll dynamically at runtime. Keep WinDivert.dll and
WinDivert64.sys next to etwarden.exe in redistributed Windows packages. Users
may replace WinDivert with an interface-compatible modified build as allowed by
LGPLv3.
"@

Set-Content -Path (Join-Path $OutDir 'THIRD_PARTY_NOTICES.txt') -Value $notice -Encoding UTF8

Write-Host ''
Write-Host '[package-release] PASS' -ForegroundColor Green
Write-Host "Output: $OutDir"
Get-ChildItem -Path $OutDir | Select-Object Name, Length | Format-Table -AutoSize
