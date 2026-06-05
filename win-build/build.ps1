<#
.SYNOPSIS
    Build git-crypt.exe for Windows (x64, MSVC, static CRT, no external deps).

.DESCRIPTION
    Locates Visual Studio with vswhere, loads the x64 developer environment,
    then configures + builds the win-build\CMakeLists.txt with Ninja. The
    resulting git-crypt.exe statically links the MSVC CRT and uses the
    Windows-native BCrypt crypto backend, so it needs no VC++ redistributable
    and no OpenSSL. The final exe is copied to win-build\dist\.

    Compiler discovery mirrors D:\github\discrete\build.ps1.

.PARAMETER Mode
    Release (default) or Debug.

.PARAMETER Clean
    Wipe win-build\build\ before configuring.

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Mode Debug -Clean
#>

[CmdletBinding()]
param(
    [ValidateSet('Release','Debug')]
    [string]$Mode = 'Release',

    [switch]$Clean
)

$ErrorActionPreference = 'Stop'
$sw = [System.Diagnostics.Stopwatch]::StartNew()
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$Here      = Split-Path -Parent $MyInvocation.MyCommand.Definition
$BuildDir  = Join-Path $Here 'build'
$DistDir   = Join-Path $Here 'dist'

function Write-Step([string]$t) { Write-Host ">> $t" -ForegroundColor Yellow }
function Write-Ok  ([string]$t) { Write-Host "   [OK] $t" -ForegroundColor Green }
function Write-Fail([string]$t) { Write-Host "   [FAIL] $t" -ForegroundColor Red }
function Write-Info([string]$t) { Write-Host "   $t" -ForegroundColor Gray }

# ---------------------------------------------------------------------------
# Locate Visual Studio (vswhere) and enter the x64 developer shell.
# ---------------------------------------------------------------------------
function Resolve-VsInstallPath {
    $candidates = [System.Collections.Generic.List[string]]::new()
    $inPath = Get-Command vswhere -ErrorAction SilentlyContinue
    if ($inPath) { $candidates.Add($inPath.Source) }
    if (${env:ProgramFiles(x86)}) { $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe')) }
    if ($env:ProgramFiles)        { $candidates.Add((Join-Path $env:ProgramFiles        'Microsoft Visual Studio\Installer\vswhere.exe')) }

    $vswhere = $candidates | Where-Object { $_ -and (Test-Path $_ -ErrorAction SilentlyContinue) } | Select-Object -First 1
    if (-not $vswhere) { throw 'vswhere.exe not found. Install Visual Studio (with the C++ Desktop workload).' }

    $vsPath = & $vswhere -latest -prerelease -products * `
                 -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
                 -property installationPath
    if (-not $vsPath) { $vsPath = & $vswhere -latest -prerelease -property installationPath }
    if (-not $vsPath) { throw 'No Visual Studio installation with the C++ workload found.' }
    return $vsPath
}

function Enter-VsDevEnvironment {
    $vsPath = Resolve-VsInstallPath
    $devShellDll = Join-Path $vsPath 'Common7\Tools\Microsoft.VisualStudio.DevShell.dll'
    if (-not (Test-Path $devShellDll)) { throw "Microsoft.VisualStudio.DevShell.dll not found at $devShellDll." }
    Write-Info "Visual Studio: $vsPath"
    Import-Module $devShellDll
    Enter-VsDevShell -VsInstallPath $vsPath -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
    Write-Ok 'MSVC x64 environment loaded'
}

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host "  git-crypt Windows build  |  Mode: $Mode  |  Arch: x64" -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

Enter-VsDevEnvironment

foreach ($tool in 'cmake','ninja') {
    $c = Get-Command $tool -ErrorAction SilentlyContinue
    if (-not $c) { Write-Fail "$tool not found on PATH after loading DevShell"; exit 1 }
    Write-Info "$tool : $($c.Source)"
}

if ($Clean -and (Test-Path $BuildDir)) {
    Write-Step "Cleaning $BuildDir"
    Remove-Item $BuildDir -Recurse -Force
}
New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
New-Item -ItemType Directory -Path $DistDir  -Force | Out-Null

Write-Step "Configuring CMake (Ninja, MSVC x64, static CRT)"
& cmake -S $Here -B $BuildDir -G Ninja "-DCMAKE_BUILD_TYPE=$Mode" | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Fail 'cmake configure failed'; exit 1 }
Write-Ok 'Configured'

Write-Step "Building ($Mode)"
& cmake --build $BuildDir --parallel | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Fail 'build failed'; exit 1 }

$exe = Join-Path $BuildDir 'bin\git-crypt.exe'
if (-not (Test-Path $exe)) { Write-Fail "git-crypt.exe not produced at $exe"; exit 1 }
Copy-Item $exe -Destination $DistDir -Force
$finalExe = Join-Path $DistDir 'git-crypt.exe'
$sz = '{0:N0} KB' -f ((Get-Item $finalExe).Length / 1KB)
Write-Ok "git-crypt.exe ($sz) -> win-build\dist\"

# ---------------------------------------------------------------------------
# Verify the exe carries no MSVC runtime / OpenSSL dependency.
# ---------------------------------------------------------------------------
Write-Step 'Checking DLL dependencies (dumpbin /dependents)'
$dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
if ($dumpbin) {
    $deps = & dumpbin /nologo /dependents $finalExe |
            Select-String -Pattern '\.dll' | ForEach-Object { $_.Line.Trim() }
    $deps | ForEach-Object { Write-Info $_ }
    $bad = $deps | Where-Object { $_ -match '(?i)(vcruntime|msvcp|msvcr|api-ms-win-crt|libcrypto|libssl)' }
    if ($bad) {
        Write-Fail "Unexpected runtime dependency found:"
        $bad | ForEach-Object { Write-Fail "  $_" }
        exit 1
    }
    Write-Ok 'No VC++ runtime / OpenSSL dependency (self-contained)'
} else {
    Write-Info 'dumpbin not available; skipped dependency check'
}

$sw.Stop()
Write-Host ''
Write-Host "  Output: $finalExe" -ForegroundColor White
Write-Host "  Time:   $($sw.Elapsed.ToString('mm\:ss\.ff'))" -ForegroundColor White
Write-Host "  Status: SUCCESS" -ForegroundColor Green
Write-Host ''
exit 0
