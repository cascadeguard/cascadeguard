#Requires -Version 5.1
<#
.SYNOPSIS
    CascadeGuard — One-shot install and scan for Windows.

.DESCRIPTION
    Installs CascadeGuard to %LOCALAPPDATA%\cascadeguard, adds it to your
    user PATH, and runs 'cascadeguard scan' in the current directory.

.PARAMETER NoInstall
    Scan only — use a temporary venv, clean up after.

.PARAMETER Yes
    Skip the confirmation prompt.

.PARAMETER Dir
    Directory to scan (default: current directory).

.PARAMETER NonInteractive
    Scan all discovered artifacts without prompting.

.PARAMETER Format
    Output format: text, json (default: text).

.PARAMETER Output
    Write results to file instead of stdout.

.EXAMPLE
    irm https://get.cascadeguard.com/install.ps1 | iex
    .\install.ps1
    .\install.ps1 -NoInstall
    .\install.ps1 -Yes -Format json -Output report.json
#>
[CmdletBinding()]
param(
    [switch]$NoInstall,
    [switch]$Yes,
    [string]$Dir,
    [switch]$NonInteractive,
    [string]$Format,
    [string]$Output
)

$ErrorActionPreference = 'Stop'

$CascadeGuardRepo   = 'https://github.com/cascadeguard/cascadeguard.git'
$CascadeGuardBranch = 'main'
$CascadeGuardHome   = Join-Path $env:LOCALAPPDATA 'cascadeguard'
$MinPythonMajor     = 3
$MinPythonMinor     = 11

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Write-Info  { param([string]$Msg) Write-Host "  $([char]0x25B8) $Msg" -ForegroundColor Cyan }
function Write-Ok    { param([string]$Msg) Write-Host "  $([char]0x2714) $Msg" -ForegroundColor Green }
function Write-Warn  { param([string]$Msg) Write-Host "  $([char]0x26A0) $Msg" -ForegroundColor Yellow }
function Write-Err   { param([string]$Msg) Write-Host "  $([char]0x2716) $Msg" -ForegroundColor Red }
function Stop-Script { param([string]$Msg) Write-Err $Msg; exit 1 }

# ---------------------------------------------------------------------------
# Environment checks
# ---------------------------------------------------------------------------
$script:PythonCmd     = $null
$script:PythonVersion = $null
$script:GitVersion    = $null
$script:DockerVersion = $null
$script:DockerRunning = $null

function Find-Python {
    foreach ($cmd in @('python', 'python3', 'py')) {
        try {
            $ver = & $cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>$null
            if ($ver) {
                $parts = $ver.Split('.')
                $major = [int]$parts[0]
                $minor = [int]$parts[1]
                if ($major -ge $MinPythonMajor -and $minor -ge $MinPythonMinor) {
                    $script:PythonCmd = $cmd
                    $script:PythonVersion = (& $cmd --version 2>&1) -join ''
                    return $true
                }
            }
        } catch { }
    }
    return $false
}

function Find-Git {
    try {
        $script:GitVersion = (git --version 2>&1) -join ''
    } catch { }
}

function Find-Docker {
    try {
        $script:DockerVersion = (docker --version 2>&1) -join ''
        try {
            docker info 2>&1 | Out-Null
            $script:DockerRunning = 'running'
        } catch {
            $script:DockerRunning = 'installed but not running'
        }
    } catch { }
}

function Show-Environment {
    Write-Host ''
    Write-Host '  Environment' -ForegroundColor White
    Write-Host '  ──────────────────────────────────────'
    Write-Host "  Platform     " -NoNewline; Write-Host "Windows/$env:PROCESSOR_ARCHITECTURE" -ForegroundColor White

    if ($script:PythonVersion) {
        Write-Host "  Python       " -NoNewline; Write-Host $script:PythonVersion -ForegroundColor Green
    } else {
        Write-Host "  Python       " -NoNewline; Write-Host "not found (3.11+ required)" -ForegroundColor Red
    }

    if ($script:GitVersion) {
        Write-Host "  Git          " -NoNewline; Write-Host $script:GitVersion -ForegroundColor Green
    } else {
        Write-Host "  Git          " -NoNewline; Write-Host "not found" -ForegroundColor DarkGray
    }

    if ($script:DockerVersion) {
        $color = if ($script:DockerRunning -eq 'running') { 'Green' } else { 'Yellow' }
        Write-Host "  Docker       " -NoNewline; Write-Host "$($script:DockerVersion) ($($script:DockerRunning))" -ForegroundColor $color
    } else {
        Write-Host "  Docker       " -NoNewline; Write-Host "not found" -ForegroundColor DarkGray
    }

    Write-Host '  ──────────────────────────────────────'
    Write-Host ''
}

# ---------------------------------------------------------------------------
# PATH management — add venv\Scripts to user PATH via registry
# ---------------------------------------------------------------------------
function Get-UserPath {
    [Environment]::GetEnvironmentVariable('Path', 'User')
}

function Add-ToUserPath {
    param([string]$VenvScripts)

    $currentPath = Get-UserPath
    if ($currentPath -split ';' | Where-Object { $_ -eq $VenvScripts }) {
        return  # already there
    }

    $newPath = "$VenvScripts;$currentPath"
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')

    # Also update current session
    $env:Path = "$VenvScripts;$env:Path"

    Write-Ok "Added to user PATH: $VenvScripts"
}

# ---------------------------------------------------------------------------
# Confirmation prompt
# ---------------------------------------------------------------------------
function Confirm-Proceed {
    param([string]$VenvScripts)

    if ($Yes) { return }

    Write-Host '  This will:'
    Write-Host '    1. Scan the current directory for container artifacts'

    if (-not $NoInstall) {
        Write-Host "    2. Install CascadeGuard to " -NoNewline
        Write-Host $CascadeGuardHome -ForegroundColor White
        Write-Host "    3. Add " -NoNewline
        Write-Host $VenvScripts -ForegroundColor White -NoNewline
        Write-Host " to your user PATH"
        Write-Host ''
        Write-Host '  Use -NoInstall to scan without keeping anything.' -ForegroundColor DarkGray
    } else {
        Write-Host '    2. Use a temporary environment (cleaned up after)'
        Write-Host ''
        Write-Host '  Nothing will be saved to disk.' -ForegroundColor DarkGray
    }

    Write-Host ''
    $answer = Read-Host '  Proceed? [Y/n]'
    if ($answer -match '^[nN]') {
        Write-Info 'Cancelled.'
        exit 0
    }
    Write-Host ''
}

# ---------------------------------------------------------------------------
# Build scan arguments
# ---------------------------------------------------------------------------
function Get-ScanArgs {
    $args = @('scan')
    if ($Dir)            { $args += '--dir';    $args += $Dir }
    if ($NonInteractive) { $args += '--non-interactive' }
    if ($Format)         { $args += '--format'; $args += $Format }
    if ($Output)         { $args += '--output'; $args += $Output }
    return $args
}

# ---------------------------------------------------------------------------
# Persistent install
# ---------------------------------------------------------------------------
function Install-Persistent {
    $venvDir     = Join-Path $CascadeGuardHome 'venv'
    $venvScripts = Join-Path $venvDir 'Scripts'
    $cgExe       = Join-Path $venvScripts 'cascadeguard.exe'
    $pipExe      = Join-Path $venvScripts 'pip.exe'

    Confirm-Proceed -VenvScripts $venvScripts

    $pipSpec = "cascadeguard-tool @ git+${CascadeGuardRepo}@${CascadeGuardBranch}#subdirectory=app"

    if (Test-Path $cgExe) {
        Write-Info 'Existing installation found, upgrading...'
        & $pipExe install --quiet --disable-pip-version-check --upgrade $pipSpec
        Write-Ok 'Upgraded cascadeguard-tool'
    } else {
        Write-Info "Installing to $CascadeGuardHome..."
        New-Item -ItemType Directory -Path $CascadeGuardHome -Force | Out-Null
        & $script:PythonCmd -m venv $venvDir
        & $pipExe install --quiet --disable-pip-version-check $pipSpec
        Write-Ok "Installed cascadeguard-tool to $CascadeGuardHome"
    }

    Add-ToUserPath -VenvScripts $venvScripts

    $scanArgs = Get-ScanArgs
    Write-Info "Running: cascadeguard $($scanArgs -join ' ')"
    Write-Host ''
    & $cgExe @scanArgs
}

# ---------------------------------------------------------------------------
# One-shot scan
# ---------------------------------------------------------------------------
function Install-OneShot {
    $tmpDir      = Join-Path ([System.IO.Path]::GetTempPath()) "cascadeguard-$(Get-Random)"
    $venvDir     = Join-Path $tmpDir 'venv'
    $venvScripts = Join-Path $venvDir 'Scripts'
    $pipExe      = Join-Path $venvScripts 'pip.exe'
    $cgExe       = Join-Path $venvScripts 'cascadeguard.exe'

    Confirm-Proceed -VenvScripts $venvScripts

    try {
        Write-Info 'Creating temporary environment...'
        & $script:PythonCmd -m venv $venvDir

        Write-Info "Installing cascadeguard from GitHub ($CascadeGuardBranch)..."
        $pipSpec = "cascadeguard-tool @ git+${CascadeGuardRepo}@${CascadeGuardBranch}#subdirectory=app"
        & $pipExe install --quiet --disable-pip-version-check $pipSpec

        Write-Ok 'Installed cascadeguard-tool (temporary)'

        $scanArgs = Get-ScanArgs
        Write-Info "Running: cascadeguard $($scanArgs -join ' ')"
        Write-Host ''
        & $cgExe @scanArgs
    } finally {
        if (Test-Path $tmpDir) {
            Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '  CascadeGuard' -ForegroundColor White -NoNewline
Write-Host ' — Repository Scanner'
Write-Host '  https://cascadeguard.com'

Find-Python | Out-Null
Find-Git
Find-Docker
Show-Environment

if (-not $script:PythonCmd) {
    Stop-Script "Python ${MinPythonMajor}.${MinPythonMinor}+ is required. Install from https://python.org"
}

if ($NoInstall) {
    Install-OneShot
} else {
    Install-Persistent
}
