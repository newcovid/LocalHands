# LocalHands — restart the daemon (and its tunnel) and verify it is really serving.
#
# Paths are derived from this script's own location, so moving or renaming the
# repository does not break it.
#
# Exit code: 0 = daemon healthy, 1 = restart failed (details in var/logs/restart.txt).

$ErrorActionPreference = 'Continue'

$Root       = Split-Path -Parent $PSScriptRoot
$LogDir     = Join-Path $Root 'var\logs'
$OutLog     = Join-Path $LogDir 'runtime.log'
$ErrLog     = Join-Path $LogDir 'runtime.err.log'
$StatusFile = Join-Path $LogDir 'restart.txt'
$ConfigFile = Join-Path $Root 'config.yaml'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# Read the port out of the config rather than hard-coding it, so a config change
# cannot leave this script killing and probing the wrong thing.
$Port = 8765
$portLine = Select-String -Path $ConfigFile -Pattern '^\s*port:\s*(\d+)' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($portLine) { $Port = [int]$portLine.Matches[0].Groups[1].Value }
$HealthUrl = "http://127.0.0.1:$Port/health"

# Give the caller's transport (an in-flight run_bash call, say) time to return
# before we kill the daemon that is serving it.
Start-Sleep -Seconds 3

# --------------------------------------------------------------------------- #
#  0. Helpers
# --------------------------------------------------------------------------- #

# Stop-Process cannot kill a process running at a higher integrity level than
# the caller — an elevated shell's daemon is out of reach of this script run
# from a Limited scheduled task. -ErrorAction SilentlyContinue hides that, so
# confirm the process is actually gone instead of trusting the call.
function Stop-ProcessVerified {
    param([int]$ProcessId)

    Stop-Process -Id $ProcessId -Force -ErrorAction SilentlyContinue
    for ($i = 0; $i -lt 12; $i++) {
        if (-not (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

# The venv's python.exe re-execs the real interpreter, so the process that ends
# up holding the port is a *child* of the one Start-Process returned. Comparing
# PIDs directly would never match; walk up the parent chain instead.
function Test-PortServedBy {
    param([int]$Port, [int]$RootPid)

    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $conn) { return $false }

    $current = [int]$conn.OwningProcess
    for ($depth = 0; $depth -lt 5; $depth++) {
        if ($current -eq $RootPid) { return $true }
        $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$current" -ErrorAction SilentlyContinue
        if (-not $proc) { return $false }
        $current = [int]$proc.ParentProcessId
        if ($current -le 0) { return $false }
    }
    return $false
}

# --------------------------------------------------------------------------- #
#  1. Kill whatever is listening on the port
# --------------------------------------------------------------------------- #
$killed = @()
$failedKills = @()

$listenerPids = @()
try {
    $listenerPids = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
                      Where-Object { $_.OwningProcess } |
                      ForEach-Object { [int]$_.OwningProcess })
} catch {}

if ($listenerPids.Count -eq 0) {
    $line = (netstat -ano | Select-String ":$Port\s.*LISTENING" | Select-Object -First 1)
    if ($line) {
        $procId = ($line -split '\s+')[-1].Trim()
        if ($procId -match '^\d+$') { $listenerPids = @([int]$procId) }
    }
}

foreach ($procId in ($listenerPids | Select-Object -Unique)) {
    if (Stop-ProcessVerified -ProcessId $procId) { $killed += $procId } else { $failedKills += $procId }
}

# The daemon stops its tunnel on a clean exit, but Stop-Process -Force skips that
# cleanup, so sweep up anything the kill above orphaned.
$strayTunnels = @()
foreach ($name in 'ngrok', 'cloudflared') {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
        if (Stop-ProcessVerified -ProcessId $_.Id) { $strayTunnels += "$name/$($_.Id)" }
        else { $failedKills += "$name/$($_.Id)" }
    }
}

# Wait for the port to actually be released rather than guessing with a sleep.
$released = $false
for ($i = 0; $i -lt 20; $i++) {
    if (-not (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) { $released = $true; break }
    Start-Sleep -Milliseconds 250
}

# Relaunching now would start a daemon that cannot bind, exits, and leaves the
# old one answering /health — a restart that reports success while changing
# nothing. Stop here instead, while the reason is still obvious.
if (-not $released) {
    $lines = @(
        "status        = FAILED",
        "at            = $(Get-Date -Format 'o')",
        "root          = $Root",
        "port          = $Port",
        "killed_pids   = $($killed -join ',')",
        "failed_kills  = $($failedKills -join ',')",
        "port_released = False",
        "last_error    = Port $Port is still held after the kill sweep; the old daemon is still serving.",
        "hint          = A process at a higher integrity level cannot be stopped from here. Re-run this script from the same elevation that started the daemon, or stop it by hand."
    )
    Set-Content -Path $StatusFile -Value ($lines -join "`n") -Encoding UTF8
    $lines -join "`n"
    exit 1
}

# --------------------------------------------------------------------------- #
#  2. Relaunch, detached
# --------------------------------------------------------------------------- #
Set-Location $Root

# Prefer the project virtualenv, where the pinned mcp 2.x lives, but stay
# runnable on a bare interpreter.
$venvPython = Join-Path $Root '.venv\Scripts\python.exe'
$python = if (Test-Path $venvPython) { $venvPython } else { 'python' }

# Truncate so the status report below shows only this run.
Set-Content -Path $OutLog -Value '' -Encoding UTF8
Set-Content -Path $ErrLog -Value '' -Encoding UTF8

$proc = Start-Process -FilePath $python `
    -ArgumentList '-m', 'localhands', '--config', 'config.yaml' `
    -WindowStyle Hidden `
    -RedirectStandardOutput $OutLog `
    -RedirectStandardError $ErrLog `
    -PassThru

# --------------------------------------------------------------------------- #
#  3. Verify it is serving — poll /health, never assume
# --------------------------------------------------------------------------- #
# Generous budget: when the daemon also brings up a tunnel, that handshake
# happens before uvicorn binds, so the first response can be tens of seconds out.
#
# A 200 from /health is necessary but not sufficient: any daemon still holding
# the port answers it, including one this script failed to stop. Requiring the
# listener to belong to the process tree just started is what distinguishes
# "restarted" from "never actually restarted".
$healthy = $false
$servedByNew = $false
$lastErr = ''
for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Milliseconds 500
    if ($proc.HasExited) { $lastErr = "process exited early with code $($proc.ExitCode)"; break }
    try {
        if ((Invoke-WebRequest -Uri $HealthUrl -TimeoutSec 3 -UseBasicParsing).StatusCode -eq 200) {
            $healthy = $true
            $servedByNew = Test-PortServedBy -Port $Port -RootPid $proc.Id
            if ($servedByNew) { break }
            $lastErr = "/health answers, but port $Port is held by a process outside the tree just started."
        }
    } catch { $lastErr = $_.Exception.Message }
}
$ok = $healthy -and $servedByNew

# --------------------------------------------------------------------------- #
#  4. Report honestly
# --------------------------------------------------------------------------- #
# The listener PID is reported alongside new_pid because the venv's python.exe
# re-execs: the process actually serving is a child of the one started here.
$listenerPid = (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
                Select-Object -First 1 -ExpandProperty OwningProcess)

$lines = @(
    "status        = $(if ($ok) { 'HEALTHY' } else { 'FAILED' })",
    "at            = $(Get-Date -Format 'o')",
    "root          = $Root",
    "python        = $python",
    "port          = $Port",
    "killed_pids   = $($killed -join ',')",
    "killed_tunnels= $($strayTunnels -join ',')",
    "failed_kills  = $($failedKills -join ',')",
    "port_released = $released",
    "new_pid       = $($proc.Id)",
    "listener_pid  = $listenerPid",
    "served_by_new = $servedByNew"
)
if (-not $ok) {
    $lines += "last_error    = $lastErr"
    $lines += '--- runtime.err.log (tail) ---'
    $lines += (Get-Content $ErrLog -Tail 30 -ErrorAction SilentlyContinue)
    $lines += '--- runtime.log (tail) ---'
    $lines += (Get-Content $OutLog -Tail 30 -ErrorAction SilentlyContinue)
}

Set-Content -Path $StatusFile -Value ($lines -join "`n") -Encoding UTF8
$lines -join "`n"

if ($ok) { exit 0 } else { exit 1 }
