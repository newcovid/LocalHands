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
#  1. Kill whatever is listening on the port
# --------------------------------------------------------------------------- #
$killed = @()
try {
    foreach ($c in (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) {
        if ($c.OwningProcess) {
            try { Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue; $killed += $c.OwningProcess } catch {}
        }
    }
} catch {}

if ($killed.Count -eq 0) {
    $line = (netstat -ano | Select-String ":$Port\s.*LISTENING" | Select-Object -First 1)
    if ($line) {
        $procId = ($line -split '\s+')[-1].Trim()
        if ($procId -match '^\d+$') {
            try { Stop-Process -Id ([int]$procId) -Force -ErrorAction SilentlyContinue; $killed += $procId } catch {}
        }
    }
}

# The daemon stops its tunnel on a clean exit, but Stop-Process -Force skips that
# cleanup, so sweep up anything the kill above orphaned.
$strayTunnels = @()
foreach ($name in 'ngrok', 'cloudflared') {
    Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
        try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue; $strayTunnels += "$name/$($_.Id)" } catch {}
    }
}

# Wait for the port to actually be released rather than guessing with a sleep.
$released = $false
for ($i = 0; $i -lt 20; $i++) {
    if (-not (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)) { $released = $true; break }
    Start-Sleep -Milliseconds 250
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
$healthy = $false
$lastErr = ''
for ($i = 0; $i -lt 120; $i++) {
    Start-Sleep -Milliseconds 500
    if ($proc.HasExited) { $lastErr = "process exited early with code $($proc.ExitCode)"; break }
    try {
        if ((Invoke-WebRequest -Uri $HealthUrl -TimeoutSec 3 -UseBasicParsing).StatusCode -eq 200) { $healthy = $true; break }
    } catch { $lastErr = $_.Exception.Message }
}

# --------------------------------------------------------------------------- #
#  4. Report honestly
# --------------------------------------------------------------------------- #
$lines = @(
    "status        = $(if ($healthy) { 'HEALTHY' } else { 'FAILED' })",
    "at            = $(Get-Date -Format 'o')",
    "root          = $Root",
    "python        = $python",
    "port          = $Port",
    "killed_pids   = $($killed -join ',')",
    "killed_tunnels= $($strayTunnels -join ',')",
    "port_released = $released",
    "new_pid       = $($proc.Id)"
)
if (-not $healthy) {
    $lines += "last_error    = $lastErr"
    $lines += '--- runtime.err.log (tail) ---'
    $lines += (Get-Content $ErrLog -Tail 30 -ErrorAction SilentlyContinue)
    $lines += '--- runtime.log (tail) ---'
    $lines += (Get-Content $OutLog -Tail 30 -ErrorAction SilentlyContinue)
}

Set-Content -Path $StatusFile -Value ($lines -join "`n") -Encoding UTF8
$lines -join "`n"

if ($healthy) { exit 0 } else { exit 1 }
