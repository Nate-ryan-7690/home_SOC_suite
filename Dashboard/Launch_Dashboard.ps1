# ============================================================
# Launch_Dashboard.ps1 — Night's Watch SOC Dashboard Launcher
# Run via desktop shortcut (set to Run as Administrator)
# Starts Flask if not already running, then opens browser
# ============================================================

# ============================================================
# USER CONFIGURATION
# ============================================================

# DashboardPath is auto-detected from the script location. The launcher
# always starts the dashboard it lives next to, so it cannot mispoint.
$DashboardPath = $PSScriptRoot
$RootPath      = Split-Path -Parent $DashboardPath

# Python executable. Two options:
#   1. Full path (recommended — survives PATH issues when running elevated):
#      "$env:USERPROFILE\AppData\Local\Programs\Python\Python3XX\python.exe"
#      Replace Python3XX with your installed version folder (e.g. Python313)
#   2. Just "python" if Python is reliably in your elevated session PATH
$PythonExe     = "$env:USERPROFILE\AppData\Local\Programs\Python\Python312\python.exe"

# Dashboard port — must match DASHBOARD_PORT in app.py
$Port          = 7001

# ============================================================
# DO NOT EDIT BELOW THIS LINE
# ============================================================
$URL           = "http://127.0.0.1:$Port"

$LogFile = "$RootPath\Logs\Dashboard_Launch.log"
function Log($msg) { "$(Get-Date -Format 'HH:mm:ss') $msg" | Add-Content $LogFile }
Log "Launcher started (root: $RootPath)"

# ── Check if Flask already running on dev port ──────────────────
$already = $false
try {
    Invoke-WebRequest -Uri $URL -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop | Out-Null
    $already = $true
} catch {}

if (-not $already) {
    Log "Flask not running — starting: $PythonExe"
    Start-Process $PythonExe -ArgumentList "app.py" `
        -WorkingDirectory $DashboardPath `
        -WindowStyle Minimized

    # Poll until Flask responds (up to 15 seconds)
    $ready = $false
    for ($i = 0; $i -lt 15; $i++) {
        Start-Sleep -Seconds 1
        try {
            Invoke-WebRequest -Uri $URL -UseBasicParsing -TimeoutSec 1 -ErrorAction Stop | Out-Null
            $ready = $true
            break
        } catch {}
    }

    if (-not $ready) {
        Log "Flask did not respond within 15 seconds"
        exit 1
    }
    Log "Flask ready"
} else {
    Log "Flask already running"
}

# ── Open dashboard in default browser ───────────────────────────
Log "Opening browser: $URL"
Start-Process $URL
