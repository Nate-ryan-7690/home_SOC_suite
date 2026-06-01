# ============================================================
# Launch_Dashboard.ps1 — Night's Watch SOC Dashboard Launcher
# Run via desktop shortcut (set to Run as Administrator)
# Starts Flask if not already running, then opens browser
# ============================================================

# ============================================================
# USER CONFIGURATION
# ============================================================

# SOC install path — change if installed outside Desktop\SOC
$DashboardPath = "$env:USERPROFILE\Desktop\SOC\Dashboard"

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

# Safety guard: abort if not pointing at the dev folder
if ($DashboardPath -notmatch 'SOC') {
    Write-Host "ERROR: DashboardPath does not point to SOC. Launcher aborted."
    exit 1
}

$LogFile = "$env:USERPROFILE\Desktop\SOC\Logs\Dashboard_Launch.log"
function Log($msg) { "$(Get-Date -Format 'HH:mm:ss') $msg" | Add-Content $LogFile }
Log "Launcher started"

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
