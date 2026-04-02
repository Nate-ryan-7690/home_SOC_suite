# ============================================================
# DoH_Detector.ps1 -- DNS-over-HTTPS Evasion Detector
# Part of Home SOC Suite -- Phase 6
#
# Detects non-whitelisted processes establishing HTTPS
# connections to known DNS-over-HTTPS resolver IPs on port 443.
# Uses connection lifecycle tracking: logs on appearance and
# disappearance only -- no poll-cycle spam.
# ============================================================

chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# ============================================================
$RootPath      = "$env:USERPROFILE\Desktop\SOC"
$LogFile       = "$RootPath\Logs\DoHDetector_Log.txt"
$ArchiveFolder = "$RootPath\Logs\Archives"
$HealthFile    = "$RootPath\Config\DoHDetector_Health.json"

$PollInterval  = 5     # Seconds between connection polls
$DoHPort       = 443   # Standard DoH port (HTTPS)

# Known public DoH resolver IPs
# Includes global providers and EU/DACH-specific resolvers
$DoHResolvers = @(
    # Cloudflare
    "1.1.1.1", "1.0.0.1",
    "2606:4700:4700::1111", "2606:4700:4700::1001",
    # Google
    "8.8.8.8", "8.8.4.4",
    "2001:4860:4860::8888", "2001:4860:4860::8844",
    # Quad9 (Swiss-based, popular in DACH)
    "9.9.9.9", "149.112.112.112",
    "2620:fe::fe", "2620:fe::9",
    # OpenDNS / Cisco Umbrella
    "208.67.222.222", "208.67.220.220",
    # AdGuard
    "176.103.130.130", "176.9.93.198",
    "94.140.14.14",   "94.140.15.15",
    # CleanBrowsing
    "185.228.168.9", "185.228.169.9",
    # Comodo Secure DNS
    "8.26.56.26", "8.20.247.20",
    # Verisign
    "64.6.64.6", "64.6.65.6",
    # DNS.watch (Germany)
    "84.200.69.80", "84.200.70.40",
    # Digitalcourage e.V. (German privacy NGO)
    "46.182.19.48",
    # Freifunk München (German community)
    "5.1.66.255"
)

# Zero-Trust: empty until 30-day baseline analysis confirms expected processes
# Populate after first month with verified legitimate DoH processes
$AllowedDoHProcesses = @()

# ============================================================
# FUNCTIONS
# ============================================================

function Write-Log($Severity, $Message) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Timestamp] [$Severity] $Message" | Out-File $LogFile -Append -Encoding UTF8
}

function Get-SeverityColor($Severity) {
    switch ($Severity) {
        "OK"         { return "Green" }
        "UNKNOWN"    { return "Yellow" }
        "SUSPICIOUS" { return "DarkYellow" }
        "CRITICAL"   { return "Red" }
        default      { return "White" }
    }
}

function Get-ProcessPath($ProcId) {
    try {
        $P    = Get-Process -Id $ProcId -ErrorAction Stop
        $Path = $P.MainModule.FileName
        if (-not [string]::IsNullOrWhiteSpace($Path)) { return $Path }
    } catch {}
    try {
        $WmiP = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcId" -ErrorAction Stop
        if (-not [string]::IsNullOrWhiteSpace($WmiP.ExecutablePath)) { return $WmiP.ExecutablePath }
    } catch {}
    return "PATH_UNAVAILABLE"
}

# ============================================================
# LOG ROTATION
# ============================================================
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) {
            New-Item -ItemType Directory -Path $ArchiveFolder | Out-Null
        }
        $ArchiveName = "DoHDetector_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# ============================================================
# INITIALIZE LOG
# ============================================================
if (-not (Test-Path $LogFile)) {
    "--- DOH DETECTOR STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- MONITORING: DNS-over-HTTPS Evasion | Port 443 to Known Resolvers ---`n" | Out-File $LogFile -Append -Encoding UTF8
}

# ============================================================
# STARTUP
# ============================================================
Write-Host "--- [DOH DETECTOR | INITIALIZING] ---" -ForegroundColor Cyan
Write-Host "[OK] Watching $($DoHResolvers.Count) known DoH resolver IPs on port $DoHPort." -ForegroundColor Green
Write-Host "[OK] Process whitelist: EMPTY (Zero-Trust -- populate after 30-day baseline)." -ForegroundColor Green
Write-Log "OK" "DoH Detector started. Watching $($DoHResolvers.Count) resolver IPs. Process whitelist empty."

# ============================================================
# STARTUP AUDIT -- SCAN EXISTING CONNECTIONS
# Seeds $TrackedConnections so existing connections do not
# double-log on the first poll cycle.
# ============================================================
Write-Host "[*] Scanning for active DoH connections at startup..." -ForegroundColor Cyan

# Key: "PID|RemoteIP"  Value: connection metadata hashtable
$TrackedConnections = @{}
$EventCount         = 0
$ScriptStartTime    = Get-Date
$CycleCount         = 0

try {
    $StartupConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Where-Object { $_.RemoteAddress -in $DoHResolvers -and $_.RemotePort -eq $DoHPort }

    if (-not $StartupConns) {
        Write-Host "[OK] No active DoH connections at startup." -ForegroundColor Green
        Write-Log "OK" "STARTUP_AUDIT: No active DoH connections found."
    } else {
        foreach ($C in $StartupConns) {
            $ProcId  = $C.OwningProcess
            $Proc    = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
            $PName   = if ($Proc) { $Proc.Name } else { "UNKNOWN(PID=$ProcId)" }
            $PPath   = Get-ProcessPath $ProcId
            $ConnKey = "$ProcId|$($C.RemoteAddress)"

            $TrackedConnections[$ConnKey] = @{
                ProcessName = $PName
                ProcessPath = $PPath
                PID         = $ProcId
                RemoteIP    = $C.RemoteAddress
                LocalPort   = $C.LocalPort
                DetectedAt  = Get-Date
            }

            $Severity = if ($AllowedDoHProcesses -contains $PName.ToLower()) { "UNKNOWN" } else { "CRITICAL" }
            $Message  = "DOH_CONN_AT_STARTUP: Process=$PName | Path=$PPath | PID=$ProcId | Resolver=$($C.RemoteAddress) | LocalPort=$($C.LocalPort)"

            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] [$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
            Write-Log $Severity $Message
            $EventCount++
        }
    }
} catch {
    Write-Host "[UNKNOWN] Startup audit failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Log "UNKNOWN" "Startup audit failed: $($_.Exception.Message)"
}

$HeartbeatAt = (Get-Date).AddSeconds(60)

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "doh_detector"
})
$HeartbeatRS = [RunspaceFactory]::CreateRunspace()
$HeartbeatRS.Open()
$HeartbeatPS = [PowerShell]::Create()
$HeartbeatPS.Runspace = $HeartbeatRS
$HeartbeatPS.AddScript({
    param($S)
    while ($S.Running) {
        $Uptime = (Get-Date) - $S.ScriptStartTime
        @{ collector=$S.CollectorName; timestamp=(Get-Date -Format "yyyy-MM-dd HH:mm:ss"); status="ACTIVE"; uptime="$([math]::Floor($Uptime.TotalHours))h$($Uptime.Minutes)m$($Uptime.Seconds)s"; cycle=$S.CycleCount } | ConvertTo-Json -Compress | Out-File $S.HealthFile -Encoding UTF8
        Start-Sleep -Seconds 5
    }
}).AddArgument($SharedState) | Out-Null
$HeartbeatPS.BeginInvoke() | Out-Null

Write-Host "--- [MONITORING STARTED | Poll every ${PollInterval}s] ---`n" -ForegroundColor Cyan

# ============================================================
# MAIN MONITORING LOOP
# ============================================================
while ($true) {
    $CycleCount++
    $SharedState.CycleCount = $CycleCount
    $Now    = Get-Date
    $NowStr = $Now.ToString("HH:mm:ss")

    # --- HEARTBEAT ---
    if ($Now -ge $HeartbeatAt) {
        Write-Host "[$NowStr] Monitoring active | Events: $EventCount | Active DoH connections tracked: $($TrackedConnections.Count)"
        $HeartbeatAt = $Now.AddSeconds(60)
    }

    # --------------------------------------------------------
    # POLL CURRENT DOH CONNECTIONS
    # --------------------------------------------------------
    try {
        $CurrentConns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Where-Object { $_.RemoteAddress -in $DoHResolvers -and $_.RemotePort -eq $DoHPort }

        # Build current key set
        $CurrentKeys = @{}
        foreach ($C in $CurrentConns) {
            $ConnKey = "$($C.OwningProcess)|$($C.RemoteAddress)"
            $CurrentKeys[$ConnKey] = $C
        }

        # --- NEW CONNECTIONS (in current, not in tracked) ---
        foreach ($Key in $CurrentKeys.Keys) {
            if (-not $TrackedConnections.ContainsKey($Key)) {
                $C      = $CurrentKeys[$Key]
                $ProcId = $C.OwningProcess
                $Proc   = Get-Process -Id $ProcId -ErrorAction SilentlyContinue
                $PName  = if ($Proc) { $Proc.Name } else { "UNKNOWN(PID=$ProcId)" }
                $PPath  = Get-ProcessPath $ProcId

                $TrackedConnections[$Key] = @{
                    ProcessName = $PName
                    ProcessPath = $PPath
                    PID         = $ProcId
                    RemoteIP    = $C.RemoteAddress
                    LocalPort   = $C.LocalPort
                    DetectedAt  = $Now
                }

                $Severity = if ($AllowedDoHProcesses -contains $PName.ToLower()) { "UNKNOWN" } else { "CRITICAL" }
                $Message  = "DOH_CONN_NEW: Process=$PName | Path=$PPath | PID=$ProcId | Resolver=$($C.RemoteAddress) | LocalPort=$($C.LocalPort)"

                Write-Host "[$NowStr] [$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
                Write-Log $Severity $Message
                $EventCount++
            }
        }

        # --- ENDED CONNECTIONS (in tracked, not in current) ---
        $EndedKeys = @($TrackedConnections.Keys | Where-Object { -not $CurrentKeys.ContainsKey($_) })
        foreach ($Key in $EndedKeys) {
            $Meta     = $TrackedConnections[$Key]
            $Duration = [Math]::Round(($Now - $Meta.DetectedAt).TotalSeconds)
            $Message  = "DOH_CONN_ENDED: Process=$($Meta.ProcessName) | PID=$($Meta.PID) | Resolver=$($Meta.RemoteIP) | Duration=${Duration}s"

            Write-Log "OK" $Message
            $TrackedConnections.Remove($Key)
            $EventCount++
        }

    } catch {
        # Never crash the main loop
    }

    Start-Sleep -Seconds $PollInterval
}
