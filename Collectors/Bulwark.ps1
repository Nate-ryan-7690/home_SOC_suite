# ============================================================
# BULWARK.ps1 - Inbound Port Monitor
# Part of Home SOC Suite
# ============================================================

# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC — change this if you installed elsewhere
# ============================================================
$RootPath = "$env:USERPROFILE\Desktop\SOC"
$LogFile = "$RootPath\Logs\Bulwark_Log.txt"
$ArchiveFolder = "$RootPath\Logs\Archives"
$HealthFile = "$RootPath\Config\Bulwark_Health.json"
$IPCache = @{}
$ConnectionTracker = @{}

# --- FUNCTIONS ---
function Get-GeoLocation($IP) {
    if ($IPCache.ContainsKey($IP)) { return $IPCache[$IP] }
    try {
        $G = Invoke-RestMethod -Uri "http://ip-api.com/json/$IP" -Method Get
        $Location = if ($G.status -eq "success") { "$($G.city), $($G.countryCode)" } else { "Unknown" }
    } catch { $Location = "Lookup Failed" }
    $IPCache[$IP] = $Location
    return $Location
}

function Get-PortProcess($Port) {
    $Conn = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($Conn) {
        $Proc = Get-Process -Id $Conn.OwningProcess -ErrorAction SilentlyContinue
        return @{
            Name = if ($Proc) { $Proc.Name } else { "System/Unknown" }
            Path = if ($Proc) { $Proc.Path } else { "System/Protected" }
            PID  = if ($Conn) { $Conn.OwningProcess } else { "Unknown" }
        }
    }
    return @{ Name = "Unknown"; Path = "Unknown"; PID = "Unknown" }
}

function Write-Log($Severity, $Message, $Path) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$Timestamp] [$Severity] $Message | Path: $Path"
    $Entry | Out-File $LogFile -Append
}

function Get-SeverityColor($Severity) {
    switch ($Severity) {
        "OK"         { return "Green" }
        "UNKNOWN"    { return "Yellow" }
        "SUSPICIOUS" { return "DarkYellow" }
        "CRITICAL"   { return "Red" }
        "PORT OPEN"  { return "Yellow" }
        "PORT CLOSE" { return "DarkGray" }
        default      { return "White" }
    }
}

# --- LOG ROTATION ---
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) { New-Item -ItemType Directory -Path $ArchiveFolder }
        $ArchiveName = "Bulwark_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# --- INITIALIZE LOG ---
if (-not (Test-Path $LogFile)) {
    "--- BULWARK LOG STARTED: $(Get-Date) ---" | Out-File $LogFile
    "--- BASELINE SNAPSHOT ---" | Out-File $LogFile -Append
}

# --- BASELINE SNAPSHOT ---
Write-Host "--- [BULWARK | CAPTURING BASELINE] ---" -ForegroundColor Cyan
$BaselinePorts = @{}

Get-NetTCPConnection -State Listen | ForEach-Object {
    $Port = $_.LocalPort
    $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $PName = if ($Proc) { $Proc.Name } else { "System/Unknown" }
    $PPath = if ($Proc) { $Proc.Path } else { "System/Protected" }
    $BaselinePorts[$Port] = @{ Name = $PName; Path = $PPath }
    $Entry = "BASELINE PORT: $Port | Process: $PName | Path: $PPath"
    $Entry | Out-File $LogFile -Append
    Write-Host $Entry -ForegroundColor DarkGray
}

"--- END BASELINE ---" | Out-File $LogFile -Append
"--- MONITORING STARTED: $(Get-Date) ---`n" | Out-File $LogFile -Append
Write-Host "--- [BASELINE CAPTURED | MONITORING STARTED] ---`n" -ForegroundColor Cyan

# --- SEED CONNECTION TRACKER ---
# Pre-populate tracker from existing connections so the first poll
# does not log every active connection as a new CONNECTION_START.
Write-Host "--- [SEEDING CONNECTION TRACKER] ---" -ForegroundColor Cyan
Get-NetTCPConnection -State Established | Where-Object {
    $_.RemoteAddress -notlike "127.0.0.1" -and
    $_.RemoteAddress -notlike "192.168.*" -and
    $_.RemoteAddress -notlike "10.*"       -and
    $_.RemoteAddress -notlike "0.0.0.0"   -and
    $_.RemoteAddress -notlike "fe80::"    -and
    $_.RemoteAddress -ne "::1"            -and
    $_.RemoteAddress -notlike "fc00::*"   -and
    $_.RemoteAddress -notlike "fd::"      -and
    $_.RemoteAddress -ne "::"
} | ForEach-Object {
    $Proc  = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $PName = if ($Proc) { $Proc.Name.ToLower() } else { "unknown" }
    $PPath = if ($Proc) { $Proc.Path } else { "System/Protected" }
    $Key   = "$PName|$($_.RemoteAddress)|$($_.RemotePort)"
    $Loc   = Get-GeoLocation $_.RemoteAddress
    $ConnectionTracker[$Key] = @{
        StartTime = Get-Date
        Cycles    = 0
        Loc       = $Loc
        PPath     = $PPath
        Severity  = "UNKNOWN"
        Seeded    = $true
    }
}
Write-Host "--- [TRACKER SEEDED: $($ConnectionTracker.Count) existing connections] ---`n" -ForegroundColor Cyan

# --- WHITELIST ---
# Add known process+country combinations here after your baseline month
# Format: "ProcessName" = @("Country1", "Country2")
$Whitelist = @{}
$ScriptStartTime = Get-Date
$CycleCount      = 0

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "bulwark"
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

# --- MAIN MONITORING LOOP ---
while ($true) {
    $CycleCount++
    $SharedState.CycleCount = $CycleCount
    Clear-Host
    $Now = Get-Date -Format "HH:mm:ss"
    Write-Host "--- [BULWARK DASHBOARD | $Now] ---" -ForegroundColor Cyan

    # --- SECTION 1: PORT DIFF ---
    Write-Host "`n--- [SECTION 1: PORT MONITOR] ---" -ForegroundColor Cyan
    $CurrentPorts = @{}

    Get-NetTCPConnection -State Listen | ForEach-Object {
        $Port = $_.LocalPort
        $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $PName = if ($Proc) { $Proc.Name } else { "System/Unknown" }
        $PPath = if ($Proc) { $Proc.Path } else { "System/Protected" }
        $CurrentPorts[$Port] = @{ Name = $PName; Path = $PPath }

    }

    # Check for new ports
    foreach ($Port in $CurrentPorts.Keys) {
        if (-not $BaselinePorts.ContainsKey($Port)) {
            $PName = $CurrentPorts[$Port].Name
            $PPath = $CurrentPorts[$Port].Path
            $Message = "PORT OPENED: $Port | Process: $PName"
            Write-Host "[PORT OPEN] $Message" -ForegroundColor Yellow
            Write-Log "PORT OPEN" $Message $PPath
            # Add to baseline so it only logs once
            $BaselinePorts[$Port] = $CurrentPorts[$Port]
        }
    }

    # Check for closed ports
    foreach ($Port in @($BaselinePorts.Keys)) {
        if (-not $CurrentPorts.ContainsKey($Port)) {
            $PName = $BaselinePorts[$Port].Name
            $PPath = $BaselinePorts[$Port].Path
            $Message = "PORT CLOSED: $Port | Process: $PName"
            Write-Host "[PORT CLOSE] $Message" -ForegroundColor DarkGray
            Write-Log "PORT CLOSE" $Message $PPath
            $BaselinePorts.Remove($Port)
        }
    }

    # Display current ports
    foreach ($Port in ($CurrentPorts.Keys | Sort-Object)) {
        $PName = $CurrentPorts[$Port].Name
        Write-Host "Port: $($Port.ToString().PadRight(6)) | Process: $PName" -ForegroundColor DarkGray
    }

    # --- SECTION 2: CONNECTION SESSION TRACKER ---
    Write-Host "`n--- [SECTION 2: CONNECTION SESSION TRACKER] ---" -ForegroundColor Cyan

    $CurrentConns = @{}
    $Conns = Get-NetTCPConnection -State Established | Where-Object {
        $_.RemoteAddress -notlike "127.0.0.1" -and
        $_.RemoteAddress -notlike "192.168.*" -and
        $_.RemoteAddress -notlike "10.*"       -and
        $_.RemoteAddress -notlike "0.0.0.0"   -and
        $_.RemoteAddress -notlike "fe80::"    -and
        $_.RemoteAddress -ne "::1"            -and
        $_.RemoteAddress -notlike "fc00::*"   -and
        $_.RemoteAddress -notlike "fd::"      -and
        $_.RemoteAddress -ne "::"
    }

    foreach ($C in $Conns) {
        $R_IP  = $C.RemoteAddress
        $Proc  = Get-Process -Id $C.OwningProcess -ErrorAction SilentlyContinue
        $PName = if ($Proc) { $Proc.Name.ToLower() } else { "unknown" }
        $PPath = if ($Proc) { $Proc.Path } else { "System/Protected" }
        $Key   = "$PName|$R_IP|$($C.RemotePort)"
        $CurrentConns[$Key] = $true

        if (-not $ConnectionTracker.ContainsKey($Key)) {
            # NEW connection — geolocate once, assess severity, log CONNECTION_START
            $Loc     = Get-GeoLocation $R_IP
            $Country = if ($Loc -match ",\s*(\w+)$") { $Matches[1] } else { "Unknown" }
            $Severity = "UNKNOWN"
            if ($Loc -eq "Lookup Failed") {
                $Severity = "SUSPICIOUS"
            } elseif ($Whitelist.ContainsKey($PName)) {
                $Severity = if ($Whitelist[$PName] -contains $Country) { "OK" } else { "CRITICAL" }
            }
            $Message = "CONNECTION_START: Process=$PName | Remote=$R_IP`:$($C.RemotePort) | Location=$Loc"
            Write-Log $Severity $Message $PPath
            Write-Host "[$Severity] NEW    Process=$($PName.PadRight(15)) | Remote=$R_IP`:$($C.RemotePort) | Location=$Loc" -ForegroundColor (Get-SeverityColor $Severity)
            $ConnectionTracker[$Key] = @{
                StartTime = Get-Date
                Cycles    = 1
                Loc       = $Loc
                PPath     = $PPath
                Severity  = $Severity
                Seeded    = $false
            }
        } else {
            # EXISTING connection — increment cycle counter, display only, no log write
            $ConnectionTracker[$Key].Cycles++
            $Info = $ConnectionTracker[$Key]
            Write-Host "[$($Info.Severity)] ACTIVE Process=$($PName.PadRight(15)) | Remote=$R_IP`:$($C.RemotePort) | Location=$($Info.Loc) | Cycles=$($Info.Cycles)" -ForegroundColor (Get-SeverityColor $Info.Severity)
        }
    }

    # Detect closed connections — log CONNECTION_END with full session data
    foreach ($Key in @($ConnectionTracker.Keys)) {
        if (-not $CurrentConns.ContainsKey($Key)) {
            $Info    = $ConnectionTracker[$Key]
            $Elapsed = [int]((Get-Date) - $Info.StartTime).TotalSeconds
            $Parts   = $Key -split '\|'
            $Message = "CONNECTION_END: Process=$($Parts[0]) | Remote=$($Parts[1]):$($Parts[2]) | Location=$($Info.Loc) | Cycles=$($Info.Cycles) | Duration=$([int]($Elapsed/60))m$($Elapsed%60)s | Started=$($Info.StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            if (-not $Info.Seeded) {
                Write-Log "OK" $Message $Info.PPath
            }
            Write-Host "[OK] CLOSED Process=$($Parts[0]) | Remote=$($Parts[1]):$($Parts[2]) | Duration=$([int]($Elapsed/60))m$($Elapsed%60)s | Cycles=$($Info.Cycles)" -ForegroundColor DarkGray
            $ConnectionTracker.Remove($Key)
        }
    }

    Write-Host "`nNext scan in 5 seconds. Log: $LogFile"
    Start-Sleep -Seconds 5
}