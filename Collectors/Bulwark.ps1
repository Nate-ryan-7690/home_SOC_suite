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
$IPCache = @{}

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

function Write-Log($Severity, $Message) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Entry = "[$Timestamp] [$Severity] $Message"
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

# --- WHITELIST ---
# Add known process+country combinations here after your baseline month
# Format: "ProcessName" = @("Country1", "Country2")
$Whitelist = @{}

# --- MAIN MONITORING LOOP ---
while ($true) {
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
            $Message = "PORT OPENED: $Port | Process: $PName | Path: $PPath"
            Write-Host "[PORT OPEN] $Message" -ForegroundColor Yellow
            Write-Log "PORT OPEN" $Message
            # Add to baseline so it only logs once
            $BaselinePorts[$Port] = $CurrentPorts[$Port]
        }
    }

    # Check for closed ports
    foreach ($Port in @($BaselinePorts.Keys)) {
        if (-not $CurrentPorts.ContainsKey($Port)) {
            $PName = $BaselinePorts[$Port].Name
            $Message = "PORT CLOSED: $Port | Process: $PName"
            Write-Host "[PORT CLOSE] $Message" -ForegroundColor DarkGray
            Write-Log "PORT CLOSE" $Message
            $BaselinePorts.Remove($Port)
        }
    }

    # Display current ports
    foreach ($Port in ($CurrentPorts.Keys | Sort-Object)) {
        $PName = $CurrentPorts[$Port].Name
        Write-Host "Port: $($Port.ToString().PadRight(6)) | Process: $PName" -ForegroundColor DarkGray
    }

    # --- SECTION 2: GEOLOCATION ANOMALY DETECTION ---
    Write-Host "`n--- [SECTION 2: CONNECTION ANOMALY MONITOR] ---" -ForegroundColor Cyan

    $Conns = Get-NetTCPConnection -State Established | Where-Object {
        $_.RemoteAddress -notlike "127.0.0.1" -and
        $_.RemoteAddress -notlike "192.168.*" -and
        $_.RemoteAddress -notlike "10.*" -and
        $_.RemoteAddress -notlike "0.0.0.0" -and
	$_.RemoteAddress -notlike "fe80::" -and
        $_.RemoteAddress -ne "::1" -and
        $_.RemoteAddress -notlike "fc00::*" -and
        $_.RemoteAddress -notlike "fd::" -and
	$_.RemoteAddress -ne "::"
	
    }

    foreach ($C in $Conns) {
        $R_IP = $C.RemoteAddress
        $Proc = Get-Process -Id $C.OwningProcess -ErrorAction SilentlyContinue
        $PName = if ($Proc) { $Proc.Name.ToLower() } else { "unknown" }
        $PPath = if ($Proc) { $Proc.Path } else { "System/Protected" }
        $Loc = Get-GeoLocation $R_IP
        $Country = if ($Loc -match ",\s*(\w+)$") { $Matches[1] } else { "Unknown" }

        # Determine severity
        if ($Whitelist.ContainsKey($PName)) {
            if ($Whitelist[$PName] -contains $Country) {
                $Severity = "OK"
            } else {
                $Severity = "CRITICAL"
                $Message = "WHITELIST ANOMALY: $PName -> $Loc | Expected: $($Whitelist[$PName] -join ', ') | Path: $PPath"
                Write-Log "CRITICAL" $Message
            }
        } else {
            if ($Country -eq "Unknown") {
                $Severity = "SUSPICIOUS"
                $Message = "UNKNOWN PROCESS + UNKNOWN LOCATION: $PName -> $R_IP | Path: $PPath"
                Write-Log "SUSPICIOUS" $Message
            } else {
                $Severity = "UNKNOWN"
            }
        }

        $Color = Get-SeverityColor $Severity
        Write-Host "[$Severity] App: $($PName.PadRight(15)) | Loc: $($Loc.PadRight(20)) | Port: $($C.RemotePort)" -ForegroundColor $Color
        Write-Host "Path: $PPath" -ForegroundColor DarkGray
        Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    }

    Write-Host "`nNext scan in 5 seconds. Log: $LogFile"
    Start-Sleep -Seconds 5
}