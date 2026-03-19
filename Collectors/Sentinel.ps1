# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC — change this if you installed elsewhere
# ============================================================
$RootPath = "$env:USERPROFILE\Desktop\SOC"
$LogFile = "$RootPath\Logs\Network_Watchdog_Log.txt"
$ArchiveFolder = "$RootPath\Logs\Archives"
$MyIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -like "*Ethernet*" -or $_.InterfaceAlias -like "*Wi-Fi*" } | Select-Object -First 1).IPAddress
$Network = (($MyIP -split "\.")[0..2] -join ".")
$IPCache = @{}
$SeenConnections = @{} 
$SeenConnectionTimes = @{}

#Functions
function Get-SeverityColor($Severity) {
    switch ($Severity) {
        "OK"         { return "Green" }
        "UNKNOWN"    { return "Cyan" }
        "SUSPICIOUS" { return "Yellow" }
        "CRITICAL"   { return "Red" }
        default      { return "Gray" }
    }
}
# Check if we need to archive the old log (Log Rotation)
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) { New-Item -ItemType Directory -Path $ArchiveFolder }
        $ArchiveName = "Log_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host " [!] Old log moved to Archives folder." -ForegroundColor Yellow
    }
}

# Initialize New Log if needed
if (-not (Test-Path $LogFile)) { 
    "--- Network Security Log Started: $(Get-Date) ---" | Out-File $LogFile 
    "--- [BOOT AUDIT] ---" | Out-File $LogFile -Append
    Get-CimInstance Win32_StartupCommand | ForEach-Object { "STARTUP: $($_.Name) -> $($_.Command)" } | Out-File $LogFile -Append
    "`nFormat: [Time] APP -> REMOTE_IP (LOCATION) | PATH" | Out-File $LogFile -Append
    "------------------------------------------------`n" | Out-File $LogFile -Append
}

while($true) {
    # 1. EXPIRE OLD CACHE ENTRIES FIRST
    $ExpiredKeys = $SeenConnections.Keys | Where-Object {
        ((Get-Date) - $SeenConnectionTimes[$_]).TotalMinutes -gt 60
    }
    $ExpiredKeys | ForEach-Object {
        $SeenConnections.Remove($_)
        $SeenConnectionTimes.Remove($_)
    }
    Clear-Host
    $Now = Get-Date -Format "HH:mm:ss"
    Write-Host "--- [TOTAL DEFENSE DASHBOARD | $Now] ---" -ForegroundColor Cyan
    Write-Host "Monitoring from: $MyIP (YOU)" -ForegroundColor Blue

    # --- SECTION 1: NEIGHBOR WATCH ---
    Get-NetNeighbor | Where-Object { $_.IPAddress -like "$Network*" -and $_.LinkLayerAddress -ne "00-00-00-00-00-00" } | ForEach-Object {
        $Color = "Gray"; $Status = $_.State
        if ($_.IPAddress -eq $MyIP) { $Color = "Blue"; $Status = "LOCAL HOST" }
	    elseif ($_.State -eq "Permanent") { $Color = "Magenta"; $Status = "GATEWAY/PERMANENT" }
        elseif ($_.State -eq "Reachable") { $Color = "Green" }
        elseif ($_.State -eq "Stale") { $Color = "Yellow" }
        Write-Host "IP: $($_.IPAddress.PadRight(15)) | MAC: $($_.LinkLayerAddress) | $Status" -ForegroundColor $Color
    }

    # --- SECTION 2: GLOBAL TRAFFIC HUNT ---
    Write-Host "`n--- [SECTION 2: GLOBAL TRAFFIC HUNT] ---" -ForegroundColor Cyan
    $Conns = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notlike "127.0.0.1" -and $_.RemoteAddress -notlike "192.168.*" -and $_.RemoteAddress -notlike "0.0.0.0" }
    
    foreach ($C in $Conns) {
        $R_IP = $C.RemoteAddress
        if (-not $IPCache.ContainsKey($R_IP)) {
            try {
                $G = Invoke-RestMethod -Uri "http://ip-api.com/json/$R_IP" -Method Get
                $IPCache[$R_IP] = if ($G.status -eq "success") { "$($G.city), $($G.countryCode)" } else { "Unknown" }
            } catch { $IPCache[$R_IP] = "Lookup Failed" }
        }
        $Proc = Get-Process -Id $C.OwningProcess -ErrorAction SilentlyContinue
        $PName = if ($Proc) { $Proc.Name } else { "System/Unknown" }
        $PPath = if ($Proc) { $Proc.Path } else { "System/Protected" }
        $Loc = $IPCache[$R_IP]
        $ID = "$PName-$PPath-$R_IP"
        $IsNewConnection = $False
        if (-not $SeenConnections.ContainsKey($ID)) {
            $IsNewConnection = $true
            $SeenConnections[$ID] = $true
            $SeenConnectionTimes[$ID] = Get-Date
        }

        # --- START OF ANALYZER ---
        $GeoFailure = ($Loc -eq "Unknown" -or $Loc -eq "Lookup Failed")
        $Severity = "UNKNOWN" 
        if ($GeoFailure) {
            $Severity = "SUSPICIOUS"
            # We set a flag here to trigger the extra log warning later
            $LogWarning = "TELEMETRY_GAP: Geolocation failed for $PName ($R_IP)"
        }
        # 2. Telemetry/Null Check (SUSPICIOUS)
        elseif ([string]::IsNullOrWhiteSpace($PPath) -or $PPath -eq "System/Protected" -or $Loc -eq "Unknown" -or $Loc -eq "Lookup Failed") {
            $Severity = "SUSPICIOUS"
        }
        else {
            # 3. Trusted Zone Check
            $TrustedZones = @(
                "C:\Windows",
                "C:\Program Files",
                "C:\Program Files (x86)",
                "$env:USERPROFILE\AppData\Local\Programs",
                "C:\Windows\System32" # Redundant but safe
            )
            $InZone = $false
            foreach ($Zone in $TrustedZones) {
                if ($PPath -like "$Zone*") {
                    $InZone = $true
                    break
                }
            }
            # 4. Environmental Violation (CRITICAL)
            if (-not $InZone) {
                $Severity = "CRITICAL"
            }
        }
        
        #Logs new connections olny with timestamp, Severity, App Name, Remote IP, Location, and Path. 
            if ($IsNewConnection) {
                if ($LogWarning) {
                    "[$Now] [Warning] $LogWarning" | Out-File $LogFile -Append
                }
            $LogEntry = "[$Now] [$Severity] NEW: $PName -> $R_IP ($Loc) | PATH: $PPath"
            $LogEntry | Out-File $LogFile -Append
        }
        
    # --- Dashboard Display ---
    $TrafficColor = Get-SeverityColor -Severity $Severity
    Write-Host "App: $($PName.PadRight(15)) | Loc: $($Loc.PadRight(18)) | Port: $($C.RemotePort)" -ForegroundColor $TrafficColor
    Write-Host "Path: $PPath" -ForegroundColor DarkGray
    Write-Host "------------------------------------------------------------" -ForegroundColor DarkGray
    }
    Write-Host "`nAutomated Archiving Enabled (7 Day Cycle)."
    Start-Sleep -Seconds 5
    
}