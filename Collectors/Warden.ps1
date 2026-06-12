# ============================================================
# Warden.ps1 -- Suite Watchdog & File Integrity Monitor
# Part of Home SOC Suite -- Phase 4
#
# Usage:
#   .\Warden.ps1                -- Start monitoring (requires Admin)
#   .\Warden.ps1 -BuildManifest -- Rebuild the hash manifest then exit
#                                  Run this after every legitimate file change
#
# Maintenance mode (suppresses FIM alerts during updates):
#   SET:   New-Item "<SOC root>\Config\maintenance.flag" -ItemType File
#   CLEAR: Remove-Item "<SOC root>\Config\maintenance.flag"
# ============================================================

param([switch]$BuildManifest)

chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# RootPath is auto-detected from the script location (Scripts folder -> SOC root)
# ============================================================
if ($PSScriptRoot) {
    $RootPath       = Split-Path -Parent $PSScriptRoot
    $RootPathSource = "auto"
} else {
    $RootPath       = "$env:USERPROFILE\Desktop\SOC"
    $RootPathSource = "fallback"
}
if (-not (Test-Path "$RootPath\Logs\Archives") -or -not (Test-Path "$RootPath\Config")) {
    Write-Warning "RootPath '$RootPath' is missing Logs\Archives or Config - verify install layout. Creating folders."
    New-Item -ItemType Directory -Path "$RootPath\Logs\Archives" -Force | Out-Null
    New-Item -ItemType Directory -Path "$RootPath\Config" -Force | Out-Null
}
$LogFile               = "$RootPath\Logs\Warden_Log.txt"
$RootPathSeverity = if ($RootPathSource -eq "auto") { "OK" } else { "SUSPICIOUS" }
Add-Content $LogFile "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$RootPathSeverity] ROOTPATH_RESOLVED: $RootPath (source: $RootPathSource)" -Encoding UTF8
$ArchiveFolder         = "$RootPath\Logs\Archives"
$HealthFile            = "$RootPath\Config\Warden_Health.json"
$ManifestFile          = "$RootPath\Config\Warden_Manifest.json"
$LogSizeFile           = "$RootPath\Config\Warden_LogSizes.json"
$SelfCheckScript       = "$RootPath\Config\Warden_SelfCheck.ps1"
$MaintenanceFlag       = "$RootPath\Config\maintenance.flag"
$RefreshSeconds        = 300   # 5-minute monitoring cycle
$ArchiveScanInterval   = 12    # Scan reports + archives every N cycles (~1 hour)
$MaintenanceTimeoutSec = 3600  # Alert SUSPICIOUS if maintenance flag active > 1 hour
$WatchTaskName         = "HomSOC_WardenSelfWatch"

# Collectors expected to be running -- analysts run on demand, not listed here.
# Maps the script filename to its heartbeat Health JSON in Config\.
# Filenames are irregular (CITYGUARD/CityGuard, Registry_Warden/RegistryWarden,
# DOH_Detector/DoHDetector) so an explicit mapping is safer than derivation.
$ExpectedCollectors = [ordered]@{
    "Sentinel.ps1"        = "Sentinel_Health.json"
    "Bulwark.ps1"         = "Bulwark_Health.json"
    "Steward.ps1"         = "Steward_Health.json"
    "CITYGUARD.ps1"       = "CityGuard_Health.json"
    "Watchman.ps1"        = "Watchman_Health.json"
    "Registry_Warden.ps1" = "RegistryWarden_Health.json"
    "Harbinger.ps1"       = "Harbinger_Health.json"
    "Bloodhound.ps1"      = "Bloodhound_Health.json"
    "SysmonWatcher.ps1"   = "SysmonWatcher_Health.json"
    "SecEventLog.ps1"     = "SecEventLog_Health.json"
    "DOH_Detector.ps1"    = "DoHDetector_Health.json"
}

# Collector silence threshold -- matches Python engine HEARTBEAT_SILENCE_THRESHOLD.
# Collectors write heartbeat every 5s; >60s old = process dead, hung, or never started.
$HeartbeatStaleSec = 60

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

function Get-SHA256($Path) {
    try {
        return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { return $null }
}

function Get-MonitoredFiles {
    # Excludes Warden operational files -- they change legitimately during normal operation
    $ExcludedConfigFiles = @(
        "Warden_Manifest.json",        # The manifest itself -- cannot be in its own manifest
        "Warden_LogSizes.json",        # Updated every cycle
        "Warden_SelfCheck.ps1",        # Auto-generated at startup
        "maintenance.flag",            # Operational flag -- not a monitored asset
        "Auditor_LogBaseline.json",    # Rebuilt every evening run by Auditor
        "Auditor_ArchiveChain.json"    # Appended every evening run by Auditor
    )
    return @{
        Scripts  = @(Get-ChildItem "$RootPath\Scripts\*.ps1" -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty FullName)
        Configs  = @(Get-ChildItem "$RootPath\Config\*" -File -ErrorAction SilentlyContinue |
                        Where-Object { $ExcludedConfigFiles -notcontains $_.Name } |
                        Select-Object -ExpandProperty FullName)
        Reports  = @(Get-ChildItem "$RootPath\Reports\*" -File -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty FullName)
        Archives = @(Get-ChildItem "$RootPath\Logs\Archives\*" -File -ErrorAction SilentlyContinue |
                        Select-Object -ExpandProperty FullName)
    }
}

function Build-Manifest {
    Write-Host "`n--- [WARDEN | BUILDING MANIFEST] ---" -ForegroundColor Cyan
    $AllFiles = Get-MonitoredFiles
    # Case-insensitive hashtable -- Windows filesystem is case-insensitive
    $Manifest = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Count    = 0

    foreach ($Category in $AllFiles.Keys) {
        foreach ($Path in $AllFiles[$Category]) {
            $Hash = Get-SHA256 $Path
            if ($Hash) {
                $Manifest[$Path] = @{ Hash = $Hash; Category = $Category }
                Write-Host "  Hashed [$Category]: $(Split-Path $Path -Leaf)" -ForegroundColor DarkGray
                $Count++
            }
        }
    }

    $Manifest | ConvertTo-Json -Depth 3 | Out-File $ManifestFile -Encoding UTF8
    Write-Log "OK" "Manifest built: $Count files hashed across $($AllFiles.Keys.Count) categories"
    Write-Host "[+] Manifest built: $Count files | Saved: $ManifestFile`n" -ForegroundColor Green
}

function Load-Manifest {
    if (-not (Test-Path $ManifestFile)) { return $null }
    try {
        $Json     = Get-Content $ManifestFile -Encoding UTF8 | ConvertFrom-Json
        $Manifest = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        $Json.PSObject.Properties | ForEach-Object {
            $Manifest[$_.Name] = @{
                Hash     = $_.Value.Hash
                Category = $_.Value.Category
            }
        }
        return $Manifest
    } catch { return $null }
}

function Test-FileIntegrity($Manifest, [string[]]$Categories) {
    $Violations = 0
    foreach ($Path in @($Manifest.Keys)) {
        if ($Categories -notcontains $Manifest[$Path].Category) { continue }

        if (-not (Test-Path $Path)) {
            $Msg = "FILE_MISSING: $(Split-Path $Path -Leaf) [$($Manifest[$Path].Category)]"
            Write-Host "[CRITICAL] $Msg" -ForegroundColor Red
            Write-Log "CRITICAL" $Msg
            $Violations++
            continue
        }

        $Current = Get-SHA256 $Path
        if ($Current -ne $Manifest[$Path].Hash) {
            $Msg = "INTEGRITY_VIOLATION: $(Split-Path $Path -Leaf) [$($Manifest[$Path].Category)] | Hash mismatch"
            Write-Host "[CRITICAL] $Msg" -ForegroundColor Red
            Write-Log "CRITICAL" $Msg
            $Violations++
        }
    }
    return $Violations
}

function Test-NewFiles($Manifest, $Category, $Severity) {
    $AllFiles = Get-MonitoredFiles
    $Files    = $AllFiles[$Category]
    if (-not $Files) { return }
    foreach ($Path in $Files) {
        if (-not $Manifest.ContainsKey($Path)) {
            $Msg   = "NEW_FILE_UNMANIFESTED: $(Split-Path $Path -Leaf) [$Category] | Not in manifest"
            $Color = Get-SeverityColor $Severity
            Write-Host "[$Severity] $Msg" -ForegroundColor $Color
            Write-Log $Severity $Msg
        }
    }
}

function Add-NewFilesToManifest($Manifest, $Category) {
    # Reports and Archives auto-enroll when first seen -- no maintenance flag needed
    # Once enrolled, any subsequent change fires CRITICAL via Test-FileIntegrity
    $AllFiles = Get-MonitoredFiles
    $Files    = $AllFiles[$Category]
    if (-not $Files) { return }
    $Added    = 0
    foreach ($Path in $Files) {
        if (-not $Manifest.ContainsKey($Path)) {
            $Hash = Get-SHA256 $Path
            if ($Hash) {
                $Manifest[$Path] = @{ Hash = $Hash; Category = $Category }
                $NowStr = (Get-Date).ToString("HH:mm:ss")
                Write-Host "[$NowStr] [OK] Auto-enrolled: $(Split-Path $Path -Leaf) [$Category]" -ForegroundColor Green
                Write-Log "OK" "AUTO_ENROLLED: $(Split-Path $Path -Leaf) [$Category] | Added to manifest"
                $Added++
            }
        }
    }
    if ($Added -gt 0) {
        $Manifest | ConvertTo-Json -Depth 3 | Out-File $ManifestFile -Encoding UTF8
    }
}

function Initialize-LogSizes {
    $Sizes = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    Get-ChildItem "$RootPath\Logs\*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
        $Sizes[$_.FullName] = $_.Length
    }
    $Sizes | ConvertTo-Json | Out-File $LogSizeFile -Encoding UTF8
    return $Sizes
}

function Test-LogIntegrity($PrevSizes) {
    $Current    = [System.Collections.Hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Violations = 0

    Get-ChildItem "$RootPath\Logs\*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
        $Current[$_.FullName] = $_.Length
    }

    foreach ($Path in @($PrevSizes.Keys)) {
        if (-not (Test-Path $Path)) {
            $Msg = "LOG_DELETED: $(Split-Path $Path -Leaf)"
            Write-Host "[CRITICAL] $Msg" -ForegroundColor Red
            Write-Log "CRITICAL" $Msg
            $Violations++
            continue
        }
        if ($Current[$Path] -lt $PrevSizes[$Path]) {
            # Rotation-aware: legitimate rotation produces BOTH a fresh live log
            # AND a matching fresh archive entry. An attacker truncating the live
            # log produces only the first. Require both before silently re-baselining.
            $CycleSlack    = $RefreshSeconds + 30
            $LiveCreated   = ((Get-Date) - (Get-Item $Path).CreationTime).TotalSeconds
            $LogLeaf       = [IO.Path]::GetFileNameWithoutExtension($Path)
            $BaseName      = $LogLeaf -replace '_Log$', ''
            $RecentArchive = Get-ChildItem "$RootPath\Logs\Archives" `
                                -Filter "${BaseName}_Archived_*" -ErrorAction SilentlyContinue |
                                Where-Object { ((Get-Date) - $_.CreationTime).TotalSeconds -le $CycleSlack } |
                                Select-Object -First 1

            if ($LiveCreated -le $CycleSlack -and $RecentArchive) {
                $NowStr = (Get-Date).ToString("HH:mm:ss")
                Write-Host "[$NowStr] [OK] LOG_ROTATED: $(Split-Path $Path -Leaf) -> $($RecentArchive.Name) (re-baselined)" -ForegroundColor Green
                Write-Log "OK" "LOG_ROTATED: $(Split-Path $Path -Leaf) -> $($RecentArchive.Name) | Re-baselined"
                continue
            }
            $Lost = $PrevSizes[$Path] - $Current[$Path]
            $Msg  = "LOG_TRUNCATED: $(Split-Path $Path -Leaf) | Was: $($PrevSizes[$Path]) bytes | Now: $($Current[$Path]) bytes | Lost: $Lost bytes"
            Write-Host "[CRITICAL] $Msg" -ForegroundColor Red
            Write-Log "CRITICAL" $Msg
            $Violations++
        }
    }
    return $Current
}

function Test-CollectorHealth {
    # Heartbeat-based detection. Each collector writes its Health JSON every 5s.
    # A heartbeat older than $HeartbeatStaleSec means the collector is dead, hung,
    # or has not yet started this Warden lifetime.
    $Invariant = [System.Globalization.CultureInfo]::InvariantCulture

    foreach ($Script in $ExpectedCollectors.Keys) {
        $HealthFile = Join-Path "$RootPath\Config" $ExpectedCollectors[$Script]

        if (-not (Test-Path $HealthFile)) {
            $Msg = "COLLECTOR_DOWN: $Script -- no heartbeat file ($($ExpectedCollectors[$Script]))"
            Write-Host "[SUSPICIOUS] $Msg" -ForegroundColor DarkYellow
            Write-Log "SUSPICIOUS" $Msg
            continue
        }

        try {
            $Json   = Get-Content $HealthFile -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
            $HbTime = [datetime]::ParseExact($Json.timestamp, "yyyy-MM-dd HH:mm:ss", $Invariant)
            $AgeSec = ((Get-Date) - $HbTime).TotalSeconds

            if ($AgeSec -gt $HeartbeatStaleSec) {
                $AgeMin = [Math]::Round($AgeSec / 60, 1)
                $Msg = "COLLECTOR_DOWN: $Script -- heartbeat stale (${AgeMin} min old, threshold ${HeartbeatStaleSec}s)"
                Write-Host "[SUSPICIOUS] $Msg" -ForegroundColor DarkYellow
                Write-Log "SUSPICIOUS" $Msg
            }
        } catch {
            $Msg = "COLLECTOR_DOWN: $Script -- heartbeat file unreadable: $($_.Exception.Message)"
            Write-Host "[SUSPICIOUS] $Msg" -ForegroundColor DarkYellow
            Write-Log "SUSPICIOUS" $Msg
        }
    }
}

function Write-SelfCheckScript {
    # Writes the helper script called by the external scheduled task
    # Hardcodes paths at generation time so no runtime dependency on Warden variables
    @"
# Warden_SelfCheck.ps1 -- Auto-generated by Warden.ps1 -- do not edit manually
# Called by scheduled task HomSOC_WardenSelfWatch every 5 minutes
`$WardenPath   = "$RootPath\Scripts\Warden.ps1"
`$ManifestPath = "$ManifestFile"
`$LogPath      = "$LogFile"
try {
    `$Hash    = (Get-FileHash `$WardenPath -Algorithm SHA256 -ErrorAction Stop).Hash
    `$ManJson = Get-Content `$ManifestPath -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json
    `$Entry   = `$ManJson.PSObject.Properties |
                    Where-Object { `$_.Name -eq `$WardenPath } |
                    Select-Object -ExpandProperty Value
    if (`$Entry -and `$Hash -ne `$Entry.Hash) {
        `$Ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        "[`$Ts] [CRITICAL] WARDEN_SELF_INTEGRITY: Warden.ps1 hash mismatch detected by external watch task" |
            Out-File `$LogPath -Append -Encoding UTF8
    }
} catch {}
"@ | Out-File $SelfCheckScript -Encoding UTF8
}

function Register-WardenWatchTask {
    # Always regenerate self-check script at startup -- ensures it reflects current paths
    Write-SelfCheckScript

    try {
        $Existing = Get-ScheduledTask -TaskName $WatchTaskName -ErrorAction SilentlyContinue
        if ($Existing) {
            Write-Host "[OK] Self-watch task already registered: $WatchTaskName" -ForegroundColor Green
            return
        }

        $Action   = New-ScheduledTaskAction -Execute "powershell.exe" `
                        -Argument "-NonInteractive -WindowStyle Hidden -File `"$SelfCheckScript`""
        $Trigger  = New-ScheduledTaskTrigger -Once -At "00:00" `
                        -RepetitionInterval (New-TimeSpan -Minutes 5)
        $Settings = New-ScheduledTaskSettingsSet `
                        -ExecutionTimeLimit (New-TimeSpan -Minutes 2) `
                        -StartWhenAvailable $true

        Register-ScheduledTask -TaskName $WatchTaskName -Action $Action `
            -Trigger $Trigger -Settings $Settings -RunLevel Highest -Force | Out-Null

        Write-Host "[OK] Self-watch task registered: $WatchTaskName" -ForegroundColor Green
        Write-Log "OK" "Self-watch scheduled task registered: $WatchTaskName"
    } catch {
        Write-Host "[UNKNOWN] Could not register self-watch task: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Log "UNKNOWN" "Self-watch task registration failed: $($_.Exception.Message)"
    }
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
        $ArchiveName = "Warden_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# ============================================================
# INITIALIZE LOG
# ============================================================
if (-not (Test-Path $LogFile)) {
    "--- WARDEN LOG STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- MONITORING: Script FIM + Log Integrity + Collector Health ---`n" |
        Out-File $LogFile -Append -Encoding UTF8
}

# ============================================================
# -BuildManifest MODE -- build manifest and exit
# ============================================================
if ($BuildManifest) {
    Build-Manifest
    exit
}

# ============================================================
# STARTUP
# ============================================================
Write-Host "--- [WARDEN | INITIALIZING] ---" -ForegroundColor Cyan

Register-WardenWatchTask

$Manifest = Load-Manifest
if (-not $Manifest) {
    Write-Host "[CRITICAL] No manifest found." -ForegroundColor Red
    Write-Host "  Run: .\Warden.ps1 -BuildManifest" -ForegroundColor Yellow
    Write-Host "  FIM inactive until manifest is built. Health and log checks active.`n" -ForegroundColor Yellow
    Write-Log "CRITICAL" "MANIFEST_MISSING: Run .\Warden.ps1 -BuildManifest to initialize FIM"
} else {
    Write-Host "[OK] Manifest loaded: $($Manifest.Count) files." -ForegroundColor Green
}

$LogSizes         = Initialize-LogSizes
$ScanCount        = 0
$MaintenanceStart = $null
$HeartbeatAt      = (Get-Date).AddSeconds(60)
$ScriptStartTime  = Get-Date

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "warden"
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

Write-Host "[OK] Log size baseline: $($LogSizes.Count) files monitored."  -ForegroundColor Green
Write-Host "--- [MONITORING STARTED | Refresh: ${RefreshSeconds}s] ---`n" -ForegroundColor Cyan

# ============================================================
# MAIN MONITORING LOOP
# ============================================================
while ($true) {
    $ScanCount++
    $SharedState.CycleCount = $ScanCount
    $Now    = Get-Date
    $NowStr = $Now.ToString("HH:mm:ss")

    # --- HEARTBEAT ---
    if ($Now -ge $HeartbeatAt) {
        $ManState  = if ($Manifest) { "$($Manifest.Count) files" } else { "NOT BUILT" }
        $MaintState = if (Test-Path $MaintenanceFlag) { "ACTIVE" } else { "off" }
        Write-Host "[$NowStr] Monitoring active | Manifest: $ManState | Maintenance: $MaintState | Scan: $ScanCount"
        $HeartbeatAt = $Now.AddSeconds(60)
    }

    # --------------------------------------------------------
    # MAINTENANCE FLAG
    # --------------------------------------------------------
    $InMaintenance = Test-Path $MaintenanceFlag
    if ($InMaintenance) {
        if (-not $MaintenanceStart) {
            $MaintenanceStart = $Now
            Write-Host "[$NowStr] [UNKNOWN] Maintenance flag active -- FIM suspended" -ForegroundColor Yellow
            Write-Log "UNKNOWN" "Maintenance flag detected -- FIM checks suspended"
        }
        $MaintSec = ($Now - $MaintenanceStart).TotalSeconds
        if ($MaintSec -gt $MaintenanceTimeoutSec) {
            $Mins = [Math]::Round($MaintSec / 60)
            $Msg  = "MAINTENANCE_TIMEOUT: Flag has been active for $Mins minutes -- possible suppression attack"
            Write-Host "[$NowStr] [SUSPICIOUS] $Msg" -ForegroundColor DarkYellow
            Write-Log "SUSPICIOUS" $Msg
        }
    } else {
        if ($MaintenanceStart) {
            Write-Host "[$NowStr] [OK] Maintenance flag cleared -- running immediate integrity check" -ForegroundColor Green
            Write-Log "OK" "Maintenance flag cleared -- FIM resumed"
            $Manifest = Load-Manifest  # Reload manifest after maintenance window
        }
        $MaintenanceStart = $null
    }

    # --------------------------------------------------------
    # SECTION 1: SCRIPT + CONFIG FIM (every cycle)
    # --------------------------------------------------------
    if ($Manifest -and -not $InMaintenance) {
        $V = Test-FileIntegrity $Manifest @("Scripts", "Configs")
        if ($V -eq 0) {
            Write-Host "[$NowStr] [OK] Scripts and configs: no violations" -ForegroundColor Green
        }
        Test-NewFiles $Manifest "Scripts" "CRITICAL"
        Test-NewFiles $Manifest "Configs" "SUSPICIOUS"
    }

    # --------------------------------------------------------
    # SECTION 2: REPORTS + ARCHIVES FIM (every $ArchiveScanInterval cycles)
    # --------------------------------------------------------
    if ($Manifest -and -not $InMaintenance -and ($ScanCount % $ArchiveScanInterval -eq 0)) {
        $V = Test-FileIntegrity $Manifest @("Reports", "Archives")
        if ($V -eq 0) {
            Write-Host "[$NowStr] [OK] Reports and archives: no violations" -ForegroundColor Green
        }
        Add-NewFilesToManifest $Manifest "Reports"
        Add-NewFilesToManifest $Manifest "Archives"
    }

    # --------------------------------------------------------
    # SECTION 3: LOG INTEGRITY (every cycle -- always active, ignores maintenance flag)
    # --------------------------------------------------------
    $LogSizes = Test-LogIntegrity $LogSizes

    # --------------------------------------------------------
    # SECTION 4: COLLECTOR HEALTH (every cycle after warmup)
    # --------------------------------------------------------
    # Skip cycle 1 -- collector spawns are staggered on slow hardware.
    # Analyst confirms dashboard green dots at startup before relying on Warden.
    if ($ScanCount -ge 2) {
        Test-CollectorHealth
    }

    Write-Host "[$NowStr] Scan $ScanCount complete. Next in ${RefreshSeconds}s."
    Start-Sleep -Seconds $RefreshSeconds
}
