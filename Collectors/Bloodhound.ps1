# ============================================================
# Bloodhound.ps1 -- DNS Query & ICMP Monitor
# Part of Home SOC Suite -- Phase 3
#
# PREREQUISITE: The DNS Client event log must be enabled.
# To enable, run once as Administrator:
#   wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
# To verify:
#   Get-WinEvent -ListLog "Microsoft-Windows-DNS-Client/Operational" | Select-Object IsEnabled
# ============================================================

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
$LogFile             = "$RootPath\Logs\Bloodhound_Log.txt"
$RootPathSeverity = if ($RootPathSource -eq "auto") { "OK" } else { "SUSPICIOUS" }
Add-Content $LogFile "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$RootPathSeverity] ROOTPATH_RESOLVED: $RootPath (source: $RootPathSource)" -Encoding UTF8
$ArchiveFolder       = "$RootPath\Logs\Archives"
$HealthFile          = "$RootPath\Config\Bloodhound_Health.json"

$PollInterval        = 10       # Seconds between DNS log polls
$DGAMinLength        = 12       # Minimum subdomain length before entropy check fires
$DGAMinEntropy       = 3.5      # Shannon entropy threshold -- tune after 30-day baseline
$HighVolumeThreshold = 20       # Queries to same domain per poll window triggers SUSPICIOUS
$ICMPSpikeMultiplier = 3.0      # Alert if ICMP delta exceeds N x rolling average
$ICMPRollingWindow   = 10       # Number of samples for ICMP rolling average
$DNSLogName          = "Microsoft-Windows-DNS-Client/Operational"
$DNSLogMaxSizeBytes  = 20971520 # 20MB -- prevents log wrapping between polls on busy machines
$DomainWhitelist     = @(
    "ip-api.com",           # Sentinel geolocation service -- our own traffic
    "api.anthropic.com",    # Claude Code API
    "a-api.anthropic.com"   # Claude Code alternate endpoint
)

# Properties index map for DNS Client Event ID 3008:
# [0] QueryName   [1] QueryType   [2] QueryOptions
# [3] ServerList  [4] IsResponse  [5] QueryResults
$QNameIdx = 0
$QTypeIdx = 1

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

function Get-StringEntropy($String) {
    if ([string]::IsNullOrEmpty($String)) { return 0 }
    $Chars   = $String.ToCharArray() | Group-Object
    $Entropy = 0
    foreach ($Char in $Chars) {
        $P        = $Char.Count / $String.Length
        $Entropy -= $P * [Math]::Log($P, 2)
    }
    return [Math]::Round($Entropy, 2)
}

function Test-DGADomain($Domain) {
    if ([string]::IsNullOrEmpty($Domain)) { return $false }
    $Subdomain = $Domain.Split(".")[0]
    $Entropy   = Get-StringEntropy $Subdomain
    return ($Subdomain.Length -ge $DGAMinLength -and $Entropy -gt $DGAMinEntropy)
}

function Get-QueryTypeName($TypeId) {
    $Types = @{
        1   = "A"
        2   = "NS"
        5   = "CNAME"
        12  = "PTR"
        15  = "MX"
        16  = "TXT"
        28  = "AAAA"
        33  = "SRV"
        255 = "ANY"
    }
    $Id = [int]$TypeId
    if ($Types.ContainsKey($Id)) { return $Types[$Id] }
    return "TYPE$Id"
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
        $ArchiveName = "Bloodhound_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# ============================================================
# INITIALIZE LOG
# ============================================================
if (-not (Test-Path $LogFile)) {
    "--- BLOODHOUND LOG STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- MONITORING: DNS Queries + ICMP Volume ---`n" | Out-File $LogFile -Append -Encoding UTF8
}

# ============================================================
# STARTUP -- DNS LOG STATE CHECK
# ============================================================
Write-Host "--- [BLOODHOUND | INITIALIZING] ---" -ForegroundColor Cyan

$DNSLogEnabled = $false
try {
    $DNSLogConfig = Get-WinEvent -ListLog $DNSLogName -ErrorAction Stop
    if ($DNSLogConfig.IsEnabled) {
        $DNSLogEnabled = $true
        Write-Host "[OK] DNS Client event log is enabled." -ForegroundColor Green
        Write-Log "OK" "DNS Client event log confirmed enabled at startup."
        try {
            $DNSLogConfig.MaximumSizeInBytes = $DNSLogMaxSizeBytes
            $DNSLogConfig.SaveChanges()
            Write-Host "[OK] DNS log max size set to 20MB." -ForegroundColor Green
        } catch {
            Write-Host "[UNKNOWN] Could not set DNS log max size -- elevation may be required." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[SUSPICIOUS] DNS Client event log is DISABLED." -ForegroundColor DarkYellow
        Write-Host "  To enable, run as Administrator:" -ForegroundColor DarkYellow
        Write-Host "  wevtutil sl `"$DNSLogName`" /e:true" -ForegroundColor White
        Write-Host "  Monitoring continues -- DNS section inactive until log is enabled." -ForegroundColor DarkYellow
        Write-Log "SUSPICIOUS" "DNS_CLIENT_LOG_DISABLED: No DNS telemetry available. Enable: wevtutil sl `"$DNSLogName`" /e:true"
    }
} catch {
    Write-Host "[UNKNOWN] DNS event log state check failed: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Log "UNKNOWN" "DNS log state check failed at startup: $($_.Exception.Message)"
}

# ============================================================
# INITIALIZE TRACKING VARIABLES
# ============================================================
$LastRecordId = 0
$QueryTracker = @{}   # domain -> count in current poll window
$SeenDomains  = @{}   # domain -> first seen timestamp

# Prime LastRecordId to current log tail -- do not replay historical events
if ($DNSLogEnabled) {
    try {
        $Latest = Get-WinEvent -LogName $DNSLogName -MaxEvents 1 -ErrorAction Stop
        if ($Latest) { $LastRecordId = $Latest.RecordId }
    } catch {}
}

# ICMP baseline
$ICMPHistory  = @()
$PrevICMPSent = $null
$PrevICMPRecv = $null

try {
    $ICMPInit     = Get-CimInstance -ClassName Win32_PerfRawData_Tcpip_ICMP -ErrorAction Stop
    $PrevICMPSent = $ICMPInit.MessagesSent
    $PrevICMPRecv = $ICMPInit.MessagesReceived
    Write-Host "[OK] ICMP baseline captured." -ForegroundColor Green
} catch {
    Write-Host "[UNKNOWN] ICMP stats unavailable: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Log "UNKNOWN" "ICMP monitoring unavailable at startup: $($_.Exception.Message)"
}

$EventCount      = 0
$HeartbeatAt     = (Get-Date).AddSeconds(60)
$ScriptStartTime = Get-Date
$CycleCount      = 0

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "bloodhound"
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
        $DNSState = if ($DNSLogEnabled) { "enabled" } else { "DISABLED" }
        Write-Host "[$NowStr] Monitoring active | DNS: $DNSState | Events this session: $EventCount"
        $HeartbeatAt = $Now.AddSeconds(60)
    }

    # ------------------------------------------------------------
    # SECTION 1: DNS QUERY PROCESSING
    # ------------------------------------------------------------
    if ($DNSLogEnabled) {
        # Re-check log state each cycle -- unexpected disablement is a signal
        try {
            $StateCheck = Get-WinEvent -ListLog $DNSLogName -ErrorAction Stop
            if (-not $StateCheck.IsEnabled) {
                $DNSLogEnabled = $false
                Write-Host "[$NowStr] [SUSPICIOUS] DNS_CLIENT_LOG_DISABLED: Log was enabled at startup but is now disabled." -ForegroundColor DarkYellow
                Write-Log "SUSPICIOUS" "DNS_CLIENT_LOG_DISABLED: Log deactivated during monitoring session. Possible tampering or update."
            }
        } catch {}

        if ($DNSLogEnabled) {
            try {
                # Use FilterHashtable with StartTime for efficiency -- avoids full log scan
                $Filter = @{
                    LogName   = $DNSLogName
                    Id        = 3008
                    StartTime = $Now.AddSeconds(-($PollInterval * 2))
                }
                $NewEvents = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue |
                    Where-Object { $_.RecordId -gt $LastRecordId }

                foreach ($Evt in ($NewEvents | Sort-Object RecordId)) {
                    $LastRecordId = $Evt.RecordId
                    $EventCount++

                    # Safe property-array access -- no XML parsing surface
                    try {
                        $QueryName = [string]$Evt.Properties[$QNameIdx].Value
                        $QueryType = Get-QueryTypeName $Evt.Properties[$QTypeIdx].Value
                    } catch {
                        Write-Log "UNKNOWN" "DNS event parse error on RecordId $($Evt.RecordId)"
                        continue
                    }

                    if ([string]::IsNullOrWhiteSpace($QueryName)) { continue }

                    # Normalize -- strip trailing dot from FQDN
                    $QueryName = $QueryName.TrimEnd('.')

                    # Skip PTR reverse lookups -- generated by Sentinel geolocation on known IPs, no forward-lookup signal
                    if ($QueryType -eq "PTR") { continue }

                    # Whitelist check
                    if ($DomainWhitelist -contains $QueryName) { continue }

                    # Query frequency tracking
                    if ($QueryTracker.ContainsKey($QueryName)) {
                        $QueryTracker[$QueryName]++
                    } else {
                        $QueryTracker[$QueryName] = 1
                    }

                    # First-seen tracking
                    $FirstSeen = -not $SeenDomains.ContainsKey($QueryName)
                    if ($FirstSeen) { $SeenDomains[$QueryName] = $Now }

                    # --- SEVERITY CLASSIFICATION ---
                    $Severity = "UNKNOWN"
                    $Flags    = @()

                    # DGA check
                    if (Test-DGADomain $QueryName) {
                        $Entropy  = Get-StringEntropy ($QueryName.Split(".")[0])
                        $Flags   += "DGA:entropy=$Entropy,len=$($QueryName.Split('.')[0].Length)"
                        $Severity = if ($FirstSeen) { "CRITICAL" } else { "SUSPICIOUS" }
                    }

                    # TXT record check -- classic DNS exfiltration channel
                    if ($QueryType -eq "TXT") {
                        $Flags += "TXT_QUERY"
                        if ($Severity -ne "CRITICAL") { $Severity = "SUSPICIOUS" }
                    }

                    # High-volume check -- DNS tunneling pattern
                    if ($QueryTracker[$QueryName] -ge $HighVolumeThreshold) {
                        $Flags += "HIGH_VOLUME:$($QueryTracker[$QueryName])"
                        if ($Severity -ne "CRITICAL") { $Severity = "SUSPICIOUS" }
                    }

                    $FlagStr = if ($Flags.Count -gt 0) { " | Flags: $($Flags -join ', ')" } else { "" }
                    $Message = "DNS QUERY: $QueryName | Type: $QueryType$FlagStr"

                    # Print elevated events to console -- UNKNOWN logged silently
                    if ($Severity -ne "UNKNOWN") {
                        Write-Host "[$NowStr] [$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
                    }

                    # Log everything -- full dataset for 30-day baseline
                    Write-Log $Severity $Message
                }

                # Reset frequency tracker each poll window
                $QueryTracker = @{}

            } catch {}
        }
    }

    # ------------------------------------------------------------
    # SECTION 2: ICMP VOLUME MONITOR
    # ------------------------------------------------------------
    if ($null -ne $PrevICMPSent) {
        try {
            $ICMPNow      = Get-CimInstance -ClassName Win32_PerfRawData_Tcpip_ICMP -ErrorAction Stop
            $DeltaSent    = $ICMPNow.MessagesSent    - $PrevICMPSent
            $DeltaRecv    = $ICMPNow.MessagesReceived - $PrevICMPRecv
            $DeltaTotal   = $DeltaSent + $DeltaRecv

            $PrevICMPSent = $ICMPNow.MessagesSent
            $PrevICMPRecv = $ICMPNow.MessagesReceived

            $ICMPHistory += $DeltaTotal
            if ($ICMPHistory.Count -gt $ICMPRollingWindow) {
                $ICMPHistory = $ICMPHistory[-$ICMPRollingWindow..-1]
            }

            # Minimum 3 samples before firing -- avoids false positives on cold start
            if ($ICMPHistory.Count -ge 3) {
                $RollingAvg = ($ICMPHistory | Measure-Object -Average).Average
                if ($RollingAvg -gt 0 -and $DeltaTotal -gt ($RollingAvg * $ICMPSpikeMultiplier)) {
                    $Message = "ICMP_SPIKE: $DeltaTotal messages this interval | Rolling avg: $([Math]::Round($RollingAvg, 1)) | Threshold: $($ICMPSpikeMultiplier)x"
                    Write-Host "[$NowStr] [SUSPICIOUS] $Message" -ForegroundColor DarkYellow
                    Write-Log "SUSPICIOUS" $Message
                }
            }
        } catch {}
    }

    Start-Sleep -Seconds $PollInterval
}
