# ============================================================
# SecEventLog.ps1 -- Windows Security Event Log Monitor
# Part of Home SOC Suite -- Phase 5
#
# REQUIRES: Administrator elevation
# Monitors Windows Security Event Log for logon anomalies,
# account manipulation, privilege escalation, service
# installation, audit policy changes, and after-hours access.
# ============================================================

chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# ============================================================
$RootPath                = "$env:USERPROFILE\Desktop\SOC"
$LogFile                 = "$RootPath\Logs\SecEventLog_Log.txt"
$ArchiveFolder           = "$RootPath\Logs\Archives"
$HealthFile              = "$RootPath\Config\SecEventLog_Health.json"

$PollInterval            = 60        # Seconds between Security log polls
$AfterHoursStart         = 0         # After-hours window start (00:00, inclusive)
$AfterHoursEnd           = 6         # After-hours window end (06:00, exclusive)
$BruteForceUserThreshold = 5         # Failed logons per username before alert
$BruteForceIPThreshold   = 10        # Failed logons per external source IP before alert
$GeoURL                  = "http://ip-api.com/json/"

$WatchEventIDs = @(
    4624,  # Successful logon
    4625,  # Failed logon
    4634,  # Account logoff
    4647,  # User-initiated logoff
    4648,  # Logon with explicit credentials (RunAs / Credential Manager)
    4672,  # Special privileges assigned to new logon (SeDebugPrivilege etc.)
    4697,  # Service installed -- classic persistence mechanism
    4719,  # System audit policy changed -- attacker covering tracks
    4720,  # User account created
    4722,  # User account enabled
    4723,  # Attempt to change account password
    4724,  # Attempt to reset account password (admin action)
    4726,  # User account deleted
    4728,  # Member added to security-enabled global group
    4732,  # Member added to security-enabled local group (incl. Administrators)
    4738,  # User account changed
    4740,  # User account locked out -- brute force signal
    4756,  # Member added to universal security group
    4776,  # Credential validation (NTLM)
    4778,  # Session reconnected to Window Station (RDP reconnect)
    4779,  # Session disconnected from Window Station (RDP disconnect)
    4798,  # User's local group membership enumerated -- recon signal
    4799   # Security-enabled local group membership enumerated -- recon signal
)

# ============================================================
# PROPERTY INDEX MAP
# Security log Properties[] array is 0-indexed. Order matches
# event XML InsertionStrings. All access via Get-EventProp
# (returns "N/A" on missing index -- never crashes).
# Validate field names on first run and adjust if needed.
#
# 4624:          [5]=TargetUser  [8]=LogonType  [11]=Workstation  [18]=IpAddress
# 4625:          [5]=TargetUser  [8]=FailureReason  [10]=LogonType  [19]=IpAddress
# 4634/4647:     [1]=TargetUser  [3]=LogonId
# 4648:          [1]=SubjectUser  [5]=TargetUser  [11]=ProcessName  [12]=IpAddress
# 4672:          [1]=SubjectUser  [2]=SubjectDomain  [4]=PrivilegeList
# 4697:          [1]=SubjectUser  [4]=ServiceName  [5]=ImagePath  [7]=StartType  [8]=ServiceAccount
# 4719:          [1]=SubjectUser  [7]=AuditPolicyChanges
# 4720/4722/
# 4723/4724/
# 4726/4738:     [1]=SubjectUser  [4]=TargetUser
# 4728/4732/4756:[1]=MemberName  [2]=GroupName  [6]=SubjectUser
# 4740:          [1]=TargetUser  [4]=SubjectComputer
# 4776:          [1]=TargetUser  [2]=Workstation  [3]=Status
# 4778/4779:     [0]=AccountName  [4]=ClientName  [5]=ClientAddress
# 4798/4799:     [0]=TargetName  [4]=SubjectUser  [8]=CallerProcess
# ============================================================

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

function Get-EventProp($Evt, $Index) {
    # Safe accessor -- returns "N/A" on missing index, null, or blank value
    try {
        $Val = [string]$Evt.Properties[$Index].Value
        if ([string]::IsNullOrWhiteSpace($Val) -or $Val -eq "-") { return "N/A" }
        return $Val
    } catch {
        return "N/A"
    }
}

function Get-LogonTypeName($TypeId) {
    $Types = @{
        0  = "System"
        2  = "Interactive"
        3  = "Network"
        4  = "Batch"
        5  = "Service"
        7  = "Unlock"
        8  = "NetworkCleartext"
        9  = "NewCredentials"
        10 = "RemoteInteractive(RDP)"
        11 = "CachedInteractive"
        12 = "CachedRemoteInteractive"
        13 = "CachedUnlock"
    }
    try {
        $Id = [int]$TypeId
        if ($Types.ContainsKey($Id)) { return $Types[$Id] }
    } catch {}
    return "TYPE$TypeId"
}

function Test-IsExternalIP($IP) {
    if ($IP -eq "N/A") { return $false }
    $S = [string]$IP
    if ([string]::IsNullOrWhiteSpace($S) -or $S -eq "-" -or $S -eq "::") { return $false }
    if ($S -eq "127.0.0.1" -or $S -eq "::1") { return $false }
    if ($S -match "^192\.168\." -or
        $S -match "^10\." -or
        $S -match "^172\.(1[6-9]|2[0-9]|3[01])\.") { return $false }
    return $true
}

function Get-GeoLocation($IP) {
    if ($IPCache.ContainsKey($IP)) { return $IPCache[$IP] }
    try {
        $Response = Invoke-RestMethod -Uri "$GeoURL$IP" -TimeoutSec 5 -ErrorAction Stop
        if ($Response.status -eq "success") {
            $GeoStr = "$($Response.country) | $($Response.regionName) | $($Response.city) | ISP: $($Response.isp)"
            $IPCache[$IP] = $GeoStr
            return $GeoStr
        } else {
            Write-Log "SUSPICIOUS" "TELEMETRY_GAP: Geolocation failed for $IP -- API status: $($Response.status)"
            $IPCache[$IP] = "GEO_UNAVAILABLE"
            return "GEO_UNAVAILABLE"
        }
    } catch {
        Write-Log "SUSPICIOUS" "TELEMETRY_GAP: Geolocation request failed for $IP -- $($_.Exception.Message)"
        $IPCache[$IP] = "GEO_UNAVAILABLE"
        return "GEO_UNAVAILABLE"
    }
}

function Resolve-SourceGeo($IPRaw) {
    if ($IPRaw -eq "N/A") { return "N/A" }
    $S = [string]$IPRaw
    if ([string]::IsNullOrWhiteSpace($S) -or $S -eq "-" -or $S -eq "::") { return "LOCAL" }
    if ($S -eq "127.0.0.1" -or $S -eq "::1") { return "LOCAL" }
    if ($S -match "^192\.168\." -or
        $S -match "^10\." -or
        $S -match "^172\.(1[6-9]|2[0-9]|3[01])\.") { return "LAN($S)" }
    return Get-GeoLocation $S
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
        $ArchiveName = "SecEventLog_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# ============================================================
# INITIALIZE LOG
# ============================================================
if (-not (Test-Path $LogFile)) {
    "--- SECEVENTLOG STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- MONITORING: Logon | Account | Privilege | Service | Audit Policy ---`n" | Out-File $LogFile -Append -Encoding UTF8
}

# ============================================================
# STARTUP
# ============================================================
Write-Host "--- [SECEVENTLOG | INITIALIZING] ---" -ForegroundColor Cyan

# Administrator elevation required -- Security log is ACL-protected
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "[CRITICAL] Not running as Administrator. Security log requires elevation." -ForegroundColor Red
    Write-Host "           Restart this script as Administrator." -ForegroundColor Red
    Write-Log "CRITICAL" "STARTUP_FAILED: Administrator elevation required to read Security event log."
    exit 1
}
Write-Host "[OK] Running as Administrator." -ForegroundColor Green

# Verify Security log accessible and report current size
try {
    $SecLogInfo = Get-WinEvent -ListLog Security -ErrorAction Stop
    $SizeMB     = [Math]::Round($SecLogInfo.FileSize / 1MB, 1)
    Write-Host "[OK] Security event log accessible. Current size: ${SizeMB} MB" -ForegroundColor Green
    Write-Log "OK" "SecEventLog started. Administrator context confirmed. Security log size: ${SizeMB} MB"
} catch {
    Write-Host "[CRITICAL] Security event log inaccessible: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "CRITICAL" "Security log inaccessible at startup: $($_.Exception.Message)"
    exit 1
}

# ============================================================
# INITIALIZE TRACKING
# ============================================================
$LastRecordId = 0
$FailedByUser = @{}   # username  -> failed logon count (session cumulative)
$FailedByIP   = @{}   # source IP -> failed logon count (session cumulative)
$IPCache      = @{}   # IP        -> geo string

# Prime LastRecordId -- monitor forward only, do not replay history
try {
    $Latest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    if ($Latest) {
        $LastRecordId = $Latest.RecordId
        Write-Host "[OK] Primed to RecordId $LastRecordId -- monitoring forward only." -ForegroundColor Green
    }
} catch {
    Write-Host "[UNKNOWN] Could not prime RecordId: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Log "UNKNOWN" "Could not prime LastRecordId: $($_.Exception.Message)"
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
    CollectorName   = "seceventlog"
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
        Write-Host "[$NowStr] Monitoring active | Events: $EventCount | Brute-force tracked: Users=$($FailedByUser.Count) IPs=$($FailedByIP.Count)"
        $HeartbeatAt = $Now.AddSeconds(60)
    }

    # --------------------------------------------------------
    # SECURITY EVENT LOG POLL
    # --------------------------------------------------------
    try {
        $Filter = @{
            LogName   = "Security"
            Id        = $WatchEventIDs
            StartTime = $Now.AddSeconds(-($PollInterval * 2))
        }
        $NewEvents = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordId -gt $LastRecordId }

        foreach ($Evt in ($NewEvents | Sort-Object RecordId)) {
            $LastRecordId = $Evt.RecordId
            $EventCount++
            $ID = $Evt.Id
            $AH = ($Evt.TimeCreated.Hour -ge $AfterHoursStart -and $Evt.TimeCreated.Hour -lt $AfterHoursEnd)

            $Severity = "UNKNOWN"
            $Message  = ""

            switch ($ID) {

                # --------------------------------------------------
                # 4624 -- SUCCESSFUL LOGON
                # --------------------------------------------------
                4624 {
                    $TargetUser   = Get-EventProp $Evt 5
                    $LogonTypeId  = Get-EventProp $Evt 8
                    $LogonTypeStr = Get-LogonTypeName $LogonTypeId
                    $Workstation  = Get-EventProp $Evt 11
                    $SourceIP     = Get-EventProp $Evt 18
                    $GeoStr       = Resolve-SourceGeo $SourceIP

                    # Service (5) and Batch (4) logons are expected system noise
                    if ($LogonTypeId -in @("4", "5")) { $Severity = "OK" }
                    elseif ($AH)                       { $Severity = "SUSPICIOUS" }
                    else                               { $Severity = "OK" }

                    $Message = "LOGON_SUCCESS: User=$TargetUser | Type=$LogonTypeStr | Workstation=$Workstation | Source=$SourceIP ($GeoStr)"
                }

                # --------------------------------------------------
                # 4625 -- FAILED LOGON
                # --------------------------------------------------
                4625 {
                    $TargetUser   = Get-EventProp $Evt 5
                    $LogonTypeId  = Get-EventProp $Evt 10
                    $LogonTypeStr = Get-LogonTypeName $LogonTypeId
                    $FailureRsn   = Get-EventProp $Evt 8
                    $SourceIP     = Get-EventProp $Evt 19
                    $GeoStr       = Resolve-SourceGeo $SourceIP

                    # Per-user tracking (covers local logon failures with no source IP)
                    if ($TargetUser -ne "N/A") {
                        if ($FailedByUser.ContainsKey($TargetUser)) { $FailedByUser[$TargetUser]++ }
                        else { $FailedByUser[$TargetUser] = 1 }
                    }
                    # Per-IP tracking (external sources only)
                    if (Test-IsExternalIP $SourceIP) {
                        if ($FailedByIP.ContainsKey($SourceIP)) { $FailedByIP[$SourceIP]++ }
                        else { $FailedByIP[$SourceIP] = 1 }
                    }

                    $Severity = if ($AH) { "SUSPICIOUS" } else { "UNKNOWN" }
                    $Flags    = @()

                    if ($TargetUser -ne "N/A" -and
                        $FailedByUser.ContainsKey($TargetUser) -and
                        $FailedByUser[$TargetUser] -ge $BruteForceUserThreshold) {
                        $Flags += "BRUTE_FORCE_USER:count=$($FailedByUser[$TargetUser])"
                        $Severity = "SUSPICIOUS"
                        $FailedByUser[$TargetUser] = 0   # Reset after alert
                    }
                    if ((Test-IsExternalIP $SourceIP) -and
                        $FailedByIP.ContainsKey($SourceIP) -and
                        $FailedByIP[$SourceIP] -ge $BruteForceIPThreshold) {
                        $Flags += "BRUTE_FORCE_IP:count=$($FailedByIP[$SourceIP])"
                        $Severity = "SUSPICIOUS"
                        $FailedByIP[$SourceIP] = 0
                    }

                    $FlagStr = if ($Flags.Count -gt 0) { " | Flags: $($Flags -join ', ')" } else { "" }
                    $Message = "LOGON_FAIL: User=$TargetUser | Type=$LogonTypeStr | Reason=$FailureRsn | Source=$SourceIP ($GeoStr)$FlagStr"
                }

                # --------------------------------------------------
                # 4634 / 4647 -- LOGOFF
                # --------------------------------------------------
                { $_ -in @(4634, 4647) } {
                    $TargetUser = Get-EventProp $Evt 1
                    $LogonId    = Get-EventProp $Evt 3
                    $Label      = if ($ID -eq 4647) { "USER_LOGOFF" } else { "ACCOUNT_LOGOFF" }
                    $Severity   = "OK"
                    $Message    = "${Label}: User=$TargetUser | LogonId=$LogonId"
                }

                # --------------------------------------------------
                # 4648 -- LOGON WITH EXPLICIT CREDENTIALS (RunAs)
                # --------------------------------------------------
                4648 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $TargetUser  = Get-EventProp $Evt 5
                    $ProcessName = Get-EventProp $Evt 11
                    $SourceIP    = Get-EventProp $Evt 12
                    $GeoStr      = Resolve-SourceGeo $SourceIP
                    $Severity    = if ($AH) { "SUSPICIOUS" } else { "UNKNOWN" }
                    $Message     = "EXPLICIT_CRED_LOGON: Subject=$SubjectUser | TargetUser=$TargetUser | Process=$ProcessName | Source=$SourceIP ($GeoStr)"
                }

                # --------------------------------------------------
                # 4672 -- SPECIAL PRIVILEGES ASSIGNED TO NEW LOGON
                # Fires on every admin logon -- log all, console only after-hours
                # --------------------------------------------------
                4672 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $Domain      = Get-EventProp $Evt 2
                    $PrivList    = Get-EventProp $Evt 4
                    $Severity    = if ($AH) { "SUSPICIOUS" } else { "UNKNOWN" }
                    $Message     = "SPECIAL_PRIV_LOGON: User=$SubjectUser | Domain=$Domain | Privileges=$PrivList"
                }

                # --------------------------------------------------
                # 4697 -- SERVICE INSTALLED
                # --------------------------------------------------
                4697 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $ServiceName = Get-EventProp $Evt 4
                    $ImagePath   = Get-EventProp $Evt 5
                    $StartType   = Get-EventProp $Evt 7
                    $SvcAccount  = Get-EventProp $Evt 8
                    $Severity    = "CRITICAL"
                    $Message     = "SERVICE_INSTALLED: Name=$ServiceName | Path=$ImagePath | StartType=$StartType | Account=$SvcAccount | InstalledBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4719 -- AUDIT POLICY CHANGED
                # --------------------------------------------------
                4719 {
                    $SubjectUser   = Get-EventProp $Evt 1
                    $PolicyChanges = Get-EventProp $Evt 7
                    $Severity      = "CRITICAL"
                    $Message       = "AUDIT_POLICY_CHANGED: ChangedBy=$SubjectUser | Changes=$PolicyChanges"
                }

                # --------------------------------------------------
                # 4720 -- USER ACCOUNT CREATED
                # --------------------------------------------------
                4720 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $TargetUser  = Get-EventProp $Evt 4
                    $Severity    = "CRITICAL"
                    $Message     = "ACCOUNT_CREATED: NewUser=$TargetUser | CreatedBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4722 -- USER ACCOUNT ENABLED
                # --------------------------------------------------
                4722 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $TargetUser  = Get-EventProp $Evt 4
                    $Severity    = "SUSPICIOUS"
                    $Message     = "ACCOUNT_ENABLED: User=$TargetUser | EnabledBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4723 -- PASSWORD CHANGE ATTEMPT (by user)
                # --------------------------------------------------
                4723 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $TargetUser  = Get-EventProp $Evt 4
                    $Severity    = if ($AH) { "SUSPICIOUS" } else { "UNKNOWN" }
                    $Message     = "PASSWORD_CHANGE_ATTEMPT: User=$TargetUser | InitiatedBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4724 -- PASSWORD RESET ATTEMPT (admin)
                # --------------------------------------------------
                4724 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $TargetUser  = Get-EventProp $Evt 4
                    $Severity    = "SUSPICIOUS"
                    $Message     = "PASSWORD_RESET_ATTEMPT: TargetUser=$TargetUser | ResetBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4726 -- USER ACCOUNT DELETED
                # --------------------------------------------------
                4726 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $TargetUser  = Get-EventProp $Evt 4
                    $Severity    = "CRITICAL"
                    $Message     = "ACCOUNT_DELETED: User=$TargetUser | DeletedBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4728 / 4732 / 4756 -- MEMBER ADDED TO GROUP
                # --------------------------------------------------
                { $_ -in @(4728, 4732, 4756) } {
                    $MemberName  = Get-EventProp $Evt 1
                    $GroupName   = Get-EventProp $Evt 2
                    $SubjectUser = Get-EventProp $Evt 6
                    $GroupType   = switch ($ID) {
                        4728 { "GlobalGroup" }
                        4732 { "LocalGroup" }
                        4756 { "UniversalGroup" }
                    }
                    $Severity = "CRITICAL"
                    $Message  = "GROUP_MEMBER_ADDED: Member=$MemberName | Group=$GroupName ($GroupType) | AddedBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4738 -- USER ACCOUNT CHANGED
                # --------------------------------------------------
                4738 {
                    $SubjectUser = Get-EventProp $Evt 1
                    $TargetUser  = Get-EventProp $Evt 4
                    $Severity    = "SUSPICIOUS"
                    $Message     = "ACCOUNT_CHANGED: User=$TargetUser | ChangedBy=$SubjectUser"
                }

                # --------------------------------------------------
                # 4740 -- USER ACCOUNT LOCKED OUT
                # --------------------------------------------------
                4740 {
                    $TargetUser = Get-EventProp $Evt 1
                    $SourceComp = Get-EventProp $Evt 4
                    $Severity   = "CRITICAL"
                    $Message    = "ACCOUNT_LOCKED_OUT: User=$TargetUser | LockedFrom=$SourceComp"
                }

                # --------------------------------------------------
                # 4776 -- CREDENTIAL VALIDATION (NTLM)
                # --------------------------------------------------
                4776 {
                    $TargetUser  = Get-EventProp $Evt 1
                    $Workstation = Get-EventProp $Evt 2
                    $Status      = Get-EventProp $Evt 3
                    $IsFailure   = ($Status -ne "0x0" -and $Status -ne "0" -and $Status -ne "N/A")
                    if ($IsFailure -and $AH) { $Severity = "SUSPICIOUS" }
                    elseif ($IsFailure)      { $Severity = "UNKNOWN" }
                    else                     { $Severity = "OK" }
                    $Message = "NTLM_CREDENTIAL_VALIDATION: User=$TargetUser | Workstation=$Workstation | Status=$Status"
                }

                # --------------------------------------------------
                # 4778 -- RDP SESSION RECONNECTED
                # --------------------------------------------------
                4778 {
                    $AccountName   = Get-EventProp $Evt 0
                    $ClientName    = Get-EventProp $Evt 4
                    $ClientAddress = Get-EventProp $Evt 5
                    $GeoStr        = Resolve-SourceGeo $ClientAddress
                    $Severity      = if ($AH) { "SUSPICIOUS" } else { "UNKNOWN" }
                    $Message       = "RDP_SESSION_RECONNECTED: User=$AccountName | Client=$ClientName | Address=$ClientAddress ($GeoStr)"
                }

                # --------------------------------------------------
                # 4779 -- RDP SESSION DISCONNECTED
                # --------------------------------------------------
                4779 {
                    $AccountName   = Get-EventProp $Evt 0
                    $ClientName    = Get-EventProp $Evt 4
                    $ClientAddress = Get-EventProp $Evt 5
                    $GeoStr        = Resolve-SourceGeo $ClientAddress
                    $Severity      = "OK"
                    $Message       = "RDP_SESSION_DISCONNECTED: User=$AccountName | Client=$ClientName | Address=$ClientAddress ($GeoStr)"
                }

                # --------------------------------------------------
                # 4798 / 4799 -- GROUP MEMBERSHIP ENUMERATED (recon)
                # --------------------------------------------------
                { $_ -in @(4798, 4799) } {
                    $TargetName  = Get-EventProp $Evt 0
                    $SubjectUser = Get-EventProp $Evt 4
                    $CallerProc  = Get-EventProp $Evt 8
                    $Label       = if ($ID -eq 4798) { "USER_GROUP_ENUM" } else { "LOCAL_GROUP_ENUM" }
                    $Severity    = if ($AH) { "SUSPICIOUS" } else { "UNKNOWN" }
                    $Message     = "${Label}: Target=$TargetName | By=$SubjectUser | Process=$CallerProc"
                }

                default {
                    $Severity = "UNKNOWN"
                    $Message  = "SECURITY_EVENT_ID=$ID (unhandled in switch)"
                }
            }

            # Elevated events to console -- OK/UNKNOWN logged silently
            if ($Severity -eq "SUSPICIOUS" -or $Severity -eq "CRITICAL") {
                Write-Host "[$NowStr] [$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
            }
            Write-Log $Severity $Message
        }

    } catch {
        # Never crash the main loop
    }

    Start-Sleep -Seconds $PollInterval
}
