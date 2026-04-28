# ============================================================
# SysmonWatcher.ps1 -- Sysmon Kernel-Level Event Monitor
# Part of Night's Watch Home SOC Suite -- Phase 7A
#
# REQUIRES: Administrator elevation + Sysmon installed and running
# Sources:  Microsoft-Windows-Sysmon/Operational
# Rules:    27 (watchlist feed), 28 (browser debugger),
#           29 (high-risk launch), 30 (AMSI tamper),
#           31 (unmanaged PS / DLL hijack), 32 (WMI persistence),
#           33 (remote thread), 34 (LSASS access),
#           35 (raw disk read), 36 (unsigned driver),
#           37 (C2 named pipe), 38 (downloaded executable),
#           39 (process hollowing)
# ============================================================

chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# ============================================================
$RootPath      = "$env:USERPROFILE\Desktop\SOC"
$LogFile       = "$RootPath\Logs\SysmonWatcher_Log.txt"
$ArchiveFolder = "$RootPath\Logs\Archives"
$HealthFile    = "$RootPath\Config\SysmonWatcher_Health.json"

$PollInterval  = 30   # seconds between Sysmon log polls
$MaxLogSizeMB  = 50   # rotate if log exceeds this size regardless of age

# High-risk launch paths -- Rule 29 (also gates EID 7 user-path classification)
$HighRiskPaths = @(
    '\Downloads\',
    '\AppData\Local\Temp\',
    '\AppData\Roaming\',
    '\Users\Public\',
    '\ProgramData\',
    '\Windows\Temp\'
)

# Event ID 10 -- Processes whitelisted as legitimate browser debuggers
# Near-zero false positives -- only known-good dev tools belong here.
$BrowserDebuggerWhitelist = @(
    'Code.exe',
    'WinDbg.exe',
    'WinDbgX.exe',
    'devenv.exe'
)

# Event ID 10 -- System and application processes that legitimately query
# browser process status using read-only access flags (monitoring, not injection).
# Validated against live log: all entries confirmed read-only access masks only.
# Add entries as: 'ProcessName.exe'
$BrowserMonitorWhitelist = @(
    'svchost.exe',       # Windows Service Host -- session/resource/job management
    'wmiprvse.exe',      # WMI Provider Host -- process status queries
    'Explorer.EXE',      # Windows Shell -- taskbar/association integration
    'MsMpEng.exe',       # Windows Defender -- process scan
    'ms-teams.exe',      # Microsoft Teams -- browser SSO / deep link integration
    'GamingServices.exe',# Xbox Gaming Services -- web-integrated features
    'pwsh.exe',          # PowerShell 7 -- SysmonWatcher host process
    'Discord.exe',       # Discord -- browser PID detection for Open Link feature
    'csrss.exe',         # Client Server Runtime -- session/window management
    'Sysmon.exe',        # Sysmon 32-bit -- process monitoring reads
    'Sysmon64.exe'       # Sysmon 64-bit -- process monitoring reads
)

# Event ID 10 -- Processes that legitimately open a handle to lsass.exe for
# read-only status queries (authentication services, WMI, monitoring).
# Validated: all confirmed QUERY_LIMITED / QUERY_INFO / SYNCHRONIZE / SET_QUOTA only.
# VM_READ is NOT whitelisted here -- that is a Mimikatz-class dangerous access on lsass.
$LsassMonitorWhitelist = @(
    'svchost.exe',       # Windows auth/session services -- routine lsass interaction
    'wmiprvse.exe',      # WMI process status query
    'pwsh.exe',          # PowerShell 7 host -- SysmonWatcher process
    'GamingServices.exe' # Xbox services -- process status query
)

# Event ID 9 -- Processes whitelisted for raw disk reads (RawAccessRead).
# All entries validated against live log session 2026-03-25.
# Any process NOT on this list that reads raw disk will still fire CRITICAL.
# NOTE: sdbinst.exe is LOLBAS-listed (shim persistence) but appears here as
# Windows running its own compatibility database checks (System32, 1 event).
# Remove it from this list if you want stricter monitoring.
$RawDiskReadWhitelist = @(
    # Windows system processes -- known EID9 false positive sources
    'svchost.exe',            # Storage/health/session services
    'SearchProtocolHost.exe', # Windows Search indexer -- #1 EID9 FP globally
    'SearchFilterHost.exe',   # Windows Search filter host
    'conhost.exe',            # Console Host (our own SysmonWatcher window)
    'dllhost.exe',            # COM Surrogate -- many COM objects access storage
    'RuntimeBroker.exe',      # UWP permission broker
    'smartscreen.exe',        # SmartScreen file reputation hashing
    'DataExchangeHost.exe',   # Windows nearby sharing
    'WmiApSrv.exe',           # WMI adapter service
    'chcp.com',               # Code page utility -- called at script startup
    'reg.exe',                # Registry tool -- hive file access (System32, 2 events)
    'sdbinst.exe',            # App compat DB installer (LOLBAS-listed -- monitor closely)
    # Applications from trusted paths
    'git.exe',                # Git -- pack file / memory-mapped repo operations
    'git-remote-https.exe',   # Git HTTPS remote helper -- clone/fetch/push operations
    'bash.exe',               # Git Bash -- same as git.exe
    'chrome.exe',             # Chrome -- disk cache mmap
    'SnippingTool.exe',       # Microsoft Snipping Tool (WindowsApps, signed)
    'ms-teamsupdate.exe',     # Microsoft Teams updater
    'FullTrustNotifier.exe',  # Adobe Acrobat DC notification client
    'python.exe',             # Python interpreter -- our engine (SQLite WAL). AppData path.
    # Background tasks and updaters
    'backgroundTaskHost.exe', # Windows UWP background task host (System32)
    'taskhostw.exe',          # Windows Task Host -- scheduled task runner (System32)
    'updater.exe',            # Google Updater -- package verification (Program Files x86)
    'GoogleUpdate.exe',       # Google Update service (Program Files x86)
    'MicrosoftEdgeUpdate.exe',# Microsoft Edge updater (Program Files x86)
    'OverwolfUpdater.exe',    # Overwolf gaming overlay updater (Program Files x86)
    'MoUsoCoreWorker.exe',    # Windows Update Orchestrator core worker
    'MpCmdRun.exe',           # Windows Defender CLI -- signature updates and scans (ProgramData)
    'claude.exe',             # Claude Code AI assistant -- file indexing operations (AppData\Roaming)
    # Windows components -- confirmed EID9 false positive sources
    'Notepad.exe',            # Windows Notepad (WindowsApps build) -- UWP app storage access
    'ScheduleEventAction.exe',# Task Scheduler helper -- action execution context
    'TiWorker.exe',           # Windows Update Trusted Installer worker
    'MsMpEng.exe',            # Windows Defender engine -- signature/quarantine store access
    # Microsoft Edge
    'msedge.exe',             # Microsoft Edge -- disk cache mmap (same pattern as chrome.exe)
    # Git Bash POSIX utilities (C:\Program Files\Git\usr\bin\)
    'grep.exe',               # Git Bash grep -- text search operations
    'head.exe',               # Git Bash head -- file inspection
    'ls.exe',                 # Git Bash ls -- directory listing
    'where.exe',              # Git Bash where -- path lookup
    # Validated additions 2026-04-23
    'AdobeARM.exe',           # Adobe update monitor (Program Files x86)
    'wsqmcons.exe',           # Windows SQM Consolidator (System32)
    'msedgewebview2.exe',     # Microsoft Edge WebView2 -- disk cache mmap
    'sc.exe',                 # Service Control Manager (System32)
    'pwsh.exe'                # PowerShell 7 UWP build (WindowsApps)
)

# Event ID 9 -- Path-anchored whitelist for vendor suites whose add-in
# processes are too numerous or unstable to list by name.
# A process whose full image path starts with any of these prefixes is
# treated identically to a named entry in $RawDiskReadWhitelist.
# WARNING: keep these narrow (vendor-specific subdirs, not all of Program Files).
$RawDiskReadPathWhitelist = @(
    'C:\Program Files (x86)\Lenovo\',   # Lenovo Vantage add-ins (13+ named processes)
    'C:\Program Files\Lenovo\'          # Lenovo 64-bit tools
)

# Event ID 1 -- Processes that legitimately launch from high-risk paths.
# These are known-signed applications whose install location overlaps with
# attacker staging areas. Downgraded from CRITICAL to SUSPICIOUS -- still logged.
$TrustedHighRiskProcesses = @(
    'MpCmdRun.exe',    # Windows Defender CLI -- runs from ProgramData\Microsoft\Windows Defender
    'MsMpEng.exe',     # Windows Defender engine
    'claude.exe'       # Claude Code -- installs to AppData\Roaming\Claude
)

# Event ID 7 -- DLL path substrings within $HighRiskPaths that are system-managed.
# Signed DLLs from these paths are suppressed to OK (routine Defender activity).
# If a DLL from one of these paths is UNSIGNED, it still fires CRITICAL -- a
# hijack of a trusted system directory is higher-severity than a random user path.
$TrustedUserPathDlls = @(
    '\Windows Defender\',
    '\Windows Defender Advanced Threat Protection\'
)

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

function Get-SysmonField($EventData, $FieldName) {
    # Extracts a named field from Sysmon event XML Data elements.
    # Sysmon XML: <EventData><Data Name="FieldName">Value</Data>...</EventData>
    # PowerShell XML adapter exposes the Name attribute as .Name,
    # and text content via .InnerText.
    try {
        $Node = $EventData | Where-Object { $_.Name -eq $FieldName }
        if ($Node -and -not [string]::IsNullOrWhiteSpace($Node.InnerText)) {
            return [string]$Node.InnerText
        }
    } catch {}
    return "N/A"
}

function Test-IsHighRiskPath($Path) {
    if ($Path -eq "N/A") { return $false }
    foreach ($P in $HighRiskPaths) {
        if ($Path -like "*$P*") { return $true }
    }
    return $false
}

function Get-FileName($FullPath) {
    if ($FullPath -eq "N/A") { return "N/A" }
    try { return [System.IO.Path]::GetFileName($FullPath) } catch { return $FullPath }
}

# ============================================================
# LOG ROTATION
# ============================================================
if (Test-Path $LogFile) {
    $LogItem    = Get-Item $LogFile
    $LogAgeDays = ((Get-Date) - $LogItem.CreationTime).TotalDays
    $LogSizeMB  = $LogItem.Length / 1MB
    if ($LogAgeDays -gt 7 -or $LogSizeMB -gt $MaxLogSizeMB) {
        if (-not (Test-Path $ArchiveFolder)) {
            New-Item -ItemType Directory -Path $ArchiveFolder | Out-Null
        }
        $ArchiveName = "SysmonWatcher_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# ============================================================
# INITIALIZE LOG
# ============================================================
if (-not (Test-Path $LogFile)) {
    "--- SYSMONWATCHER STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- MONITORING: Process | Driver | DLL | Thread | Pipe | WMI | Tamper ---`n" | Out-File $LogFile -Append -Encoding UTF8
}

# ============================================================
# STARTUP CHECKS
# ============================================================
Write-Host "--- [SYSMONWATCHER | INITIALIZING] ---" -ForegroundColor Cyan

# Administrator elevation check
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    Write-Host "[CRITICAL] Not running as Administrator. Sysmon log requires elevation." -ForegroundColor Red
    Write-Log "CRITICAL" "STARTUP_FAILED: Administrator elevation required to read Sysmon event log."
    exit 1
}
Write-Host "[OK] Running as Administrator." -ForegroundColor Green

# Sysmon service presence and state check
$SysmonSvc = Get-Service -Name "sysmon" -ErrorAction SilentlyContinue
if (-not $SysmonSvc) {
    Write-Host "[SUSPICIOUS] SYSMON_NOT_INSTALLED: Sysmon service not found. No kernel-level events collected." -ForegroundColor DarkYellow
    Write-Log "SUSPICIOUS" "SYSMON_NOT_INSTALLED: Sysmon service not found. Install Sysmon and configure with sysmonconfig.xml."
    exit 1
}
if ($SysmonSvc.Status -ne "Running") {
    Write-Host "[CRITICAL] Sysmon service not running. Status: $($SysmonSvc.Status)" -ForegroundColor Red
    Write-Log "CRITICAL" "SYSMON_NOT_RUNNING: Sysmon service status=$($SysmonSvc.Status). Kernel-level events offline."
    exit 1
}
Write-Host "[OK] Sysmon service: Running." -ForegroundColor Green

# Verify Sysmon Operational log accessible
try {
    $SysmonLogInfo = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
    $SizeMB = [Math]::Round($SysmonLogInfo.FileSize / 1MB, 1)
    Write-Host "[OK] Sysmon Operational log accessible. Size: ${SizeMB} MB" -ForegroundColor Green
    Write-Log "OK" "SysmonWatcher started. Sysmon service Running. Log size: ${SizeMB} MB"
} catch {
    Write-Host "[CRITICAL] Sysmon Operational log inaccessible: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "CRITICAL" "Sysmon log inaccessible at startup: $($_.Exception.Message)"
    exit 1
}

# ============================================================
# INITIALIZE TRACKING
# ============================================================
$LastRecordId = 0
$EventCount   = 0

# Prime LastRecordId -- monitor forward only, do not replay history
try {
    $Latest = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction Stop
    if ($Latest) {
        $LastRecordId = $Latest.RecordId
        Write-Host "[OK] Primed to RecordId $LastRecordId -- monitoring forward only." -ForegroundColor Green
    }
} catch {
    Write-Host "[UNKNOWN] Could not prime RecordId: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Log "UNKNOWN" "Could not prime LastRecordId: $($_.Exception.Message)"
}

$HeartbeatAt     = (Get-Date).AddSeconds(60)
$ScriptStartTime = Get-Date
$CycleCount      = 0

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "sysmon_watcher"
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
        Write-Host "[$NowStr] SysmonWatcher active | Events processed: $EventCount"
        $HeartbeatAt = $Now.AddSeconds(60)
    }

    # --------------------------------------------------------
    # SYSMON LOG POLL
    # --------------------------------------------------------
    try {
        $Filter = @{
            LogName   = "Microsoft-Windows-Sysmon/Operational"
            StartTime = $Now.AddSeconds(-($PollInterval * 2))
        }
        $NewEvents = Get-WinEvent -FilterHashtable $Filter -ErrorAction SilentlyContinue |
            Where-Object { $_.RecordId -gt $LastRecordId }

        foreach ($Evt in ($NewEvents | Sort-Object RecordId)) {
            $LastRecordId = $Evt.RecordId
            $EventCount++
            $ID = $Evt.Id

            # Parse Sysmon event XML
            try {
                $EvtXml  = [xml]$Evt.ToXml()
                $EvtData = $EvtXml.Event.EventData.Data
            } catch {
                Write-Log "UNKNOWN" "SYSMON_EID${ID}: XML parse failed for RecordId=$($Evt.RecordId)"
                continue
            }

            $Severity = "UNKNOWN"
            $Message  = ""

            switch ($ID) {

                # --------------------------------------------------
                # EID 1 -- PROCESS CREATION
                # Rule 29: High-risk path launch (CRITICAL)
                # Rule 29: Encoded PowerShell command (SUSPICIOUS)
                # Rule 27: All process creation feeds correlator watchlist
                # --------------------------------------------------
                1 {
                    $Image      = Get-SysmonField $EvtData "Image"
                    $CmdLine    = Get-SysmonField $EvtData "CommandLine"
                    $ParentImg  = Get-SysmonField $EvtData "ParentImage"
                    $User       = Get-SysmonField $EvtData "User"
                    $Hashes     = Get-SysmonField $EvtData "Hashes"
                    $Integrity  = Get-SysmonField $EvtData "IntegrityLevel"
                    $ProcName   = Get-FileName $Image
                    $ParentName = Get-FileName $ParentImg

                    $IsHighRisk       = Test-IsHighRiskPath $Image
                    $IsEncoded        = ($CmdLine -match '-[Ee]nc(odedCommand)?\s' -or $CmdLine -match ' -ec ')
                    $IsTrustedHighRisk = ($TrustedHighRiskProcesses | Where-Object { $ProcName -eq $_ }).Count -gt 0

                    if ($IsHighRisk -and $IsTrustedHighRisk) {
                        # Known-signed app in high-risk path -- log as SUSPICIOUS, not CRITICAL
                        $Severity = "SUSPICIOUS"
                        $Message  = "SYSMON_EID1_HIGH_RISK_LAUNCH: Process=$ProcName | Path=$Image | Parent=$ParentName | User=$User | Integrity=$Integrity | Hashes=$Hashes | CmdLine=$CmdLine"
                    } elseif ($IsHighRisk) {
                        $Severity = "CRITICAL"
                        $Message  = "SYSMON_EID1_HIGH_RISK_LAUNCH: Process=$ProcName | Path=$Image | Parent=$ParentName | User=$User | Integrity=$Integrity | Hashes=$Hashes | CmdLine=$CmdLine"
                    } elseif ($IsEncoded) {
                        $Severity = "SUSPICIOUS"
                        $Message  = "SYSMON_EID1_ENCODED_CMD: Process=$ProcName | Parent=$ParentName | User=$User | Hashes=$Hashes | CmdLine=$CmdLine"
                    } else {
                        $Severity = "OK"
                        $Message  = "SYSMON_EID1_PROCESS_START: Process=$ProcName | Path=$Image | Parent=$ParentName | User=$User | Hashes=$Hashes"
                    }
                }

                # --------------------------------------------------
                # EID 5 -- PROCESS TERMINATED
                # Rule 27: Watchlist lifecycle -- correlator resolves dormant entries
                # Logged OK (high volume) -- correlator filters on GUID match
                # --------------------------------------------------
                5 {
                    $Image    = Get-SysmonField $EvtData "Image"
                    $ProcId   = Get-SysmonField $EvtData "ProcessId"
                    $ProcGuid = Get-SysmonField $EvtData "ProcessGuid"
                    $ProcName = Get-FileName $Image
                    $Severity = "OK"
                    $Message  = "SYSMON_EID5_PROCESS_END: Process=$ProcName | PID=$ProcId | GUID=$ProcGuid | Path=$Image"
                }

                # --------------------------------------------------
                # EID 6 -- DRIVER LOADED
                # Rule 36: Unsigned driver loaded
                # Config pre-filters to Signed=false -- all events here are unsigned
                # --------------------------------------------------
                6 {
                    $ImageLoaded = Get-SysmonField $EvtData "ImageLoaded"
                    $Hashes      = Get-SysmonField $EvtData "Hashes"
                    $Signed      = Get-SysmonField $EvtData "Signed"
                    $Signature   = Get-SysmonField $EvtData "Signature"
                    $SigStatus   = Get-SysmonField $EvtData "SignatureStatus"
                    $DriverName  = Get-FileName $ImageLoaded
                    $Severity    = "CRITICAL"
                    $Message     = "SYSMON_EID6_UNSIGNED_DRIVER: Driver=$DriverName | Path=$ImageLoaded | Signed=$Signed | Signature=$Signature | SigStatus=$SigStatus | Hashes=$Hashes"
                }

                # --------------------------------------------------
                # EID 7 -- IMAGE LOADED
                # Rule 31: Unmanaged PS host (SMA.dll loaded by non-PowerShell process)
                # Rule 31: Unsigned DLL from user-writable path (DLL hijacking)
                # Rule 31: Signed DLL from user path (suspicious)
                # Rule 31: Scripting engine DLL (Office macro / LOLBAS)
                # NOTE: high volume -- OK events logged silently to reduce noise
                # --------------------------------------------------
                7 {
                    $Image       = Get-SysmonField $EvtData "Image"
                    $ImageLoaded = Get-SysmonField $EvtData "ImageLoaded"
                    $Signed      = Get-SysmonField $EvtData "Signed"
                    $Signature   = Get-SysmonField $EvtData "Signature"
                    $Hashes      = Get-SysmonField $EvtData "Hashes"
                    $ProcName    = Get-FileName $Image
                    $DllName     = Get-FileName $ImageLoaded

                    $IsSMA            = ($ImageLoaded -like "*System.Management.Automation*")
                    $IsPwsh           = ($Image -like "*\powershell.exe" -or $Image -like "*\pwsh.exe")
                    $IsUserPath       = Test-IsHighRiskPath $ImageLoaded
                    $IsScriptDll      = ($DllName -in @("vbscript.dll","jscript.dll","jscript9.dll","scrrun.dll","wshom.ocx"))
                    $IsTrustedSubpath = ($TrustedUserPathDlls | Where-Object { $ImageLoaded -like "*$_*" }).Count -gt 0

                    if ($IsSMA -and -not $IsPwsh) {
                        # SMA.dll outside PowerShell = unmanaged PS host (BYOI / living-off-the-land)
                        $Severity = "CRITICAL"
                        $Message  = "SYSMON_EID7_UNMANAGED_PWSH: Process=$ProcName | DLL=System.Management.Automation.dll | Signed=$Signed | Hashes=$Hashes | ProcessPath=$Image"
                    } elseif ($IsUserPath -and $IsTrustedSubpath -and $Signed -eq "true") {
                        # Signed DLL from known system subpath within ProgramData (Defender etc.) -- routine
                        $Severity = "OK"
                        $Message  = "SYSMON_EID7_IMAGE_LOAD: Process=$ProcName | DLL=$DllName | Signed=$Signed | Hashes=$Hashes"
                    } elseif ($IsUserPath -and $IsTrustedSubpath -and $Signed -eq "false") {
                        # UNSIGNED DLL from a supposed-trusted system path -- potential hijack of Defender directory
                        # Reuses DLL_HIJACK subtype so Rule 31 fires. Note field distinguishes this case.
                        $Severity = "CRITICAL"
                        $Message  = "SYSMON_EID7_DLL_HIJACK: Process=$ProcName | DLL=$DllName | Path=$ImageLoaded | Signed=$Signed | Note=UNSIGNED_DLL_IN_TRUSTED_SYSTEM_PATH | Hashes=$Hashes"
                    } elseif ($IsUserPath -and $Signed -eq "false") {
                        # Unsigned DLL from user-writable path
                        $Severity = "CRITICAL"
                        $Message  = "SYSMON_EID7_DLL_HIJACK: Process=$ProcName | DLL=$DllName | Path=$ImageLoaded | Signed=$Signed | Hashes=$Hashes"
                    } elseif ($IsUserPath) {
                        # Signed DLL from user-writable path -- still anomalous
                        $Severity = "SUSPICIOUS"
                        $Message  = "SYSMON_EID7_DLL_USERPATH: Process=$ProcName | DLL=$DllName | Path=$ImageLoaded | Signed=$Signed | Hashes=$Hashes"
                    } elseif ($IsScriptDll) {
                        # Scripting engine loaded -- possible macro/LOLBAS abuse
                        $Severity = "SUSPICIOUS"
                        $Message  = "SYSMON_EID7_SCRIPT_ENGINE: Process=$ProcName | DLL=$DllName | Signed=$Signed | Hashes=$Hashes"
                    } else {
                        $Severity = "OK"
                        $Message  = "SYSMON_EID7_IMAGE_LOAD: Process=$ProcName | DLL=$DllName | Signed=$Signed | Hashes=$Hashes"
                    }
                }

                # --------------------------------------------------
                # EID 8 -- CREATEREMOTETHREAD
                # Rule 33: Remote Thread Injection
                # No whitelisting -- legitimate software does not inject threads
                # --------------------------------------------------
                8 {
                    $SrcImage  = Get-SysmonField $EvtData "SourceImage"
                    $TgtImage  = Get-SysmonField $EvtData "TargetImage"
                    $StartAddr = Get-SysmonField $EvtData "StartAddress"
                    $StartMod  = Get-SysmonField $EvtData "StartModule"
                    $StartFunc = Get-SysmonField $EvtData "StartFunction"
                    $SrcName   = Get-FileName $SrcImage
                    $TgtName   = Get-FileName $TgtImage
                    $Severity  = "CRITICAL"
                    $Message   = "SYSMON_EID8_REMOTE_THREAD: Source=$SrcName | Target=$TgtName | StartAddr=$StartAddr | StartModule=$StartMod | StartFunc=$StartFunc"
                }

                # --------------------------------------------------
                # EID 9 -- RAWACCESSREAD
                # Rule 35: Raw disk read (NTDS.dit, SAM, LSASS dump staging)
                # --------------------------------------------------
                9 {
                    $Image      = Get-SysmonField $EvtData "Image"
                    $Device     = Get-SysmonField $EvtData "Device"
                    $User       = Get-SysmonField $EvtData "User"
                    $ProcName   = Get-FileName $Image
                    $IsRawWhitelisted = ($RawDiskReadWhitelist | Where-Object { $ProcName -eq $_ }).Count -gt 0
                    # Path whitelist: covers vendor suites with many named add-ins (Lenovo Vantage etc.)
                    if (-not $IsRawWhitelisted -and $Image) {
                        $IsRawWhitelisted = ($RawDiskReadPathWhitelist | Where-Object { $Image -like "$_*" }).Count -gt 0
                    }

                    if ($IsRawWhitelisted) {
                        # Known-good process -- log silently for audit trail
                        $Severity = "OK"
                        $Message  = "SYSMON_EID9_RAW_DISK_READ: Process=$ProcName | Device=$Device | User=$User | Path=$Image"
                    } else {
                        # Unlisted process doing raw disk access -- credential dump / data theft vector
                        $Severity = "CRITICAL"
                        $Message  = "SYSMON_EID9_RAW_DISK_READ: Process=$ProcName | Device=$Device | User=$User | Path=$Image"
                    }
                }

                # --------------------------------------------------
                # EID 10 -- PROCESSACCESS
                # Rule 34: LSASS access (credential dumping)
                # Rule 28: Browser debugger attachment (unauthorized)
                # --------------------------------------------------
                10 {
                    $SrcImage      = Get-SysmonField $EvtData "SourceImage"
                    $TgtImage      = Get-SysmonField $EvtData "TargetImage"
                    $Access        = Get-SysmonField $EvtData "GrantedAccess"
                    $CallTrace     = Get-SysmonField $EvtData "CallTrace"
                    $SrcName       = Get-FileName $SrcImage
                    $TgtName       = Get-FileName $TgtImage

                    $IsLsass            = ($TgtImage -like "*\lsass.exe")
                    $IsBrowser          = ($TgtImage -like "*\chrome.exe" -or $TgtImage -like "*\msedge.exe" -or
                                           $TgtImage -like "*\firefox.exe" -or $TgtImage -like "*\brave.exe")
                    $IsDebugWhitelisted = ($BrowserDebuggerWhitelist | Where-Object { $SrcImage -like "*\$_" }).Count -gt 0
                    $IsBrowserMonitor   = ($BrowserMonitorWhitelist  | Where-Object { $SrcName -eq $_ }).Count -gt 0
                    $IsLsassMonitor     = ($LsassMonitorWhitelist    | Where-Object { $SrcName -eq $_ }).Count -gt 0
                    # Chrome's multi-process sandbox uses PROCESS_ALL_ACCESS on its own children.
                    # Path-anchored: both source and target must be from Chrome's install directory.
                    # Name-only whitelist would suppress a compromised chrome.exe injecting into Chrome.
                    $IsChromeSelf = (
                        ($SrcImage -like "*\Google\Chrome\*\chrome.exe") -and
                        ($TgtImage -like "*\Google\Chrome\*\chrome.exe")
                    )
                    # Windows system processes (csrss, svchost, Sysmon, etc.) legitimately open
                    # browser handles with PROCESS_ALL_ACCESS for process lifecycle management,
                    # session control, and kernel monitoring. Two-factor: name must be in
                    # $BrowserMonitorWhitelist AND path must be under C:\Windows\.
                    # An attacker cannot spoof both factors without admin + writing to System32.
                    $IsWindowsSystemMonitor = (
                        $IsBrowserMonitor -and
                        ($SrcImage -like "C:\Windows\*" -or $SrcImage -like "C:\WINDOWS\*")
                    )

                    # Parse access mask for bit-level threat classification.
                    # Browser dangerous: 0x002A = CREATE_THREAD | VM_OPERATION | VM_WRITE
                    # Lsass dangerous:   0x003A = CREATE_THREAD | VM_OPERATION | VM_READ | VM_WRITE
                    # (VM_READ on lsass = credential dump vector -- Mimikatz-class access)
                    $AccessInt = 0
                    try { $AccessInt = [Convert]::ToInt64(($Access -replace '^0[xX]',''), 16) } catch {}
                    $IsBrowserDangerous = ($AccessInt -band 0x002A) -ne 0
                    $IsLsassDangerous   = ($AccessInt -band 0x003A) -ne 0

                    if ($IsLsass -and $IsLsassDangerous) {
                        # Dangerous access to lsass -- credential dump / injection (Rule 34)
                        $Severity = "CRITICAL"
                        $Message  = "SYSMON_EID10_LSASS_ACCESS: Source=$SrcName | Target=lsass.exe | Access=$Access | SourcePath=$SrcImage | CallTrace=$CallTrace"
                    } elseif ($IsLsass -and $IsLsassMonitor) {
                        # Known system process with read-only lsass handle -- routine
                        $Severity = "OK"
                        $Message  = "SYSMON_EID10_LSASS_MONITOR: Source=$SrcName | Target=lsass.exe | Access=$Access"
                    } elseif ($IsLsass) {
                        # Unknown process, non-dangerous access -- log for correlator
                        $Severity = "UNKNOWN"
                        $Message  = "SYSMON_EID10_LSASS_READ_ACCESS: Source=$SrcName | Target=lsass.exe | Access=$Access | SourcePath=$SrcImage"
                    } elseif ($IsBrowser -and $IsChromeSelf) {
                        # Chrome sandbox/GPU process management -- path-anchored self-access
                        $Severity = "OK"
                        $Message  = "SYSMON_EID10_BROWSER_MONITOR: Source=$SrcName | Target=$TgtName | Access=$Access"
                    } elseif ($IsBrowser -and $IsWindowsSystemMonitor) {
                        # Trusted Windows system process (path-anchored + whitelist) -- allowed
                        # regardless of access flags. csrss, svchost, Sysmon use PROCESS_ALL_ACCESS
                        # for legitimate process management and cannot be distinguished by mask alone.
                        $Severity = "OK"
                        $Message  = "SYSMON_EID10_BROWSER_MONITOR: Source=$SrcName | Target=$TgtName | Access=$Access"
                    } elseif ($IsBrowser -and $IsBrowserDangerous -and -not $IsDebugWhitelisted) {
                        # Unknown/non-system process with write/inject capability -- true threat (Rule 28)
                        $Severity = "CRITICAL"
                        $Message  = "SYSMON_EID10_BROWSER_DEBUGGER: Source=$SrcName | Target=$TgtName | Access=$Access | SourcePath=$SrcImage"
                    } elseif ($IsBrowser -and $IsDebugWhitelisted) {
                        # Known legitimate dev tool (VS Code, WinDbg) -- path-anchored match
                        $Severity = "OK"
                        $Message  = "SYSMON_EID10_BROWSER_DEBUG_WHITELISTED: Source=$SrcName | Target=$TgtName | Access=$Access"
                    } elseif ($IsBrowser -and $IsBrowserMonitor) {
                        # Known process with non-dangerous browser handle (non-Windows path)
                        $Severity = "OK"
                        $Message  = "SYSMON_EID10_BROWSER_MONITOR: Source=$SrcName | Target=$TgtName | Access=$Access"
                    } elseif ($IsBrowser) {
                        # Unknown process, read-only access -- log for correlator, no console alert
                        $Severity = "UNKNOWN"
                        $Message  = "SYSMON_EID10_BROWSER_READ_ACCESS: Source=$SrcName | Target=$TgtName | Access=$Access | SourcePath=$SrcImage"
                    } else {
                        $Severity = "SUSPICIOUS"
                        $Message  = "SYSMON_EID10_PROCESS_ACCESS: Source=$SrcName | Target=$TgtName | Access=$Access | SourcePath=$SrcImage"
                    }
                }

                # --------------------------------------------------
                # EID 11 -- FILECREATE
                # Rule 38: Executable written to high-risk path
                # Config pre-filters to executable extensions only
                # --------------------------------------------------
                11 {
                    $Image        = Get-SysmonField $EvtData "Image"
                    $Target       = Get-SysmonField $EvtData "TargetFilename"
                    $User         = Get-SysmonField $EvtData "User"
                    $ProcName     = Get-FileName $Image
                    $FileName     = Get-FileName $Target
                    $IsHot        = Test-IsHighRiskPath $Target
                    # PowerShell writes __PSScriptPolicyTest_*.ps1 to Temp to probe execution policy.
                    # These are self-cleaning and entirely harmless -- suppress to OK.
                    $IsPolicyTest = ($FileName -like "__PSScriptPolicyTest_*")

                    if ($IsHot -and -not $IsPolicyTest) {
                        $Severity = "SUSPICIOUS"
                        $Message  = "SYSMON_EID11_FILE_HOTPATH: Process=$ProcName | File=$FileName | Path=$Target | User=$User"
                    } else {
                        $Severity = "OK"
                        $Message  = "SYSMON_EID11_FILE_CREATED: Process=$ProcName | File=$FileName | Path=$Target | User=$User"
                    }
                }

                # --------------------------------------------------
                # EID 12 -- REGISTRYEVENT
                # Rule 30: AMSI provider key tampered
                # Config pre-filters to AMSI\Providers key only
                # --------------------------------------------------
                12 {
                    $EvtType  = Get-SysmonField $EvtData "EventType"
                    $Image    = Get-SysmonField $EvtData "Image"
                    $TgtObj   = Get-SysmonField $EvtData "TargetObject"
                    $Details  = Get-SysmonField $EvtData "Details"
                    $ProcName = Get-FileName $Image
                    $Severity = "CRITICAL"
                    $Message  = "SYSMON_EID12_AMSI_TAMPER: Type=$EvtType | Process=$ProcName | Key=$TgtObj | Details=$Details"
                }

                # --------------------------------------------------
                # EID 15 -- FILECREATESTREAMHASH (Zone.Identifier ADS)
                # Rule 38: Internet-origin executable (MotW tag present)
                # --------------------------------------------------
                15 {
                    $Image    = Get-SysmonField $EvtData "Image"
                    $Target   = Get-SysmonField $EvtData "TargetFilename"
                    $Hash     = Get-SysmonField $EvtData "Hash"
                    $Contents = Get-SysmonField $EvtData "Contents"
                    $ProcName = Get-FileName $Image
                    $FileName = Get-FileName $Target
                    $Severity = "SUSPICIOUS"
                    $Message  = "SYSMON_EID15_DOWNLOADED_FILE: Process=$ProcName | File=$FileName | Path=$Target | Hashes=$Hash | ZoneContents=$Contents"
                }

                # --------------------------------------------------
                # EID 17 -- PIPE CREATED
                # Rule 37: C2 named pipe (Cobalt Strike, Metasploit, Brute Ratel)
                # Config pre-filters to known C2 pipe name patterns
                # --------------------------------------------------
                17 {
                    $Image    = Get-SysmonField $EvtData "Image"
                    $PipeName = Get-SysmonField $EvtData "PipeName"
                    $User     = Get-SysmonField $EvtData "User"
                    $ProcName = Get-FileName $Image
                    $Severity = "CRITICAL"
                    $Message  = "SYSMON_EID17_C2_PIPE_CREATED: Process=$ProcName | PipeName=$PipeName | User=$User | Path=$Image"
                }

                # --------------------------------------------------
                # EID 18 -- PIPE CONNECTED
                # Rule 37: C2 named pipe connection
                # --------------------------------------------------
                18 {
                    $Image    = Get-SysmonField $EvtData "Image"
                    $PipeName = Get-SysmonField $EvtData "PipeName"
                    $User     = Get-SysmonField $EvtData "User"
                    $ProcName = Get-FileName $Image
                    $Severity = "CRITICAL"
                    $Message  = "SYSMON_EID18_C2_PIPE_CONNECTED: Process=$ProcName | PipeName=$PipeName | User=$User | Path=$Image"
                }

                # --------------------------------------------------
                # EID 19 -- WMIEVENT FILTER (persistence step 1: event filter)
                # Rule 32: WMI Persistence Binding
                # --------------------------------------------------
                19 {
                    $Operation = Get-SysmonField $EvtData "Operation"
                    $User      = Get-SysmonField $EvtData "User"
                    $Namespace = Get-SysmonField $EvtData "EventNamespace"
                    $Name      = Get-SysmonField $EvtData "Name"
                    $Query     = Get-SysmonField $EvtData "Query"
                    $Severity  = "CRITICAL"
                    $Message   = "SYSMON_EID19_WMI_FILTER: Op=$Operation | User=$User | Namespace=$Namespace | Name=$Name | Query=$Query"
                }

                # --------------------------------------------------
                # EID 20 -- WMIEVENT CONSUMER (persistence step 2: consumer)
                # Rule 32
                # --------------------------------------------------
                20 {
                    $Operation = Get-SysmonField $EvtData "Operation"
                    $User      = Get-SysmonField $EvtData "User"
                    $Name      = Get-SysmonField $EvtData "Name"
                    $Type      = Get-SysmonField $EvtData "Type"
                    $Dest      = Get-SysmonField $EvtData "Destination"
                    $Severity  = "CRITICAL"
                    $Message   = "SYSMON_EID20_WMI_CONSUMER: Op=$Operation | User=$User | Name=$Name | Type=$Type | Destination=$Dest"
                }

                # --------------------------------------------------
                # EID 21 -- WMIEVENT BINDING (persistence step 3: filter-consumer bind)
                # Rule 32: This event = WMI persistence is now active
                # --------------------------------------------------
                21 {
                    $Operation = Get-SysmonField $EvtData "Operation"
                    $User      = Get-SysmonField $EvtData "User"
                    $Consumer  = Get-SysmonField $EvtData "Consumer"
                    $Filter    = Get-SysmonField $EvtData "Filter"
                    $Severity  = "CRITICAL"
                    $Message   = "SYSMON_EID21_WMI_BINDING: Op=$Operation | User=$User | Consumer=$Consumer | Filter=$Filter"
                }

                # --------------------------------------------------
                # EID 25 -- PROCESS TAMPERING
                # Rule 39: Process hollowing / herpaderping confirmed
                # Sysmon reports Type: "Image is replaced" or "Image is locked"
                # --------------------------------------------------
                25 {
                    $Image      = Get-SysmonField $EvtData "Image"
                    $TamperType = Get-SysmonField $EvtData "Type"
                    $ProcId     = Get-SysmonField $EvtData "ProcessId"
                    $ProcGuid   = Get-SysmonField $EvtData "ProcessGuid"
                    $ProcName   = Get-FileName $Image

                    if ($TamperType -eq "Image is replaced") {
                        # Confirmed process hollowing / herpaderping -- PE body swapped in memory.
                        # Highest-confidence injection signal from Sysmon.
                        $Severity = "CRITICAL"
                    } else {
                        # "Image is locked" -- file in use during execution.
                        # Common false positive for POSIX-emulation runtimes (Git Bash, WSL utils).
                        # Still logged for correlator context -- TamperType is in the message body.
                        $Severity = "SUSPICIOUS"
                    }
                    $Message = "SYSMON_EID25_PROCESS_TAMPER: Process=$ProcName | PID=$ProcId | TamperType=$TamperType | GUID=$ProcGuid | Path=$Image"
                }

                default {
                    $Severity = "UNKNOWN"
                    $Message  = "SYSMON_EID${ID}_UNHANDLED: RecordId=$($Evt.RecordId)"
                }
            }

            # SUSPICIOUS and CRITICAL go to console. OK logged silently.
            if ($Severity -eq "SUSPICIOUS" -or $Severity -eq "CRITICAL") {
                Write-Host "[$NowStr] [$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
            }
            if ($Severity -ne "OK" -or $ID -eq 5) {
                Write-Log $Severity $Message
            }
        }

    } catch {
        # Never crash the main loop
    }

    Start-Sleep -Seconds $PollInterval
}
