# ============================================================
# Harbinger.ps1 - Process Execution Monitor
# Part of Home SOC Suite
# Requires: Administrator elevation
# ============================================================

# --- ENCODING ---
chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC - change this if you installed elsewhere
# ============================================================
$RootPath      = "$env:USERPROFILE\Desktop\SOC"
$LogFile       = "$RootPath\Logs\Harbinger_Log.txt"
$ArchiveFolder = "$RootPath\Logs\Archives"
$BaselineFile  = "$RootPath\Config\Harbinger_Baseline.json"
$HealthFile    = "$RootPath\Config\Harbinger_Health.json"
$HeartbeatSecs = 30    # Seconds between status lines when idle

# --- HIGH RISK EXECUTION PATHS ---
$HighRiskPaths = @(
    "$env:USERPROFILE\Downloads",
    "$env:TEMP",
    "$env:USERPROFILE\AppData\Local\Temp",
    "C:\Users\Public"
)

# --- BYOI INTERPRETERS (flag if outside Program Files) ---
$BYOIInterpreters = @("python", "python3", "perl", "ruby", "lua", "node", "php")

# --- WINDOWS SCRIPT HOSTS (flag if outside System32/SysWOW64) ---
$WindowsInterpreters = @("powershell", "pwsh", "cmd", "wscript", "cscript", "mshta")

# --- LOLBINS (always log at SUSPICIOUS) ---
$LOLBins = @("certutil", "bitsadmin", "regsvr32", "rundll32", "msiexec", "wmic", "forfiles", "msbuild")

# --- TRUSTED PARENT → CHILD EXACT PATH PAIRS ---
# Keys = SHA256(path.ToLower()). CMD values = Base64(pattern).
# Four factors must match: parent path + parent CMD + child path + child CMD.
# powershell.exe health checks stay SUSPICIOUS — no stable CMD pattern to anchor to.
$TrustedParentChildMap = @{}

# --- VERSION DETECTION ---
$PSMajor = $PSVersionTable.PSVersion.Major

# --- FUNCTIONS ---
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

function Get-PathHash($Path) {
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Path.ToLower())
    $SHA   = [System.Security.Cryptography.SHA256]::Create()
    ([BitConverter]::ToString($SHA.ComputeHash($Bytes)) -replace '-', '').ToLower()
}

function Decode-Pattern($Encoded) {
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Encoded))
}

function Get-ProcessSeverity($NameLower, $PPath) {
    $PathLower = if ($PPath) { $PPath.ToLower() } else { "" }

    # 1. Execution from high-risk path
    foreach ($Risk in $HighRiskPaths) {
        if ($PathLower -like "$($Risk.ToLower())*") { return "CRITICAL" }
    }

    # 2. BYOI interpreter
    if ($NameLower -in $BYOIInterpreters) {
        if ($PathLower -ne "" -and $PathLower -notlike "*\program files*") { return "CRITICAL" }
        return "SUSPICIOUS"
    }

    # 3. Windows script hosts from wrong location
    if ($NameLower -in $WindowsInterpreters) {
        if ($PathLower -ne "" -and
            $PathLower -notlike "*\system32\*" -and
            $PathLower -notlike "*\syswow64\*" -and
            $PathLower -notlike "*\windowsapps\*") {
            return "CRITICAL"
        }
        return "SUSPICIOUS"
    }

    # 4. LOLBins
    if ($NameLower -in $LOLBins) { return "SUSPICIOUS" }

    # 5. AppData execution (non-temp - temp already caught above)
    if ($PathLower -like "*\appdata\*") { return "SUSPICIOUS" }

    return "UNKNOWN"
}

# --- LOG ROTATION ---
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) { New-Item -ItemType Directory -Path $ArchiveFolder | Out-Null }
        $ArchiveName = "Harbinger_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# --- INITIALIZE LOG ---
if (-not (Test-Path $LogFile)) {
    "--- HARBINGER LOG STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- MONITORING: Process Creation + Interpreter + LOLBin ---`n" | Out-File $LogFile -Append -Encoding UTF8
}

# --- LOAD OR INITIALIZE BASELINE ---
$Baseline = @{}
if (Test-Path $BaselineFile) {
    try {
        $Json = Get-Content $BaselineFile -Encoding UTF8 | ConvertFrom-Json
        if ($Json -and $Json.PSObject) {
            $Json.PSObject.Properties | ForEach-Object { $Baseline[$_.Name] = $_.Value }
        }
        Write-Host "[+] Baseline loaded: $($Baseline.Count) known processes" -ForegroundColor Green
    } catch {
        Write-Host "[!] Baseline load failed - starting fresh." -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] No baseline found - all processes will log as UNKNOWN until established." -ForegroundColor Yellow
}

# --- STARTUP SNAPSHOT ---
Write-Host "--- [HARBINGER | CAPTURING STARTUP SNAPSHOT] ---" -ForegroundColor Cyan
Write-Host "[i] Running on PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
Write-Host "Reading all running processes..." -ForegroundColor DarkGray

try {
    $AllProcs   = Get-CimInstance Win32_Process -ErrorAction Stop
    $ProcLookup     = @{}
    $ProcPathLookup = @{}
    $ProcCmdLookup  = @{}
    foreach ($P in $AllProcs) {
        $ProcLookup[$P.ProcessId]     = $P.Name
        $ProcPathLookup[$P.ProcessId] = $P.ExecutablePath
        $ProcCmdLookup[$P.ProcessId]  = $P.CommandLine
    }

    Write-Host "[+] Found $($AllProcs.Count) running processes" -ForegroundColor Green
    "--- STARTUP SNAPSHOT AT $(Get-Date) | $($AllProcs.Count) processes ---" | Out-File $LogFile -Append -Encoding UTF8

    foreach ($Proc in $AllProcs) {
        $PName      = $Proc.Name
        $NameKey    = ($PName -replace '\.exe$', '').ToLower()
        $PPath      = if ($Proc.ExecutablePath) { $Proc.ExecutablePath } else { "" }
        $PCmd       = if ($Proc.CommandLine)    { $Proc.CommandLine }    else { "" }
        $PPID       = $Proc.ParentProcessId
        $ParentName = if ($ProcLookup.ContainsKey($PPID)) { $ProcLookup[$PPID] } else { "Unknown" }
        $Severity   = Get-ProcessSeverity $NameKey $PPath

        # TrustedParentChildMap override (parent path + parent CMD + child path + child CMD)
        $ParentExe = $ProcPathLookup[$PPID]
        $ParentCmd = $ProcCmdLookup[$PPID]
        if ($ParentExe) {
            $PHash = Get-PathHash $ParentExe
            if ($TrustedParentChildMap.ContainsKey($PHash)) {
                $Entry   = $TrustedParentChildMap[$PHash]
                $PCmdPat = if ($Entry.ParentCmd) { Decode-Pattern $Entry.ParentCmd } else { $null }
                $PCmdOk  = (-not $PCmdPat) -or ($ParentCmd -like $PCmdPat)
                if ($PCmdOk -and $PPath) {
                    $CHash = Get-PathHash $PPath
                    if ($Entry.Children.ContainsKey($CHash)) {
                        $CCmdPat = Decode-Pattern $Entry.Children[$CHash]
                        if (-not $CCmdPat -or $PCmd -like $CCmdPat) { $Severity = "OK" }
                    }
                }
            }
        }

        Write-Log $Severity "STARTUP: $PName | PID: $($Proc.ProcessId) | Parent: $ParentName ($PPID) | Path: $PPath | CMD: $PCmd"

        if (-not $Baseline.ContainsKey($NameKey)) { $Baseline[$NameKey] = 0 }
        $Baseline[$NameKey]++
    }

    "--- END SNAPSHOT ---`n" | Out-File $LogFile -Append -Encoding UTF8
    Write-Host "[+] Startup snapshot logged to $LogFile" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not capture startup snapshot: $($_.Exception.Message)" -ForegroundColor Yellow
}

# --- SAVE BASELINE AFTER SNAPSHOT ---
try { $Baseline | ConvertTo-Json | Out-File $BaselineFile -Encoding UTF8 } catch {}

# --- REGISTER EVENT SUBSCRIPTION ---
Write-Host "`n--- [REGISTERING PROCESS WATCHER] ---" -ForegroundColor Cyan
$Query = "SELECT * FROM Win32_ProcessStartTrace"

try {
    if ($PSMajor -ge 7) {
        Write-Host "[i] Using CIM event subscription (PS 7+)" -ForegroundColor DarkGray
        Register-CimIndicationEvent -Query $Query -SourceIdentifier "HarbingerProcess" -ErrorAction Stop
    } else {
        Write-Host "[i] Using WMI event subscription (PS 5.1)" -ForegroundColor DarkGray
        Register-WmiEvent -Query $Query -SourceIdentifier "HarbingerProcess" -ErrorAction Stop
    }
    Write-Host "[+] Process watcher registered" -ForegroundColor Green
} catch {
    Write-Host "[!] FAILED: Could not register process watcher." -ForegroundColor Red
    Write-Host "    Ensure this script is running as Administrator." -ForegroundColor Red
    Write-Host "    Error: $($_.Exception.Message)" -ForegroundColor Red
    Write-Log "CRITICAL" "WATCHER REGISTRATION FAILED: $($_.Exception.Message)"
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "--- [MONITORING STARTED | $(Get-Date -Format 'HH:mm:ss')] ---`n" -ForegroundColor Cyan

$EventCount      = 0
$LastHeartbeat   = Get-Date
$ScriptStartTime = Get-Date
$CycleCount      = 0

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "harbinger"
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

# --- MAIN EVENT LOOP ---
while ($true) {
    $CycleCount++
    $SharedState.CycleCount = $CycleCount
    $NewEvent = Wait-Event -SourceIdentifier "HarbingerProcess" -Timeout 5

    if ($NewEvent) {
        $EventCount++
        $Proc  = $NewEvent.SourceEventArgs.NewEvent
        $PName = $Proc.ProcessName
        $ProcID = $Proc.ProcessID
        $PPID   = $Proc.ParentProcessID
        Remove-Event -EventIdentifier $NewEvent.EventIdentifier

        # Enrich: path + cmdline (process may have already exited)
        $PPath = ""
        $PCmd  = ""
        try {
            $PInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcID" -ErrorAction SilentlyContinue
            if ($PInfo) {
                $PPath = if ($PInfo.ExecutablePath) { $PInfo.ExecutablePath } else { "" }
                $PCmd  = if ($PInfo.CommandLine)    { $PInfo.CommandLine }    else { "" }
            }
        } catch {}

        # Resolve parent name
        $ParentName = "Unknown"
        try {
            $ParentProc = Get-Process -Id $PPID -ErrorAction SilentlyContinue
            if ($ParentProc) { $ParentName = $ParentProc.Name }
        } catch {}

        $NameKey  = ($PName -replace '\.exe$', '').ToLower()
        $Severity = Get-ProcessSeverity $NameKey $PPath

        # TrustedParentChildMap override (parent path + parent CMD + child path + child CMD)
        try {
            $PI = Get-CimInstance Win32_Process -Filter "ProcessId = $PPID" -ErrorAction SilentlyContinue
            if ($PI -and $PI.ExecutablePath) {
                $PHash = Get-PathHash $PI.ExecutablePath
                if ($TrustedParentChildMap.ContainsKey($PHash)) {
                    $Entry   = $TrustedParentChildMap[$PHash]
                    $PCmdPat = if ($Entry.ParentCmd) { Decode-Pattern $Entry.ParentCmd } else { $null }
                    $PCmdOk  = (-not $PCmdPat) -or ($PI.CommandLine -like $PCmdPat)
                    if ($PCmdOk -and $PPath) {
                        $CHash = Get-PathHash $PPath
                        if ($Entry.Children.ContainsKey($CHash)) {
                            $CCmdPat = Decode-Pattern $Entry.Children[$CHash]
                            if (-not $CCmdPat -or $PCmd -like $CCmdPat) { $Severity = "OK" }
                        }
                    }
                }
            }
        } catch {}

        # New to baseline = UNKNOWN minimum
        if (-not $Baseline.ContainsKey($NameKey)) {
            if ($Severity -eq "OK") { $Severity = "UNKNOWN" }
            $Baseline[$NameKey] = 1
            try { $Baseline | ConvertTo-Json | Out-File $BaselineFile -Encoding UTF8 } catch {}
        } else {
            $Baseline[$NameKey]++
        }

        $Message = "NEW PROCESS: $PName | PID: $ProcID | Parent: $ParentName ($PPID) | Path: $PPath | CMD: $PCmd"
        Write-Log $Severity $Message

        $Now   = Get-Date -Format "HH:mm:ss"
        $Color = Get-SeverityColor $Severity
        Write-Host "[$Now] [$Severity] $PName (PID: $ProcID) | Parent: $ParentName | Path: $PPath" -ForegroundColor $Color
        if ($PCmd -and ($Severity -eq "SUSPICIOUS" -or $Severity -eq "CRITICAL")) {
            Write-Host "       CMD: $PCmd" -ForegroundColor DarkGray
        }

        $LastHeartbeat = Get-Date

    } else {
        # Heartbeat when idle
        if (((Get-Date) - $LastHeartbeat).TotalSeconds -ge $HeartbeatSecs) {
            $Now = Get-Date -Format "HH:mm:ss"
            Write-Host "[$Now] Monitoring active | Events this session: $EventCount" -ForegroundColor DarkGray
            $LastHeartbeat = Get-Date
        }
    }

}
