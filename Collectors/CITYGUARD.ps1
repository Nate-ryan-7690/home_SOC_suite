# ============================================================
# CITYGUARD.ps1 - Scheduled Task Monitor
# Part of Home SOC Suite
# City Guard shortcut
# ============================================================

# --- ENCODING ---
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
$LogFile         = "$RootPath\Logs\CityGuard_Log.txt"
$RootPathSeverity = if ($RootPathSource -eq "auto") { "OK" } else { "SUSPICIOUS" }
Add-Content $LogFile "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$RootPathSeverity] ROOTPATH_RESOLVED: $RootPath (source: $RootPathSource)" -Encoding UTF8
$ArchiveFolder   = "$RootPath\Logs\Archives"
$HealthFile      = "$RootPath\Config\CityGuard_Health.json"
$RefreshSeconds  = 300

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

function Get-TaskSeverity($Task) {
    $Action = $Task.Action   # snapshot property (string built by Get-TaskSnapshot)
    $Path   = $Task.Path     # snapshot property (TaskPath stored as .Path)

    # Critical indicators
    if ($Action -like "*AppData*Temp*" -or
        $Action -like "*AppData*Roaming*" -or
        $Action -like "*Users*Public*") {
        return "CRITICAL"
    }

    # Suspicious indicators
    if ($Path -eq "\" -or $Path -like "*\User*") {
        return "SUSPICIOUS"
    }

    # Unknown - system folders, could be legitimate
    return "UNKNOWN"
}

function Get-TaskSnapshot {
    $Tasks = Get-ScheduledTask | ForEach-Object {
        $Action = ""
        $Trigger = ""
        try { $Action  = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " | " } catch {}
        try { $Trigger = ($_.Triggers | ForEach-Object { $_.CimClass.CimClassName }) -join " | " } catch {}

        [PSCustomObject]@{
            Name        = $_.TaskName
            Path        = $_.TaskPath
            State       = $_.State
            Action      = $Action
            Trigger     = $Trigger
            FullKey     = "$($_.TaskPath)$($_.TaskName)"
        }
    }
    return $Tasks
}

# --- LOG ROTATION ---
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) {
            New-Item -ItemType Directory -Path $ArchiveFolder
        }
        $ArchiveName = "CityGuard_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# --- INITIALIZE LOG ---
if (-not (Test-Path $LogFile)) {
    "--- CITYGUARD LOG STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- SESSION SNAPSHOT ---" | Out-File $LogFile -Append -Encoding UTF8
}

# --- CAPTURE SESSION BASELINE ---
Write-Host "--- [CITYGUARD | CAPTURING TASK SNAPSHOT] ---" -ForegroundColor Cyan
Write-Host "Reading all scheduled tasks..." -ForegroundColor DarkGray

$BaselineSnapshot = Get-TaskSnapshot
$BaselineKeys     = $BaselineSnapshot | ForEach-Object { $_.FullKey }

Write-Host "[+] Snapshot captured: $($BaselineSnapshot.Count) tasks found" -ForegroundColor Green

# Log the full snapshot
"--- SNAPSHOT AT $(Get-Date) | Total Tasks: $($BaselineSnapshot.Count) ---" | Out-File $LogFile -Append -Encoding UTF8
$BaselineSnapshot | ForEach-Object {
    "SNAPSHOT: $($_.Path)$($_.Name) | State: $($_.State) | Trigger: $($_.Trigger) | Action: $($_.Action)" | Out-File $LogFile -Append -Encoding UTF8
}
"--- END SNAPSHOT ---`n" | Out-File $LogFile -Append -Encoding UTF8
Write-Log "INFO" "Session started - $($BaselineSnapshot.Count) tasks in baseline"

Write-Host "[+] Snapshot logged to $LogFile" -ForegroundColor Green
Write-Host "--- [MONITORING STARTED] ---`n" -ForegroundColor Cyan

Start-Sleep -Seconds 2
$ScriptStartTime = Get-Date
$CycleCount      = 0

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "cityguard"
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
    Write-Host "--- [CITYGUARD DASHBOARD | $Now] ---" -ForegroundColor Cyan
    Write-Host "Monitoring $($BaselineSnapshot.Count) scheduled tasks | Refresh: every $RefreshSeconds seconds`n" -ForegroundColor DarkGray

    # --- GET CURRENT TASKS ---
    $CurrentSnapshot = Get-TaskSnapshot
    $CurrentKeys     = $CurrentSnapshot | ForEach-Object { $_.FullKey }

    # --- CHECK FOR NEW TASKS ---
    Write-Host "--- [NEW TASKS] ---" -ForegroundColor Cyan
    $NewTasks = $CurrentSnapshot | Where-Object { $_.FullKey -notin $BaselineKeys }

    if ($NewTasks) {
        foreach ($Task in $NewTasks) {
            $Severity = Get-TaskSeverity $Task
            $Color    = Get-SeverityColor $Severity
            $Message  = "NEW TASK: $($Task.Path)$($Task.Name) | State: $($Task.State) | Trigger: $($Task.Trigger) | Action: $($Task.Action)"
            Write-Host "[$Severity] $Message" -ForegroundColor $Color
            Write-Log $Severity $Message
            # Add to baseline to avoid repeat alerts
            $BaselineSnapshot += $Task
            $BaselineKeys     += $Task.FullKey
        }
    } else {
        Write-Host "No new tasks detected." -ForegroundColor Green
    }

    # --- CHECK FOR DELETED TASKS ---
    Write-Host "`n--- [DELETED TASKS] ---" -ForegroundColor Cyan
    $DeletedKeys = $BaselineKeys | Where-Object { $_ -notin $CurrentKeys }

    if ($DeletedKeys) {
        foreach ($Key in $DeletedKeys) {
            $Task     = $BaselineSnapshot | Where-Object { $_.FullKey -eq $Key } | Select-Object -First 1
            $Message  = "TASK DELETED: $Key | Was: $($Task.Action)"
            Write-Host "[UNKNOWN] $Message" -ForegroundColor Yellow
            Write-Log "UNKNOWN" $Message
            # Remove from baseline
            $BaselineSnapshot = $BaselineSnapshot | Where-Object { $_.FullKey -ne $Key }
            $BaselineKeys     = $BaselineKeys     | Where-Object { $_ -ne $Key }
        }
    } else {
        Write-Host "No deleted tasks detected." -ForegroundColor Green
    }

    # --- CHECK FOR MODIFIED TASKS ---
    Write-Host "`n--- [MODIFIED TASKS] ---" -ForegroundColor Cyan
    $ModifiedCount = 0

    foreach ($Current in $CurrentSnapshot) {
        $Previous = $BaselineSnapshot | Where-Object { $_.FullKey -eq $Current.FullKey } | Select-Object -First 1
        if ($Previous) {
            if ($Current.Action -ne $Previous.Action -or $Current.Trigger -ne $Previous.Trigger) {
                $Severity = Get-TaskSeverity $Current
                $Color    = Get-SeverityColor $Severity
                $Message  = "MODIFIED TASK: $($Current.FullKey) | Old Action: $($Previous.Action) | New Action: $($Current.Action)"
                Write-Host "[$Severity] $Message" -ForegroundColor $Color
                Write-Log $Severity $Message
                $ModifiedCount++

                # Update baseline
                $BaselineSnapshot = $BaselineSnapshot | Where-Object { $_.FullKey -ne $Current.FullKey }
                $BaselineSnapshot += $Current
            }
        }
    }

    if ($ModifiedCount -eq 0) {
        Write-Host "No modified tasks detected." -ForegroundColor Green
    }

    # --- SUMMARY ---
    Write-Host "`n--- [SUMMARY] ---" -ForegroundColor Cyan
    Write-Host "Total tasks monitored : $($BaselineSnapshot.Count)" -ForegroundColor White
    Write-Host "New tasks this session : $(($BaselineKeys | Where-Object { $_ -notin ($BaselineSnapshot | Select-Object -First ($BaselineSnapshot.Count - $NewTasks.Count) | ForEach-Object { $_.FullKey }) }).Count)" -ForegroundColor White
    Write-Host "Log: $LogFile" -ForegroundColor DarkGray

    Write-Host "`nNext scan in $RefreshSeconds seconds."
    Start-Sleep -Seconds $RefreshSeconds
}