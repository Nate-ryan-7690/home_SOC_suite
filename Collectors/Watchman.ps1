# ============================================================
# WATCHMAN.ps1 - Power & Session Event Monitor
# Part of Home SOC Suite
# Watchman shortcut
# ============================================================

# --- ENCODING ---
chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC — change this if you installed elsewhere
# ============================================================
$RootPath        = "$env:USERPROFILE\Desktop\SOC"
$LogFile        = "$RootPath\Logs\Watchman_Log.txt"
$ArchiveFolder  = "$RootPath\Logs\Archives"
$HealthFile     = "$RootPath\Config\Watchman_Health.json"
$RefreshSeconds = 60
$LastEventTime  = $null

# --- EVENT IDs TO MONITOR ---
$PowerEventIDs = @(1, 42, 107, 41, 1074, 6005, 6006)

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

function Get-EventSeverity($EventID, $Hour) {
    # Unexpected shutdown is always critical
    if ($EventID -eq 41) { return "CRITICAL" }

    # Any power event between midnight and 6am is suspicious
    if ($Hour -ge 0 -and $Hour -lt 6) { return "SUSPICIOUS" }

    # Normal power events during day
    return "OK"
}

function Get-EventDescription($EventID) {
    switch ($EventID) {
        1     { return "System woke from sleep" }
        42    { return "System entering sleep" }
        107   { return "System resumed from sleep" }
        41    { return "UNEXPECTED SHUTDOWN - system crashed or lost power" }
        1074  { return "Clean shutdown or restart initiated" }
        6005  { return "System boot - Event Log service started" }
        6006  { return "System shutdown - Event Log service stopped" }
        default { return "Unknown power event" }
    }
}

# --- LOG ROTATION ---
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) {
            New-Item -ItemType Directory -Path $ArchiveFolder
        }
        $ArchiveName = "Watchman_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# --- INITIALIZE LOG ---
if (-not (Test-Path $LogFile)) {
    "--- WATCHMAN LOG STARTED: $(Get-Date) ---`n" | Out-File $LogFile -Encoding UTF8
}

# --- LOAD HISTORICAL EVENTS ON STARTUP ---
Write-Host "--- [WATCHMAN | LOADING HISTORICAL EVENTS] ---" -ForegroundColor Cyan
Write-Host "Reading System event log history..." -ForegroundColor DarkGray

try {
    $HistoricalEvents = Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -in $PowerEventIDs } |
        Sort-Object TimeCreated |
        Select-Object -Last 50

    Write-Host "[+] Found $($HistoricalEvents.Count) recent power events" -ForegroundColor Green

    # Log historical events not already in log
    $ExistingLog = if (Test-Path $LogFile) { Get-Content $LogFile -Encoding UTF8 } else { @() }

    foreach ($Event in $HistoricalEvents) {
        $Hour        = $Event.TimeCreated.Hour
        $Severity    = Get-EventSeverity $Event.Id $Hour
        $Description = Get-EventDescription $Event.Id
        $Timestamp   = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
        $Message     = "EventID $($Event.Id) | $Description | Time: $Timestamp"

        # Only log if not already recorded
        if (-not ($ExistingLog | Where-Object { $_.Contains("Time: $Timestamp") })) {
            Write-Log $Severity $Message
        }
    }

    # Set last event time to most recent historical event
    if ($HistoricalEvents.Count -gt 0) {
        $LastEventTime = ($HistoricalEvents | Select-Object -Last 1).TimeCreated
    }

    Write-Host "[+] Historical events logged" -ForegroundColor Green
} catch {
    Write-Host "[!] Could not load historical events: $($_.Exception.Message)" -ForegroundColor Yellow
}

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
    CollectorName   = "watchman"
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
    Write-Host "--- [WATCHMAN DASHBOARD | $Now] ---" -ForegroundColor Cyan

    # --- SECTION 1: RECENT POWER EVENTS ---
    Write-Host "`n--- [RECENT POWER EVENTS] ---" -ForegroundColor Cyan

    try {
        $RecentEvents = Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
            Where-Object { $_.Id -in $PowerEventIDs } |
            Sort-Object TimeCreated -Descending |
            Select-Object -First 10

        foreach ($Event in $RecentEvents) {
            $Hour        = $Event.TimeCreated.Hour
            $Severity    = Get-EventSeverity $Event.Id $Hour
            $Description = Get-EventDescription $Event.Id
            $Color       = Get-SeverityColor $Severity
            $Time        = $Event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")

            Write-Host "[$Severity] $Time | ID: $($Event.Id) | $Description" -ForegroundColor $Color

            # Log new events since last check
            if ($null -eq $LastEventTime -or $Event.TimeCreated -gt $LastEventTime) {
                $Message = "EventID $($Event.Id) | $Description | Time: $Time"
                Write-Log $Severity $Message

                if ($Severity -eq "CRITICAL") {
                    Write-Host "  *** CRITICAL: $Description ***" -ForegroundColor Red
                }
            }
        }

        # Update last event time
        if ($RecentEvents.Count -gt 0) {
            $LastEventTime = ($RecentEvents | Select-Object -First 1).TimeCreated
        }

    } catch {
        Write-Host "Could not read power events this cycle." -ForegroundColor DarkGray
    }

    # --- SECTION 2: CURRENT POWER STATE ---
    Write-Host "`n--- [CURRENT SYSTEM STATE] ---" -ForegroundColor Cyan

    $Uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    Write-Host "System uptime  : $([math]::Floor($Uptime.TotalHours))h $($Uptime.Minutes)m" -ForegroundColor Green
    Write-Host "Last boot      : $((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    Write-Host "Current time   : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White

    # --- SECTION 3: ALERTS ---
    Write-Host "`n--- [ALERTS] ---" -ForegroundColor Cyan

    # Check for unexpected shutdowns in recent history
    $Crashes = Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 41 } |
        Select-Object -First 3

    if ($Crashes) {
        Write-Host "WARNING: Recent unexpected shutdowns detected:" -ForegroundColor Red
        $Crashes | ForEach-Object {
            Write-Host "  $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')) - Unexpected shutdown" -ForegroundColor Red
        }
    } else {
        Write-Host "No unexpected shutdowns detected." -ForegroundColor Green
    }

    # Check for after hours activity today
    $Today       = (Get-Date).Date
    $AfterHours  = Get-WinEvent -LogName System -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Id -in $PowerEventIDs -and
            $_.TimeCreated -ge $Today -and
            $_.TimeCreated.Hour -ge 0 -and
            $_.TimeCreated.Hour -lt 6
        }

    if ($AfterHours) {
        Write-Host "SUSPICIOUS: After hours power activity detected today:" -ForegroundColor DarkYellow
        $AfterHours | ForEach-Object {
            Write-Host "  $($_.TimeCreated.ToString('HH:mm:ss')) - $(Get-EventDescription $_.Id)" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "No after hours activity today." -ForegroundColor Green
    }

    Write-Host "`nNext scan in $RefreshSeconds seconds. Log: $LogFile"
    Start-Sleep -Seconds $RefreshSeconds
}