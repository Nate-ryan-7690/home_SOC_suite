# ============================================================
# CASTELLAN.ps1 - CityGuard Log Auditor
# Part of Home SOC Suite
# Castellan shortcut
# ============================================================

# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC — change this if you installed elsewhere
# ============================================================
$RootPath    = "$env:USERPROFILE\Desktop\SOC"
$LogFile    = "$RootPath\Logs\CityGuard_Log.txt"
$ReportFile = "$RootPath\Reports\Castellan_Report.txt"

# --- START TRANSCRIPT ---
Start-Transcript -Path $ReportFile -Force | Out-Null

Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "       CITYGUARD AUDIT: WEEKLY SUMMARY" -ForegroundColor Cyan
Write-Host "       Generated on: $(Get-Date)" -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Gray

# --- CHECK LOG EXISTS ---
if (-not (Test-Path $LogFile)) {
    Write-Host "[!] ERROR: No CityGuard log found at $LogFile" -ForegroundColor Red
    Stop-Transcript
    Read-Host "Press Enter to exit"
    exit
}

# --- LOAD DATA ---
$Data = Get-Content $LogFile -Encoding UTF8

# --- SECTION 1: SESSION SUMMARY ---
Write-Host "[ Session Summary ]" -ForegroundColor Yellow

$Sessions     = $Data | Select-String "Session started -"
$FirstLine    = $Data | Where-Object { $_ -match "CITYGUARD LOG STARTED" } | Select-Object -First 1
$LastEntry    = $Data | Where-Object { $_ -match "^\[20" } | Select-Object -Last 1

Write-Host "Log started    : $($FirstLine -replace '--- ','')" -ForegroundColor White
Write-Host "Last entry     : $($LastEntry.Substring(0,[Math]::Min(25,$LastEntry.Length)))" -ForegroundColor White
Write-Host "Total sessions : $($Sessions.Count)" -ForegroundColor White

# Show task count per session
if ($Sessions.Count -gt 0) {
    Write-Host "`nTask baseline per session:" -ForegroundColor White
    $Sessions | ForEach-Object {
        if ($_.ToString() -match "(\d+) tasks in baseline") {
            Write-Host "  $($_.ToString().Substring(0,25))... Tasks: $($Matches[1])" -ForegroundColor DarkGray
        }
    }
}

# --- SECTION 2: NEW TASKS ---
Write-Host "`n[ New Tasks Detected ]" -ForegroundColor Yellow

$NewTasks = $Data | Select-String "\[NEW TASK\]|\] NEW TASK:"

if ($NewTasks.Count -gt 0) {
    Write-Host "Total new tasks detected: $($NewTasks.Count)" -ForegroundColor DarkYellow
    $NewTasks | ForEach-Object {
        $Line = $_.ToString()
        if ($Line -match "\[CRITICAL\]")    { $Color = "Red" }
        elseif ($Line -match "\[SUSPICIOUS\]") { $Color = "DarkYellow" }
        else                                { $Color = "Yellow" }
        Write-Host "  $Line" -ForegroundColor $Color
    }
} else {
    Write-Host "RESULT: No new tasks detected." -ForegroundColor Green
}

# --- SECTION 3: DELETED TASKS ---
Write-Host "`n[ Deleted Tasks ]" -ForegroundColor Yellow

$DeletedTasks = $Data | Select-String "TASK DELETED:"

if ($DeletedTasks.Count -gt 0) {
    Write-Host "Total deleted tasks: $($DeletedTasks.Count)" -ForegroundColor DarkYellow
    $DeletedTasks | ForEach-Object {
        Write-Host "  $($_.ToString())" -ForegroundColor Yellow
    }
} else {
    Write-Host "RESULT: No deleted tasks detected." -ForegroundColor Green
}

# --- SECTION 4: MODIFIED TASKS ---
Write-Host "`n[ Modified Tasks ]" -ForegroundColor Yellow

$ModifiedTasks = $Data | Select-String "MODIFIED TASK:"

if ($ModifiedTasks.Count -gt 0) {
    Write-Host "Total modified tasks: $($ModifiedTasks.Count)" -ForegroundColor DarkYellow
    $ModifiedTasks | ForEach-Object {
        $Line = $_.ToString()
        if ($Line -match "\[CRITICAL\]")       { $Color = "Red" }
        elseif ($Line -match "\[SUSPICIOUS\]") { $Color = "DarkYellow" }
        else                                   { $Color = "Yellow" }
        Write-Host "  $Line" -ForegroundColor $Color
    }
} else {
    Write-Host "RESULT: No modified tasks detected." -ForegroundColor Green
}

# --- SECTION 5: AFTER HOURS CHANGES ---
Write-Host "`n[ After Hours Changes (00:00 - 06:00) ]" -ForegroundColor Yellow

$AfterHours = $Data | Where-Object {
    if ($_ -match "^\[(\d{4}-\d{2}-\d{2}) (\d{2}):\d{2}:\d{2}\]") {
        [int]$Hour = $Matches[2]
        ($Hour -ge 0 -and $Hour -lt 6) -and
        ($_ -match "NEW TASK|TASK DELETED|MODIFIED TASK")
    }
}

if ($AfterHours) {
    Write-Host "WARNING: Task changes detected outside normal hours:" -ForegroundColor Red
    $AfterHours | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
} else {
    Write-Host "RESULT: No after hours task changes detected." -ForegroundColor Green
}

# --- SECTION 6: RECURRING PATTERNS ---
Write-Host "`n[ Recurring Patterns ]" -ForegroundColor Yellow

try {
    $AllChanges = $Data | Where-Object { $_ -match "NEW TASK:|TASK DELETED:|MODIFIED TASK:" }

    $TaskNames = $AllChanges | ForEach-Object {
        if ($_ -match "(?:NEW TASK|TASK DELETED|MODIFIED TASK):\s*\\[^\|]+") {
            $Matches[0] -replace "(?:NEW TASK|TASK DELETED|MODIFIED TASK):\s*", ""
        }
    }

    $Recurring = $TaskNames | Group-Object | Where-Object { $_.Count -gt 1 }

    if ($Recurring) {
        Write-Host "WARNING: Tasks that changed multiple times:" -ForegroundColor DarkYellow
        $Recurring | ForEach-Object {
            Write-Host "  $($_.Name) - appeared $($_.Count) times" -ForegroundColor DarkYellow
        }
    } else {
        Write-Host "RESULT: No recurring patterns detected." -ForegroundColor Green
    }
} catch {
    Write-Host "Could not analyze recurring patterns." -ForegroundColor DarkGray
}

# --- FINALIZE ---
Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "REPORT SAVED TO: $ReportFile" -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Gray

Stop-Transcript | Out-Null
Write-Host "`n"
Read-Host "Audit Complete. Press Enter to close"