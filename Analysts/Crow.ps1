# ============================================================
# CROW.ps1 - Bulwark Log Auditor
# Part of Home SOC Suite
# Lord Commander shortcut
# ============================================================

# ============================================================
# USER CONFIGURATION
# RootPath is auto-detected from the script location (Scripts folder -> SOC root)
# ============================================================
if ($PSScriptRoot) {
    $RootPath = Split-Path -Parent $PSScriptRoot
} else {
    $RootPath = "$env:USERPROFILE\Desktop\SOC"
}
$LogFile = "$RootPath\Logs\Bulwark_Log.txt"
$ReportFile = "$RootPath\Reports\Crow_Report.txt"

# --- START TRANSCRIPT ---
Start-Transcript -Path $ReportFile -Force | Out-Null

Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "       BULWARK AUDIT: WEEKLY SUMMARY" -ForegroundColor Cyan
Write-Host "       Generated on: $(Get-Date)" -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Gray

# --- CHECK LOG EXISTS ---
if (-not (Test-Path $LogFile)) {
    Write-Host "[!] ERROR: No Bulwark log found at $LogFile" -ForegroundColor Red
    Stop-Transcript
    Read-Host "Press Enter to exit"
    exit
}

# --- LOAD DATA ---
$Data = Get-Content $LogFile

# --- SECTION 1: LOG PERIOD ---
$FirstLine = $Data | Where-Object { $_ -match "BULWARK LOG STARTED" } | Select-Object -First 1
$LastEntry = $Data | Where-Object { $_ -match "^\[20" } | Select-Object -Last 1
Write-Host "[ Log Period ]" -ForegroundColor Yellow
Write-Host "Start : $($FirstLine -replace '--- ','')" -ForegroundColor White
Write-Host "Last Entry : $($LastEntry.Substring(0,[Math]::Min(25,$LastEntry.Length)))" -ForegroundColor White

# --- SECTION 2: BASELINE SUMMARY ---
Write-Host "`n[ Baseline Ports at Startup ]" -ForegroundColor Yellow
$BaselinePorts = $Data | Select-String "BASELINE PORT:"
Write-Host "Total baseline ports captured: $($BaselinePorts.Count)" -ForegroundColor White
$BaselinePorts | ForEach-Object {
    Write-Host "  $($_.ToString())" -ForegroundColor DarkGray
}

# --- SECTION 3: PORT ACTIVITY ---
Write-Host "`n[ Port Activity Summary ]" -ForegroundColor Yellow
$PortOpen  = $Data | Select-String "\[PORT OPEN\]"
$PortClose = $Data | Select-String "\[PORT CLOSE\]"
Write-Host "Total PORT OPEN events  : $($PortOpen.Count)" -ForegroundColor White
Write-Host "Total PORT CLOSE events : $($PortClose.Count)" -ForegroundColor White

# Most active processes opening ports
Write-Host "`n[ Top 5 Processes Opening Ports ]" -ForegroundColor Yellow
try {
    $PortOpen | ForEach-Object {
        $Line = $_.ToString()
        if ($Line -match "Process: (\w+)") { $Matches[1] }
    } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 |
    Format-Table Name, Count -HideTableHeaders
} catch { Write-Host "Could not calculate top processes." -ForegroundColor DarkGray }

# --- SECTION 4: AFTER HOURS ACTIVITY ---
Write-Host "[ After Hours Port Activity (00:00 - 06:00) ]" -ForegroundColor Yellow
$AfterHours = $Data | Where-Object {
    if ($_ -match "^\[(\d{4}-\d{2}-\d{2}) (\d{2}):\d{2}:\d{2}\] \[PORT OPEN\]") {
        [int]$Hour = $Matches[2]
        $Hour -ge 0 -and $Hour -lt 6
    }
}
if ($AfterHours) {
    Write-Host "WARNING: Port activity detected outside normal hours:" -ForegroundColor DarkYellow
    $AfterHours | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
} else {
    Write-Host "RESULT: No after hours port activity detected." -ForegroundColor Green
}

# --- SECTION 5: SEVERITY BREAKDOWN ---
Write-Host "`n[ Severity Breakdown ]" -ForegroundColor Yellow
$Critical   = $Data | Select-String "\[CRITICAL\]"
$Suspicious = $Data | Select-String "\[SUSPICIOUS\]"
$Unknown    = $Data | Select-String "\[UNKNOWN\]"
$OK         = $Data | Select-String "\[OK\]"

Write-Host "CRITICAL   : $($Critical.Count)"   -ForegroundColor Red
Write-Host "SUSPICIOUS : $($Suspicious.Count)" -ForegroundColor DarkYellow
Write-Host "UNKNOWN    : $($Unknown.Count)"    -ForegroundColor Yellow
Write-Host "OK         : $($OK.Count)"         -ForegroundColor Green

# --- SECTION 6: CRITICAL AND SUSPICIOUS EVENTS ---
if ($Critical.Count -gt 0 -or $Suspicious.Count -gt 0) {
    Write-Host "`n[ CRITICAL AND SUSPICIOUS EVENTS - REVIEW REQUIRED ]" -ForegroundColor Red
    $Critical | ForEach-Object {
        Write-Host "CRITICAL: $($_.ToString())" -ForegroundColor Red
    }
    $Suspicious | ForEach-Object {
        Write-Host "SUSPICIOUS: $($_.ToString())" -ForegroundColor DarkYellow
    }
} else {
    Write-Host "`n[ CRITICAL AND SUSPICIOUS EVENTS ]" -ForegroundColor Yellow
    Write-Host "RESULT: No critical or suspicious events detected." -ForegroundColor Green
}

# --- SECTION 7: PROCESSES WITH NO PATH ---
Write-Host "`n[ Processes With No Path Captured ]" -ForegroundColor Yellow
$NoPath = $Data | Where-Object {
    $_ -match "\[PORT OPEN\]" -and $_ -match "Path: $"
}
if ($NoPath) {
    Write-Host "WARNING: The following processes opened ports but had no path captured:" -ForegroundColor DarkYellow
    $NoPath | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
} else {
    Write-Host "RESULT: All port opening processes had paths captured." -ForegroundColor Green
}

# --- SECTION 8: SHORT LIVED PORTS ---
Write-Host "`n[ Short Lived Ports (opened and closed within 60 seconds) ]" -ForegroundColor Yellow
try {
    $OpenEvents  = @{}
    $ShortLived  = @()

    $Data | ForEach-Object {
        $Line = $_
        if ($Line -match "^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[PORT OPEN\] PORT OPENED: (\d+)") {
            $OpenEvents[$Matches[2]] = [datetime]$Matches[1]
        }
        if ($Line -match "^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[PORT CLOSE\] PORT CLOSED: (\d+)") {
            $Port      = $Matches[2]
            $CloseTime = [datetime]$Matches[1]
            if ($OpenEvents.ContainsKey($Port)) {
                $Duration = ($CloseTime - $OpenEvents[$Port]).TotalSeconds
                if ($Duration -le 60) {
                    $ShortLived += "Port $Port open for $Duration seconds"
                }
                $OpenEvents.Remove($Port)
            }
        }
    }

    if ($ShortLived) {
        Write-Host "WARNING: Short lived port activity detected:" -ForegroundColor DarkYellow
        $ShortLived | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
    } else {
        Write-Host "RESULT: No suspiciously short lived ports detected." -ForegroundColor Green
    }
} catch { Write-Host "Could not calculate short lived ports." -ForegroundColor DarkGray }

# --- FINALIZE ---
Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "REPORT SAVED TO: $ReportFile" -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Gray

Stop-Transcript | Out-Null
Write-Host "`n"
Read-Host "Audit Complete. Press Enter to close"