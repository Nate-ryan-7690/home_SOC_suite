# ============================================================
# LEDGER.ps1 - Steward Log Auditor
# Part of Home SOC Suite
# Maester shortcut
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
$LogFile    = "$RootPath\Logs\Steward_Log.txt"
$ReportFile = "$RootPath\Reports\Ledger_Report.txt"

# --- START TRANSCRIPT ---
Start-Transcript -Path $ReportFile -Force | Out-Null

Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "       STEWARD AUDIT: WEEKLY SUMMARY" -ForegroundColor Cyan
Write-Host "       Generated on: $(Get-Date)" -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Gray

# --- CHECK LOG EXISTS ---
if (-not (Test-Path $LogFile)) {
    Write-Host "[!] ERROR: No Steward log found at $LogFile" -ForegroundColor Red
    Stop-Transcript
    Read-Host "Press Enter to exit"
    exit
}

# --- LOAD DATA ---
$Data = Get-Content $LogFile -Encoding UTF8

# --- SECTION 1: LOG PERIOD ---
$FirstLine  = $Data | Where-Object { $_ -match "STEWARD LOG STARTED" } | Select-Object -First 1
$LastEntry  = $Data | Where-Object { $_ -match "^\[20" } | Select-Object -Last 1

Write-Host "[ Log Period ]" -ForegroundColor Yellow
Write-Host "Start      : $($FirstLine -replace '--- ','')" -ForegroundColor White
Write-Host "Last Entry : $($LastEntry.Substring(0,[Math]::Min(25,$LastEntry.Length)))" -ForegroundColor White

# --- SECTION 2: SEVERITY BREAKDOWN ---
Write-Host "`n[ Severity Breakdown ]" -ForegroundColor Yellow

$Critical   = $Data | Select-String "\[CRITICAL\]"
$Suspicious = $Data | Select-String "\[SUSPICIOUS\]"
$Unknown    = $Data | Select-String "\[UNKNOWN\]"

Write-Host "CRITICAL   : $($Critical.Count)"   -ForegroundColor Red
Write-Host "SUSPICIOUS : $($Suspicious.Count)" -ForegroundColor DarkYellow
Write-Host "UNKNOWN    : $($Unknown.Count)"    -ForegroundColor Yellow

# --- SECTION 3: CRITICAL EVENTS ---
Write-Host "`n[ Critical Events - Review Required ]" -ForegroundColor Red

$SystemCritical = $Data | Select-String "\[CRITICAL\] CRITICAL"
$DiskCritical   = $Data | Select-String "\[CRITICAL\] High disk"
$ProcCritical   = $Data | Select-String "\[CRITICAL\] HIGH CPU"

if ($Critical.Count -gt 0) {
    Write-Host "System CPU/RAM spikes : $($SystemCritical.Count)" -ForegroundColor Red
    Write-Host "Disk I/O spikes       : $($DiskCritical.Count)"  -ForegroundColor Red
    Write-Host "Process CPU spikes    : $($ProcCritical.Count)"  -ForegroundColor Red
    Write-Host "`nFull critical entries:" -ForegroundColor Red
    $Critical | ForEach-Object { Write-Host "  $($_.ToString())" -ForegroundColor Red }
} else {
    Write-Host "RESULT: No critical events detected." -ForegroundColor Green
}

# --- SECTION 4: TOP CPU CONSUMERS ---
Write-Host "`n[ Top CPU Consumers ]" -ForegroundColor Yellow

try {
    $CPUEntries = $Data | Where-Object { $_ -match "HIGH CPU:" }

    $CPUData = $CPUEntries | ForEach-Object {
        if ($_ -match "HIGH CPU: (\S+) at ([\d,\.]+)%") {
            [PSCustomObject]@{
                Process    = $Matches[1]
                CPUPercent = [double]($Matches[2] -replace ',', '.')
            }
        }
    }

    if ($CPUData) {
        $CPUData | Group-Object Process | ForEach-Object {
            $Avg  = [math]::Round(($_.Group.CPUPercent | Measure-Object -Average).Average, 1)
            $Peak = [math]::Round(($_.Group.CPUPercent | Measure-Object -Maximum).Maximum, 1)
            [PSCustomObject]@{
                Process = $_.Name
                Count   = $_.Count
                Avg     = $Avg
                Peak    = $Peak
            }
        } | Sort-Object Peak -Descending | Select-Object -First 10 |
        ForEach-Object {
            $Color = if ($_.Peak -ge 90) { "Red" } elseif ($_.Peak -ge 70) { "DarkYellow" } else { "Yellow" }
            Write-Host "$($_.Process.PadRight(20)) Appearances: $($_.Count.ToString().PadLeft(4)) | Avg: $($_.Avg)% | Peak: $($_.Peak)%" -ForegroundColor $Color
        }
    } else {
        Write-Host "No CPU consumer data found." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "Could not analyze CPU data." -ForegroundColor DarkGray
}

# --- SECTION 5: RAM PATTERN ANALYSIS ---
Write-Host "`n[ RAM Pattern Analysis ]" -ForegroundColor Yellow

try {
    $RAMEntries = $Data | Where-Object { $_ -match "RAM:" }

    $RAMData = $RAMEntries | ForEach-Object {
        if ($_ -match "(\S+) at .+ \| RAM: ([\d,\.]+) MB" -or $_ -match "HIGH CPU: (\S+) at .+RAM: ([\d,\.]+)") {
            [PSCustomObject]@{
                Process = $Matches[1]
                RAM     = [double]($Matches[2] -replace ',', '.')
            }
        }
    }

    if ($RAMData) {
        $RAMData | Group-Object Process | ForEach-Object {
            $Min    = [math]::Round(($_.Group.RAM | Measure-Object -Minimum).Minimum, 1)
            $Max    = [math]::Round(($_.Group.RAM | Measure-Object -Maximum).Maximum, 1)
            $Avg    = [math]::Round(($_.Group.RAM | Measure-Object -Average).Average, 1)
            

            # Trend detection - check if RAM values are consistently growing
            $Values  = $_.Group.RAM
            $First   = ($Values | Select-Object -First 3 | Measure-Object -Average).Average
            $Last    = ($Values | Select-Object -Last 3 | Measure-Object -Average).Average
            $Trend   = if ($Last - $First -gt 200) { "WARNING - Growth detected" } else { "Stable" }

            $Color = if ($Trend -like "WARNING*") { "DarkYellow" } elseif ($Max -gt 3000) { "Yellow" } else { "Green" }

            Write-Host "$($_.Name.PadRight(20)) Min: $($Min)MB  Max: $($Max)MB  Avg: $($Avg)MB  Trend: $Trend" -ForegroundColor $Color
        } | Out-Null
    } else {
        Write-Host "No RAM data found." -ForegroundColor DarkGray
    }
} catch {
    Write-Host "Could not analyze RAM data." -ForegroundColor DarkGray
}

# --- SECTION 6: DISK I/O SUMMARY ---
Write-Host "`n[ Disk I/O Summary ]" -ForegroundColor Yellow

try {
    $DiskEntries = $Data | Where-Object { $_ -match "High disk I/O" }
    Write-Host "Total disk spikes logged: $($DiskEntries.Count)" -ForegroundColor White

    if ($DiskEntries.Count -gt 0) {
        $ReadValues  = $DiskEntries | ForEach-Object {
            if ($_ -match "Read: ([\d,\.]+) KB/s") { [double]($Matches[1] -replace ',', '.') }
        }
        $WriteValues = $DiskEntries | ForEach-Object {
            if ($_ -match "Write: ([\d,\.]+) KB/s") { [double]($Matches[1] -replace ',', '.') }
        }

        $PeakRead  = [math]::Round(($ReadValues  | Measure-Object -Maximum).Maximum, 2)
        $PeakWrite = [math]::Round(($WriteValues | Measure-Object -Maximum).Maximum, 2)

        Write-Host "Peak Read  : $PeakRead KB/s"  -ForegroundColor White
        Write-Host "Peak Write : $PeakWrite KB/s" -ForegroundColor White
    }
} catch {
    Write-Host "Could not analyze disk data." -ForegroundColor DarkGray
}

# --- SECTION 7: AFTER HOURS ACTIVITY ---
Write-Host "`n[ After Hours Activity (00:00 - 06:00) ]" -ForegroundColor Yellow

$AfterHours = $Data | Where-Object {
    if ($_ -match "^\[(\d{4}-\d{2}-\d{2}) (\d{2}):\d{2}:\d{2}\]") {
        [int]$Hour = $Matches[2]
        $Hour -ge 0 -and $Hour -lt 6
    }
}

if ($AfterHours) {
    Write-Host "WARNING: Resource activity detected outside normal hours:" -ForegroundColor DarkYellow
    $AfterHours | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
} else {
    Write-Host "RESULT: No after hours activity detected." -ForegroundColor Green
}

# --- SECTION 8: CORRELATION DETECTION ---
Write-Host "`n[ Correlation Detection ]" -ForegroundColor Yellow

try {
    $Correlations = @()

    $Data | ForEach-Object {
        if ($_ -match "^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[CRITICAL\] CRITICAL CPU") {
            $Timestamp = $Matches[1]
            $NearbyDisk = $Data | Where-Object {
                if ($_ -match "^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] \[CRITICAL\] High disk") {
                    $T = [datetime]$Matches[1]
                    $Diff = [math]::Abs(([datetime]$Timestamp - $T).TotalSeconds)
                    $Diff -le 30
                }
            }
            if ($NearbyDisk) {
                $Correlations += "[$Timestamp] CPU spike correlated with disk spike within 30 seconds"
            }
        }
    }

    if ($Correlations) {
        Write-Host "WARNING: Correlated CPU and disk spikes detected:" -ForegroundColor DarkYellow
        $Correlations | Select-Object -Unique | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkYellow }
    } else {
        Write-Host "RESULT: No correlated spikes detected." -ForegroundColor Green
    }
} catch {
    Write-Host "Could not calculate correlations." -ForegroundColor DarkGray
}

# --- FINALIZE ---
Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "REPORT SAVED TO: $ReportFile" -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Gray

Stop-Transcript | Out-Null
Write-Host "`n"
Read-Host "Audit Complete. Press Enter to close"