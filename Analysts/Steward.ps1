# ============================================================
# STEWARD.ps1 - System Resource Monitor
# Part of Home SOC Suite
# Quartermaster shortcut
# ============================================================

# --- ENCODING FIX ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# --- VERSION ADAPTIVE DISPLAY ---
if ($PSVersionTable.PSVersion.Major -ge 7) {
    $BarFilled = "█"
    $BarEmpty  = "░"
} else {
    $BarFilled = "#"
    $BarEmpty  = "-"
}

# --- CONFIGURATION ---
$SOCPath     = "$env:USERPROFILE\Desktop\SOC"
$LogFile          = "$SOCPath\Logs\Steward_Log.txt"
$ArchiveFolder    = "$SOCPath\Logs\Archives"
$BaselineFile     = "$SOCPath\Config\Steward_Baseline.json"
$TopProcesses     = 5
$RefreshSeconds   = 10
$ProcessorCount   = (Get-CimInstance Win32_Processor).NumberOfLogicalProcessors

# --- THRESHOLDS ---
$CPUCritical      = 90
$CPUSuspicious    = 70
$CPUUnknown       = 40
$RAMCritical      = 95

# --- FUNCTIONS ---
function Write-Log($Severity, $Message) {
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Timestamp] [$Severity] $Message" | Out-File $LogFile -Append -Encoding UTF8
}

function Get-RAMPercent {
    $OS = Get-CimInstance Win32_OperatingSystem
    return [math]::Round((($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / $OS.TotalVisibleMemorySize) * 100, 1)
}

function Get-RAMUsedGB {
    $OS = Get-CimInstance Win32_OperatingSystem
    return [math]::Round(($OS.TotalVisibleMemorySize - $OS.FreePhysicalMemory) / 1MB, 2)
}

function Get-TotalRAMGB {
    $OS = Get-CimInstance Win32_OperatingSystem
    return [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
}

function Draw-Bar($Percent, $Width = 10) {
    $Filled = [math]::Round(($Percent / 100) * $Width)
    $Empty  = $Width - $Filled
    return ("[$($BarFilled * $Filled)$($BarEmpty * $Empty)]")
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

# --- LOG ROTATION ---
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) {
            New-Item -ItemType Directory -Path $ArchiveFolder
        }
        $ArchiveName = "Steward_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# --- INITIALIZE LOG ---
if (-not (Test-Path $LogFile)) {
    "--- STEWARD LOG STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- BASELINE MODE: Collecting data for threshold establishment ---`n" | Out-File $LogFile -Append -Encoding UTF8
}

# --- LOAD OR INITIALIZE BASELINE ---
$Baseline = @{}
if (Test-Path $BaselineFile) {
    try {
        $Baseline = Get-Content $BaselineFile -Encoding UTF8 | ConvertFrom-Json 
        Write-Host "[+] Baseline loaded from $BaselineFile" -ForegroundColor Green
    } catch {
        Write-Host "[!] Could not load baseline, starting fresh." -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] No baseline found - running in collection mode." -ForegroundColor Yellow
    Write-Host "    Run for one month then analyze Steward_Baseline.json" -ForegroundColor DarkGray
}

Start-Sleep -Seconds 2

# --- MAIN MONITORING LOOP ---
$SampleCount = 0

while ($true) {
    Clear-Host
    $Now = Get-Date -Format "HH:mm:ss"
    $SampleCount++
    Write-Host "--- [STEWARD DASHBOARD | $Now | Sample: $SampleCount] ---" -ForegroundColor Cyan

    # --- SECTION 1: OVERALL SYSTEM HEALTH ---
    $CPUTotal = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
    $RAMPct   = Get-RAMPercent
    $RAMUsed  = Get-RAMUsedGB
    $RAMTotal = Get-TotalRAMGB

    Write-Host "`n--- [SECTION 1: SYSTEM HEALTH] ---" -ForegroundColor Cyan

    $CPUColor = if ($CPUTotal -ge $CPUCritical) { "Red" } elseif ($CPUTotal -ge 70) { "DarkYellow" } elseif ($CPUTotal -ge 40) { "Yellow" } else { "Green" }
    $RAMColor = if ($RAMPct -ge $RAMCritical) { "Red" } elseif ($RAMPct -ge 80) { "DarkYellow" } elseif ($RAMPct -ge 60) { "Yellow" } else { "Green" }

    Write-Host "CPU Total : $(Draw-Bar $CPUTotal) $CPUTotal%" -ForegroundColor $CPUColor
    Write-Host "RAM Total : $(Draw-Bar $RAMPct) $RAMPct% ($RAMUsed GB / $RAMTotal GB)" -ForegroundColor $RAMColor

    # --- SECTION 2: TOP CPU CONSUMERS ---
    Write-Host "`n--- [SECTION 2: TOP $TopProcesses CPU CONSUMERS] ---" -ForegroundColor Cyan

    try {
        $CPUCounters = Get-Counter '\Prozess(*)\Prozessorzeit (%)' -SampleInterval 1 -MaxSamples 2 -ErrorAction SilentlyContinue

        $CPUSample = $CPUCounters.CounterSamples | Where-Object {
            $_.InstanceName -ne '_total' -and
            $_.InstanceName -ne 'idle' -and
            $_.CookedValue -gt 0
        }

        $CPUResults = $CPUSample | ForEach-Object {
            $CPUPercent = [math]::Round($_.CookedValue / $ProcessorCount, 1)
            $ProcName   = $_.InstanceName
            $ProcRAM    = (Get-Process -Name $ProcName -ErrorAction SilentlyContinue |
                          Measure-Object WorkingSet64 -Sum).Sum
            $PRAM = [math]::Round($ProcRAM / 1MB, 1)

            [PSCustomObject]@{
                Name       = $ProcName
                CPUPercent = $CPUPercent
                RAM        = $PRAM
            }
        }

        $TopCPU = $CPUResults | Sort-Object CPUPercent -Descending | Select-Object -First $TopProcesses

        foreach ($Proc in $TopCPU) {
            $PName    = $Proc.Name.PadRight(20)
            $Severity = "OK"

            if ($Proc.CPUPercent -ge $CPUCritical)       { $Severity = "CRITICAL" }
            elseif ($Proc.CPUPercent -ge $CPUSuspicious)  { $Severity = "SUSPICIOUS" }
            elseif ($Proc.CPUPercent -ge $CPUUnknown)     { $Severity = "UNKNOWN" }

            $Color = Get-SeverityColor $Severity
            Write-Host "[$Severity] $PName CPU: $($Proc.CPUPercent.ToString().PadLeft(6))%  RAM: $($Proc.RAM) MB" -ForegroundColor $Color

            if ($Severity -ne "OK") {
                Write-Log $Severity "HIGH CPU: $($Proc.Name) at $($Proc.CPUPercent)% | RAM: $($Proc.RAM) MB"
            }

            # Update baseline
            $PKey = $Proc.Name.ToLower()
            if (-not ($Baseline.PSObject.Properties.Name -contains $PKey)) {
                $Baseline.$PKey = @{
                    cpu_samples = @($Proc.CPUPercent)
                    ram_samples = @($Proc.RAM)
                }
            } else {
                $Baseline.$PKey.cpu_samples += $Proc.CPUPercent
                $Baseline.$PKey.ram_samples += $Proc.RAM
            }
        }
    } catch {
        Write-Host "CPU counter data unavailable this cycle." -ForegroundColor DarkGray
    }

    # --- SECTION 3: TOP RAM CONSUMERS ---
    Write-Host "`n--- [SECTION 3: TOP $TopProcesses RAM CONSUMERS] ---" -ForegroundColor Cyan

    $TopRAM = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First $TopProcesses

    foreach ($Proc in $TopRAM) {
        $PName = $Proc.Name.PadRight(20)
        $PRAM  = [math]::Round($Proc.WorkingSet64 / 1MB, 1)
        $PGRAM = [math]::Round($Proc.WorkingSet64 / 1GB, 2)

        $RAMColor2 = if ($PRAM -gt 2000) { "DarkYellow" } elseif ($PRAM -gt 1000) { "Yellow" } else { "Green" }
        Write-Host "$PName RAM: $PRAM MB ($PGRAM GB)" -ForegroundColor $RAMColor2
    }

    # --- SECTION 4: DISK I/O ---
    Write-Host "`n--- [SECTION 4: DISK I/O] ---" -ForegroundColor Cyan

    try {
        $DiskData  = Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk | Where-Object { $_.Name -eq "_Total" }
        $DiskRead  = [math]::Round($DiskData.DiskReadBytesPersec / 1KB, 2)
        $DiskWrite = [math]::Round($DiskData.DiskWriteBytesPersec / 1KB, 2)

        $DiskColor = if ($DiskRead -gt 50000 -or $DiskWrite -gt 50000) { "Red" } elseif ($DiskRead -gt 10000 -or $DiskWrite -gt 10000) { "DarkYellow" } else { "Green" }
        Write-Host "Disk Read : $DiskRead KB/s" -ForegroundColor $DiskColor
        Write-Host "Disk Write: $DiskWrite KB/s" -ForegroundColor $DiskColor

        if ($DiskRead -gt 50000 -or $DiskWrite -gt 50000) {
            Write-Log "CRITICAL" "High disk I/O - Read: $DiskRead KB/s Write: $DiskWrite KB/s"
        }
    } catch {
        Write-Host "Disk I/O data unavailable" -ForegroundColor DarkGray
    }

    # --- SECTION 5: ALERTS ---
    Write-Host "`n--- [SECTION 5: ALERTS] ---" -ForegroundColor Cyan

    $AlertCount = 0

    if ($CPUTotal -ge $CPUCritical) {
        $Msg = "CRITICAL CPU: System at $CPUTotal%"
        Write-Host $Msg -ForegroundColor Red
        Write-Log "CRITICAL" $Msg
        $AlertCount++
    }

    if ($RAMPct -ge $RAMCritical) {
        $Msg = "CRITICAL RAM: System at $RAMPct%"
        Write-Host $Msg -ForegroundColor Red
        Write-Log "CRITICAL" $Msg
        $AlertCount++
    }

    if ($AlertCount -eq 0) {
        Write-Host "No critical alerts." -ForegroundColor Green
    }

    # --- SAVE BASELINE EVERY 10 SAMPLES ---
    if ($SampleCount % 10 -eq 0) {
        try {
            $Baseline | ConvertTo-Json -Depth 5 | Out-File $BaselineFile -Encoding UTF8
            Write-Host "[+] Baseline saved." -ForegroundColor DarkGray
        } catch {
            Write-Host "[!] Could not save baseline." -ForegroundColor DarkGray
        }
    }

    Write-Host "`nNext scan in $($RefreshSeconds - 1) seconds. Log: $LogFile"
    Start-Sleep -Seconds ($RefreshSeconds - 3)
}