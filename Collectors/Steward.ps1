# ============================================================
# STEWARD.ps1 - System Resource Monitor
# Part of Home SOC Suite
# Quartermaster shortcut
# ============================================================
#
# SUPPORTED OS LANGUAGES (CPU counter path detection):
# -------------------------------------------------------
# Language         Counter Path
# --------         ------------
# English          \Process(*)\% Processor Time
# German           \Prozess(*)\Prozessorzeit (%)
# French           \Processus(*)\% temps processeur
# Spanish          \Proceso(*)\% de tiempo de procesador
# Italian          \Processo(*)\% Tempo processore
# Portuguese       \Processo(*)\% de Tempo do Processador
# Russian          \Процесс(*)\% загруженности процессора
# Chinese (Simp.)  \Process(*)\% Processor Time  (typically English)
#
# To add support for another language, add the localized counter
# path to the $PathsToTry array in Get-WorkingCounterPath below.
#
# VERSION NOTES:
# PS 7+  : Individual Write-Host calls, Clear-Host, 10 second refresh
#          SampleInterval 1, MaxSamples 3, full per-process RAM lookup
# PS 5.1 : Single-write ANSI string buffer, Clear-Host, 10 second refresh
#          SampleInterval 1, MaxSamples 2, cached RAM lookup to reduce lag
# ============================================================
 
# --- ENCODING FIX ---
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
 
# --- VERSION DETECTION ---
$PSMajor = $PSVersionTable.PSVersion.Major
 
# --- VERSION ADAPTIVE SETTINGS ---
if ($PSMajor -ge 7) {
    $BarFilled      = "█"
    $BarEmpty       = "░"
} else {
    $BarFilled      = "#"
    $BarEmpty       = "-"
}
 
$RefreshSeconds = 10
 
# --- ANSI COLOR TABLE (PS 5.1 string-buffer branch) ---
$e = [char]27
$C = @{
    Reset      = "$e[0m"
    Cyan       = "$e[36m"
    Green      = "$e[32m"
    Yellow     = "$e[33m"
    DarkYellow = "$e[93m"
    Red        = "$e[31m"
    DarkGray   = "$e[90m"
    White      = "$e[37m"
}
 
# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC — change this if you installed elsewhere
# ============================================================
$RootPath          = "$env:USERPROFILE\Desktop\SOC"
$LogFile          = "$RootPath\Logs\Steward_Log.txt"
$ArchiveFolder    = "$RootPath\Logs\Archives"
$BaselineFile     = "$RootPath\Config\Steward_Baseline.json"
$StatusFile       = "$RootPath\Config\Steward_Status.json"
$TopProcesses     = 5
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
 
function Get-SeverityANSI($Severity) {
    switch ($Severity) {
        "OK"         { return $C.Green }
        "UNKNOWN"    { return $C.Yellow }
        "SUSPICIOUS" { return $C.DarkYellow }
        "CRITICAL"   { return $C.Red }
        default      { return $C.White }
    }
}
 
function Get-WorkingCounterPath {
    $PathsToTry = @(
        "\Process(*)\% Processor Time",           # English / Chinese (Simplified)
        "\Prozess(*)\Prozessorzeit (%)",           # German
        "\Processus(*)\% temps processeur",        # French
        "\Proceso(*)\% de tiempo de procesador",   # Spanish
        "\Processo(*)\% Tempo processore",         # Italian
        "\Processo(*)\% de Tempo do Processador",  # Portuguese
        "\Процесс(*)\% загруженности процессора"   # Russian
    )
    foreach ($Path in $PathsToTry) {
        try {
            $Test = Get-Counter $Path -SampleInterval 1 -MaxSamples 1 -ErrorAction Stop
            if ($Test) { return $Path }
        } catch {}
    }
    return $null
}
 
function ConvertTo-Hashtable {
    param([Parameter(ValueFromPipeline)]$InputObject)
    $Hash = @{}
    if ($InputObject -and $InputObject.PSObject) {
        foreach ($Prop in $InputObject.PSObject.Properties) {
            $Hash[$Prop.Name] = $Prop.Value
        }
    }
    return $Hash
}
 
# --- DETECT COUNTER PATH AT STARTUP ---
Write-Host "Detecting CPU counter path..." -ForegroundColor DarkGray
$CPUCounterPath = Get-WorkingCounterPath
 
if ($CPUCounterPath) {
    Write-Host "[+] Counter path detected: $CPUCounterPath" -ForegroundColor Green
} else {
    Write-Host "[!] Could not detect CPU counter path - Section 2 will be unavailable." -ForegroundColor Red
}
 
Write-Host "[i] Running on PowerShell $($PSVersionTable.PSVersion)" -ForegroundColor DarkGray
 
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
        $JsonObj  = Get-Content $BaselineFile -Encoding UTF8 | ConvertFrom-Json
        $Baseline = ConvertTo-Hashtable $JsonObj
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
$SampleCount  = 0
$RAMCache     = @{}
$RAMCacheTick = 0
 
while ($true) {
    $SampleCount++
    $Now = Get-Date -Format "HH:mm:ss"
 
    # --- COLLECT SYSTEM DATA ---
    $CPUTotal = [math]::Round((Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average, 1)
    $RAMPct   = Get-RAMPercent
    $RAMUsed  = Get-RAMUsedGB
    $RAMTotal = Get-TotalRAMGB
 
    # --- COLLECT CPU PROCESS DATA ---
    $TopCPU = $null
    if ($CPUCounterPath) {
        try {
            if ($PSMajor -ge 7) {
                $CPUCounters = Get-Counter $CPUCounterPath -SampleInterval 1 -MaxSamples 3 -ErrorAction Stop
                $CPUSample   = $CPUCounters.CounterSamples | Where-Object {
                    $_.InstanceName -ne '_total' -and $_.InstanceName -ne 'idle'
                }
                $CPUResults = $CPUSample | Group-Object InstanceName | ForEach-Object {
                    $CPUPercent   = [math]::Round(($_.Group | Measure-Object CookedValue -Average).Average / $ProcessorCount, 2)
                    $ProcName     = $_.Name
                    $ProcBaseName = $ProcName -replace '#\d+$', ''
                    $ProcRAM      = (Get-Process -Name $ProcBaseName -ErrorAction SilentlyContinue |
                                    Measure-Object WorkingSet64 -Sum).Sum
                    $PRAM = [math]::Round($ProcRAM / 1MB, 1)
                    [PSCustomObject]@{ Name = $ProcName; CPUPercent = $CPUPercent; RAM = $PRAM }
                }
            } else {
                $CPUCounters = Get-Counter $CPUCounterPath -SampleInterval 1 -MaxSamples 2 -ErrorAction Stop
                $CPUSample   = $CPUCounters.CounterSamples | Where-Object {
                    $_.InstanceName -ne '_total' -and $_.InstanceName -ne 'idle'
                }
                $RAMCacheTick++
                if ($RAMCacheTick -ge 5 -or $RAMCache.Count -eq 0) {
                    $RAMCache = @{}
                    Get-Process -ErrorAction SilentlyContinue | ForEach-Object {
                        $Key = $_.Name.ToLower()
                        if (-not $RAMCache.ContainsKey($Key)) { $RAMCache[$Key] = 0 }
                        $RAMCache[$Key] += $_.WorkingSet64
                    }
                    $RAMCacheTick = 0
                }
                $CPUResults = $CPUSample | Group-Object InstanceName | ForEach-Object {
                    $CPUPercent   = [math]::Round(($_.Group | Measure-Object CookedValue -Average).Average / $ProcessorCount, 2)
                    $ProcName     = $_.Name
                    $ProcBaseName = ($ProcName -replace '#\d+$', '').ToLower()
                    $RawRAM       = if ($RAMCache.ContainsKey($ProcBaseName)) { $RAMCache[$ProcBaseName] } else { 0 }
                    $PRAM         = [math]::Round($RawRAM / 1MB, 1)
                    [PSCustomObject]@{ Name = $ProcName; CPUPercent = $CPUPercent; RAM = $PRAM }
                }
            }
            $TopCPU = $CPUResults | Sort-Object CPUPercent -Descending | Select-Object -First $TopProcesses
            #Log All Processes above threshold regardless of top 5 display
            $CPUResults | Where-Object { $_.CPUPercent -ge $CPUUnknown } | ForEach-Object {
                $Severity = "OK"
                if ($_.CPUPercent -ge $CPUCritical)      { $Severity = "CRITICAL" }
                elseif ($_.CPUPercent -ge $CPUSuspicious) { $Severity = "SUSPICIOUS" }
                elseif ($_.CPUPercent -ge $CPUUnknown)    { $Severity = "UNKNOWN" }
                if ($Severity -ne "OK") {
                    Write-Log $Severity "HIGH CPU: $($_.Name) at $($_.CPUPercent)% | RAM: $($_.RAM) MB"
                }
            }
        } catch {}
    }
 
    # --- COLLECT RAM PROCESS DATA ---
    $TopRAM = Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First $TopProcesses
 
    # --- COLLECT DISK DATA ---
    $DiskRead  = $null
    $DiskWrite = $null
    try {
        $DiskData  = Get-CimInstance Win32_PerfFormattedData_PerfDisk_LogicalDisk | Where-Object { $_.Name -eq "_Total" }
        $DiskRead  = [math]::Round($DiskData.DiskReadBytesPersec / 1KB, 2)
        $DiskWrite = [math]::Round($DiskData.DiskWriteBytesPersec / 1KB, 2)
    } catch {}
 
    # --- UPDATE BASELINE ---
    if ($TopCPU) {
        foreach ($Proc in $TopCPU) {
            $PKey = $Proc.Name.ToLower()
            if (-not $Baseline.ContainsKey($PKey)) {
                $Baseline[$PKey] = @{ cpu_samples = @($Proc.CPUPercent); ram_samples = @($Proc.RAM) }
            } else {
                $Baseline[$PKey].cpu_samples += $Proc.CPUPercent
                $Baseline[$PKey].ram_samples += $Proc.RAM
            }
        }
    }
 
    # --- SAVE BASELINE EVERY 10 SAMPLES ---
    if ($SampleCount % 10 -eq 0) {
        try {
            $Baseline | ConvertTo-Json -Depth 5 | Out-File $BaselineFile -Encoding UTF8
        } catch {}
    }
 
    # --- LOG ALERTS ---
    if ($CPUTotal -ge $CPUCritical) { Write-Log "CRITICAL" "HIGH CPU: System at $CPUTotal%" }
    if ($RAMPct -ge $RAMCritical)   { Write-Log "CRITICAL" "HIGH RAM: System at $RAMPct%" }
    if ($TopCPU) {
        foreach ($Proc in $TopCPU) {
            $Severity = "OK"
            if ($Proc.CPUPercent -ge $CPUCritical)      { $Severity = "CRITICAL" }
            elseif ($Proc.CPUPercent -ge $CPUSuspicious) { $Severity = "SUSPICIOUS" }
            elseif ($Proc.CPUPercent -ge $CPUUnknown)    { $Severity = "UNKNOWN" }
            if ($Severity -ne "OK") {
                Write-Log $Severity "HIGH CPU: $($Proc.Name) at $($Proc.CPUPercent)% | RAM: $($Proc.RAM) MB"
            }
        }
    }
 
    # --- WRITE STATUS FILE (read by Dashboard every 60s) ---
    try {
        $StatusData = @{
            timestamp      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            sample         = $SampleCount
            cpu_total      = $CPUTotal
            ram_pct        = $RAMPct
            ram_used_gb    = $RAMUsed
            ram_total_gb   = $RAMTotal
            disk_read_kbs  = $DiskRead
            disk_write_kbs = $DiskWrite
            top_cpu        = @()
            top_ram        = @()
        }
        if ($TopCPU) {
            $StatusData.top_cpu = @($TopCPU | ForEach-Object {
                $Sev = "OK"
                if ($_.CPUPercent -ge $CPUCritical)      { $Sev = "CRITICAL" }
                elseif ($_.CPUPercent -ge $CPUSuspicious) { $Sev = "SUSPICIOUS" }
                elseif ($_.CPUPercent -ge $CPUUnknown)    { $Sev = "UNKNOWN" }
                @{ name = $_.Name; cpu_pct = $_.CPUPercent; ram_mb = $_.RAM; severity = $Sev }
            })
        }
        $StatusData.top_ram = @($TopRAM | ForEach-Object {
            $PRAM  = [math]::Round($_.WorkingSet64 / 1MB, 1)
            $PGRAM = [math]::Round($_.WorkingSet64 / 1GB, 2)
            @{ name = $_.Name; ram_mb = $PRAM; ram_gb = $PGRAM }
        })
        $StatusData | ConvertTo-Json -Depth 3 | Out-File $StatusFile -Encoding UTF8
    } catch {}

    # ==========================================================
    # --- PS 7+ RENDER BRANCH: individual Write-Host calls ---
    # ==========================================================
    if ($PSMajor -ge 7) {
        Clear-Host
        Write-Host "--- [STEWARD DASHBOARD | $Now | Sample: $SampleCount] ---" -ForegroundColor Cyan
 
        $CPUColor = if ($CPUTotal -ge $CPUCritical) { "Red" } elseif ($CPUTotal -ge 70) { "DarkYellow" } elseif ($CPUTotal -ge 40) { "Yellow" } else { "Green" }
        $RAMColor = if ($RAMPct -ge $RAMCritical)   { "Red" } elseif ($RAMPct -ge 80)   { "DarkYellow" } elseif ($RAMPct -ge 60) { "Yellow" } else { "Green" }
 
        Write-Host "`n--- [SECTION 1: SYSTEM HEALTH] ---" -ForegroundColor Cyan
        Write-Host "CPU Total : $(Draw-Bar $CPUTotal) $CPUTotal%" -ForegroundColor $CPUColor
        Write-Host "RAM Total : $(Draw-Bar $RAMPct) $RAMPct% ($RAMUsed GB / $RAMTotal GB)" -ForegroundColor $RAMColor
 
        Write-Host "`n--- [SECTION 2: TOP $TopProcesses CPU CONSUMERS] ---" -ForegroundColor Cyan
        if ($TopCPU) {
            foreach ($Proc in $TopCPU) {
                $Severity = "OK"
                if ($Proc.CPUPercent -ge $CPUCritical)      { $Severity = "CRITICAL" }
                elseif ($Proc.CPUPercent -ge $CPUSuspicious) { $Severity = "SUSPICIOUS" }
                elseif ($Proc.CPUPercent -ge $CPUUnknown)    { $Severity = "UNKNOWN" }
                $Color = Get-SeverityColor $Severity
                $PName = $Proc.Name.PadRight(20)
                Write-Host "[$Severity] $PName CPU: $($Proc.CPUPercent.ToString().PadLeft(7))%  RAM: $($Proc.RAM) MB" -ForegroundColor $Color
            }
        } else {
            Write-Host "CPU counter data unavailable this cycle." -ForegroundColor DarkGray
        }
 
        Write-Host "`n--- [SECTION 3: TOP $TopProcesses RAM CONSUMERS] ---" -ForegroundColor Cyan
        foreach ($Proc in $TopRAM) {
            $PName = $Proc.Name.PadRight(20)
            $PRAM  = [math]::Round($Proc.WorkingSet64 / 1MB, 1)
            $PGRAM = [math]::Round($Proc.WorkingSet64 / 1GB, 2)
            $RC    = if ($PRAM -gt 2000) { "DarkYellow" } elseif ($PRAM -gt 1000) { "Yellow" } else { "Green" }
            Write-Host "$PName RAM: $PRAM MB ($PGRAM GB)" -ForegroundColor $RC
        }
 
        Write-Host "`n--- [SECTION 4: DISK I/O] ---" -ForegroundColor Cyan
        if ($null -ne $DiskRead) {
            $DC = if ($DiskRead -gt 50000 -or $DiskWrite -gt 50000) { "Red" } elseif ($DiskRead -gt 10000 -or $DiskWrite -gt 10000) { "DarkYellow" } else { "Green" }
            Write-Host "Disk Read : $DiskRead KB/s" -ForegroundColor $DC
            Write-Host "Disk Write: $DiskWrite KB/s" -ForegroundColor $DC
        } else {
            Write-Host "Disk I/O data unavailable" -ForegroundColor DarkGray
        }
 
        Write-Host "`n--- [SECTION 5: ALERTS] ---" -ForegroundColor Cyan
        $AlertCount = 0
        if ($CPUTotal -ge $CPUCritical) { Write-Host "CRITICAL CPU: System at $CPUTotal%" -ForegroundColor Red; $AlertCount++ }
        if ($RAMPct -ge $RAMCritical)   { Write-Host "CRITICAL RAM: System at $RAMPct%" -ForegroundColor Red;   $AlertCount++ }
        if ($AlertCount -eq 0) { Write-Host "No critical alerts." -ForegroundColor Green }
 
        Write-Host "`nNext scan in $($RefreshSeconds - 1) seconds. Log: $LogFile"
        Start-Sleep -Seconds ($RefreshSeconds - 4)
 
    # ==========================================================
    # --- PS 5.1 RENDER BRANCH: single ANSI string write ---
    # ==========================================================
    } else {
        $CPUColor = if ($CPUTotal -ge $CPUCritical) { $C.Red } elseif ($CPUTotal -ge 70) { $C.DarkYellow } elseif ($CPUTotal -ge 40) { $C.Yellow } else { $C.Green }
        $RAMColor = if ($RAMPct -ge $RAMCritical)   { $C.Red } elseif ($RAMPct -ge 80)   { $C.DarkYellow } elseif ($RAMPct -ge 60) { $C.Yellow } else { $C.Green }
 
        $Out  = "$($C.Cyan)--- [STEWARD DASHBOARD | $Now | Sample: $SampleCount] ---$($C.Reset)`n"
 
        $Out += "`n$($C.Cyan)--- [SECTION 1: SYSTEM HEALTH] ---$($C.Reset)`n"
        $Out += "${CPUColor}CPU Total : $(Draw-Bar $CPUTotal) $CPUTotal%$($C.Reset)`n"
        $Out += "${RAMColor}RAM Total : $(Draw-Bar $RAMPct) $RAMPct% ($RAMUsed GB / $RAMTotal GB)$($C.Reset)`n"
 
        $Out += "`n$($C.Cyan)--- [SECTION 2: TOP $TopProcesses CPU CONSUMERS] ---$($C.Reset)`n"
        if ($TopCPU) {
            foreach ($Proc in $TopCPU) {
                $Severity = "OK"
                if ($Proc.CPUPercent -ge $CPUCritical)      { $Severity = "CRITICAL" }
                elseif ($Proc.CPUPercent -ge $CPUSuspicious) { $Severity = "SUSPICIOUS" }
                elseif ($Proc.CPUPercent -ge $CPUUnknown)    { $Severity = "UNKNOWN" }
                $SC    = Get-SeverityANSI $Severity
                $PName = $Proc.Name.PadRight(20)
                $Out  += "${SC}[$Severity] $PName CPU: $($Proc.CPUPercent.ToString().PadLeft(7))%  RAM: $($Proc.RAM) MB$($C.Reset)`n"
            }
        } else {
            $Out += "$($C.DarkGray)CPU counter data unavailable this cycle.$($C.Reset)`n"
        }
 
        $Out += "`n$($C.Cyan)--- [SECTION 3: TOP $TopProcesses RAM CONSUMERS] ---$($C.Reset)`n"
        foreach ($Proc in $TopRAM) {
            $PName = $Proc.Name.PadRight(20)
            $PRAM  = [math]::Round($Proc.WorkingSet64 / 1MB, 1)
            $PGRAM = [math]::Round($Proc.WorkingSet64 / 1GB, 2)
            $RC    = if ($PRAM -gt 2000) { $C.DarkYellow } elseif ($PRAM -gt 1000) { $C.Yellow } else { $C.Green }
            $Out  += "${RC}$PName RAM: $PRAM MB ($PGRAM GB)$($C.Reset)`n"
        }
 
        $Out += "`n$($C.Cyan)--- [SECTION 4: DISK I/O] ---$($C.Reset)`n"
        if ($null -ne $DiskRead) {
            $DC   = if ($DiskRead -gt 50000 -or $DiskWrite -gt 50000) { $C.Red } elseif ($DiskRead -gt 10000 -or $DiskWrite -gt 10000) { $C.DarkYellow } else { $C.Green }
            $Out += "${DC}Disk Read : $DiskRead KB/s$($C.Reset)`n"
            $Out += "${DC}Disk Write: $DiskWrite KB/s$($C.Reset)`n"
        } else {
            $Out += "$($C.DarkGray)Disk I/O data unavailable$($C.Reset)`n"
        }
 
        $Out += "`n$($C.Cyan)--- [SECTION 5: ALERTS] ---$($C.Reset)`n"
        $AlertCount = 0
        if ($CPUTotal -ge $CPUCritical) { $Out += "$($C.Red)CRITICAL CPU: System at $CPUTotal%$($C.Reset)`n"; $AlertCount++ }
        if ($RAMPct -ge $RAMCritical)   { $Out += "$($C.Red)CRITICAL RAM: System at $RAMPct%$($C.Reset)`n";   $AlertCount++ }
        if ($AlertCount -eq 0) { $Out += "$($C.Green)No critical alerts.$($C.Reset)`n" }
 
        $Out += "`n$($C.DarkGray)Next scan in $($RefreshSeconds - 1) seconds. Log: $LogFile$($C.Reset)"
 
        Clear-Host
        Write-Host $Out
 
        Start-Sleep -Seconds ($RefreshSeconds - 3)
    }
}