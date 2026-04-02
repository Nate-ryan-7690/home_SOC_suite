# ============================================================
# Registry_Warden.ps1 - Persistence & Service Monitor
# Part of Home SOC Suite
# ============================================================

# --- ENCODING ---
chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC - change this if you installed elsewhere
# ============================================================
$RootPath        = "$env:USERPROFILE\Desktop\SOC"
$LogFile         = "$RootPath\Logs\RegistryWarden_Log.txt"
$ArchiveFolder   = "$RootPath\Logs\Archives"
$BaselineFile    = "$RootPath\Config\RegistryWarden_Baseline.json"
$HealthFile      = "$RootPath\Config\RegistryWarden_Health.json"
$RefreshSeconds  = 60
$ServiceInterval = 5    # Scan services every N cycles (~5 minutes)

# --- KEYS TO MONITOR ---
$RunKeys = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)
$ServicesKey = "HKLM:\SYSTEM\CurrentControlSet\Services"

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

function Get-RunKeySeverity($ValueData) {
    if ($ValueData -like "*\AppData\*Temp*" -or
        $ValueData -like "*\Temp\*"          -or
        $ValueData -like "*\Public\*"        -or
        $ValueData -like "*\Downloads\*") {
        return "CRITICAL"
    }
    if ($ValueData -like "*\AppData\Roaming\*" -or
        $ValueData -like "*\AppData\Local\*") {
        return "SUSPICIOUS"
    }
    return "UNKNOWN"
}

function Get-ServiceSeverity($ImagePath) {
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return "UNKNOWN" }
    if ($ImagePath -like "*\AppData\*Temp*" -or
        $ImagePath -like "*\Temp\*"          -or
        $ImagePath -like "*\Public\*") {
        return "CRITICAL"
    }
    if ($ImagePath -like "*\AppData\*") { return "SUSPICIOUS" }
    return "UNKNOWN"
}

function Get-RunKeySnapshot {
    $Snapshot = @{}
    foreach ($Key in $RunKeys) {
        try {
            $Props  = Get-ItemProperty -Path $Key -ErrorAction Stop
            $Values = @{}
            $Props.PSObject.Properties | Where-Object {
                $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider')
            } | ForEach-Object { $Values[$_.Name] = $_.Value }
            $Snapshot[$Key] = $Values
        } catch {
            $Snapshot[$Key] = @{}
        }
    }
    return $Snapshot
}

function Get-ServicesSnapshot {
    $Services = @{}
    try {
        Get-ChildItem -Path $ServicesKey -ErrorAction Stop | ForEach-Object {
            $Name = $_.PSChildName
            try {
                $Props = Get-ItemProperty -Path $_.PSPath -ErrorAction Stop
                $Services[$Name] = @{
                    ImagePath = $Props.ImagePath
                    Start     = $Props.Start
                    Type      = $Props.Type
                }
            } catch {
                $Services[$Name] = @{ ImagePath = $null; Start = $null; Type = $null }
            }
        }
    } catch {}
    return $Services
}

function Test-SAMIntegrity {
    try {
        $Users = Get-LocalUser -ErrorAction Stop

        # Detect duplicate RIDs - primary RID hijack indicator
        $RIDs       = $Users | ForEach-Object { ($_.SID.Value -split '-')[-1] }
        $Duplicates = $RIDs | Group-Object | Where-Object { $_.Count -gt 1 }
        if ($Duplicates) {
            return @{ Severity = "CRITICAL"; Message = "DUPLICATE RID DETECTED: RID $($Duplicates.Name -join ', ') assigned to multiple accounts" }
        }

        # Guest account should never be enabled
        $Guest = $Users | Where-Object { $_.SID.Value -like '*-501' }
        if ($Guest -and $Guest.Enabled) {
            return @{ Severity = "SUSPICIOUS"; Message = "GUEST ACCOUNT ENABLED: $($Guest.Name) | SID: $($Guest.SID)" }
        }

        return @{ Severity = "OK"; Message = "SAM integrity check passed" }
    } catch {
        return @{ Severity = "UNKNOWN"; Message = "SAM check failed: $($_.Exception.Message)" }
    }
}

# --- LOG ROTATION ---
if (Test-Path $LogFile) {
    $LogAge = (Get-Item $LogFile).CreationTime
    if ($LogAge -lt (Get-Date).AddDays(-7)) {
        if (-not (Test-Path $ArchiveFolder)) { New-Item -ItemType Directory -Path $ArchiveFolder | Out-Null }
        $ArchiveName = "RegistryWarden_Archived_$(Get-Date -Format 'yyyy-MM-dd').txt"
        Move-Item -Path $LogFile -Destination "$ArchiveFolder\$ArchiveName"
        Write-Host "[!] Old log archived." -ForegroundColor Yellow
    }
}

# --- INITIALIZE LOG ---
if (-not (Test-Path $LogFile)) {
    "--- REGISTRY WARDEN LOG STARTED: $(Get-Date) ---" | Out-File $LogFile -Encoding UTF8
    "--- MONITORING: Run Keys + Services + SAM ---`n" | Out-File $LogFile -Append -Encoding UTF8
}

# --- STARTUP SNAPSHOT ---
Write-Host "--- [REGISTRY WARDEN | INITIALIZING] ---" -ForegroundColor Cyan
Write-Host "Reading Run keys..." -ForegroundColor DarkGray
$CurrentRunKeys = Get-RunKeySnapshot
Write-Host "Reading Services (this may take a moment)..." -ForegroundColor DarkGray
$CurrentServices = Get-ServicesSnapshot
Write-Host "[+] Found $($CurrentServices.Count) services" -ForegroundColor Green

# --- LOAD OR CREATE BASELINE ---
$BaselineRunKeys  = @{}
$BaselineServices = @{}

if (Test-Path $BaselineFile) {
    try {
        $Json = Get-Content $BaselineFile -Encoding UTF8 | ConvertFrom-Json

        if ($Json.RunKeys) {
            $Json.RunKeys.PSObject.Properties | ForEach-Object {
                $KeyName = $_.Name
                $BaselineRunKeys[$KeyName] = @{}
                if ($_.Value -and $_.Value.PSObject) {
                    $_.Value.PSObject.Properties | ForEach-Object {
                        $BaselineRunKeys[$KeyName][$_.Name] = $_.Value
                    }
                }
            }
        }

        if ($Json.Services) {
            $Json.Services.PSObject.Properties | ForEach-Object {
                $SvcName = $_.Name
                $Props   = $_.Value
                $BaselineServices[$SvcName] = @{
                    ImagePath = $Props.ImagePath
                    Start     = $Props.Start
                    Type      = $Props.Type
                }
            }
        }

        Write-Host "[+] Baseline loaded: $($BaselineServices.Count) services, $($BaselineRunKeys.Count) run key sets" -ForegroundColor Green
    } catch {
        Write-Host "[!] Baseline load failed - using current state as new baseline." -ForegroundColor Yellow
        $BaselineRunKeys  = $CurrentRunKeys
        $BaselineServices = $CurrentServices
        @{ RunKeys = $BaselineRunKeys; Services = $BaselineServices } |
            ConvertTo-Json -Depth 5 | Out-File $BaselineFile -Encoding UTF8
    }
} else {
    Write-Host "[!] No baseline found - saving current state as baseline." -ForegroundColor Yellow
    $BaselineRunKeys  = $CurrentRunKeys
    $BaselineServices = $CurrentServices
    @{ RunKeys = $BaselineRunKeys; Services = $BaselineServices } |
        ConvertTo-Json -Depth 5 | Out-File $BaselineFile -Encoding UTF8
    Write-Log "OK" "Baseline created: $($BaselineServices.Count) services, $($BaselineRunKeys.Count) run key sets"
    Write-Host "[+] Baseline saved to $BaselineFile" -ForegroundColor Green
}

Write-Host "--- [MONITORING STARTED] ---`n" -ForegroundColor Cyan
Start-Sleep -Seconds 2

# --- MAIN MONITORING LOOP ---
$ScanCount       = 0
$BaselineChanged = $false
$ScriptStartTime = Get-Date

# --- HEARTBEAT RUNSPACE ---
$SharedState = [System.Collections.Hashtable]::Synchronized(@{
    Running         = $true
    CycleCount      = 0
    ScriptStartTime = $ScriptStartTime
    HealthFile      = $HealthFile
    CollectorName   = "registry_warden"
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

while ($true) {
    $ScanCount++
    $SharedState.CycleCount = $ScanCount
    $BaselineChanged = $false
    Clear-Host
    $Now = Get-Date -Format "HH:mm:ss"
    Write-Host "--- [REGISTRY WARDEN DASHBOARD | $Now | Scan: $ScanCount] ---" -ForegroundColor Cyan

    # --- SECTION 1: RUN KEYS ---
    Write-Host "`n--- [SECTION 1: RUN KEYS] ---" -ForegroundColor Cyan
    $CurrentRunKeys = Get-RunKeySnapshot
    $RunAlertCount  = 0

    foreach ($Key in $RunKeys) {
        $ShortKey = if ($Key -like "HKCU*") { "HKCU\Run" } elseif ($Key -like "*RunOnce") { "HKLM\RunOnce" } else { "HKLM\Run" }
        $Current  = $CurrentRunKeys[$Key]
        if (-not $BaselineRunKeys.ContainsKey($Key)) { $BaselineRunKeys[$Key] = @{} }
        $Baseline = $BaselineRunKeys[$Key]

        # New entries
        foreach ($Name in $Current.Keys) {
            if (-not $Baseline.ContainsKey($Name)) {
                $Severity = Get-RunKeySeverity $Current[$Name]
                $Message  = "NEW RUN ENTRY [$ShortKey]: `"$Name`" = $($Current[$Name])"
                Write-Host "[$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
                Write-Log $Severity $Message
                $BaselineRunKeys[$Key][$Name] = $Current[$Name]
                $RunAlertCount++; $BaselineChanged = $true
            }
        }

        # Removed entries
        foreach ($Name in @($Baseline.Keys)) {
            if (-not $Current.ContainsKey($Name)) {
                $Message = "REMOVED RUN ENTRY [$ShortKey]: `"$Name`""
                Write-Host "[UNKNOWN] $Message" -ForegroundColor Yellow
                Write-Log "UNKNOWN" $Message
                $BaselineRunKeys[$Key].Remove($Name)
                $RunAlertCount++; $BaselineChanged = $true
            }
        }

        # Modified entries
        foreach ($Name in $Current.Keys) {
            if ($Baseline.ContainsKey($Name) -and ($Current[$Name] -ne $Baseline[$Name])) {
                $Severity = Get-RunKeySeverity $Current[$Name]
                $Message  = "MODIFIED RUN ENTRY [$ShortKey]: `"$Name`" | Was: $($Baseline[$Name]) | Now: $($Current[$Name])"
                Write-Host "[$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
                Write-Log $Severity $Message
                $BaselineRunKeys[$Key][$Name] = $Current[$Name]
                $RunAlertCount++; $BaselineChanged = $true
            }
        }
    }

    if ($RunAlertCount -eq 0) { Write-Host "No run key changes detected." -ForegroundColor Green }

    # Display current entries
    Write-Host "`nCurrent Run entries:" -ForegroundColor DarkGray
    foreach ($Key in $RunKeys) {
        $ShortKey = if ($Key -like "HKCU*") { "HKCU\Run" } elseif ($Key -like "*RunOnce") { "HKLM\RunOnce" } else { "HKLM\Run" }
        $Entries  = $CurrentRunKeys[$Key]
        if ($Entries.Count -gt 0) {
            Write-Host "  [$ShortKey]" -ForegroundColor DarkGray
            foreach ($Name in $Entries.Keys) {
                Write-Host "    $Name = $($Entries[$Name])" -ForegroundColor DarkGray
            }
        }
    }

    # --- SECTION 2: SERVICES ---
    Write-Host "`n--- [SECTION 2: SERVICES] ---" -ForegroundColor Cyan

    if ($ScanCount % $ServiceInterval -eq 0) {
        $CurrentServices   = Get-ServicesSnapshot
        $ServiceAlertCount = 0

        # New services
        foreach ($Name in $CurrentServices.Keys) {
            if (-not $BaselineServices.ContainsKey($Name)) {
                $ImagePath = $CurrentServices[$Name].ImagePath
                $Severity  = Get-ServiceSeverity $ImagePath
                $Message   = "NEW SERVICE: $Name | ImagePath: $ImagePath | Start: $($CurrentServices[$Name].Start)"
                Write-Host "[$Severity] $Message" -ForegroundColor (Get-SeverityColor $Severity)
                Write-Log $Severity $Message
                $BaselineServices[$Name] = $CurrentServices[$Name]
                $ServiceAlertCount++; $BaselineChanged = $true
            }
        }

        # Removed services
        foreach ($Name in @($BaselineServices.Keys)) {
            if (-not $CurrentServices.ContainsKey($Name)) {
                $Message = "SERVICE REMOVED: $Name | Was: $($BaselineServices[$Name].ImagePath)"
                Write-Host "[UNKNOWN] $Message" -ForegroundColor Yellow
                Write-Log "UNKNOWN" $Message
                $BaselineServices.Remove($Name)
                $ServiceAlertCount++; $BaselineChanged = $true
            }
        }

        # Modified ImagePath
        foreach ($Name in $CurrentServices.Keys) {
            if ($BaselineServices.ContainsKey($Name)) {
                $OldPath = $BaselineServices[$Name].ImagePath
                $NewPath = $CurrentServices[$Name].ImagePath
                if ($OldPath -ne $NewPath -and -not ([string]::IsNullOrWhiteSpace($OldPath) -and [string]::IsNullOrWhiteSpace($NewPath))) {
                    $Message = "SERVICE PATH CHANGED: $Name | Was: $OldPath | Now: $NewPath"
                    Write-Host "[SUSPICIOUS] $Message" -ForegroundColor DarkYellow
                    Write-Log "SUSPICIOUS" $Message
                    $BaselineServices[$Name].ImagePath = $NewPath
                    $ServiceAlertCount++; $BaselineChanged = $true
                }
            }
        }

        if ($ServiceAlertCount -eq 0) {
            Write-Host "No service changes detected. ($($BaselineServices.Count) services monitored)" -ForegroundColor Green
        }
    } else {
        $NextScan = $ServiceInterval - ($ScanCount % $ServiceInterval)
        Write-Host "Services scan in $NextScan cycle(s). ($($BaselineServices.Count) services in baseline)" -ForegroundColor DarkGray
    }

    # --- SECTION 3: SAM INTEGRITY ---
    Write-Host "`n--- [SECTION 3: SAM INTEGRITY] ---" -ForegroundColor Cyan
    $SAM   = Test-SAMIntegrity
    $Color = Get-SeverityColor $SAM.Severity
    Write-Host "[$($SAM.Severity)] $($SAM.Message)" -ForegroundColor $Color
    if ($SAM.Severity -ne "OK") { Write-Log $SAM.Severity $SAM.Message }

    # --- SAVE BASELINE IF CHANGED ---
    if ($BaselineChanged) {
        try {
            @{ RunKeys = $BaselineRunKeys; Services = $BaselineServices } |
                ConvertTo-Json -Depth 5 | Out-File $BaselineFile -Encoding UTF8
        } catch {}
    }

    Write-Host "`nNext scan in $RefreshSeconds seconds. Log: $LogFile"
    Start-Sleep -Seconds $RefreshSeconds
}
