# ============================================================
# Auditor.ps1 -- Suite Integrity Auditor
# Part of Home SOC Suite -- Phase 4
#
# Analyst script. Run manually as a bookend to each monitoring
# session. Does NOT run continuously.
# Requires all collectors and Warden to be stopped before running
# so that log files are fully static and hashes are reliable.
#
# OPERATIONAL WORKFLOW:
#
#   MORNING (before starting collectors):
#     1. .\Auditor.ps1 -Mode Morning
#     2. Review output -- only proceed if verdict is CLEAN
#     3. Start collectors (Sentinel, Bulwark, Steward, CITYGUARD,
#        Watchman, Registry_Warden, Harbinger, Bloodhound)
#     4. Start Warden
#
#   EVENING (after stopping all collectors and Warden):
#     1. Stop all collectors (close their windows)
#     2. Stop Warden (close its window)
#     3. .\Auditor.ps1 -Mode Evening
#     4. Review report in Reports\
#
#   FIRST RUN: Run Evening mode first to establish the log
#   baseline. Morning mode requires an evening baseline to compare
#   against.
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Morning','Evening')]
    [string]$Mode
)

chcp 65001 | Out-Null

# ============================================================
# USER CONFIGURATION
# RootPath is auto-detected from the script location (Scripts folder -> SOC root)
# ============================================================
if ($PSScriptRoot) {
    $RootPath = Split-Path -Parent $PSScriptRoot
} else {
    $RootPath = "$env:USERPROFILE\Desktop\SOC"
}
$ReportFolder     = "$RootPath\Reports"
$LogFolder        = "$RootPath\Logs"
$ArchiveFolder    = "$RootPath\Logs\Archives"
$BaselineFile     = "$RootPath\Config\Auditor_LogBaseline.json"
$ChainFile        = "$RootPath\Config\Auditor_ArchiveChain.json"
$RunTimestamp     = Get-Date -Format "yyyy-MM-dd_HH-mm"
$RunDateTime      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ReportFile       = "$ReportFolder\Auditor_${RunTimestamp}_${Mode}.txt"

# Log line format -- must match all suite collector output
# Valid:   [2026-03-20 10:15:32] [CRITICAL] Message
# Skipped: --- LOG STARTED --- (legitimate headers)
$LogLinePattern   = '^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[(OK|UNKNOWN|SUSPICIOUS|CRITICAL)\] '
$LogHeaderPattern = '^---'

# Log files that use a different format and are excluded from format validation
# Engine_Log.txt and Alert_Log.txt use the Python engine format (UTC timestamp, MEDIUM severity)
$FormatCheckExclude = @("Engine_Log.txt", "Alert_Log.txt")

# All scripts that should be stopped before running Auditor
$CollectorNames = @(
    "Sentinel.ps1", "Bulwark.ps1", "Steward.ps1", "CITYGUARD.ps1",
    "Watchman.ps1", "Registry_Warden.ps1", "Harbinger.ps1",
    "Bloodhound.ps1", "DOH_Detector.ps1", "SecEventLog.ps1",
    "SysmonWatcher.ps1", "Warden.ps1"
)

# ============================================================
# FUNCTIONS
# ============================================================

function Write-Report($Line, $Color = "White") {
    # Writes to both console and report file simultaneously
    Write-Host $Line -ForegroundColor $Color
    $Line | Out-File $ReportFile -Append -Encoding UTF8
}

function Write-ReportSection($Title) {
    Write-Report ""
    Write-Report "[SECTION: $Title]" "Cyan"
    Write-Report ("-" * 56) "DarkGray"
}

function Get-SHA256File($Path) {
    try {
        return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    } catch { return $null }
}

function Get-SHA256String($String) {
    # Hashes a string value -- used for archive chain link computation
    try {
        $Bytes = [System.Text.Encoding]::UTF8.GetBytes($String)
        $Hash  = [System.Security.Cryptography.SHA256]::Create().ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($Hash) -replace '-', '')
    } catch { return $null }
}

function Test-CollectorStatus {
    $Running = @()
    try {
        $Processes = Get-CimInstance Win32_Process `
            -Filter "Name='powershell.exe' OR Name='pwsh.exe'" -ErrorAction Stop
        foreach ($Name in $CollectorNames) {
            if ($Processes | Where-Object { $_.CommandLine -like "*$Name*" }) {
                $Running += $Name
            }
        }
    } catch {}
    return $Running
}

function Test-LogLineFormat($LogPath) {
    # Returns count of format violations and up to 5 examples
    # Caps at $MaxLines to guard against very large log files (e.g. SysmonWatcher)
    $Violations = @()
    $LineNum    = 0
    $MaxLines   = 10000
    try {
        foreach ($Line in [System.IO.File]::ReadLines($LogPath)) {
            $LineNum++
            if ($LineNum -gt $MaxLines) { break }
            if ([string]::IsNullOrWhiteSpace($Line)) { continue }
            if ($Line -match $LogHeaderPattern)       { continue }
            if ($Line -notmatch $LogLinePattern) {
                $Violations += "    Line $($LineNum): $($Line.Substring(0, [Math]::Min(80, $Line.Length)))"
                if ($Violations.Count -ge 5) { break }
            }
        }
    } catch {}
    return @{ Count = $Violations.Count; Examples = $Violations }
}

function Build-LogBaseline {
    # Evening: hash all current log files and save as baseline
    $Baseline = @{
        created = $RunDateTime
        mode    = "Evening"
        logs    = @{}
    }
    $Count = 0
    Get-ChildItem "$LogFolder\*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
        $Hash = Get-SHA256File $_.FullName
        if ($Hash) {
            $Baseline.logs[$_.FullName] = @{
                hash     = $Hash
                size     = $_.Length
                filename = $_.Name
            }
            $Count++
        }
    }
    $Baseline | ConvertTo-Json -Depth 4 | Out-File $BaselineFile -Encoding UTF8
    return $Count
}

function Test-LogBaseline {
    # Morning: compare current log hashes to evening baseline
    if (-not (Test-Path $BaselineFile)) { return $null }
    try {
        $Json    = Get-Content $BaselineFile -Encoding UTF8 | ConvertFrom-Json
        $Results = @{
            Violations   = @()
            Missing      = @()
            NewFiles     = @()
            BaselineDate = $Json.created
        }

        # Check files that were in the baseline
        $Json.logs.PSObject.Properties | ForEach-Object {
            $Path     = $_.Name
            $Expected = $_.Value
            if (-not (Test-Path $Path)) {
                $Results.Missing += $Expected.filename
                return
            }
            $Current = Get-SHA256File $Path
            if ($Current -ne $Expected.hash) {
                $Results.Violations += $Expected.filename
            }
        }

        # Check for new log files that appeared overnight
        Get-ChildItem "$LogFolder\*.txt" -ErrorAction SilentlyContinue | ForEach-Object {
            if (-not ($Json.logs.PSObject.Properties.Name -contains $_.FullName)) {
                $Results.NewFiles += $_.Name
            }
        }

        return $Results
    } catch { return $null }
}

function Load-ArchiveChain {
    if (-not (Test-Path $ChainFile)) { return @() }
    try {
        $Json  = Get-Content $ChainFile -Encoding UTF8 | ConvertFrom-Json
        $Chain = @()
        foreach ($Entry in $Json.chain) {
            $Chain += @{
                filename        = $Entry.filename
                enrolled_at     = $Entry.enrolled_at
                file_hash       = $Entry.file_hash
                prev_chain_hash = $Entry.prev_chain_hash
                chain_hash      = $Entry.chain_hash
            }
        }
        return ,$Chain
    } catch { return @() }
}

function Save-ArchiveChain($Chain) {
    @{ chain = @($Chain) } | ConvertTo-Json -Depth 4 | Out-File $ChainFile -Encoding UTF8
}

function Test-ArchiveChain($Chain) {
    # Verify chain integrity: mathematical link between entries + file hashes
    # Chain structure: chain_hash = SHA256(file_hash + prev_chain_hash)
    # First entry: prev_chain_hash = "GENESIS"
    $Results  = @{ Violations = @(); Missing = @(); Checked = 0 }
    $PrevHash = "GENESIS"

    foreach ($Entry in $Chain) {
        $Results.Checked++
        $ArchivePath = "$ArchiveFolder\$($Entry.filename)"

        # Verify this entry's chain_hash is mathematically valid
        $Expected = Get-SHA256String ($Entry.file_hash + $Entry.prev_chain_hash)
        if ($Expected -ne $Entry.chain_hash) {
            $Results.Violations += "CHAIN_BROKEN: $($Entry.filename) | chain_hash mismatch -- entry may have been tampered"
        }

        # Verify this entry links correctly to the previous entry
        if ($Entry.prev_chain_hash -ne $PrevHash) {
            $Results.Violations += "CHAIN_LINK_BROKEN: $($Entry.filename) | prev_chain_hash does not match previous entry -- possible insertion or reordering"
        }

        # Verify archive file still exists and is unmodified
        if (-not (Test-Path $ArchivePath)) {
            $Results.Missing += $Entry.filename
        } else {
            $FileHash = Get-SHA256File $ArchivePath
            if ($FileHash -ne $Entry.file_hash) {
                $Results.Violations += "ARCHIVE_TAMPERED: $($Entry.filename) | file hash mismatch -- archive was modified after enrollment"
            }
        }

        $PrevHash = $Entry.chain_hash
    }
    return $Results
}

function Add-NewArchivesToChain($Chain) {
    # Evening only: enroll archive files not yet in the chain
    $ChainFilenames = $Chain | ForEach-Object { $_.filename }
    $NewFiles       = Get-ChildItem "$ArchiveFolder\*" -File -ErrorAction SilentlyContinue |
                          Where-Object { $ChainFilenames -notcontains $_.Name } |
                          Sort-Object CreationTime   # Chronological order preserves chain integrity

    $Added    = 0
    $PrevHash = if ($Chain.Count -gt 0) { $Chain[-1].chain_hash } else { "GENESIS" }

    foreach ($File in $NewFiles) {
        $FileHash  = Get-SHA256File $File.FullName
        if (-not $FileHash) { continue }
        $ChainHash = Get-SHA256String ($FileHash + $PrevHash)
        $Chain    += @{
            filename        = $File.Name
            enrolled_at     = $RunDateTime
            file_hash       = $FileHash
            prev_chain_hash = $PrevHash
            chain_hash      = $ChainHash
        }
        $PrevHash = $ChainHash
        $Added++
    }
    return @{ Chain = $Chain; Added = $Added }
}

# ============================================================
# ENSURE REPORTS FOLDER EXISTS
# ============================================================
if (-not (Test-Path $ReportFolder)) {
    New-Item -ItemType Directory -Path $ReportFolder | Out-Null
}

# ============================================================
# REPORT HEADER
# ============================================================
$Sep = "=" * 58

Write-Report $Sep "DarkGray"
Write-Report "  AUDITOR INTEGRITY REPORT" "Cyan"
Write-Report "  Mode    : $Mode" "White"
Write-Report "  Run     : $RunDateTime" "White"
Write-Report "  Host    : $env:COMPUTERNAME" "White"
Write-Report $Sep "DarkGray"

$TotalViolations = 0

# ============================================================
# SECTION 1: COLLECTOR STATUS
# ============================================================
Write-ReportSection "COLLECTOR STATUS"
$Running = Test-CollectorStatus

if ($Running.Count -eq 0) {
    Write-Report "  [OK] No collectors or Warden running -- logs are static" "Green"
} else {
    Write-Report "  [WARNING] $($Running.Count) script(s) still running -- log hashes unreliable:" "DarkYellow"
    foreach ($R in $Running) { Write-Report "    - $R" "DarkYellow" }
    Write-Report "  Stop all collectors and Warden before running Auditor." "DarkYellow"
    $TotalViolations++
}

# ============================================================
# SECTION 2: LOG LINE FORMAT VALIDATION
# ============================================================
Write-ReportSection "LOG LINE FORMAT VALIDATION"
$LogFiles        = Get-ChildItem "$LogFolder\*.txt" -ErrorAction SilentlyContinue
$FormatViolTotal = 0
$FilesChecked    = 0

foreach ($LF in $LogFiles) {
    if ($FormatCheckExclude -contains $LF.Name) { continue }
    $Result = Test-LogLineFormat $LF.FullName
    $FilesChecked++
    if ($Result.Count -gt 0) {
        Write-Report "  [SUSPICIOUS] $($LF.Name) | $($Result.Count) format violation(s)" "DarkYellow"
        foreach ($Ex in $Result.Examples) { Write-Report $Ex "DarkYellow" }
        $FormatViolTotal += $Result.Count
        $TotalViolations++
    }
}
if ($FormatViolTotal -eq 0) {
    Write-Report "  [OK] $FilesChecked file(s) checked -- all lines conform to suite format" "Green"
}

# ============================================================
# SECTION 3: LOG INTEGRITY
# ============================================================
Write-ReportSection "LOG INTEGRITY ($Mode)"

if ($Mode -eq "Morning") {
    $HashResults = Test-LogBaseline
    if ($null -eq $HashResults) {
        Write-Report "  [UNKNOWN] No evening baseline found." "Yellow"
        Write-Report "  Run .\Auditor.ps1 -Mode Evening first to establish baseline." "Yellow"
    } else {
        Write-Report "  Baseline from : $($HashResults.BaselineDate)" "DarkGray"

        if ($HashResults.Violations.Count -eq 0 -and
            $HashResults.Missing.Count    -eq 0 -and
            $HashResults.NewFiles.Count   -eq 0) {
            Write-Report "  [OK] All log files match evening baseline -- no overnight modifications" "Green"
        }
        foreach ($V in $HashResults.Violations) {
            Write-Report "  [CRITICAL] LOG_MODIFIED: $V | Hash differs from evening baseline" "Red"
            $TotalViolations++
        }
        foreach ($M in $HashResults.Missing) {
            Write-Report "  [CRITICAL] LOG_MISSING: $M | Present in baseline but not found" "Red"
            $TotalViolations++
        }
        foreach ($N in $HashResults.NewFiles) {
            Write-Report "  [SUSPICIOUS] LOG_NEW_OVERNIGHT: $N | Not present in evening baseline" "DarkYellow"
            $TotalViolations++
        }
    }
} else {
    $Count = Build-LogBaseline
    Write-Report "  [OK] Log baseline built: $Count file(s) hashed" "Green"
    Write-Report "  Saved : $BaselineFile" "DarkGray"
    Write-Report "  Morning run will compare against this baseline." "DarkGray"
}

# ============================================================
# SECTION 4: ARCHIVE CHAIN INTEGRITY
# ============================================================
Write-ReportSection "ARCHIVE CHAIN INTEGRITY"
$Chain = Load-ArchiveChain

if ($Mode -eq "Evening") {
    $EnrollResult = Add-NewArchivesToChain $Chain
    $Chain        = $EnrollResult.Chain
    if ($EnrollResult.Added -gt 0) {
        Write-Report "  [OK] Enrolled $($EnrollResult.Added) new archive(s) into chain" "Green"
        foreach ($Entry in $Chain[-$EnrollResult.Added..-1]) {
            Write-Report "    + $($Entry.filename)" "DarkGray"
        }
    }
    Save-ArchiveChain $Chain
}

if ($Chain.Count -eq 0) {
    Write-Report "  [UNKNOWN] Archive chain is empty -- no archives enrolled yet" "Yellow"
} else {
    $ChainResults = Test-ArchiveChain $Chain
    Write-Report "  Chain entries : $($Chain.Count)" "DarkGray"
    Write-Report "  Verified      : $($ChainResults.Checked)" "DarkGray"

    if ($ChainResults.Violations.Count -eq 0 -and $ChainResults.Missing.Count -eq 0) {
        Write-Report "  [OK] Chain intact -- all links valid, all archive files unmodified" "Green"
    }
    foreach ($V in $ChainResults.Violations) {
        Write-Report "  [CRITICAL] $V" "Red"
        $TotalViolations++
    }
    foreach ($M in $ChainResults.Missing) {
        Write-Report "  [UNKNOWN] ARCHIVE_MISSING: $M | Enrolled in chain but file not found" "Yellow"
    }
}

# ============================================================
# FINAL VERDICT
# ============================================================
Write-Report ""
Write-Report $Sep "DarkGray"
if ($TotalViolations -eq 0) {
    Write-Report "  VERDICT: SUITE INTEGRITY CLEAN" "Green"
    if ($Mode -eq "Morning") {
        Write-Report "  Safe to start collectors and Warden." "Green"
    } else {
        Write-Report "  Session archived cleanly. Safe to shut down." "Green"
    }
} else {
    Write-Report "  VERDICT: VIOLATIONS FOUND ($TotalViolations)" "Red"
    if ($Mode -eq "Morning") {
        Write-Report "  DO NOT start collectors until violations are investigated." "Red"
    } else {
        Write-Report "  Investigate before next morning startup." "Red"
    }
}
Write-Report "  Report : $ReportFile" "DarkGray"
Write-Report $Sep "DarkGray"
