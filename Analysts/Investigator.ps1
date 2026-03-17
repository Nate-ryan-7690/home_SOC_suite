# --- INVESTIGATOR: THE CLEAN SUMMARY ---
# ============================================================
# USER CONFIGURATION
# Set $RootPath to the folder where you installed the SOC Suite
# Default is Desktop\SOC — change this if you installed elsewhere
# ============================================================
$RootPath = "$env:USERPROFILE\Desktop\SOC"
$LogFile = "$RootPath\Logs\Network_Watchdog_Log.txt"
$ReportFile = "$RootPath\Reports\Weekly_Audit_Report.txt"

# 1. Start a clean log of just the output
Start-Transcript -Path $ReportFile -Force | Out-Null

Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "       SECURITY AUDIT: WEEKLY SUMMARY" -ForegroundColor Cyan
Write-Host "       Generated on: $(Get-Date)" -ForegroundColor Cyan
Write-Host "================================================`n" -ForegroundColor Gray

# 2. Check if the source log actually exists
if (-not (Test-Path $LogFile)) { 
    Write-Host "[!] ERROR: No source log found at $LogFile" -ForegroundColor Red
    Stop-Transcript
    Read-Host "Press Enter to exit"
    exit 
}

# 3. Load the data
$Data = Get-Content $LogFile
$NewConns = $Data | Select-String "NEW:"

Write-Host "[+] Total New Connections Logged: $($NewConns.Count)" -ForegroundColor White

# 4. Top Apps Analysis
Write-Host "`n[ Top 5 Chattiest Apps ]" -ForegroundColor Yellow
try {
    $NewConns | ForEach-Object { 
        $Line = $_.ToString()
        if ($Line -match "NEW: (.*?) ->") { $Matches[1].Trim() }
    } | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | Format-Table Name, Count -HideTableHeaders
} catch { Write-Host "Could not calculate top apps." }

# 5. Red Flag Search
Write-Host "[ Potential Red Flags (Temp/User Folders) ]" -ForegroundColor Red
$RedFlags = $Data | Select-String "AppData\\Local\\Temp" | Select-String -NotMatch "Discord","Teams","OneDrive"
if ($RedFlags) { 
    $RedFlags | ForEach-Object { Write-Host "FOUND: $($_.ToString())" -ForegroundColor Cyan } 
} else { 
    Write-Host "RESULT: No suspicious temporary paths found." -ForegroundColor Green 
}

# 6. Finalize
Write-Host "`n================================================" -ForegroundColor Gray
Write-Host "REPORT SAVED TO: $ReportFile" -ForegroundColor Magenta
Write-Host "================================================" -ForegroundColor Gray

# Stop the transcript and wait for user
Stop-Transcript | Out-Null
Write-Host "`n"
Read-Host "Audit Complete. Press Enter to close"