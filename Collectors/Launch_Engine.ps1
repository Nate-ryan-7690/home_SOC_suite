# Launch_Engine.ps1
# RootPath is auto-detected from the script location (Scripts folder -> SOC root)
if ($PSScriptRoot) {
    $RootPath = Split-Path -Parent $PSScriptRoot
} else {
    $RootPath = "$env:USERPROFILE\Desktop\SOC"
}
$EnginePath = "$RootPath\Engine"
$ConfigPath = "$RootPath\Config"
$proc = Start-Process pwsh.exe -ArgumentList "-NoExit", "-Command", "cd '$EnginePath'; python engine.py" -Verb RunAs -PassThru
$proc.Id | Out-File "$ConfigPath\Engine.pid" -Encoding UTF8
