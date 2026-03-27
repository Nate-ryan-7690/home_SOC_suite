# Launch_Engine.ps1
$EnginePath = "$env:USERPROFILE\Desktop\SOC\Engine"
$ConfigPath = "$env:USERPROFILE\Desktop\SOC\Config"
$proc = Start-Process pwsh.exe -ArgumentList "-NoExit", "-Command", "cd '$EnginePath'; python engine.py" -Verb RunAs -PassThru
$proc.Id | Out-File "$ConfigPath\Engine.pid" -Encoding UTF8
