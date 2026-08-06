# Registers a Windows Scheduled Task that launches pysentinel-siem
# automatically at logon -- running elevated (no UAC click needed at
# logon: Task Scheduler grants that non-interactively for an admin
# account when the task's RunLevel is Highest) and restarting itself if
# the process ever dies unexpectedly. Run this once, from an elevated
# PowerShell prompt:
#
#   .\register_autostart.ps1
#
# To undo: .\unregister_autostart.ps1
# To launch it right now instead of waiting for next logon:
#   Start-ScheduledTask -TaskName "pysentinel-siem"

$TaskName = "pysentinel-siem"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonwExe = Join-Path $ProjectDir ".venv\Scripts\pythonw.exe"
$ScriptPath = Join-Path $ProjectDir "desktop_app.py"

if (-not (Test-Path $PythonwExe)) {
    Write-Error "pythonw.exe not found at $PythonwExe -- create the venv first (python -m venv .venv; pip install -r requirements.txt)."
    exit 1
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script from an elevated (Run as Administrator) PowerShell prompt -- registering a task with RunLevel Highest requires it."
    exit 1
}

$action = New-ScheduledTaskAction -Execute $PythonwExe -Argument "`"$ScriptPath`"" -WorkingDirectory $ProjectDir
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Registered scheduled task '$TaskName' -- pysentinel-siem will now launch automatically at logon."
Write-Host "It runs elevated without a UAC prompt (Task Scheduler grants that non-interactively for an admin account)."
Write-Host "Crash resilience: Windows will restart it up to 3 times, 1 minute apart, if the process dies."
Write-Host ""
Write-Host "To undo:                .\unregister_autostart.ps1"
Write-Host "To launch it right now:  Start-ScheduledTask -TaskName '$TaskName'"
