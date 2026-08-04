# Creates a desktop shortcut that launches the pysentinel-siem desktop
# app with no console window (uses pythonw.exe, the windowless Python
# interpreter, instead of python.exe). Run this once:
#
#   .\create_shortcut.ps1
#
# The shortcut still triggers one UAC prompt on launch (the app
# self-elevates, since it reads Security/Sysmon) -- this script only
# gets rid of the distracting console window and the need to type a
# command at all.

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonwExe = Join-Path $ProjectDir ".venv\Scripts\pythonw.exe"
$ScriptPath = Join-Path $ProjectDir "desktop_app.py"

if (-not (Test-Path $PythonwExe)) {
    Write-Error "pythonw.exe not found at $PythonwExe -- create the venv first (python -m venv .venv; pip install -r requirements.txt)."
    exit 1
}

$ShortcutPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "pysentinel-siem.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $PythonwExe
$Shortcut.Arguments = "`"$ScriptPath`""
$Shortcut.WorkingDirectory = $ProjectDir
$Shortcut.Description = "pysentinel-siem -- local SIEM dashboard"
$Shortcut.Save()

Write-Host "Shortcut created: $ShortcutPath"
Write-Host "Double-click it any time to launch pysentinel-siem (one UAC prompt, no console window)."
