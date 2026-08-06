# One-command setup: creates the virtual environment and installs
# dependencies, so getting from a fresh clone/download to a runnable app
# is "run this once" instead of three separate manual commands. Safe to
# re-run any time (e.g. after pulling an update with new dependencies) --
# every step here is a no-op if already done.
#
#   .\setup.ps1
#
# After this finishes, either:
#   .\create_shortcut.ps1   (once, for a double-click desktop icon)
#   .\start.bat             (browser dashboard)
#   python desktop_app.py   (native app, from an activated venv)

$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectDir

$PythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $PythonCmd) {
    Write-Error "Python isn't on PATH. Install Python 3.10+ from https://python.org (check `"Add python.exe to PATH`" during install), then re-run this script."
    exit 1
}

$versionOutput = & python --version 2>&1
if ($versionOutput -match "Python (\d+)\.(\d+)") {
    $major = [int]$Matches[1]
    $minor = [int]$Matches[2]
    if ($major -lt 3 -or ($major -eq 3 -and $minor -lt 10)) {
        Write-Error "Found $versionOutput -- this project needs Python 3.10 or newer. Install a newer version from https://python.org."
        exit 1
    }
} else {
    Write-Warning "Couldn't parse '$versionOutput' to confirm the Python version -- continuing anyway."
}

$VenvPython = Join-Path $ProjectDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "Creating virtual environment (.venv)..."
    python -m venv .venv
    if (-not (Test-Path $VenvPython)) {
        Write-Error "Virtual environment creation failed -- .venv\Scripts\python.exe wasn't created."
        exit 1
    }
} else {
    Write-Host "Virtual environment already exists -- skipping creation."
}

Write-Host "Installing dependencies..."
& $VenvPython -m pip install --quiet --upgrade pip
& $VenvPython -m pip install --quiet -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Error "pip install failed -- see the output above."
    exit 1
}

Write-Host ""
Write-Host "Setup complete. Next:" -ForegroundColor Green
Write-Host "  .\create_shortcut.ps1   -- once, for a double-click desktop icon (recommended)"
Write-Host "  .\start.bat             -- browser dashboard, no shortcut needed"
Write-Host ""
Write-Host "Optional, only if you want them (see README for details):" -ForegroundColor DarkGray
Write-Host "  - Sysmon (needed for PowerShell/credential/persistence detection rules)" -ForegroundColor DarkGray
Write-Host "  - A free ThreatFox API key (needed for the threat-intel feed)" -ForegroundColor DarkGray
