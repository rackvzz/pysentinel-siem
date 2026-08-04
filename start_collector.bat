@echo off
REM Launches the collector. Self-elevates via UAC if not already running
REM as Administrator (the Security/Sysmon channels require it), so you
REM can just double-click this or run it from a regular terminal.
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting Administrator privileges for the collector...
    powershell -NoProfile -Command "Start-Process -FilePath '%~dp0.venv\Scripts\python.exe' -ArgumentList '\"%~dp0run_collector.py\"' -WorkingDirectory '%~dp0' -Verb RunAs"
    exit /b
)

.venv\Scripts\python.exe run_collector.py
