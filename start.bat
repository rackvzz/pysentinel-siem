@echo off
REM One-command launch: starts the collector (its own elevated window,
REM will prompt for UAC once) and the dashboard (its own window), then
REM opens the dashboard in your browser. Close either window to stop it.
REM
REM First run on a fresh clone (no .venv yet)? This bootstraps itself via
REM setup.ps1 before doing anything else -- no separate manual step needed.
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo First run detected -- setting up the virtual environment and dependencies...
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\setup.ps1"
    if not exist ".venv\Scripts\python.exe" (
        echo Setup failed -- see the messages above.
        pause
        exit /b 1
    )
)

echo Starting collector (will prompt for Administrator)...
start "pysentinel-siem collector" cmd /c ".\start_collector.bat"

echo Starting dashboard...
start "pysentinel-siem dashboard" cmd /c ".\start_dashboard.bat"

timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000
