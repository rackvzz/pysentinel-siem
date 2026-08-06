@echo off
REM Launches the dashboard. No elevation needed.
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

.venv\Scripts\python.exe run_dashboard.py
