@echo off
REM One-command launch: starts the collector (its own elevated window,
REM will prompt for UAC once) and the dashboard (its own window), then
REM opens the dashboard in your browser. Close either window to stop it.
cd /d "%~dp0"

echo Starting collector (will prompt for Administrator)...
start "pysentinel-siem collector" cmd /c ".\start_collector.bat"

echo Starting dashboard...
start "pysentinel-siem dashboard" cmd /c ".\start_dashboard.bat"

timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000
