@echo off
REM Launches the dashboard. No elevation needed.
cd /d "%~dp0"
.venv\Scripts\python.exe run_dashboard.py
