@echo off
chcp 65001 >nul
REM Double-click: download trivy.exe / terraform.exe into tools\ (once). No AWS account needed.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_tools.ps1"
echo.
echo Done. Next: double-click run_experiments.bat
pause
