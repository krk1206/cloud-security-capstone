@echo off
chcp 65001 >nul
REM Double-click: predeploy demo (mock, offline plan, no push)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0predeploy_demo.ps1" %1
pause
