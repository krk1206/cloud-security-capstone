@echo off
chcp 65001 >nul
REM Double-click: unit + integration tests
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_tests.ps1"
pause
