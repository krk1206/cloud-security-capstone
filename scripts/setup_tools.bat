@echo off
REM 더블클릭용: trivy.exe / terraform.exe 를 tools\ 에 받는다 (한 번만). AWS 계정 불필요
chcp 65001 >nul
powershell -ExecutionPolicy Bypass -File "%~dp0setup_tools.ps1"
pause
