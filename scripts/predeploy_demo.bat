@echo off
REM 더블클릭용. PowerShell 스크립트를 호출한다 (mock, 오프라인 plan, push 없음)
powershell -ExecutionPolicy Bypass -File "%~dp0predeploy_demo.ps1" %1
pause
