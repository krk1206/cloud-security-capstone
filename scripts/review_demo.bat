@echo off
REM 더블클릭용: B·C 로컬 검토 흐름 데모 (도구·API 불필요). 인자: manual | mock | split
powershell -ExecutionPolicy Bypass -File "%~dp0review_demo.ps1" %1
pause
