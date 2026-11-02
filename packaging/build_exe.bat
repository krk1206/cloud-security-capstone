@echo off
REM Build IaCPatch.exe (Windows, once). Result: IaCPatch.exe in the repo root.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_exe.ps1" %*
pause
