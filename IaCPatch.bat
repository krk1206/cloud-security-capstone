@echo off
REM Opens the IaCPatch screen in your browser (local server on 127.0.0.1). Same as IaCPatch.exe, but needs Python 3.10+.
REM Picks a Python 3.10+ (the "py -3" launcher may point at an old 3.7 - seen on a team PC).
REM trivy/terraform go to tools\ via the "tool setup" button (or scripts\setup_tools.bat).
REM Does NOT: call any LLM API, run Claude Code, touch AWS, terraform apply, git push.
setlocal enabledelayedexpansion
set "IACPATCH_ROOT=%~dp0"
set "PYTHONPATH=%~dp0src"
set "PYTHONIOENCODING=utf-8"
set "PYCMD="
for %%C in ("py -3.14" "py -3.13" "py -3.12" "py -3.11" "py -3.10" "python" "python3" "py -3") do (
  if not defined PYCMD (
    %%~C "%~dp0scripts\pyver.py" >nul 2>nul
    if !errorlevel! equ 0 set "PYCMD=%%~C"
  )
)
if not defined PYCMD (
  echo Python 3.10 or newer was not found. Install it from python.org and tick "Add python.exe to PATH".
  pause
  exit /b 1
)
echo using: %PYCMD%
%PYCMD% -X utf8 -m iacpatch.app %*
if errorlevel 1 (
  echo.
  echo IaCPatch exited with an error. See experiments\run_experiments.log
  pause
)
endlocal
