@echo off
REM One click: unit tests -> experiments (8 steps) -> HTML report -> browser.
REM Needs Python 3 on this PC. trivy/terraform go to tools\ via the "tool setup" button (or scripts\setup_tools.bat).
REM Does NOT: call any LLM API, run Claude Code, touch AWS, terraform apply, git push.
setlocal
set "IACPATCH_ROOT=%~dp0"
set "PYTHONPATH=%~dp0src"
set "PYTHONIOENCODING=utf-8"
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -X utf8 -m iacpatch.app %*
) else (
  python -X utf8 -m iacpatch.app %*
)
if errorlevel 1 (
  echo.
  echo IaCPatch exited with an error. If Python is missing, install Python 3 from python.org and tick "Add to PATH".
  pause
)
endlocal
