@echo off
chcp 65001 >nul
REM Windows -> WSL -> project runner (docs/PROJECT_REVIEW_WEEK4.md section 12). Double-click.
REM Requires: WSL with Ubuntu, python3, tools installed inside WSL (bash scripts/setup_tools.sh).
REM wsl --cd converts the Windows path of this repo to the WSL path (/mnt/c/...).
set "REPO=%~dp0.."
echo [wsl] repo: %REPO%
wsl.exe --cd "%REPO%" -e bash -lc "echo host: $(hostname) ; bash scripts/run_experiments.sh ; echo ; echo done - see experiments/RESULTS_SUMMARY.md ; read -p \"Press Enter to close\" _"
if errorlevel 1 (
  echo [wsl] failed. Is WSL installed?  In PowerShell: wsl --install   (then: bash scripts/setup_tools.sh inside WSL)
  pause
)
