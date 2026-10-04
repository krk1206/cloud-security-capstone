@echo off
chcp 65001 >nul
REM Double-click: run the whole experiment (uses tools\ trivy/terraform; NOT_RUN if missing). No LLM API / AWS / push.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_experiments.ps1" %*
echo.
echo Done. Results: experiments\RESULTS_SUMMARY.md
pause
