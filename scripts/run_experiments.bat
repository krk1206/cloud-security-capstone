@echo off
REM 더블클릭용: 혼자 돌리는 실험 한 방 (tools\ 의 trivy/terraform 사용, 없으면 NOT_RUN). LLM API·AWS·push 없음
chcp 65001 >nul
powershell -ExecutionPolicy Bypass -File "%~dp0run_experiments.ps1" %*
echo.
echo 끝. 결과: experiments\RESULTS_SUMMARY.md
pause
