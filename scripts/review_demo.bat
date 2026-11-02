@echo off
chcp 65001 >nul
REM Double-click: B/C local review demo (no tools/API needed). arg: manual | mock | split
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0review_demo.ps1" %1
pause
