@echo off
rem Double-click helper: runs install.ps1 with the given arguments.
rem Example: install.bat -Config ..\targets.json -TeamsWebhookUrl "https://..."
rem For -RunAs System (default), right-click and "Run as administrator".
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
pause
