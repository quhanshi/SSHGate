@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Build-Frontend.ps1"
pause
