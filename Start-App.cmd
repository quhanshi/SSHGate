@echo off
setlocal
cd /d "%~dp0"
if exist "%~dp0dist\SSHGate\SSHGate.exe" (
  start "SSH Gate" "%~dp0dist\SSHGate\SSHGate.exe" --config "%~dp0config.json"
  exit /b 0
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\Start-Backend.ps1"
if errorlevel 1 pause
