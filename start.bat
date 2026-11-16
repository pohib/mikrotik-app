@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul

echo Starting MikroTik VPN Manager v1.10.0...
echo Log: startup.log
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1"
set "RC=%ERRORLEVEL%"
echo.
echo Launcher exit code: %RC%
echo Press any key to close this window...
pause >nul
exit /b %RC%
