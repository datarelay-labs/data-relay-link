@echo off
REM frp-autostart.cmd — product boot entrypoint for the SYSTEM scheduled task.
REM Redirect stdout/stderr so PowerShell Write-Host cannot hang without a console.
setlocal
set "FRP_ROOT=%~dp0.."
set "LOG=%FRP_ROOT%\logs\autostart.log"
if not exist "%FRP_ROOT%\logs" mkdir "%FRP_ROOT%\logs" >nul 2>&1
echo START %DATE% %TIME%>>"%LOG%"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0FrpClient.ps1" start >>"%LOG%" 2>&1
set "RC=%ERRORLEVEL%"
echo EXIT %RC% %DATE% %TIME%>>"%LOG%"
exit /b %RC%
