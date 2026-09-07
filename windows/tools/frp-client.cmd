@echo off
REM frp-client.cmd — Windows PowerShell 5.1 wrapper (ExecutionPolicy Bypass, -File only; no irm|iex)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0FrpClient.ps1" %*
