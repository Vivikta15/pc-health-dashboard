@echo off
rem Launcher: runs PCHealth.ps1 without needing to change PowerShell's execution policy.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCHealth.ps1" %*
