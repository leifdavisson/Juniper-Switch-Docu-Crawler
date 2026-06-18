@echo off
REM Cisco Switch Docu-Crawler - Windows 11 Bootstrap
REM Bypasses PowerShell execution policies to run the pre-req checker and script.

cd /d "%~dp0"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "run.ps1"
pause
