@echo off
cd /d "%~dp0"
"%~dp0MarkEmptyContainers.exe" revert
echo.
pause
