@echo off
cd /d "%~dp0"
"%~dp0MarkEmptyContainers.exe" apply
echo.
pause
