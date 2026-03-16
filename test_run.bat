@echo off
echo Starting RDP Scanner...
echo.
target\release\rdpscan.exe
echo.
echo Exit code: %ERRORLEVEL%
pause
