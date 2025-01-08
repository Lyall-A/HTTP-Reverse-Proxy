@echo off
cd %~dp0

:LOOP
reverseproxy start

echo Restarting in 5 seconds...
timeout /t 5 > nul
goto :LOOP