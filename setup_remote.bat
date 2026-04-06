@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup_remote.ps1" %*
exit /b %ERRORLEVEL%
