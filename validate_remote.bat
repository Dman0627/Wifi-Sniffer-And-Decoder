@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0validate_remote.ps1" %*
exit /b %ERRORLEVEL%
