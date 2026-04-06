@echo off
setlocal
powershell -ExecutionPolicy Bypass -File "%~dp0setup_remote.ps1" %*
exit /b %ERRORLEVEL%
