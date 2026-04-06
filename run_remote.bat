@echo off
setlocal
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_remote.ps1" %*
exit /b %ERRORLEVEL%
