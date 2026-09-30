@echo off
setlocal
rem Запуск из консоли: logmask service.log  (добавьте папку в PATH, чтобы вызывать отовсюду)
chcp 65001 >nul
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
%PY% "%~dp0logmask.py" %*
exit /b %errorlevel%
