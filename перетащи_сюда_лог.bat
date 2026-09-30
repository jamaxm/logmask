@echo off
setlocal
rem Перетащите мышкой один или несколько лог-файлов (или папку) на этот файл.
rem Рядом появятся копии с суффиксом .masked — исходники не меняются.
chcp 65001 >nul
if "%~1"=="" (
  echo Перетащите лог-файл или папку на этот значок.
  pause
  exit /b 2
)
where py >nul 2>nul
if %errorlevel%==0 (set "PY=py -3") else (set "PY=python")
%PY% "%~dp0logmask.py" %*
echo.
pause
