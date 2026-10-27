@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Environnement projet absent. Suivre README.md.
  pause
  exit /b 1
)
.venv\Scripts\python.exe -I scripts\dev.py
if errorlevel 1 pause
endlocal
