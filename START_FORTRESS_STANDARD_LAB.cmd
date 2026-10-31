@echo off
setlocal
cd /d "%~dp0"
echo FORTRESS STANDARD LAB - local synthetic demo only, not the production app.
echo Open the URL shown below manually. The lab expires after about 60 seconds.
echo Keep this window open; press Ctrl+Break to stop.
"%~dp0.venv\Scripts\python.exe" -I -B "%~dp0scripts\fortress_standard_lab_server.py"
exit /b %errorlevel%
