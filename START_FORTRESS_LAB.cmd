@echo off
setlocal
cd /d "%~dp0"
echo FORTRESS LAB - local synthetic demo only, not the production app.
echo Open the URL shown below manually. The lab expires after about 60 seconds.
echo Keep this window open; press Ctrl+Break or Ctrl+C to stop.
"%~dp0.venv\Scripts\python.exe" -I -B "%~dp0scripts\fortress_lab_demo.py"
exit /b %errorlevel%
