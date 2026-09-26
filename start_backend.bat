@echo off
set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
echo ============================================================
echo Starting Malicious File Analyzer Backend
echo Server URL: http://localhost:5000
echo API Docs:   http://localhost:5000/docs
echo ============================================================
"C:\msys64\ucrt64\bin\python.exe" backend\app.py
pause
