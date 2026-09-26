@echo off
set "PATH=C:\msys64\ucrt64\bin;C:\msys64\usr\bin;%PATH%"
echo ============================================================
echo Running Malicious File Analyzer Test Suite
echo ============================================================
"C:\msys64\ucrt64\bin\pytest.exe" -v tests\
pause
