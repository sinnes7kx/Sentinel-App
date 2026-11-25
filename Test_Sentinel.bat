@echo off
setlocal
cd /d "%~dp0"
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if not errorlevel 1 goto launcher

for /f "delims=" %%I in ('where.exe python.exe 2^>nul') do (
    call :probe "%%I"
    if not errorlevel 1 goto interpreter
)
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    call :probe "%%D\python.exe"
    if not errorlevel 1 goto interpreter
)
echo Sentinel requires Python 3.10 or later.
pause
exit /b 1

:launcher
py -3 test_local.py
goto finished

:interpreter
"%SENTINEL_PYTHON%" test_local.py

:finished
set "TEST_EXIT=%ERRORLEVEL%"
echo.
echo Test exit code: %TEST_EXIT%
echo See the log path printed above for details.
pause
exit /b %TEST_EXIT%

:probe
if not exist "%~1" exit /b 1
"%~1" -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>&1
if errorlevel 1 exit /b 1
set "SENTINEL_PYTHON=%~1"
exit /b 0
