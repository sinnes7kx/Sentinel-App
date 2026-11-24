@echo off
cd /d "%~dp0"
py -3 -m pip install "dnspython>=2.6,<3"
pause
