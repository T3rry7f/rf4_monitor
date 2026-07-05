@echo off
setlocal

cd /d "%~dp0"

echo [rf4_monitor] Starting RF4 monitor launcher
echo [rf4_monitor] Tip: run as Administrator if you need to update the system hosts file or bind 80/443/9216 directly.

if exist ".venv\Scripts\python.exe" goto run_venv

where py >nul 2>nul
if not errorlevel 1 goto run_py

where python >nul 2>nul
if not errorlevel 1 goto run_python

echo.
echo [rf4_monitor] Python 3 was not found.
echo [rf4_monitor] Install Python 3 first, then run 安装依赖.bat.
pause
exit /b 1

:run_venv
echo [rf4_monitor] Using .venv\Scripts\python.exe
".venv\Scripts\python.exe" rf4_monitor.py %*
goto finish

:run_py
echo [rf4_monitor] Using py -3
py -3 rf4_monitor.py %*
goto finish

:run_python
echo [rf4_monitor] Using python
python rf4_monitor.py %*

:finish
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
    echo.
    echo [rf4_monitor] Launcher exited with code %EXIT_CODE%.
    pause
)
exit /b %EXIT_CODE%
