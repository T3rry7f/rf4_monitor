@echo off
setlocal

cd /d "%~dp0"

echo [rf4_monitor] Installing full Python dependencies from requirements.txt
echo [rf4_monitor] Using Tsinghua PyPI mirror: https://pypi.tuna.tsinghua.edu.cn/simple

pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple --trusted-host pypi.tuna.tsinghua.edu.cn
if errorlevel 1 (
    echo.
    echo [rf4_monitor] Dependency install failed.
    pause
    exit /b 1
)

echo.
echo [rf4_monitor] Dependency install completed successfully.
pause
