@echo off
REM IoT Security Dashboard - Quick Start

echo.
echo ========================================
echo  IoT Security Dashboard - Startup
echo ========================================
echo.

REM Install dependencies
echo [1/2] Installing Python dependencies...
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo Error installing dependencies
    pause
    exit /b 1
)

echo.
echo [2/2] Starting dashboard on http://localhost:5000...
echo.
echo Press Ctrl+C to stop the server
echo.

REM Run the dashboard
py dashboard.py

pause
