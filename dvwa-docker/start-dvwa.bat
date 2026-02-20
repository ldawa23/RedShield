@echo off
title DVWA Docker + Ngrok Setup
color 0A

echo.
echo  ╔═══════════════════════════════════════════════════════════════╗
echo  ║       🛡️  DVWA Docker + Ngrok Setup for RedShield  🛡️         ║
echo  ╚═══════════════════════════════════════════════════════════════╝
echo.

REM Change to script directory
cd /d "%~dp0"

REM Check if Docker is running
echo [1/5] Checking Docker status...
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  ⚠️  Docker is not running!
    echo.
    echo  Please do the following:
    echo    1. Open Docker Desktop from Start Menu
    echo    2. Wait for it to fully start (green icon in system tray)
    echo    3. Run this script again
    echo.
    pause
    exit /b 1
)
echo     ✅ Docker is running

REM Pull DVWA image
echo.
echo [2/5] Pulling DVWA Docker image...
docker pull vulnerables/web-dvwa

REM Stop existing container if any
echo.
echo [3/5] Cleaning up existing containers...
docker stop dvwa 2>nul
docker rm dvwa 2>nul

REM Start DVWA container
echo.
echo [4/5] Starting DVWA container on port 8888...
docker-compose up -d

REM Wait for container to be ready
echo.
echo [5/5] Waiting for DVWA to initialize (15 seconds)...
timeout /t 15 /nobreak >nul

echo.
echo  ╔═══════════════════════════════════════════════════════════════╗
echo  ║                   ✅ DVWA IS NOW RUNNING!                     ║
echo  ╠═══════════════════════════════════════════════════════════════╣
echo  ║                                                               ║
echo  ║   Local URL:     http://localhost:8888                        ║
echo  ║   Login:         admin / password                             ║
echo  ║   Security:      Set to LOW for testing                       ║
echo  ║                                                               ║
echo  ║   First time? Go to http://localhost:8888/setup.php           ║
echo  ║   and click "Create / Reset Database"                         ║
echo  ║                                                               ║
echo  ╚═══════════════════════════════════════════════════════════════╝
echo.
echo  🌐 Starting ngrok tunnel...
echo  Copy the "Forwarding" URL to use in RedShield
echo.
echo  ───────────────────────────────────────────────────────────────
"%~dp0ngrok.exe" http 8888
