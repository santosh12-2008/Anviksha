@echo off
title Anviksha (अन्वीक्षा) Platform Launcher
echo ========================================================
echo   Launching Anviksha (अन्वीक्षा) AI Forensics Platform
echo   Cognitive Email Threat Detection, Geolocation & Intel
echo ========================================================
echo.
echo Starting Backend Server on http://127.0.0.1:8000 ...
start "Anviksha Backend" cmd /k "cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 2 /nobreak >nul

echo Starting Frontend Server on http://127.0.0.1:5173 ...
start "Anviksha Frontend" cmd /k "cd frontend && npm run dev -- --host 127.0.0.1 --port 5173"

echo.
echo Both servers started!
echo Open your browser at: http://127.0.0.1:5173
echo.
pause
