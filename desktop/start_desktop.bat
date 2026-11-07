@echo off
title NetCheck Desktop Companion
echo ==============================================
echo  NetCheck - Securitate Retea (Desktop Wrapper)
echo ==============================================
echo.
echo Se porneste aplicatia de desktop cu System Tray si Widget...

REM Verificare python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [Eroare] Python nu a fost gasit in PATH. Te rugam sa instalezi Python.
    pause
    exit /b 1
)

REM Pornire companion desktop
python "%~dp0netcheck_desktop.py"

pause
