@echo off
REM ============================================================
REM  iniciar_panel.bat
REM  Lanza el panel web (FastAPI + Uvicorn) en segundo plano.
REM  Acceso:  http://localhost:8080
REM ============================================================
cd /d "%~dp0"
start "" /B pythonw.exe "%~dp0panel_web.py"
exit /b 0
