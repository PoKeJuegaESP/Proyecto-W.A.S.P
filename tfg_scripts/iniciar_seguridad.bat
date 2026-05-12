@echo off
REM ============================================================
REM  iniciar_seguridad.bat
REM  Lanza el script seguridad_activa.py en segundo plano (sin ventana).
REM  Pensado para ejecutarse al arranque de Windows Server.
REM ============================================================
cd /d "%~dp0"
start "" /B pythonw.exe "%~dp0seguridad_activa.py"
exit /b 0
