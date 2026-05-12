@echo off
REM ============================================================
REM  ejecutar_backup.bat
REM  Lanza una copia de seguridad puntual.
REM  Programar en el Programador de Tareas (diario/semanal).
REM ============================================================
cd /d "%~dp0"
python.exe "%~dp0backup_seguro.py"
exit /b %errorlevel%
