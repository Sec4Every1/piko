@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Piko-Interactive.ps1"
if errorlevel 1 (
  echo.
  echo Installazione non completata. Consulta il messaggio qui sopra.
  pause
  exit /b 1
)
endlocal
