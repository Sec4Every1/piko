@echo off
setlocal
powershell.exe -NoLogo -NoProfile -File "%~dp0Start-Piko.ps1"
if errorlevel 1 (
  echo.
  echo piko non e' stato avviato. Leggere il messaggio qui sopra.
  echo Consultare MANUALE_UTENTE.md nella stessa cartella.
  pause
  exit /b 1
)
endlocal
