@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Piko-Interactive.ps1" -RecoverInconsistentInstallation
if errorlevel 1 (
  echo.
  echo Recupero non completato. Gli originali e i backup disponibili sono conservati; consulta il messaggio qui sopra.
  pause
  exit /b 1
)
endlocal
