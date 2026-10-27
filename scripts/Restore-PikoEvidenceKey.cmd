@echo off
setlocal
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Install-Piko-Interactive.ps1" -RestoreEvidenceKey
if errorlevel 1 (
  echo.
  echo Recupero non completato. Archivio, chiavi e copie conservati.
  pause
  exit /b 1
)
endlocal
