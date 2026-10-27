@echo off
setlocal
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0Install-Piko-Interactive.ps1" -ResumeInterruptedUpdate
if errorlevel 1 (
  echo.
  echo Ripresa non completata. Archivio e copie conservati; consulta il messaggio qui sopra.
  pause
  exit /b 1
)
endlocal
