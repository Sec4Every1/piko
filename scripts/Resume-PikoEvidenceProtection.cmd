@echo off
setlocal
powershell.exe -NoLogo -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0Install-Piko-Interactive.ps1" -ResumeEvidenceProtection
if errorlevel 1 (
  echo Attivazione non completata. Stato e copie conservati.
  pause
  exit /b 1
)
endlocal
