@echo off
rem TODO(PAT-signed): Replace this script with actual signtool signing.
rem Requires an OV/EV Authenticode code-signing certificate + Windows SDK signtool.exe.
rem To sign: signtool.exe sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /f cert.pfx /p %CERT_PASSWORD% %1
rem SmartScreen warning: unsigned MSI will trigger "Windows protected your PC" on install.
rem The pilot admin can proceed by clicking "More info" -> "Run anyway".
echo [sign-hook] Signing not configured. Binary is UNSIGNED.
exit /b 0
