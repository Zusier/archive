@echo off
SETLOCAL EnableDelayedExpansion
set filename=ServiceBackup.reg
del /F %filename% >nul 2>&1

echo Windows Registry Editor Version 5.00 >> %filename%
echo. >> %filename%
echo ;Services Backup on %date% at %time% >> %filename%
echo. >> %filename%
for /f "skip=1" %%i in ('wmic service get Name^| findstr "[a-z]"^| findstr /V "TermService"') do (
	set svc=%%i
	set svc=!svc: =!
	for /f "tokens=3" %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!svc!" /t REG_DWORD /s /c /f "Start" /e^| findstr "[0-4]$"') do (
		set /A start=%%i
		echo !start!
		echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!svc!] >> %filename%
		echo "Start"=dword:0000000!start! >> %filename%
		echo. >> %filename%
	)
) >nul 2>&1

notepad %filename%