@echo off
SETLOCAL EnableDelayedExpansion
set filename=ServiceAndDriverBackup.reg
del /F %filename% >nul 2>&1

echo Windows Registry Editor Version 5.00 >> %filename%
echo. >> %filename%
echo ;Services Backup on %date% at %time% >> %filename%
echo. >> %filename%

for /f "tokens=1" %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /t REG_DWORD /s /f "Start"^| findstr "CurrentControlSet\Services"') do (
	set svc=%%i
	for /f "tokens=3" %%i in ('reg query "!svc!" /t REG_DWORD /s /c /f "Start" /e^| findstr "[0-4]$"') do (
		set /A start=%%i
		echo [!svc!] >> %filename%
		echo "Start"=dword:0000000!start! >> %filename%
		echo. >> %filename%
	)
) >nul 2>&1

notepad %filename%