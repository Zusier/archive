:: 1. Get list of services.
:: 2. Write reg path of services to reg file
:: 3. Get state of services
:: 4. Translate text state (e.g. Disabled) to number (e.g. 4)

@echo off
SETLOCAL EnableDelayedExpansion

del /F ServiceBackup.reg >nul 2>&1

echo Windows Registry Editor Version 5.00 >> ServiceBackup.reg
echo. >> ServiceBackup.reg
echo ;Services and Drivers Backup on %date% at%time% >> ServiceBackup.reg
echo. >> ServiceBackup.reg

for /f "tokens=1" %%i in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" /t REG_DWORD /s /f "Start"^| findstr "CurrentControlSet\Services"') do (
	echo [%%i] >> ServiceBackup.reg
	set svc=%%i
	for /f "tokens=3" %%i in ('reg query "!svc!" /t REG_DWORD /s /c /f "Start" /e^| findstr "[0-4]$"') do (
		set start=%%i
		if !start!==0x4 set start="Start"=dword:00000004
		if !start!==0x3 set start="Start"=dword:00000003
		if !start!==0x2 set start="Start"=dword:00000002
		if !start!==0x1 set start="Start"=dword:00000001
		if !start!==0x0 set start="Start"=dword:00000000
		echo.!start! >> ServiceBackup.reg
		echo. >> ServiceBackup.reg
	)

)

notepad ServiceBackup.reg