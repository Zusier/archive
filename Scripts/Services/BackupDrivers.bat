@echo off
SETLOCAL EnableDelayedExpansion
set filename=DriverBackup.reg
del /F %filename% >nul 2>&1

echo Windows Registry Editor Version 5.00 >> %filename%
echo. >> %filename%
echo ;Services Backup on %date% at%time% >> %filename%
echo. >> %filename%

for /f "delims=," %%i in ('driverquery /FO CSV') do (
	set svc=%%~i
	for /f "tokens=3" %%f in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%%~i" /t REG_DWORD /s /c /f "Start" /e^| findstr "[0-4]$"') do (
		set start=%%f
		if !start!==0x4 (
			echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!svc!] >> %filename%
			echo "Start"=dword:00000004 >> %filename%
			echo. >> %filename% )
		if !start!==0x3 (
			echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!svc!] >> %filename%
			echo "Start"=dword:00000003 >> %filename%
			echo. >> %filename% )
		if !start!==0x2 (
			echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!svc!] >> %filename%
			echo "Start"=dword:00000002 >> %filename%
			echo. >> %filename% )
		if !start!==0x1 (
			echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!svc!] >> %filename%
			echo "Start"=dword:00000001 >> %filename%
			echo. >> %filename% )
		if !start!==0x0 (
			echo [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\!svc!] >> %filename%
			echo "Start"=dword:00000000 >> %filename%
			echo. >> %filename% )
	) 
) >nul 2>&1

notepad %filename%